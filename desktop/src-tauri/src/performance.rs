use serde::Serialize;
use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};

#[derive(Default)]
pub struct PerformanceState(Arc<Mutex<Option<Sampler>>>);

struct Sampler {
    system: System,
    last: Instant,
    last_snapshot: Snapshot,
}

#[derive(Clone, Debug, PartialEq, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    cpu_percent: Option<f32>,
    memory_bytes: u64,
    process_count: usize,
}

fn sample(state: &Mutex<Option<Sampler>>) -> Result<Snapshot, String> {
    let mut guard = state.lock().map_err(|_| "PERFORMANCE_UNAVAILABLE")?;
    if let Some(sampler) = guard.as_ref() {
        if sampler.last.elapsed() < Duration::from_secs(1) {
            return Ok(sampler.last_snapshot.clone());
        }
    }
    let first = guard.is_none();
    let sampler = guard.get_or_insert_with(|| Sampler {
        system: System::new(),
        last: Instant::now(),
        last_snapshot: Snapshot::default(),
    });
    sampler.system.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::nothing().with_cpu().with_memory(),
    );
    let mut pids = HashSet::from([Pid::from_u32(std::process::id())]);
    loop {
        let previous = pids.len();
        for (id, process) in sampler.system.processes() {
            if process
                .parent()
                .is_some_and(|parent| pids.contains(&parent))
            {
                pids.insert(*id);
            }
        }
        if pids.len() == previous {
            break;
        }
    }
    let mut snapshot = Snapshot::default();
    let mut cpu = 0.0;
    for id in pids {
        if let Some(process) = sampler.system.process(id) {
            snapshot.memory_bytes += process.memory();
            cpu += process.cpu_usage();
            snapshot.process_count += 1;
        }
    }
    let cores = std::thread::available_parallelism()
        .map(|value| value.get())
        .unwrap_or(1) as f32;
    snapshot.cpu_percent = if first {
        None
    } else {
        Some((cpu / cores).clamp(0.0, 100.0))
    };
    sampler.last = Instant::now();
    sampler.last_snapshot = snapshot.clone();
    Ok(snapshot)
}

fn stop(state: &Mutex<Option<Sampler>>) -> Result<(), String> {
    *state.lock().map_err(|_| "PERFORMANCE_UNAVAILABLE")? = None;
    Ok(())
}

#[tauri::command]
pub async fn performance_sample(
    state: tauri::State<'_, PerformanceState>,
) -> Result<Snapshot, String> {
    let sampler = Arc::clone(&state.0);
    // Enumerating the process tree must not block Tauri's async executor or the UI.
    tauri::async_runtime::spawn_blocking(move || sample(&sampler))
        .await
        .map_err(|_| "PERFORMANCE_UNAVAILABLE")?
}

#[tauri::command]
pub async fn performance_stop(state: tauri::State<'_, PerformanceState>) -> Result<(), String> {
    let sampler = Arc::clone(&state.0);
    tauri::async_runtime::spawn_blocking(move || stop(&sampler))
        .await
        .map_err(|_| "PERFORMANCE_UNAVAILABLE")?
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{BufRead, BufReader, Read, Write},
        process::{Child, Command, Stdio},
        sync::mpsc,
    };

    struct FixtureChild(Child);
    impl Drop for FixtureChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    fn native_samples_cache_release_and_restart_without_an_old_cpu_baseline() {
        let state = PerformanceState::default();
        assert!(state.0.lock().unwrap().is_none());
        let first = sample(&state.0).unwrap();
        assert_eq!(first.cpu_percent, None);
        assert!(first.memory_bytes > 0);
        assert!(first.process_count >= 1);
        assert_eq!(sample(&state.0).unwrap(), first);
        let json = serde_json::to_value(&first).unwrap();
        assert_eq!(json.as_object().unwrap().len(), 3);
        assert!(json["cpuPercent"].is_null());
        assert_eq!(json["memoryBytes"], first.memory_bytes);
        assert_eq!(json["processCount"], first.process_count);

        std::thread::sleep(Duration::from_millis(1050));
        let next = sample(&state.0).unwrap();
        assert!(next
            .cpu_percent
            .is_some_and(|cpu| cpu.is_finite() && (0.0..=100.0).contains(&cpu)));
        stop(&state.0).unwrap();
        assert!(
            state.0.lock().unwrap().is_none(),
            "stop must release the process snapshot"
        );
        stop(&state.0).unwrap();
        assert_eq!(sample(&state.0).unwrap().cpu_percent, None);
        stop(&state.0).unwrap();
    }

    #[test]
    fn native_sample_includes_a_live_child_process() {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command.env("OPEN_REVERSELAB_PERFORMANCE_FIXTURE", "1");
        command
            .args([
                "--exact",
                "performance::tests::fixture_child",
                "--ignored",
                "--nocapture",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x08000000);
        }
        let mut child = FixtureChild(command.spawn().unwrap());
        let output = child.0.stdout.take().unwrap();
        let (send, receive) = mpsc::channel();
        let reader = std::thread::spawn(move || {
            for line in BufReader::new(output).lines().map_while(Result::ok) {
                if line == "PERFORMANCE_FIXTURE_READY" {
                    let _ = send.send(());
                }
            }
        });
        receive
            .recv_timeout(Duration::from_secs(10))
            .expect("child process ready");
        let state = PerformanceState::default();
        let snapshot = sample(&state.0).unwrap();
        let guard = state.0.lock().unwrap();
        let system = &guard.as_ref().unwrap().system;
        let child_process = system.process(Pid::from_u32(child.0.id())).unwrap();
        let root = system.process(Pid::from_u32(std::process::id())).unwrap();
        assert_eq!(child_process.parent(), Some(root.pid()));
        assert!(child_process.memory() >= 16 * 1024 * 1024);
        assert!(snapshot.process_count >= 2);
        assert!(snapshot.memory_bytes >= child_process.memory() + root.memory());
        drop(guard);
        child.0.stdin.as_mut().unwrap().write_all(b"x").unwrap();
        assert!(child.0.wait().unwrap().success());
        reader.join().unwrap();
        stop(&state.0).unwrap();
    }

    #[test]
    #[ignore = "child-process fixture, launched by the native sampling test"]
    fn fixture_child() {
        if std::env::var("OPEN_REVERSELAB_PERFORMANCE_FIXTURE").as_deref() != Ok("1") {
            return;
        }
        let memory = vec![1_u8; 16 * 1024 * 1024];
        println!("PERFORMANCE_FIXTURE_READY");
        std::io::stdout().flush().unwrap();
        let mut signal = [0];
        std::io::stdin().read_exact(&mut signal).unwrap();
        std::hint::black_box(memory);
    }
}
