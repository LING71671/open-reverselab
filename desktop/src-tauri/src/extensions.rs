use serde_json::{json, Value};
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::sync::{atomic::{AtomicBool, Ordering}, Arc};

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

async fn service_operation(service: &'static str, request: Value, execution_id: Option<String>, timeout_ms: Option<u64>, on_started: tauri::ipc::Channel<Value>) -> Result<Value, String> {
    let root = super::get_repo_root()?;
    let execution_id = execution_id.unwrap_or_else(|| format!("extension-{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos()));
    let cancelled = Arc::new(AtomicBool::new(false));
    {
        let mut executions = super::EXECUTIONS.get_or_init(Default::default).lock().map_err(|e| e.to_string())?;
        if super::updates::INSTALLING.load(Ordering::SeqCst) { return Err("UPDATE_BUSY: Update installation is starting".into()); }
        if executions.contains_key(&execution_id) { return Err("Execution is already running".into()); }
        executions.insert(execution_id.clone(), cancelled.clone());
    }
    if on_started.send(json!({"kind": "started"})).is_err() { cancelled.store(true, Ordering::SeqCst); }
    let result = tauri::async_runtime::spawn_blocking(move || -> Result<Value, String> {
        if cancelled.load(Ordering::SeqCst) || timeout_ms == Some(0) { return Err("Operation cancelled".into()); }
        let mut command = Command::new("python");
        command.arg(root.join(format!("scripts/misc/desktop_{service}.py")))
            .current_dir(root).env("PYTHONIOENCODING", "utf-8")
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
        #[cfg(target_os = "windows")]
        command.creation_flags(super::CREATE_NO_WINDOW);
        #[cfg(unix)]
        { use std::os::unix::process::CommandExt; command.process_group(0); }
        let input = serde_json::to_vec(&request).map_err(|e| e.to_string())?;
        let mut child = command.spawn().map_err(|e| format!("Extension service unavailable: {e}"))?;
        let mut stdin = child.stdin.take().ok_or("Service stdin unavailable")?;
        let writer = std::thread::spawn(move || stdin.write_all(&input));
        let mut stdout = child.stdout.take().ok_or("Service stdout unavailable")?;
        let reader = std::thread::spawn(move || { let mut bytes = Vec::new(); stdout.read_to_end(&mut bytes).map(|_| bytes) });
        let mut stderr = child.stderr.take().ok_or("Service stderr unavailable")?;
        // Drain diagnostics without retaining credentials emitted by third-party servers.
        let errors = std::thread::spawn(move || std::io::copy(&mut stderr, &mut std::io::sink()));
        let start = std::time::Instant::now();
        let mut stopped = false;
        let status = loop {
            if let Some(status) = child.try_wait().map_err(|e| e.to_string())? { break status; }
            if cancelled.load(Ordering::SeqCst) || super::execution_expired(timeout_ms, start.elapsed()) {
                stopped = true;
                #[cfg(target_os = "windows")]
                { let _ = Command::new("taskkill").args(["/PID", &child.id().to_string(), "/T", "/F"]).creation_flags(super::CREATE_NO_WINDOW).output(); }
                #[cfg(unix)]
                { let _ = Command::new("kill").args(["-KILL", "--", &format!("-{}", child.id())]).output(); }
                let _ = child.kill();
                break child.wait().map_err(|e| e.to_string())?;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        let _ = writer.join();
        let bytes = reader.join().map_err(|_| "Service output reader failed")?.map_err(|e| e.to_string())?;
        let _ = errors.join();
        if stopped { return Ok(json!({"ok": false, "error": {"code": "execution-stopped", "message": "Operation stopped; execution outcome is unknown", "outcome": "unknown"}})); }
        let result: Value = serde_json::from_slice(&bytes).map_err(|_| "Invalid extension service response")?;
        if !status.success() && result.get("error").is_none() { return Err("Extension service failed".into()); }
        Ok(result)
    }).await.map_err(|e| e.to_string());
    if let Ok(mut executions) = super::EXECUTIONS.get_or_init(Default::default).lock() { executions.remove(&execution_id); }
    result?
}

#[tauri::command]
pub async fn extensions_operation(request: Value, execution_id: Option<String>, timeout_ms: Option<u64>, on_started: tauri::ipc::Channel<Value>) -> Result<Value, String> {
    service_operation("extensions", request, execution_id, timeout_ms, on_started).await
}

#[tauri::command]
pub async fn mcp_operation(request: Value, execution_id: Option<String>, timeout_ms: Option<u64>, on_started: tauri::ipc::Channel<Value>) -> Result<Value, String> {
    service_operation("mcp", request, execution_id, timeout_ms, on_started).await
}
