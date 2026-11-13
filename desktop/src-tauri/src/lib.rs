use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tauri::Manager;
mod updates;
mod network;

static RESOURCE_ROOT: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x08000000;

fn get_repo_root() -> Result<PathBuf, String> {
    if let Some(root) = std::env::var_os("REVERSELAB_ROOT") {
        let root = PathBuf::from(root);
        if root.join("kb").is_dir() && root.join("scripts").is_dir() {
            return root.canonicalize().map_err(|e| e.to_string());
        }
        return Err("REVERSELAB_ROOT must point to an open-reverselab workspace".to_string());
    }
    let locations = [
        RESOURCE_ROOT.get().cloned(),
        std::env::current_exe().ok().and_then(|path| path.parent().map(|parent| parent.join("runtime"))),
        std::env::current_dir().ok(),
        std::env::current_exe()
            .ok()
            .and_then(|path| path.parent().map(Path::to_path_buf)),
    ];
    for location in locations.into_iter().flatten() {
        for ancestor in location.ancestors() {
            if ancestor.join("kb").is_dir() && ancestor.join("scripts").is_dir() {
                return ancestor.canonicalize().map_err(|e| e.to_string());
            }
        }
    }
    Err("Workspace not found. Start ReverseLab from the repository or set REVERSELAB_ROOT.".to_string())
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KbTechniqueItem {
    pub id: String,
    pub board: String,
    pub category: String,
    pub title: String,
    pub path: String,
    pub signals: Vec<String>,
    pub mcp_tools: Vec<String>,
    pub track: String,
    pub related_paths: Vec<String>,
}

#[tauri::command]
fn greet(name: &str) -> String {
    format!("Hello, {}! You've been greeted from Rust!", name)
}

#[tauri::command]
async fn workspace_operation(request: Value) -> Result<Value, String> {
    let root = get_repo_root()?;
    tauri::async_runtime::spawn_blocking(move || {
        use std::io::Write;
        use std::process::Stdio;
        let mut command = Command::new("python");
        command.arg(root.join("scripts/misc/desktop_workspace.py"))
            .current_dir(root).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
        #[cfg(target_os = "windows")]
        command.creation_flags(CREATE_NO_WINDOW);
        let mut child = command.spawn().map_err(|e| e.to_string())?;
        let input = serde_json::to_vec(&request).map_err(|e| e.to_string())?;
        child.stdin.take().ok_or("Workspace stdin unavailable")?.write_all(&input).map_err(|e| e.to_string())?;
        let output = child.wait_with_output().map_err(|e| e.to_string())?;
        let result: Value = serde_json::from_slice(&output.stdout).map_err(|e| format!("Workspace response: {}", e))?;
        if !output.status.success() { return Err(result["error"].as_str().unwrap_or("Workspace operation failed").to_string()); }
        Ok(result)
    }).await.map_err(|e| e.to_string())?
}

#[tauri::command]
fn get_env_snapshot() -> Result<Value, String> {
    let env_path = if let Ok(custom) = std::env::var("REVERSELAB_ENV_DIR") {
        PathBuf::from(custom).join("env.md")
    } else if let Ok(profile) = std::env::var("USERPROFILE") {
        PathBuf::from(profile).join(".open-reverselab").join("env").join("env.md")
    } else {
        return Err("Unable to locate USERPROFILE".to_string());
    };

    if !env_path.exists() {
        return Ok(json!({
            "status": "missing",
            "message": "Environment snapshot env.md not found",
            "path": env_path.to_string_lossy()
        }));
    }

    let content = fs::read_to_string(&env_path).map_err(|e| e.to_string())?;

    // Parse markdown sections
    let mut current_section = String::new();
    let mut sections: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("## ") {
            current_section = trimmed.trim_start_matches("## ").trim().to_string();
            sections.entry(current_section.clone()).or_default();
        } else if !current_section.is_empty() && (trimmed.starts_with("- ") || trimmed.starts_with("* ")) {
            sections
                .entry(current_section.clone())
                .or_default()
                .push(trimmed[2..].trim().to_string());
        }
    }

    Ok(json!({
        "status": "ok",
        "raw_path": env_path.to_string_lossy(),
        "sections": sections,
        "raw": content
    }))
}

#[tauri::command]
async fn triage_target(target: String, timeout_ms: Option<u64>, execution_id: Option<String>, route: Option<network::Route>) -> Result<Value, String> {
    let repo_root = get_repo_root()?;
    let script_path = repo_root.join("scripts").join("misc").join("triage_target.py");
    if !script_path.is_file() { return Err("Triage script not found".into()); }
    let script_json = serde_json::to_string(&script_path.to_string_lossy()).map_err(|e| e.to_string())?;
    let target_json = serde_json::to_string(&target).map_err(|e| e.to_string())?;
    let code = format!("import runpy, sys\nsys.argv = [{}, {}]\nrunpy.run_path({}, run_name='__main__')", script_json, target_json, script_json);
    let output = run_python_code(code, timeout_ms, execution_id, route).await?;
    if output["success"].as_bool() != Some(true) { return Err(output["stderr"].as_str().unwrap_or("Triage failed").to_string()); }
    serde_json::from_str(output["stdout"].as_str().unwrap_or("")).map_err(|e| format!("Invalid triage output: {}", e))
}

fn run_kb_command(args: &[&str]) -> Result<Value, String> {
    let repo_root = get_repo_root()?;
    let script = repo_root.join("scripts").join("misc").join("desktop_kb.py");
    let mut command = Command::new("python");
    command.arg(script).args(args).current_dir(&repo_root);

    #[cfg(target_os = "windows")]
    command.creation_flags(CREATE_NO_WINDOW);

    let output = command
        .output()
        .map_err(|e| format!("Failed to read knowledge base: {}", e))?;
    let parsed: Value = serde_json::from_slice(&output.stdout).map_err(|e| {
        format!(
            "Invalid knowledge base response: {}. {}",
            e,
            String::from_utf8_lossy(&output.stderr)
        )
    })?;
    if !output.status.success() {
        return Err(parsed
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("Knowledge base request failed")
            .to_string());
    }
    Ok(parsed)
}

#[tauri::command]
async fn list_kb_techniques(track: Option<String>) -> Result<Vec<KbTechniqueItem>, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let result = run_kb_command(&["list", "--track", track.as_deref().unwrap_or("both")])?;
        serde_json::from_value(result).map_err(|e| format!("Invalid knowledge catalog: {}", e))
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn read_kb_doc(relative_path: String) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let result = run_kb_command(&["read", "--path", &relative_path])?;
        result
            .get("content")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| "Invalid knowledge document response".to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

static EXECUTIONS: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<String, std::sync::Arc<std::sync::atomic::AtomicBool>>>> = std::sync::OnceLock::new();

#[tauri::command]
fn cancel_python_execution(execution_id: String) -> Result<bool, String> {
    let executions = EXECUTIONS.get_or_init(Default::default).lock().map_err(|e| e.to_string())?;
    if let Some(cancelled) = executions.get(&execution_id) {
        cancelled.store(true, std::sync::atomic::Ordering::SeqCst);
        return Ok(true);
    }
    Ok(false)
}

#[tauri::command]
async fn run_python_code(code: String, timeout_ms: Option<u64>, execution_id: Option<String>, route: Option<network::Route>) -> Result<Value, String> {
    let repo_root = get_repo_root()?;
    let execution_id = execution_id.unwrap_or_else(|| format!("python-{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos()));
    let cancelled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    {
        let mut executions = EXECUTIONS.get_or_init(Default::default).lock().map_err(|e| e.to_string())?;
        if updates::INSTALLING.load(std::sync::atomic::Ordering::SeqCst) { return Err("UPDATE_BUSY: Update installation is starting".into()); }
        if executions.contains_key(&execution_id) { return Err("Execution is already running".into()); }
        executions.insert(execution_id.clone(), cancelled.clone());
    }
    let result = tauri::async_runtime::spawn_blocking(move || -> Result<Value, String> {
        let run_id = format!("reverselab-{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos());
        let script_path = std::env::temp_dir().join(format!("{}.py", run_id));
        let stdout_path = std::env::temp_dir().join(format!("{}.stdout", run_id));
        let stderr_path = std::env::temp_dir().join(format!("{}.stderr", run_id));
        let outcome = (|| -> Result<Value, String> {
            let mut cmd = Command::new("python");
            let prelude = if let Some(route) = &route { network::configure_python(&mut cmd, route)? } else { String::new() };
            // Keep proxy credentials out of the temporary source file.
            let code = if prelude.is_empty() { code } else { format!("{}\nexec(compile({}, '<goal>', 'exec'))", prelude, serde_json::to_string(&code).map_err(|e| e.to_string())?) };
            fs::write(&script_path, code).map_err(|e| e.to_string())?;
            cmd.arg(&script_path).current_dir(repo_root)
                .env("PYTHONIOENCODING", "utf-8")
                .stdout(fs::File::create(&stdout_path).map_err(|e| e.to_string())?)
                .stderr(fs::File::create(&stderr_path).map_err(|e| e.to_string())?);
            #[cfg(target_os = "windows")]
            cmd.creation_flags(CREATE_NO_WINDOW);
            let start = std::time::Instant::now();
            let mut child = cmd.spawn().map_err(|e| e.to_string())?;
            let limit = std::time::Duration::from_millis(timeout_ms.unwrap_or(15000).clamp(1, 60000));
            let mut stopped = false;
            let status = loop {
                if let Some(status) = child.try_wait().map_err(|e| e.to_string())? { break status; }
                if cancelled.load(std::sync::atomic::Ordering::SeqCst) || start.elapsed() >= limit {
                    stopped = true;
                    #[cfg(target_os = "windows")]
                    { let _ = Command::new("taskkill").args(["/PID", &child.id().to_string(), "/T", "/F"]).creation_flags(CREATE_NO_WINDOW).output(); }
                    let _ = child.kill();
                    break child.wait().map_err(|e| e.to_string())?;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            };
            let read_output = |path: &Path| -> String {
                use std::io::Read;
                let mut bytes = Vec::new();
                if let Ok(file) = fs::File::open(path) { let _ = file.take(4 * 1024 * 1024).read_to_end(&mut bytes); }
                let mut text = String::from_utf8_lossy(&bytes).to_string();
                if let Some(route) = &route {
                    for secret in [&route.username, &route.password].into_iter().flatten().filter(|secret| !secret.is_empty()) {
                        text = text.replace(secret.as_str(), "[redacted]");
                        let encoded: String = reqwest::Url::parse("http://localhost").ok().and_then(|mut url| { url.set_password(Some(secret)).ok()?; Some(url.password()?.to_string()) }).unwrap_or_default();
                        if !encoded.is_empty() { text = text.replace(&encoded, "[redacted]"); }
                    }
                }
                text
            };
            let mut stderr = read_output(&stderr_path);
            if stopped { stderr.push_str("\nExecution cancelled or time budget exhausted"); }
            Ok(json!({"success": status.success() && !stopped, "exit_code": status.code(), "stdout": read_output(&stdout_path), "stderr": stderr, "execution_time_ms": start.elapsed().as_millis() as u64, "stopped": stopped}))
        })();
        for path in [&script_path, &stdout_path, &stderr_path] { let _ = fs::remove_file(path); }
        outcome
    }).await.map_err(|e| e.to_string());
    if let Ok(mut executions) = EXECUTIONS.get_or_init(Default::default).lock() { executions.remove(&execution_id); }
    result?
}

#[tauri::command]
fn save_analysis_report(
    target: String,
    summary: String,
    script: String,
    key: Option<String>,
    flag: Option<String>,
    goal_id: Option<String>,
    track: Option<String>,
    attempt: Option<u64>,
    execution_output: Option<Value>,
) -> Result<Value, String> {
    let repo_root = get_repo_root()?;
    let safe_component = |value: &str| value.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).take(100).collect::<String>();
    let scope = safe_component(goal_id.as_deref().unwrap_or("session"));
    let track = safe_component(track.as_deref().unwrap_or("blue"));
    let route = format!("{}-{}", track, attempt.unwrap_or(1));
    let reports_dir = repo_root.join("reports").join(&scope).join(&route);
    let exports_dir = repo_root.join("exports").join(&scope).join(&route);
    let _ = fs::create_dir_all(&reports_dir);
    let _ = fs::create_dir_all(&exports_dir);

    let clean_name = Path::new(&target)
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "target".to_string());

    let clean_name = safe_component(&clean_name);
    let report_filename = format!("{}_analysis.md", clean_name);
    let script_filename = format!("{}_decrypt.py", clean_name);

    let report_path = reports_dir.join(&report_filename);
    let script_path = exports_dir.join(&script_filename);

    let mut report_md = format!(
        "# Analysis Report: {}\n\n## 1. Summary\n{}\n\n## 2. Key Artifacts\n- Target: {}\n- Recovered Key: {}\n- Flag: {}\n\n## 3. Script\n```python\n{}\n```\n",
        target,
        summary,
        target,
        key.as_deref().unwrap_or("None"),
        flag.as_deref().unwrap_or("None"),
        script
    );

    if let Some(output) = execution_output { report_md.push_str(&format!("\n## Execution Output\n```json\n{}\n```\n", output)); }
    fs::write(&report_path, report_md).map_err(|e| format!("Failed to save report: {}", e))?;
    fs::write(&script_path, &script).map_err(|e| format!("Failed to save script: {}", e))?;

    let rel_report = report_path
        .strip_prefix(&repo_root)
        .unwrap_or(&report_path)
        .to_string_lossy()
        .replace('\\', "/");
    let rel_script = script_path
        .strip_prefix(&repo_root)
        .unwrap_or(&script_path)
        .to_string_lossy()
        .replace('\\', "/");

    Ok(json!({
        "status": "saved",
        "report_path": rel_report,
        "script_path": rel_script
    }))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _, _| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.set_focus();
            }
        }))
        .manage(updates::UpdateState::default())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .setup(|app| {
            if let Ok(directory) = app.path().resource_dir() { let _ = RESOURCE_ROOT.set(directory.join("runtime")); }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            network::network_request,
            network::network_cancel,
            network::network_probe,
            updates::update_installation_info,
            updates::update_check,
            updates::update_download,
            updates::update_install,
            greet,
            workspace_operation,
            get_env_snapshot,
            triage_target,
            list_kb_techniques,
            read_kb_doc,
            run_python_code,
            cancel_python_execution,
            save_analysis_report
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
