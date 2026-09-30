use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x08000000;

fn get_repo_root() -> PathBuf {
    if let Ok(cwd) = std::env::current_dir() {
        for ancestor in cwd.ancestors() {
            if ancestor.join("kb").is_dir() && ancestor.join("scripts").is_dir() {
                return ancestor.to_path_buf();
            }
        }
    }
    PathBuf::from(r"E:\open-reverseLab")
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
}

#[tauri::command]
fn greet(name: &str) -> String {
    format!("Hello, {}! You've been greeted from Rust!", name)
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
async fn triage_target(target: String) -> Result<Value, String> {
    let repo_root = get_repo_root();
    let script_path = repo_root.join("scripts").join("misc").join("triage_target.py");

    if !script_path.exists() {
        return Err(format!("Triage script not found at: {}", script_path.display()));
    }

    let mut cmd = Command::new("python");
    cmd.arg(&script_path).arg(&target).current_dir(&repo_root);

    #[cfg(target_os = "windows")]
    cmd.creation_flags(CREATE_NO_WINDOW);

    let output = cmd
        .output()
        .map_err(|e| format!("Failed to spawn python triage script: {}", e))?;

    if !output.status.success() {
        let err_msg = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "Triage failed with code {:?}: {}",
            output.status.code(),
            err_msg
        ));
    }

    let stdout_str = String::from_utf8_lossy(&output.stdout);
    let parsed: Value = serde_json::from_str(&stdout_str).map_err(|e| {
        format!(
            "Failed to parse triage JSON output: {}. Raw: {}",
            e, stdout_str
        )
    })?;

    Ok(parsed)
}

#[tauri::command]
fn list_kb_techniques() -> Result<Vec<KbTechniqueItem>, String> {
    let repo_root = get_repo_root();
    let kb_root = repo_root.join("kb");

    if !kb_root.exists() {
        return Err(format!("KB directory not found: {}", kb_root.display()));
    }

    let boards = ["pe-reverse", "apk-reverse", "ctf-website", "general"];
    let mut items = Vec::new();

    for board in boards {
        let tech_dir = kb_root.join(board).join("techniques");
        if !tech_dir.exists() {
            continue;
        }

        // Recursively or directly scan subdirectories under techniques
        if let Ok(entries) = fs::read_dir(&tech_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    let category = path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string();
                    if let Ok(sub_entries) = fs::read_dir(&path) {
                        for sub_entry in sub_entries.flatten() {
                            let sub_path = sub_entry.path();
                            if sub_path.extension().and_then(|s| s.to_str()) == Some("md") {
                                if let Some(item) =
                                    parse_technique_file(&sub_path, board, &category, &repo_root)
                                {
                                    items.push(item);
                                }
                            }
                        }
                    }
                } else if path.extension().and_then(|s| s.to_str()) == Some("md") {
                    let file_name = path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string();
                    if file_name != "attack-network.md" && file_name != "README.md" {
                        if let Some(item) =
                            parse_technique_file(&path, board, "general", &repo_root)
                        {
                            items.push(item);
                        }
                    }
                }
            }
        }
    }

    Ok(items)
}

fn parse_technique_file(
    path: &Path,
    board: &str,
    category: &str,
    repo_root: &Path,
) -> Option<KbTechniqueItem> {
    let content = fs::read_to_string(path).ok()?;
    let rel_path = path
        .strip_prefix(repo_root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/");
    let file_stem = path.file_stem()?.to_string_lossy().to_string();

    let mut title = file_stem.clone();
    let mut signals = Vec::new();
    let mut mcp_tools = Vec::new();

    for line in content.lines().take(60) {
        let trimmed = line.trim();
        if trimmed.starts_with("# ") && title == file_stem {
            title = trimmed[2..].trim().to_string();
        } else if trimmed.to_lowercase().starts_with("信号")
            || trimmed.to_lowercase().starts_with("signals:")
        {
            let sig_str = trimmed.split(':').nth(1).unwrap_or("");
            for s in sig_str.split(&[',', '、', ';'][..]) {
                let s_clean = s.trim().trim_matches(&['[', ']', '"', '\''][..]);
                if !s_clean.is_empty() {
                    signals.push(s_clean.to_string());
                }
            }
        } else if trimmed.contains("mcp_") || trimmed.contains("MCP") {
            for word in trimmed.split_whitespace() {
                if word.starts_with('`') && word.ends_with('`') && word.len() > 3 {
                    let tool = word.trim_matches('`');
                    if tool.contains('_') && !mcp_tools.contains(&tool.to_string()) {
                        mcp_tools.push(tool.to_string());
                    }
                }
            }
        }
    }

    Some(KbTechniqueItem {
        id: format!("{}:{}", board, file_stem),
        board: board.to_string(),
        category: category.to_string(),
        title,
        path: rel_path,
        signals,
        mcp_tools,
    })
}

#[tauri::command]
fn read_kb_doc(relative_path: String) -> Result<String, String> {
    let repo_root = get_repo_root();
    let clean_path = relative_path
        .trim_start_matches('/')
        .trim_start_matches('\\');
    let full_path = repo_root.join(clean_path);

    if !full_path.starts_with(&repo_root) {
        return Err("Security error: Path traversal denied".to_string());
    }

    if !full_path.exists() {
        return Err(format!("File not found: {}", full_path.display()));
    }

    fs::read_to_string(&full_path).map_err(|e| format!("Failed to read file: {}", e))
}

#[tauri::command]
async fn run_python_code(code: String) -> Result<Value, String> {
    let repo_root = get_repo_root();
    let temp_dir = repo_root.join(".open-reverselab").join("tmp");
    let _ = fs::create_dir_all(&temp_dir);
    let run_id = format!(
        "run_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
    );
    let temp_file = temp_dir.join(format!("{}.py", run_id));

    fs::write(&temp_file, &code).map_err(|e| format!("Failed to write temp script: {}", e))?;

    let start = std::time::Instant::now();
    let mut cmd = Command::new("python");
    cmd.arg(&temp_file).current_dir(&repo_root);

    #[cfg(target_os = "windows")]
    cmd.creation_flags(CREATE_NO_WINDOW);

    let output = cmd
        .output()
        .map_err(|e| format!("Failed to execute python: {}", e))?;
    let duration_ms = start.elapsed().as_millis() as u64;

    let _ = fs::remove_file(&temp_file);

    let stdout_str = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr_str = String::from_utf8_lossy(&output.stderr).to_string();

    Ok(json!({
        "success": output.status.success(),
        "exit_code": output.status.code(),
        "stdout": stdout_str,
        "stderr": stderr_str,
        "execution_time_ms": duration_ms
    }))
}

#[tauri::command]
fn save_analysis_report(
    target: String,
    summary: String,
    script: String,
    key: Option<String>,
    flag: Option<String>,
) -> Result<Value, String> {
    let repo_root = get_repo_root();
    let reports_dir = repo_root.join("reports");
    let exports_dir = repo_root.join("exports");
    let _ = fs::create_dir_all(&reports_dir);
    let _ = fs::create_dir_all(&exports_dir);

    let clean_name = Path::new(&target)
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "target".to_string());

    let report_filename = format!("{}_analysis.md", clean_name);
    let script_filename = format!("{}_decrypt.py", clean_name);

    let report_path = reports_dir.join(&report_filename);
    let script_path = exports_dir.join(&script_filename);

    let report_md = format!(
        "# Analysis Report: {}\n\n## 1. Summary\n{}\n\n## 2. Key Artifacts\n- Target: {}\n- Recovered Key: {}\n- Flag: {}\n\n## 3. Verified Script\n```python\n{}\n```\n",
        target,
        summary,
        target,
        key.as_deref().unwrap_or("None"),
        flag.as_deref().unwrap_or("None"),
        script
    );

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
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            greet,
            get_env_snapshot,
            triage_target,
            list_kb_techniques,
            read_kb_doc,
            run_python_code,
            save_analysis_report
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
