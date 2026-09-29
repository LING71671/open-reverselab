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

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            greet,
            get_env_snapshot,
            triage_target,
            list_kb_techniques,
            read_kb_doc
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
