use serde::Serialize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tauri::{ipc::Channel, AppHandle, State};
use tauri_plugin_updater::{Update, UpdaterExt};

pub static INSTALLING: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateError { code: &'static str, message: String }
fn fault(code: &'static str, message: impl Into<String>) -> UpdateError { UpdateError { code, message: message.into() } }
fn classify(error: tauri_plugin_updater::Error, stage: &'static str) -> UpdateError {
    use tauri_plugin_updater::Error::*;
    let code = match &error {
        Minisign(_) | Base64(_) | SignatureUtf8(_) | SignedVersionMismatch { .. } | MissingSignedVersion => "UPDATE_SIGNATURE",
        Reqwest(_) | Network(_) | ReleaseNotFound => "UPDATE_NETWORK",
        Serialization(_) | Semver(_) | UrlParse(_) | EmptyEndpoints | TargetNotFound(_) | TargetsNotFound(_) => "UPDATE_MANIFEST",
        UnsupportedArch | UnsupportedOs => "UPDATE_UNSUPPORTED",
        Io(_) | TempDirNotFound => "UPDATE_STORAGE",
        _ => stage,
    };
    fault(code, error.to_string())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallationInfo { version: String, mode: &'static str }
fn installation_mode() -> &'static str {
    if cfg!(debug_assertions) { return "development"; }
    if !cfg!(all(target_os = "windows", target_arch = "x86_64")) { return "unsupported"; }
    let installed = std::env::current_exe().ok().and_then(|exe| exe.parent().map(|root| {
        root.join("uninstall.exe").is_file() && root.join("runtime/kb").is_dir() && root.join("runtime/scripts").is_dir()
    })).unwrap_or(false);
    if installed { "installed" } else { "portable" }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Release { version: String, notes: String }
#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DownloadProgress { downloaded: u64, total: Option<u64> }
#[derive(Default)]
struct Slot { update: Option<Update>, bytes: Option<Vec<u8>> }
#[derive(Default)]
pub struct UpdateState(tauri::async_runtime::Mutex<Slot>);

#[tauri::command]
pub fn update_installation_info(app: AppHandle) -> InstallationInfo {
    InstallationInfo { version: app.package_info().version.to_string(), mode: installation_mode() }
}

#[tauri::command]
pub async fn update_check(app: AppHandle, state: State<'_, UpdateState>) -> Result<Option<Release>, UpdateError> {
    let mut slot = state.0.try_lock().map_err(|_| fault("UPDATE_BUSY", "An update operation is already running"))?;
    let update = app.updater_builder().timeout(Duration::from_secs(20)).build()
        .map_err(|e| classify(e, "UPDATE_MANIFEST"))?.check().await.map_err(|e| classify(e, "UPDATE_NETWORK"))?;
    if let Some(update) = &update {
        let url = &update.download_url;
        if url.scheme() != "https" || url.host_str() != Some("github.com") || !url.path().starts_with("/LING71671/open-reverselab/releases/download/") {
            return Err(fault("UPDATE_MANIFEST", "The release asset is outside the official release repository"));
        }
    }
    let release = update.as_ref().map(|update| Release { version: update.version.clone(), notes: update.body.clone().unwrap_or_default() });
    slot.update = update;
    slot.bytes = None;
    Ok(release)
}

#[tauri::command]
pub async fn update_download(state: State<'_, UpdateState>, on_progress: Channel<DownloadProgress>) -> Result<(), UpdateError> {
    if installation_mode() != "installed" { return Err(fault("UPDATE_UNSUPPORTED", "In-app installation requires the Windows installer edition")); }
    let mut slot = state.0.try_lock().map_err(|_| fault("UPDATE_BUSY", "An update operation is already running"))?;
    let mut update = slot.update.clone().ok_or_else(|| fault("UPDATE_NOT_READY", "Check for an update first"))?;
    slot.bytes = None;
    update.timeout = Some(Duration::from_secs(600));
    let mut downloaded = 0_u64;
    let bytes = update.download(|chunk, total| {
        downloaded = downloaded.saturating_add(chunk as u64);
        let _ = on_progress.send(DownloadProgress { downloaded, total });
    }, || {}).await.map_err(|e| classify(e, "UPDATE_DOWNLOAD"))?;
    // Tauri returns bytes only after verifying the Minisign signature.
    slot.bytes = Some(bytes);
    Ok(())
}

#[tauri::command]
pub async fn update_install(state: State<'_, UpdateState>) -> Result<(), UpdateError> {
    if installation_mode() != "installed" { return Err(fault("UPDATE_UNSUPPORTED", "In-app installation requires the Windows installer edition")); }
    let mut slot = state.0.try_lock().map_err(|_| fault("UPDATE_BUSY", "An update operation is already running"))?;
    let update = slot.update.clone().ok_or_else(|| fault("UPDATE_NOT_READY", "Check for an update first"))?;
    if slot.bytes.is_none() { return Err(fault("UPDATE_NOT_READY", "Download and verify the update first")); }
    {
        let executions = crate::EXECUTIONS.get_or_init(Default::default).lock().map_err(|_| fault("UPDATE_BUSY", "Execution state unavailable"))?;
        if !executions.is_empty() { return Err(fault("UPDATE_TASKS_ACTIVE", "Python work is still running")); }
        if INSTALLING.swap(true, Ordering::SeqCst) { return Err(fault("UPDATE_BUSY", "Installation is already starting")); }
        if crate::network::has_active_requests() { INSTALLING.store(false, Ordering::SeqCst); return Err(fault("UPDATE_TASKS_ACTIVE", "Network requests are still running")); }
    }
    let bytes = slot.bytes.take().unwrap();
    let outcome = tauri::async_runtime::spawn_blocking(move || update.install(bytes)).await;
    INSTALLING.store(false, Ordering::SeqCst);
    outcome.map_err(|e| fault("UPDATE_INSTALL", e.to_string()))?.map_err(|e| classify(e, "UPDATE_INSTALL"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signatures_are_classified_separately_from_network_failures() {
        assert_eq!(classify(tauri_plugin_updater::Error::MissingSignedVersion, "UPDATE_DOWNLOAD").code, "UPDATE_SIGNATURE");
        assert_eq!(classify(tauri_plugin_updater::Error::ReleaseNotFound, "UPDATE_NETWORK").code, "UPDATE_NETWORK");
        assert_eq!(classify(tauri_plugin_updater::Error::TargetsNotFound(vec![]), "UPDATE_NETWORK").code, "UPDATE_MANIFEST");
    }
}
