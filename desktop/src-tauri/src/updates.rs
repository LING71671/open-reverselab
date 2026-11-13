use serde::{Deserialize, Serialize};
use semver::Version;
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
pub struct Release { version: String, notes: String, url: String }
#[derive(Debug, Deserialize, Clone, Copy, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum UpdateChannel { Stable, Beta }
#[derive(Serialize)]
pub struct UpdateCheck { status: &'static str, release: Option<Release> }
#[derive(Debug, Deserialize)]
struct PublishedAsset { name: String, browser_download_url: String, state: String }
#[derive(Debug, Deserialize)]
struct PublishedRelease {
    tag_name: String,
    html_url: String,
    draft: bool,
    prerelease: bool,
    assets: Vec<PublishedAsset>,
}
struct Candidate<'a> { release: &'a PublishedRelease, version: Version, endpoint: reqwest::Url }

const RELEASE_API: &str = "https://api.github.com/repos/LING71671/open-reverselab/releases";
fn official_url(value: &str, prefix: &str) -> Result<reqwest::Url, UpdateError> {
    let url = reqwest::Url::parse(value).map_err(|e| fault("UPDATE_MANIFEST", e.to_string()))?;
    if url.scheme() != "https" || url.host_str() != Some("github.com") || !url.username().is_empty() || url.password().is_some() || url.query().is_some() || url.fragment().is_some() || !url.path().starts_with(prefix) {
        return Err(fault("UPDATE_MANIFEST", "The release URL is outside the official release repository"));
    }
    Ok(url)
}
fn candidate(releases: &[PublishedRelease], channel: UpdateChannel) -> Result<Option<Candidate<'_>>, UpdateError> {
    let mut candidates = Vec::new();
    for release in releases {
        if release.draft { continue; }
        let Ok(version) = Version::parse(release.tag_name.strip_prefix('v').unwrap_or(&release.tag_name)) else { continue; };
        if channel == UpdateChannel::Stable && (release.prerelease || !version.pre.is_empty()) { continue; }
        let Some(asset) = release.assets.iter().find(|asset| asset.name == "latest.json" && asset.state == "uploaded") else { continue; };
        official_url(&release.html_url, "/LING71671/open-reverselab/releases/tag/")?;
        let endpoint = official_url(&asset.browser_download_url, "/LING71671/open-reverselab/releases/download/")?;
        candidates.push(Candidate { release, version, endpoint });
    }
    Ok(candidates.into_iter().max_by(|a, b| a.version.cmp_precedence(&b.version)))
}
fn validate_manifest(expected: &Version, actual: &str, download_url: &str, release: &PublishedRelease) -> Result<(), UpdateError> {
    let actual = Version::parse(actual).map_err(|e| fault("UPDATE_MANIFEST", e.to_string()))?;
    if &actual != expected {
        return Err(fault("UPDATE_MANIFEST", "The manifest version does not match its published release"));
    }
    official_url(download_url, "/LING71671/open-reverselab/releases/download/")?;
    if !release.assets.iter().any(|asset| asset.state == "uploaded" && asset.browser_download_url == download_url) {
        return Err(fault("UPDATE_MANIFEST", "The installer is not an uploaded asset of the selected release"));
    }
    Ok(())
}
async fn published_releases() -> Result<Vec<PublishedRelease>, UpdateError> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let client = reqwest::Client::builder().timeout(Duration::from_secs(20)).user_agent(concat!("open-reverselab/", env!("CARGO_PKG_VERSION")))
        .build().map_err(|e| fault("UPDATE_NETWORK", e.to_string()))?;
    let mut releases = Vec::new();
    let mut page = 1;
    loop {
        // Public discovery deliberately uses no account credentials: draft releases are never updates.
        let response = client.get(format!("{RELEASE_API}?per_page=100&page={page}"))
            .header("Accept", "application/vnd.github+json").send().await
            .map_err(|e| fault("UPDATE_NETWORK", e.to_string()))?.error_for_status()
            .map_err(|e| fault("UPDATE_NETWORK", e.to_string()))?;
        let body = response.bytes().await.map_err(|e| fault("UPDATE_NETWORK", e.to_string()))?;
        let batch: Vec<PublishedRelease> = serde_json::from_slice(&body).map_err(|e| fault("UPDATE_MANIFEST", e.to_string()))?;
        let last_page = batch.len() < 100;
        releases.extend(batch);
        if last_page { break; }
        page += 1;
    }
    Ok(releases)
}
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
pub async fn update_check(app: AppHandle, state: State<'_, UpdateState>, channel: UpdateChannel) -> Result<UpdateCheck, UpdateError> {
    let mut slot = state.0.try_lock().map_err(|_| fault("UPDATE_BUSY", "An update operation is already running"))?;
    // A failed new check must not leave an older channel's package available for download/install.
    slot.update = None;
    slot.bytes = None;
    let releases = published_releases().await?;
    let Some(candidate) = candidate(&releases, channel)? else { return Ok(UpdateCheck { status: "unpublished", release: None }); };
    if candidate.version.cmp_precedence(&app.package_info().version).is_le() {
        return Ok(UpdateCheck { status: "current", release: None });
    }
    let expected = candidate.version;
    // Fetch the actual asset returned by GitHub. Tauri retains signature verification and platform selection.
    let update = app.updater_builder().timeout(Duration::from_secs(20)).endpoints(vec![candidate.endpoint])
        .map_err(|e| classify(e, "UPDATE_MANIFEST"))?.version_comparator(|_, _| true).build()
        .map_err(|e| classify(e, "UPDATE_MANIFEST"))?.check().await.map_err(|e| classify(e, "UPDATE_NETWORK"))?;
    let update = update.ok_or_else(|| fault("UPDATE_MANIFEST", "The published manifest returned no release"))?;
    validate_manifest(&expected, &update.version, update.download_url.as_str(), candidate.release)?;
    let release = Release { version: update.version.clone(), notes: update.body.clone().unwrap_or_default(), url: candidate.release.html_url.clone() };
    slot.update = Some(update);
    Ok(UpdateCheck { status: "available", release: Some(release) })
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
    fn published(version: &str, prerelease: bool, manifest: bool) -> PublishedRelease {
        let tag = format!("v{version}");
        let mut assets = vec![PublishedAsset { name: "setup.exe".into(), browser_download_url: format!("https://github.com/LING71671/open-reverselab/releases/download/{tag}/setup.exe"), state: "uploaded".into() }];
        if manifest { assets.push(PublishedAsset { name: "latest.json".into(), browser_download_url: format!("https://github.com/LING71671/open-reverselab/releases/download/{tag}/latest.json"), state: "uploaded".into() }); }
        PublishedRelease { tag_name: tag.clone(), html_url: format!("https://github.com/LING71671/open-reverselab/releases/tag/{tag}"), draft: false, prerelease, assets }
    }
    #[test]
    fn channels_use_semver_and_exclude_drafts_and_unpublished_assets() {
        let mut draft = published("9.0.0", false, true);
        draft.draft = true;
        let releases = vec![published("2.9.0", false, true), published("2.10.0", false, true), published("3.0.0-beta.2", true, true), draft, published("4.0.0", false, false)];
        assert_eq!(candidate(&releases, UpdateChannel::Stable).unwrap().unwrap().version.to_string(), "2.10.0");
        assert_eq!(candidate(&releases, UpdateChannel::Beta).unwrap().unwrap().version.to_string(), "3.0.0-beta.2");
        let incomplete = vec![published("2.0.0", false, false)];
        assert!(candidate(&incomplete, UpdateChannel::Stable).unwrap().is_none());
    }
    #[test]
    fn stable_never_accepts_prerelease_tags_and_beta_can_graduate_to_stable() {
        let mislabeled = vec![published("3.0.0-beta.1", false, true)];
        assert!(candidate(&mislabeled, UpdateChannel::Stable).unwrap().is_none());
        let releases = vec![published("2.0.0-beta.10", true, true), published("2.0.0", false, true)];
        let selected = candidate(&releases, UpdateChannel::Beta).unwrap().unwrap();
        assert_eq!(selected.version, Version::parse("2.0.0").unwrap());
        assert!(selected.version > Version::parse("2.0.0-beta.10").unwrap());
        assert!(Version::parse("1.2.1").unwrap() < Version::parse("2.0.0-beta.1").unwrap());
    }
    #[test]
    fn release_urls_must_be_actual_official_assets() {
        let mut release = published("2.0.0", false, true);
        let expected = Version::parse("2.0.0").unwrap();
        assert!(validate_manifest(&expected, "2.0.0", &release.assets[0].browser_download_url, &release).is_ok());
        assert_eq!(validate_manifest(&expected, "2.1.0", &release.assets[0].browser_download_url, &release).unwrap_err().code, "UPDATE_MANIFEST");
        assert!(validate_manifest(&expected, "2.0.0", "https://github.com/LING71671/open-reverselab/releases/download/v2.0.0/missing.exe", &release).is_err());
        release.assets[1].browser_download_url = "https://example.com/latest.json".into();
        assert!(candidate(&[release], UpdateChannel::Stable).is_err());
        assert!(official_url("https://user@github.com/LING71671/open-reverselab/releases/tag/v2.0.0", "/LING71671/open-reverselab/releases/tag/").is_err());
    }
    #[tokio::test]
    #[ignore = "Contacts the public GitHub release API; run explicitly for release discovery verification"]
    async fn public_release_discovery() {
        let releases = published_releases().await.expect("public release metadata");
        assert!(releases.iter().all(|release| !release.draft));
        for channel in [UpdateChannel::Stable, UpdateChannel::Beta] {
            let found = candidate(&releases, channel).unwrap();
            println!("{channel:?}: public_releases={}, installable={}", releases.len(), found.as_ref().map(|item| item.version.to_string()).unwrap_or_else(|| "none".into()));
        }
    }
    #[test]
    fn signatures_are_classified_separately_from_network_failures() {
        assert_eq!(classify(tauri_plugin_updater::Error::MissingSignedVersion, "UPDATE_DOWNLOAD").code, "UPDATE_SIGNATURE");
        assert_eq!(classify(tauri_plugin_updater::Error::ReleaseNotFound, "UPDATE_NETWORK").code, "UPDATE_NETWORK");
        assert_eq!(classify(tauri_plugin_updater::Error::TargetsNotFound(vec![]), "UPDATE_NETWORK").code, "UPDATE_MANIFEST");
    }
}
