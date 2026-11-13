# Application updates

[简体中文](UPDATES.zh-CN.md)

**Settings → Application updates** shows the current version, update channel, release notes, and download progress. Automatic checks start 20 seconds after launch and run at most once a day. They can be disabled. Manual checks are available in the desktop app; skipping a version hides its notification. Background checks never download, install, or stop Goals.

## Update channels

- **Stable** accepts public production releases, excluding both GitHub prereleases and versions with a SemVer prerelease identifier.
- **Beta** accepts public prereleases and production releases. Prerelease builds such as `2.0.0-beta.1` initially select this channel; production builds select Stable. An explicit choice is retained.
- Both channels compare SemVer precedence and only offer higher versions. A beta can advance to the corresponding production version. Switching to Stable never installs an older version.

Discovery uses the public GitHub Releases API without account credentials and selects an uploaded `latest.json` asset. Draft releases are excluded. The manifest endpoint, release page, and installer come from the actual release record. A channel without an update manifest shows that no installable update has been published and creates no release link. Network failures remain errors. A published version that does not exceed the installed build reports no newer version in the selected channel.

Changing channels clears the selected release, skipped version, check time, and downloaded-ready state. Check and download again before installation. Channel selection is locked during checks, downloads, and installation. Update requests use the system network and proxy, independently of the model and target-access proxy pools.

## Installation

The Windows x64 installer edition uses the official Tauri updater:

1. Read the selected release's actual `latest.json` asset. Its version must match the release tag, and its installer must be an uploaded asset of that release.
2. Download the NSIS installer only after the user requests it. Progress uses received bytes; if the server omits the total, show the downloaded size.
3. Verify the Minisign signature with the application's embedded public key, including its signed version. A failed signature cannot advance to installation.
4. When the user selects **Install and reopen**, check running and queued Goals across all opened workspaces, wait for workspace persistence, and check the workload again.
5. The native layer checks for Python execution and active network requests, blocks new execution, and starts the installer. The installer closes the app, replaces its files and bundled resources, and reopens it.

Downloading can proceed while Goals run. Installation waits for all work to finish. Default workspace data, model settings, and update preferences live outside the program directory and survive upgrades. Keep custom workspaces outside the installer-managed `runtime/` directory.

Portable packages and source builds can check versions and read release notes; upgrade them manually from the release page. In-app installation is enabled only for Windows x64 NSIS installations containing `runtime/kb/`, `runtime/scripts/`, and `uninstall.exe`. Browser preview explicitly disables checks and installation.

## Responsibilities and states

| Module | Responsibility |
| --- | --- |
| `src/services/updates/updateController.ts` | Platform-independent state machine, channel preferences, check interval, skipped versions, and persistence before installation |
| `src/services/updates/updateService.ts` | Tauri IPC and cross-workspace workload protection |
| `src/views/settings/UpdatesPane.tsx` | Channel selection, actions, progress, status, and error details |
| `src-tauri/src/updates.rs` | Public release discovery, HTTPS manifest retrieval, version and asset validation, download, signature verification, and installation lock |
| `src/services/goals/workspaceRuntime.ts` | Saving and workload tracking for loaded and opening workspaces |

The normal sequence is `idle → checking → available → downloading → ready → installing`. No higher version produces `current`; no published installation manifest produces `unpublished`. Check failures enter `error`; download failures return to `available`. Workspace save failures retain `ready`. Installer launch or temporary-file failures require a fresh download. Navigation away from settings does not cancel downloads or discard state. Downloaded bytes remain in process memory and must be downloaded again after exiting. Updates are full packages.

Update diagnostics are independent of individual Goal health events and appear in the update panel's error details. Current errors also appear in health monitoring. Network failures never report that the app is current. The application uses a single instance; another launch focuses the existing window.

| Error code | Meaning and recovery |
| --- | --- |
| `UPDATE_NETWORK` | Release service or network unavailable; check connectivity and retry |
| `UPDATE_MANIFEST` | Invalid release metadata, missing platform, version mismatch, or an installer outside the selected official release; retry after the release assets are corrected |
| `UPDATE_SIGNATURE` | Package signature, signed version, or public key mismatch; check again and download the correct package |
| `UPDATE_DOWNLOAD` | Download failed; retry the download |
| `UPDATE_INSTALL` | Installer could not start; download again or manually run the official installer |
| `UPDATE_STORAGE` | Workspace persistence or temporary-file failure; check permissions and free space |
| `UPDATE_TASKS_ACTIVE` | Running or queued work remains; wait for all workspaces to finish |
| `UPDATE_BUSY` | Another update operation is running; wait for it to finish |
| `UPDATE_UNSUPPORTED` | This execution mode cannot install in-app; use the release package |
| `UPDATE_NOT_READY` | No verified package is ready; download first |

## Release contract

Keep `package.json`, the Cargo package and lockfile, and `tauri.conf.json` aligned. Windows releases provide an installer, its `.sig`, `latest.json`, and SHA256 checksums. A portable ZIP can also be included.

The installer bundles `src-tauri/release-resources/` as `runtime/`. This ignored staging directory must not be committed. Build it from the final release commit's `git archive`, including complete `kb/` and `scripts/` trees and their referenced root configuration, board documentation, and tool indexes. Do not recursively package a development workspace. External analysis tools, Python, and private data are not bundled.

Keep the signing private key on the maintainer's machine or in CI secrets. Put the public key in `plugins.updater.pubkey`. Set `TAURI_SIGNING_PRIVATE_KEY` to the local private-key file and `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` to its password, or an empty value for an unencrypted key. Then build:

```powershell
pnpm tauri build --bundles nsis --config src-tauri/tauri.release.conf.json
```

Tauri CLI 2.12+ binds the application version when signing during `build`. Manual signing requires `--app-version <version>` because this application enables `requireSignedVersion`. Back up the private key: installed clients cannot verify updates signed by a replacement key. Updater signatures and Windows Authenticode signatures serve separate purposes.

Replace the signature placeholder below with the complete contents of the generated `.sig` file:

```json
{
  "version": "2.0.0",
  "notes": "Release notes for this version",
  "pub_date": "2026-11-13T00:00:00Z",
  "platforms": {
    "windows-x86_64": {
      "url": "https://github.com/LING71671/open-reverselab/releases/download/v2.0.0/ReverseLab-v2.0.0-windows-x64-setup.exe",
      "signature": "<complete installer signature>"
    }
  }
}
```

Upload and verify all assets before publishing. Production releases use a production tag and stable release status; test releases use a tag such as `v2.0.0-beta.1` and GitHub's prerelease flag. Both channels use the `latest.json` attached to their selected release. Existing stable clients using `releases/latest/download/latest.json` still depend on GitHub's latest production release. A draft or a tag without a Release does not make an update available. Never reuse an old package or signature under a different JSON version.

## Verification

```sh
pnpm build
node --experimental-strip-types --test tests/updateController.test.ts
cargo test --locked --manifest-path src-tauri/Cargo.toml --lib updates::tests
```

State-machine and native selection tests cover channel migration, draft filtering, version ordering, missing releases, download and signature failures, concurrent actions, workload guards, persistence failures, and the final pre-install check. They use synthetic release records and mock adapters.

Run actual public metadata discovery separately:

```sh
cargo test --locked --manifest-path src-tauri/Cargo.toml --lib updates::tests::public_release_discovery -- --ignored --nocapture
```

This check only reads the public API. It does not download or install an executable. Full upgrade acceptance still requires an isolated Windows installation, a real signed package, and an upgrade to the next version. A release that predates the updater cannot acquire it through an update mechanism it does not contain.

Implementation reference: [Tauri updater](https://v2.tauri.app/plugin/updater/).
