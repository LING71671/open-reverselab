# Desktop releases

[简体中文](RELEASING.zh-CN.md)

The `v2.0.0-beta.1` packages were withdrawn on 2026-11-14 while desktop and knowledge-base distribution are separated. The procedure below records the previous combined package layout; it must be updated before the next desktop release. Publish the replacement under a new version and tag.

Python 3.11+, WebView2, and external analysis tools are separate dependencies; see the [desktop guide](site/en/desktop.md).

## Prepare the release commit

1. Keep `desktop/package.json`, `desktop/src-tauri/Cargo.toml`, its lockfile, and `desktop/src-tauri/tauri.conf.json` on `2.0.0-beta.1`.
2. Update [CHANGELOG.md](CHANGELOG.md) and its Chinese counterpart with the actual features and completed checks. Keep user acceptance and unperformed evaluations separate from regression results.
3. Follow the [update signing contract](desktop/UPDATES.md). The private key stays on the release machine or in a CI secret.
4. Run `python scripts/misc/public_release_check.py` before committing. Keep private targets, credentials, reports, and local screenshots out of the release. Use a GitHub noreply author address for public commits.

Relevant development checks are documented in [desktop/DEV_GUIDE.md](desktop/DEV_GUIDE.md). Reuse completed checks for unchanged inputs; record the checks actually performed for this release.

## Stage and build

Build from the committed release source in a clean checkout, with frozen-lockfile dependencies. The packager rejects tracked or untracked worktree changes. Root README and website download changes can be prepared separately and published after the Release becomes public.

From the repository root:

```sh
python scripts/misc/package_desktop_release.py stage
```

Staging uses `git archive HEAD` to populate `desktop/src-tauri/release-resources/` and writes `RELEASE.json` with the version and commit. The generated directory is ignored and becomes the installer's `runtime/` resource tree.

Set `TAURI_SIGNING_PRIVATE_KEY` in the build process to the local private-key file and `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` to its password. Do not print these values. From `desktop/`:

```sh
pnpm install --frozen-lockfile
pnpm tauri build --config src-tauri/tauri.release.conf.json --bundles nsis
```

The generated NSIS installer and `.sig` are under `desktop/src-tauri/target/release/bundle/nsis/`. From the repository root:

```sh
python scripts/misc/package_desktop_release.py package --installer <NSIS-EXE> --notes <release-notes.md>
```

The packager checks the staged commit and version, source/build ordering, the installer's embedded `RELEASE.json`, and the signed version metadata. It requires 7-Zip to read installer resources.

## Release assets

`dist/release/` contains:

| Asset | Purpose |
| --- | --- |
| `OpenReverseLab-v2.0.0-beta.1-windows-x64-setup.exe` | Windows installer |
| `OpenReverseLab-v2.0.0-beta.1-windows-x64-setup.exe.sig` | Complete updater signature |
| `OpenReverseLab-v2.0.0-beta.1-windows-x64.zip` | Portable package |
| `latest.json` | Version, notes, timestamp, platform URL, and signature |
| `SHA256SUMS` | Hashes of the release assets |

The portable ZIP expands to `OpenReverseLab-2.0.0-beta.1/`; its launcher is `OpenReverseLab.exe`. Extract the entire package. Its resources and scripts must stay beside the executable in their packaged locations.

## Publish and update channels

Use tag `v2.0.0-beta.1` at the same commit used for staging and building. Create a draft GitHub Release, pass the notes through `--notes-file`, and upload the complete asset set. Confirm that the manifest version, platform entry, installer URL, signature, and checksums match those assets. Publish it with the **prerelease** flag, without marking it as the latest production release.

The desktop discovers releases through the public GitHub Releases API:

- **Stable** selects public production releases, excluding GitHub prereleases and SemVer prerelease versions.
- **Beta** selects public beta and production releases. A beta build initially selects Beta; a production build selects Stable. A user's explicit choice is retained.
- Both channels select only higher SemVer versions and read the `latest.json` attached to the selected Release. Drafts and bare tags do not provide an installable update.

The current channels do not rely on one fixed `releases/latest/download/latest.json` endpoint. Older clients that use that endpoint still follow GitHub's latest production release; a beta should not replace it.

After the Release and assets are public, publish the corresponding root README and website download entries. Website publication does not itself publish an installer. Keep published tags and artifact/signature pairs immutable.

## Installation and platform scope

The installer edition verifies updater signatures and signed versions, then waits for running/queued Goals and workspace writes before installation. Portable and source builds use the release page or rebuild workflow for upgrades. See [application updates](desktop/UPDATES.md).

Updater signing and Windows Authenticode code signing are separate. Back up the updater key; clients cannot verify a replacement key's signatures automatically. macOS/Linux desktop binaries are outside this Windows release; do not upload placeholder packages or empty platform entries.
