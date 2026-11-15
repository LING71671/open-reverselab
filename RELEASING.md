# Desktop releases

[简体中文](RELEASING.zh-CN.md)

The `v2.0.0-beta2` distribution packages only the desktop runtime. Knowledge packs and MCP servers are independent extensions. The earlier `v2.0.0-beta.1` tag remains unchanged.

Python 3.11+, WebView2, and external analysis tools are separate dependencies; see the [desktop guide](site/en/desktop.md).

## Prepare the release commit

1. Keep `desktop/package.json`, `desktop/src-tauri/Cargo.toml`, its lockfile, and `desktop/src-tauri/tauri.conf.json` on the new release version.
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

Staging reads `git archive HEAD` and selects the explicit `RUNTIME_FILES` allowlist to populate `desktop/src-tauri/release-resources/` and writes `RELEASE.json` with the version and commit. Knowledge articles, MCP server sources, examples, and workspace data are excluded. The generated directory is ignored and becomes the installer's `runtime/` resource tree.

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
| `OpenReverseLab-v<VERSION>-windows-x64-setup.exe` | Windows installer |
| `OpenReverseLab-v<VERSION>-windows-x64-setup.exe.sig` | Complete updater signature |
| `OpenReverseLab-v<VERSION>-windows-x64.zip` | Portable package |
| `latest.json` | Version, notes, timestamp, platform URL, and signature |
| `SHA256SUMS` | Hashes of the release assets |

The portable ZIP expands to `OpenReverseLab-<VERSION>/`; its launcher is `OpenReverseLab.exe`. Extract the entire package. Its resources and scripts must stay beside the executable in their packaged locations.

## Publish and update channels

Use tag `v<VERSION>` at the same commit used for staging and building. Create a draft GitHub Release, pass the notes through `--notes-file`, and upload the complete asset set. Confirm that the manifest version, platform entry, installer URL, signature, and checksums match those assets. For `v2.0.0-beta2`, publish without GitHub's prerelease flag and mark it Latest so the repository sidebar displays the current desktop download. Keep beta in the version and release title; the desktop Stable channel still excludes this SemVer prerelease.

The desktop discovers releases through the public GitHub Releases API:

- **Stable** selects public production releases, excluding GitHub prereleases and SemVer prerelease versions.
- **Beta** selects public beta and production releases. A beta build initially selects Beta; a production build selects Stable. A user's explicit choice is retained.
- Both channels select only higher SemVer versions and read the `latest.json` attached to the selected Release. Drafts and bare tags do not provide an installable update.

The current channels do not rely on one fixed `releases/latest/download/latest.json` endpoint. Older clients using that endpoint follow GitHub's Latest selection, including this beta.

After the Release and assets are public, publish the corresponding root README and website download entries. Website publication does not itself publish an installer. Keep published tags and artifact/signature pairs immutable.

## Publish knowledge separately

Official content is maintained in [open-reverselab-knowledge](https://github.com/LING71671/open-reverselab-knowledge), with its own version in `reverselab.extension.json`. From a clean checkout of that repository, validate and build a ZIP:

```sh
python scripts/build.py --version <CONTENT-VERSION> --output ../knowledge.kbpack.zip
python scripts/extension_protocol.py check ../knowledge.kbpack.zip
```

Commit knowledge changes in that repository. To update the application's linked version, update its `kb` submodule commit and `reverselab.registry.json` repository URL/version together. The website builds that pinned content. The root catalog and the knowledge repository URL both support application imports without a desktop release. For a release ZIP, publish it as a separate knowledge asset and use its SHA256 in catalog artifact entries. MCP descriptors use the same extension protocol and retain independent versions. Neither package contains local connection credentials.

## Installation and platform scope

The installer edition verifies updater signatures and signed versions, then waits for running/queued Goals and workspace writes before installation. Portable and source builds use the release page or rebuild workflow for upgrades. See [application updates](desktop/UPDATES.md).

Updater signing and Windows Authenticode code signing are separate. Back up the updater key; clients cannot verify a replacement key's signatures automatically. macOS/Linux desktop binaries are outside this Windows release; do not upload placeholder packages or empty platform entries.
