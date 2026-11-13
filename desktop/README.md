# ReverseLab Desktop

A desktop workspace for target-bound security analysis with separate `red`, `blue`, and `both` strategies. Goals run in a queue, emit a live workflow graph, collect execution evidence, and finish only after verification or an explicit stop condition.

[中文说明](README.zh-CN.md)

## Run

Install the dependencies with `pnpm install` in this directory. Use `pnpm dev` for the local browser preview or `pnpm tauri dev` for the desktop application. Python must be available on PATH. Native builds also require Rust and the platform's Tauri build prerequisites. `REVERSELAB_ROOT` can identify the repository containing the shared knowledge base and scripts.

The first launch creates a local default workspace outside this repository. The workspace selector opens or creates other directories. Importing a sample preserves an original copy and creates a separate working copy. Goals, reports, and scripts are stored inside the workspace's `.reverselab` directory.

Configure an OpenAI-compatible chat-completions endpoint and model in Settings. API keys stay in local application storage. Basic SHA256 verification uses a deterministic local path and does not need a model. Other goals use the configured model for planning and independent evidence assessment.

## Behavior

- Switch `red / blue / both` at the upper left. `both` starts isolated red and blue branches and joins their results.
- Enter a file, directory, or URL target and an objective. Optional limits default to 10 minutes and 32,000 tokens per Goal. The default queue runs two Goals per workspace.
- Switch workspaces or inspect another Goal while execution continues. Each runner retains its original workspace.
- Browse the actual knowledge index, including defense articles and paired references. Shared articles appear in both tracks.
- Inspect workflow nodes, execution history, tool output, verification, reports, and health events. Unobserved services remain unknown.
- Light/dark themes follow the OFFFOLD palette. Motion respects reduced-motion preferences.

The current execution adapter runs bounded Python observations. Native debugger, device-control, and production hardening adapters are not implemented by this desktop rewrite. A generic model-assisted verification result is not a formal proof; reports preserve the actual output and verification assertions. BLA/REA interoperability is a documented benchmark target, not a claim of completed upstream testing.

## Engineering documentation

- [Architecture](ARCHITECTURE.md) and [Agent runtime contracts](AGENT_SYSTEM.md)
- [Workspace ownership and persistence](WORKSPACES.md)
- [BLA / REA threat profiles and validation plan](ADVERSARIAL_PROFILES.md)
- [Application updates](UPDATES.md)
- [Health events and error codes](ERROR_CODES.md)
- [UI design](DESIGN_BRIEF.md) and [development guide](DEV_GUIDE.md)

## Checks

From this directory:

```sh
pnpm build
node --test src/services/goals/goalManager.test.mjs src/engine/tests/pipeline.test.mjs
node --experimental-strip-types --test tests/*.test.ts
cargo check --manifest-path src-tauri/Cargo.toml
```

From the repository root, run the relevant Python tests with pytest and `python scripts/misc/public_release_check.py` before publishing. Private workspaces, samples, reports, credentials, and local screenshots must remain outside public changes.

## v2.0.0 release package

Download the Windows x64 installer from [Releases](https://github.com/LING71671/open-reverselab/releases/tag/v2.0.0). Run the installer, then launch ReverseLab. Settings → Application updates checks versions and downloads signed updates after running tasks finish. Portable ZIP builds are also available; extract the entire directory and upgrade through the installer. Python 3.10+ must be available as `python`; [WebView2 Runtime](https://v2.tauri.app/start/prerequisites/#webview2) is also required. Install external analysis tools separately.

Use Settings for installed-build updates. For portable builds, close the app and extract the new version into a separate directory. Default workspaces are outside the application directory. Back up a custom workspace's `.reverselab/` before opening it. History restoration does not restart interrupted processes or relocate stored absolute paths. Do not replace the executable or move a workspace during a run.

## Model and execution data

API keys are held in WebView local storage without OS-keychain integration. Model-assisted tasks send context and selected evidence to the configured endpoint; the app is not an air-gapped environment. Python actions run with the current user's permissions. Unsent drafts and document positions survive navigation during the current workspace session, without promising persistence across application restarts.

Packaging and release checks are documented in [RELEASING.md](../RELEASING.md).
