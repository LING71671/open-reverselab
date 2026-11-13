---
title: Desktop installation and updates
description: Download Open ReverseLab v2.0.0-beta.1 for Windows, configure a model, create a workspace, and run Goals.
---
# Desktop installation and updates

[Download v2.0.0-beta.1](https://github.com/LING71671/open-reverselab/releases/tag/v2.0.0-beta.1) for the Windows x64 installer or portable ZIP. Release notes, signature files, and SHA256 checksums are on the same release page.

## Install on Windows

1. Install Python 3.11+, make `python` available on PATH, and install Microsoft Edge WebView2 Runtime.
2. Download and run `OpenReverseLab-v2.0.0-beta.1-windows-x64-setup.exe`. For the portable edition, extract the complete ZIP and run `OpenReverseLab.exe`.
3. Start the application and save your provider's API endpoint, API key, and model ID in Settings. Model-assisted work uses the saved configuration.
4. Choose a workspace and create a Goal with a file, directory, or URL target and the result you want. Basic SHA256 verification can run locally.

First launch creates a default workspace. You can also create or open other directories. Workspaces hold samples, Goals, evidence, and reports. Keep them outside the installation directory. Install external tools such as Ghidra and Frida separately as needed.

## red / blue / both

Select a strategy at the top left. Red organizes analysis hypotheses and observation paths; blue uses defense guidance to examine behavior and controls. Both runs the two strategies in parallel. Each can plan multiple actions, exchange evidence during execution, and assess its own responsibilities before the combined objective is checked.

Goals and ready actions have no default concurrency cap. Time and token budgets are also optional. Adding requirements during a run keeps the same Goal's evidence and history and applies the new objective at an execution boundary. Stopping cancels execution and retains recorded progress.

The transcript presents analysis progress, with expandable plans, scripts, tool output, and verification details. The canvas shows actual dependencies and evidence links, with card details, zoom, execution follow, and full-screen mode.

## Application updates

Choose a channel in Settings → Application updates. Beta builds default to the Beta channel, which accepts beta and production releases. Stable accepts production releases only. Both channels offer only higher versions; changing channels does not downgrade the application.

The application reads an update manifest from the actual GitHub Release assets. It downloads only after the user requests it, verifies the package signature, and waits for all opened workspaces' tasks and writes before installation. Update a portable edition by downloading and fully extracting the new package. Update a source build by pulling changes and rebuilding.

See [application updates](https://github.com/LING71671/open-reverselab/blob/main/desktop/UPDATES.md). The updater signature verifies the package against the release key; it is separate from Windows Authenticode code signing.

## Run from source

Install Node.js 22+, pnpm, Python 3.11+, and the Rust toolchain. Windows builds also require Microsoft C++ Build Tools. Clone the repository, then run:

```sh
cd desktop
pnpm install --frozen-lockfile
pnpm tauri dev
```

The [complete build instructions](https://github.com/LING71671/open-reverselab#build-the-desktop) cover resource preparation and packaging. `pnpm dev` starts the browser development preview.

## Data and platforms

The configured model endpoint receives task context and selected evidence. API keys are stored in local WebView storage. Generated Python runs with the current user's permissions. Performance warnings and Sentry diagnostics are separate options, both off by default.

Desktop packages in this release support Windows x64. macOS / Linux retain the repository's CLI/MCP workflow; native desktop packages for those platforms are not provided.

[Desktop guide](https://github.com/LING71671/open-reverselab/blob/main/desktop/README.md) · [Developer guide](https://github.com/LING71671/open-reverselab/blob/main/desktop/DEV_GUIDE.md) · [Agent runtime](https://github.com/LING71671/open-reverselab/blob/main/desktop/AGENT_SYSTEM.md)
