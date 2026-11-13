---
title: Desktop installation and updates
description: Build the Open ReverseLab desktop preview, configure a model, create a workspace and run Goals.
---
# Desktop installation and updates

The desktop is being prepared for `v2.0.0-beta.1`; its installer has not been published. Try the source preview now. Published downloads are listed on [Releases](https://github.com/LING71671/open-reverselab/releases).

## Run from source

Install Node.js 22+, pnpm, Python 3.10+ and the Rust toolchain. Windows also requires Microsoft C++ Build Tools and WebView2 Runtime. Clone the repository, then run:

```sh
cd desktop
pnpm install --frozen-lockfile
pnpm tauri dev
```

The [complete build instructions](https://github.com/LING71671/open-reverselab#build-the-desktop) cover resource preparation and packaging. Install external tools such as Ghidra and Frida separately as needed.

The first launch creates a default workspace. You can also create or open another directory. Workspaces hold samples, Goals, evidence and reports. Configure a model provider, API endpoint, key and model ID, then create a Goal with a target and desired result.

## red / blue / both

Switch modes at the top left. red investigates analysis and validation paths; blue uses defense guidance and checks; both runs independent branches and joins their evidence. The live canvas shows branch status. Multiple Goals can queue, with two running per workspace by default.

Goals have no time or token limit by default. Set either under Run limits. Add instructions or adjust the objective during a run while retaining the same Goal's evidence and history, or stop it manually. Cross-branch coordination and completion checks are still under validation; set a limit for unfamiliar tasks and inspect the recorded evidence.

## Application updates

Update the source preview by pulling changes and rebuilding. See [application updates](https://github.com/LING71671/open-reverselab/blob/main/desktop/UPDATES.md) for the installed-build signature mechanism; available downloads are listed on Releases. Keep workspaces outside the source and installation directories.

## Data and platforms

The configured model endpoint receives task context and analysis evidence. API keys are stored in the local WebView storage. Generated Python runs with the current user's permissions.

Windows x64 is the desktop packaging target. Repository scripts work on macOS / Linux; native desktop packages for those platforms are not currently provided.

[Developer guide](https://github.com/LING71671/open-reverselab/blob/main/desktop/DEV_GUIDE.md) · [Agent architecture](https://github.com/LING71671/open-reverselab/blob/main/desktop/AGENT_SYSTEM.md)
