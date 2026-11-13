---
title: Desktop installation and updates
description: Install ReverseLab on Windows, create a workspace and configure application updates.
---
# Desktop installation and updates

[Download v1.3.0](https://github.com/LING71671/open-reverselab/releases/tag/v1.3.0)

## Install on Windows

Run the Windows x64 installer. It includes the desktop interface, knowledge base and repository scripts. Python 3.10+ must be on PATH, and Microsoft Edge WebView2 Runtime is required. Install external tools such as Ghidra and Frida separately as needed.

The first launch creates a default workspace. You can also create or open another directory. Workspaces hold samples, Goals, evidence and reports. Configure a model provider, API endpoint, key and model ID, then create a Goal with a target and desired result.

## red / blue / both

Switch modes at the top left. red investigates analysis and validation paths; blue uses defense guidance and checks; both runs independent branches and joins their evidence. The live canvas shows branch status. Multiple Goals can queue, with two running per workspace by default.

Time and token limits are optional; omitted limits use runner defaults. Repeated actions or a lack of progress trigger alternative paths. Exhausting paths or limits saves the available results.

## Application updates

Use Settings to check versions, read release notes and download an update. Installed builds verify update signatures. Running tasks must finish and records must be saved before installation. Portable builds migrate through the new installer. Keep workspaces outside the installation directory.

## Data and platforms

The configured model endpoint receives task context and analysis evidence. API keys are stored in the local WebView storage. Generated Python runs with the current user's permissions.

This release provides a Windows x64 installer. Repository scripts work on macOS / Linux; desktop builds still require validation on those platforms.

[Developer guide](https://github.com/LING71671/open-reverselab/blob/main/desktop/DEV_GUIDE.md) · [Agent architecture](https://github.com/LING71671/open-reverselab/blob/main/desktop/AGENT_SYSTEM.md)
