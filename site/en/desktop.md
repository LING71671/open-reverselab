---
title: Desktop installation and updates
description: Download the Open ReverseLab Windows desktop beta, install knowledge extensions, configure a model, and run Goals.
---
# Desktop installation and updates

[Download v2.0.0-beta2](https://github.com/LING71671/open-reverselab/releases/tag/v2.0.0-beta2) for Windows x64 as an installer or portable ZIP. The desktop packages do not bundle a knowledge base or MCP server. Import knowledge packs and add MCP connections in the application after installation.

## Windows installation

1. Install Python 3.11+, make `python` available on PATH, and install Microsoft Edge WebView2 Runtime.
2. Download and run the `-setup.exe` installer, or extract the complete portable ZIP and launch `OpenReverseLab.exe`.
3. Start the application and save your provider's API endpoint, API key, and model ID in Settings. If the provider offers a model catalog, switch models directly in the Goal composer.
4. Choose a workspace and create a Goal with a file, directory, or URL target and the result you want. Basic SHA256 verification can run locally.

First launch creates a default workspace. You can also create or open other directories. Workspaces hold samples, Goals, evidence, and reports. Keep them outside the installation directory. Install external tools such as Ghidra and Frida separately as needed.

## red / blue / both

Select a strategy at the top left. Red organizes analysis hypotheses and observation paths; blue uses defense guidance to examine behavior and controls. Both runs the two strategies in parallel. Each can plan multiple actions, exchange evidence during execution, and assess its own responsibilities before the combined objective is checked.

New tool evidence from a peer can reopen a blocked branch for further planning, forks, and joins. Repeated observations do not keep restarting the same route. When a target file has a measured SHA256, observations and verification are associated with that content version.

Goals and ready actions have no default concurrency cap. Time and token budgets are also optional. Adding requirements during a run keeps the same Goal's evidence and history and applies the new objective at an execution boundary. Stopping cancels execution and retains recorded progress.

The transcript presents analysis progress, with expandable plans, scripts, tool output, and verification details. The canvas shows actual dependencies and evidence links, with card details, zoom, execution follow, and full-screen mode.

Switching red, blue, and both restores each strategy's selected Goal. Unsent drafts are saved locally per workspace and Goal, so editing can continue after switching workspaces or reloading.

## Install knowledge and MCP

The desktop runtime and knowledge packs are distributed independently. Open **Extensions → Sources**, browse **Open ReverseLab official knowledge**, and install the pack. Other repositories, local folders, and ZIPs work too. Sources stores catalogs for later browsing.

Knowledge packs can be enabled, disabled, removed, and exported. For GitHub installations, choose **Check for updates**, then **Update to …** to install the version found on the source repository's default branch. Selected-network export includes referenced methods and documents; the ZIP can be imported again. Running Goals retain pinned documents, methods, and networks when packs are updated.

Under MCP, import a descriptor or add a standalone connection, configure a stdio command or Streamable HTTP endpoint, then verify the connection to discover tools and resources. Connection values stay local and are excluded from knowledge exports.

[Extension protocol and usage](https://github.com/LING71671/open-reverselab/blob/main/EXTENSIONS.md) · [Extension authoring skill](https://github.com/LING71671/open-reverselab/tree/main/tools/skills/create-reverselab-extension)

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

This release provides a Windows x64 installer and portable ZIP. macOS / Linux retain the repository's CLI/MCP workflow; native desktop packages for those platforms are not provided.

[Desktop guide](https://github.com/LING71671/open-reverselab/blob/main/desktop/README.md) · [Developer guide](https://github.com/LING71671/open-reverselab/blob/main/desktop/DEV_GUIDE.md) · [Agent runtime](https://github.com/LING71671/open-reverselab/blob/main/desktop/AGENT_SYSTEM.md)
