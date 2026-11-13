# Open ReverseLab Desktop

[简体中文](README.zh-CN.md)

Open ReverseLab organizes target-based analysis into Goals, with a live execution canvas, readable analysis progress, and saved evidence. Choose `red`, `blue`, or `both`, enter a file, directory, or URL target, and describe the result you need.

This guide describes the current desktop source preview. Public downloads and their supported features are listed in [Releases](https://github.com/LING71671/open-reverselab/releases); a version in the source tree does not mean its release package is available.

## Start from source

Run these commands in `desktop/`:

```sh
pnpm install --frozen-lockfile
pnpm dev
```

For the native desktop app, use `pnpm tauri dev`. Python 3.10+ must be available as `python`. Native builds also need Rust and the [Tauri platform prerequisites](https://v2.tauri.app/start/prerequisites/), including WebView2 on Windows. Install analysis tools separately. Browser preview uses local development services for workspace and Python operations; native proxy routing, process monitoring, and update installation require the desktop app.

`REVERSELAB_ROOT` can point to the repository containing the knowledge base and scripts. See the [development guide](DEV_GUIDE.md) for build and verification commands.

## Create a Goal

1. Open or create a workspace through the workspace selector. First launch creates a default workspace outside the application and repository directories.
2. Open **Settings → Model**, enter a chat-completions-compatible API address, API key, and model ID, then save. You can fetch the provider's model list or enter the ID directly. **Save and test** sends a short request to that provider.
3. Select `red / blue / both` at the upper left. Enter the **Target** separately from the **Goal**. Importing a file or directory through **Samples** preserves an original copy and creates a working copy; entering an external path directly uses that path.
4. Start the Goal. Time and token budgets are optional and blank by default. Goals and ready actions have no default concurrency cap.

The model comes from saved settings or an explicitly configured `VITE_LLM_MODEL`. No provider or model is substituted when configuration is missing. Basic SHA256 verification can use a deterministic local check; other Goals use the configured model to plan actions and independently assess their evidence.

While a Goal runs, send additional requirements from its input area. They remain in the same Goal, appear as pending, and take effect after the current step ends. Earlier evidence and history remain available; the revised objective must pass its own verification. **Stop** cancels the run and retains its recorded progress.

Create other Goals or switch workspaces while work continues. Each runner keeps the workspace in which it started. The model generates a short task title; double-click the title or press **F2** on the task to rename it. Your title takes precedence over generated titles.

## Read progress and evidence

The **Body** view shows the Agent's analysis progress and conclusions. Plans, scripts, structured data, tool output, and verification details are expandable. Report paths remain available with the result.

The **Canvas** shows actual actions, dependencies, evidence handoffs, and joins. Click a card to expand its details or open its execution record. Pan and zoom to inspect a branch, use **Follow workflow** to follow current work, or open the full-screen canvas; **Esc** exits full screen. Manual navigation turns following off until you enable it again.

`red` and `blue` use separate strategies and knowledge routes. In `both`, each side can create parallel actions and share evidence with the other side; the graph includes those cross-links. Each branch is checked separately before the combined objective is verified.

Knowledge lives in [`kb/red/`](../kb/red), [`kb/blue/`](../kb/blue), and [`kb/shared/`](../kb/shared). Red uses attack networks, blue uses defense networks, and both can retrieve shared references. The knowledge view reads the actual index and links paired articles.

Health monitoring groups observed events by Goal, Agent, model, knowledge base, tool, and storage. A service with no observation remains unknown. The current execution adapters provide target triage and Python execution; scripts can use installed libraries and command-line tools. Dedicated debugger, device-control, and hardening adapters require their own integration. BLA / REA acceptance work is tracked in the [adversarial validation plan](ADVERSARIAL_PROFILES.md).

## Settings

Settings opens as a full page, with categories for workspaces, models, proxy pools, diagnostics, local tools, and application updates. **Return to workspace** restores the workspace view.

- [Proxy pools](NETWORK.md): independent routes for model requests and Python target access, named nodes, authentication, connection tests, and model failover.
- [Diagnostics](DIAGNOSTICS.md): optional background performance warnings and optional Sentry error and timing reports. Both are off by default.
- [Application updates](UPDATES.md): version checks, download progress, signature verification, and installation for supported installed builds. Installation waits for running and queued Goals in all open workspaces.

## Workspace and data

Goals, reports, scripts, and imported samples are stored under the workspace's `.reverselab/` directory. Back up that directory before moving a workspace or upgrading an installed build. Restoring history does not restart interrupted external processes or relocate absolute target paths. Keep application files and workspace data in separate directories. See [workspace storage](WORKSPACES.md).

API keys and proxy credentials are held in local WebView storage without OS-keychain integration. Model-assisted tasks send task context and selected evidence to the endpoint you configure. Python actions run with the current user's permissions. Drafts and reading positions survive navigation during the current workspace session.

For local development, `VITE_LLM_BASE_URL`, `VITE_LLM_API_KEY`, and `VITE_LLM_MODEL` can seed configuration. Vite embeds `VITE_*` values in the frontend build; keep private keys out of distributed builds and public commits.

Use Open ReverseLab for legal, authorized analysis. Read the [disclaimer](../DISCLAIMER.md). Private samples, targets, reports, credentials, and local screenshots stay outside public changes.

## Engineering references

- [Architecture](ARCHITECTURE.md) and [Agent runtime contracts](AGENT_SYSTEM.md)
- [Health events and error codes](ERROR_CODES.md)
- [UI design](DESIGN_BRIEF.md) and [development checks](DEV_GUIDE.md)
- [Packaging and release checks](../RELEASING.md)
