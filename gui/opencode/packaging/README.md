# ReverseLab GUI Packaging

The finished product should be a packaged ReverseLab GUI app: users open it and the ReverseLab workflow starts. OpenCode is a bundled or discovered runtime dependency, not the visible product.

The app still uses the original ReverseLab principle:

```text
signal -> KB route -> technique file -> MCP/tool execution -> evidence -> notes/reports
```

## Target User Experience

1. User downloads and extracts `ReverseLab-GUI-<version>-windows-x64.zip` or runs the installer.
2. User opens `ReverseLabGUI.exe`.
3. The app opens a native desktop window and locates the bundled workspace or asks for a ReverseLab workspace folder.
4. The app starts:
   - local ReverseLab GUI bridge
   - OpenCode runtime when bundled or discovered
   - ReverseLab MCP server through the existing runtime/tool configuration
5. The default screen is the CTF Website workbench.

## Packaged Layout

```text
ReverseLab-GUI/
  ReverseLabGUI.exe
  app/
    gui/
    opencode-runtime/
  workspace/
    AI-USAGE.md
    boards/
    kb/
    scripts/
    tools/
    templates/
  runtime/
    opencode/
    node/
    python/
    uv/
  data/
    cases/
    exports/
    notes/
    reports/
    samples/
```

`workspace/` contains the public ReverseLab repository contents. `data/` contains user-generated evidence and should not be overwritten by upgrades.

## Release Modes

- **Portable zip**: preferred first release. No installer, no registry writes.
- **Installer**: later, after update and data migration rules are stable.
- **Developer mode**: run from the repository with `scripts/gui/reverselab_opencode_gui.ps1`.

Developer mode is intentionally light: a static Web UI is served by
`scripts/gui/reverselab_gui_server.py`, and OpenCode is treated as a runtime
dependency on a separate local port. The packaged Windows app embeds that local
GUI in WebView2 instead of opening the user's browser.

`ReverseLabGUI.exe` is a lightweight Windows desktop shell built from
`gui/opencode/packaging/windows/ReverseLabGUI.cs`. It opens a WinForms window,
starts the auditable `ReverseLabGUI.ps1` script next to it with `-NoBrowser`,
then embeds the local ReverseLab GUI through WebView2.

Developer packaging:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\gui\package_reverselab_gui.ps1 -Clean -Zip
```

This stages `dist\ReverseLab-GUI-dev\` and writes
`dist\ReverseLab-GUI-dev-windows-x64.zip`.

Optional bundled runtimes can be copied into the portable package:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\gui\package_reverselab_gui.ps1 -Clean -Zip -PythonRoot C:\path\to\python -OpenCodeRoot C:\path\to\opencode
```

At launch, ReverseLab GUI prefers bundled runtime paths under `runtime\python`
and `runtime\opencode`, then falls back to tools discovered on `PATH`.

## Build Inputs

- OpenCode upstream release or fork checkout
- ReverseLab repository
- .NET SDK, only for building the desktop shell exe
- Microsoft Edge WebView2 Runtime on the target machine, or the Evergreen runtime installed by Windows/Edge
- Node/Bun runtime or OpenCode binary
- Python runtime and `uv`
- `tools/skills/mcp/ReverseLabToolsMCP`

## First Version Scope

The first packaged GUI only needs to make the CTF route first-class:

- New target/case form
- Signal input
- KB router result panel
- Technique reader
- Tool execution panel
- Evidence file browser
- Notes/report shortcuts
- AI chat bound to `reverselab-ctf`

Other boards can remain accessible through the AI/chat route until later GUI panels are added.
