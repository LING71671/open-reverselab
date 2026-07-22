# Codex-only local tooling

This local toolset is for Codex only.

Use these root-level launchers:

- `CODEX.bat`
- `LAUNCHER.bat`

What it does:

- registers the global Codex MCP server `open_reverselab_codex`
- merges a managed global Codex developer-instructions block
- preserves any existing workspace `.codex/config.toml`
- lets you bind other projects to open-reverselab Codex mode
- creates per-project `.codex/` runtime files when a target project is bound
- stores local adapter state, reports, and backups under `.open-reverselab-local/`

What it does not do:

- it does not replace the upstream `START_HERE.bat`
- it does not modify the repo-local upstream `.mcp.json`
- it does not manage `.claude/`
- `LAUNCHER.bat` routes its `Claude` and `Other CLI` entries back to the
  upstream `START_HERE` flow; this adapter only adds a real Codex integration
  path

Recommended flow:

- run `CODEX.bat`
- choose `1. 安装/修复 全局 Codex MCP`
- restart Codex App and Codex CLI
- open the real target project
- say `启用 open-reverselab Codex 模式`
- confirm the previewed changes when asked

Project outputs:

- `.codex/`
- `.open-reverselab-codex/`
- `notes/open-reverselab/`
- `reports/open-reverselab/`
- `exports/open-reverselab/`
- `patches/open-reverselab/` on demand
- `projects/open-reverselab/` on demand
