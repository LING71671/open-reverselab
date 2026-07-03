# ReverseLab OpenCode Runtime Adapter

This directory contains the OpenCode runtime adapter for ReverseLab GUI.

It does not vendor the full OpenCode upstream tree. Instead, it provides:

- ReverseLab OpenCode config templates
- ReverseLab agents and prompts under `config/agent/`
- optional OpenCode core/UI patch files for maintainers who want a full custom upstream checkout
- local launch scripts that resolve paths from this repository

## First Version Target

The first version makes the CTF Website route GUI-first while preserving the existing implementation:

1. read root `AI-USAGE.md`
2. read `boards/ctf-website/AI-USAGE.md`
3. read `kb/ctf-website/techniques/attack-network.md`
4. route signals through `scripts/ctf-website/kb_router.py` or MCP `kb_router`
5. read matched technique files
6. run existing MCP/CLI tools
7. write evidence to `exports/ctf-website/`
8. update notes/reports

## Start

From the repository root:

```powershell
.\scripts\gui\reverselab_opencode_gui.ps1
```

The script sets `REVERSELAB_ROOT` to the current repository, sets `OPENCODE_CONFIG` to `gui/opencode/config/opencode.reverselab.jsonc`, and starts OpenCode in local server mode.

## Runtime Boundary

OpenCode is a dependency, not the ReverseLab product. ReverseLab GUI owns the visible workflow and can bundle or discover OpenCode at runtime.

The adapter is responsible for:

- generating local OpenCode config from the current workspace path
- registering ReverseLab MCP
- selecting the `reverselab-ctf` default agent
- keeping local execution unrestricted for authorized lab use

## Optional Fork Patch Track

When working inside a full OpenCode checkout, apply the patches in `gui/opencode/patches/` to make the upstream app a ReverseLab-branded GUI.

The repository remains publishable: no user-specific absolute paths, samples, credentials, private cases, or target identifiers should be committed.
