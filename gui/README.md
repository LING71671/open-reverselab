# ReverseLab GUI

ReverseLab GUI is the primary operator surface for this repository.

It follows an OpenDesign-style architecture: ReverseLab owns the GUI, workflow, domain model, packaging, and evidence layout; OpenCode is used as the local AI runtime for providers, sessions, MCP, and tool calls.

The design goal is simple: keep the existing ReverseLab principles and toolchain unchanged, but make the GUI the main way technical users operate it. The GUI drives the same route:

```text
AI-USAGE.md -> board AI-USAGE.md -> kb_router -> kb_read_file -> MCP tool mapping -> tool execution -> exports/notes/reports
```

## Layout

- `app/` - ReverseLab GUI product source and screen specs
- `opencode/` - OpenCode runtime adapter, config templates, agents, and optional upstream patches

The first product screen is the CTF Website workbench.
