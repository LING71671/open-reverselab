# CTF Website Workbench

This is the first ReverseLab GUI screen.

## Purpose

Make the existing CTF route visual and one-click without changing the underlying method.

## Primary Flow

1. User creates or opens a case.
2. GUI reads:
   - `AI-USAGE.md`
   - `boards/ctf-website/AI-USAGE.md`
   - `kb/ctf-website/techniques/attack-network.md`
3. User enters a signal.
4. GUI calls `kb_router`.
5. User opens a technique file.
6. GUI displays the MCP tool mapping.
7. User runs existing tool actions.
8. GUI stores output under the existing ReverseLab evidence directories.

## Panels

- **Case**: case name, target, scope note, output directory
- **Attack Network**: rendered `attack-network.md` graph and checklists
- **Signal Router**: signal input, ranked KB files, confidence
- **Technique**: Markdown reader with copy/run affordances for existing commands
- **Tool Output**: command stream, exit code, generated artifact links
- **Evidence**: `exports/ctf-website`, `notes/ctf-website`, `reports/ctf-website`
- **AI**: OpenCode-backed `reverselab-ctf` chat

## Acceptance Criteria

- Running a signal through the GUI produces the same KB route as the CLI.
- Opening a ranked technique file reads the existing Markdown from `kb/ctf-website/techniques/`.
- Tool actions call existing scripts or MCP tools.
- Evidence files are visible from the GUI after execution.
- No GUI-only state is required to understand the result.

