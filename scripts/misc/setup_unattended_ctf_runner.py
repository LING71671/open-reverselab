#!/usr/bin/env python3
"""
Generate local Claude Code / Codex profiles for unattended Web CTF loops.

The generated files are machine-local runner configuration.  They are meant to
live in this workspace folder and are ignored by git when possible.

Codex model_instructions_file points at the committed repo-root CODEX.md via
configure_codex_model_instructions.py (no local ctf_optimized.md prompt).
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CONFIGURE_SCRIPT = Path(__file__).resolve().parent / "configure_codex_model_instructions.py"

MCP_BLOCK = """
[mcp_servers.reverse_lab_tools]
command = "uv"
args = [
  "run",
  "--project",
  "tools/skills/mcp/ReverseLabToolsMCP",
  "python",
  "tools/skills/mcp/ReverseLabToolsMCP/reverse_lab_tools_mcp.py",
]
""".lstrip()

CLAUDE_SETTINGS = {
    "permissions": {
        "allow": [
            "Bash(*)",
            "Read(*)",
            "Write(*)",
            "Edit(*)",
            "MultiEdit(*)",
            "Glob(*)",
            "Grep(*)",
            "LS(*)",
            "WebFetch(*)",
            "WebSearch(*)",
        ],
        "deny": [],
    }
}


def write_text(path: Path, content: str, overwrite: bool) -> str:
    if path.exists() and not overwrite:
        return "exists"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return "written"


def write_json(path: Path, payload: dict, overwrite: bool) -> str:
    return write_text(path, json.dumps(payload, ensure_ascii=False, indent=2) + "\n", overwrite)


def ensure_gitignore_entries(overwrite: bool) -> str:
    gitignore = ROOT / ".gitignore"
    entries = [".codex/", ".claude/settings.local.json"]
    if not gitignore.exists():
        gitignore.write_text("\n".join(entries) + "\n", encoding="utf-8")
        return "written"

    text = gitignore.read_text(encoding="utf-8")
    changed = False
    for entry in entries:
        if entry not in text:
            text = text.rstrip() + "\n" + entry + "\n"
            changed = True
    if changed and overwrite:
        gitignore.write_text(text, encoding="utf-8")
        return "updated"
    return "ok" if not changed else "needs-update"


def ensure_key(text: str, key: str, value_line: str) -> str:
    pattern = re.compile(rf"(?m)^\s*{re.escape(key)}\s*=")
    if pattern.search(text):
        return text
    lines = text.splitlines(keepends=True)
    out: list[str] = []
    inserted = False
    for ln in lines:
        out.append(ln)
        if (not inserted) and ln.strip().startswith("model_instructions_file"):
            out.append(value_line if value_line.endswith("\n") else value_line + "\n")
            inserted = True
    if not inserted:
        out.insert(0, value_line if value_line.endswith("\n") else value_line + "\n")
    return "".join(out)


def merge_runner_extras(path: Path, overwrite: bool) -> str:
    """Add approval/sandbox/MCP while preserving model_instructions_file and other keys."""
    if path.exists() and not overwrite:
        # Still ensure critical runner keys if missing, without full rewrite intent.
        pass

    if not path.exists():
        # configure script should have created it; create minimal if needed
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('model_instructions_file = "../CODEX.md"\n', encoding="utf-8")

    before = path.read_text(encoding="utf-8")
    text = before
    text = ensure_key(text, "approval_policy", 'approval_policy = "never"')
    text = ensure_key(text, "sandbox_mode", 'sandbox_mode = "danger-full-access"')
    if "[mcp_servers.reverse_lab_tools]" not in text:
        if text and not text.endswith("\n"):
            text += "\n"
        text += "\n" + MCP_BLOCK
    while "\n\n\n" in text:
        text = text.replace("\n\n\n", "\n\n")

    if text == before and path.exists() and not overwrite:
        return "unchanged"
    path.write_text(text, encoding="utf-8")
    return "updated" if before else "written"


def configure_model_instructions() -> dict:
    proc = subprocess.run(
        [sys.executable, str(CONFIGURE_SCRIPT)],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise SystemExit(
            f"configure_codex_model_instructions.py failed ({proc.returncode}):\n"
            f"{proc.stdout}\n{proc.stderr}"
        )
    return json.loads(proc.stdout)


def main() -> int:
    parser = argparse.ArgumentParser(description="Create unattended CTF runner profiles for Claude Code and Codex.")
    parser.add_argument("--overwrite", action="store_true", help="Overwrite / refresh local runner extras.")
    parser.add_argument("--skip-gitignore", action="store_true", help="Do not update .gitignore for local runner files.")
    args = parser.parse_args()

    if not (ROOT / "CODEX.md").is_file():
        print("ERROR: CODEX.md missing at repository root", file=sys.stderr)
        return 1

    configure_result = configure_model_instructions()

    outputs = {
        "codex_model_instructions": configure_result,
        "codex_config_runner": merge_runner_extras(ROOT / ".codex" / "config.toml", args.overwrite),
        "codex_ctf_config_runner": merge_runner_extras(ROOT / ".codex" / "ctf.config.toml", args.overwrite),
        "claude_settings": write_json(ROOT / ".claude" / "settings.local.json", CLAUDE_SETTINGS, args.overwrite),
    }
    if not args.skip_gitignore:
        outputs["gitignore"] = ensure_gitignore_entries(overwrite=True)

    obsolete = ROOT / ".codex" / "ctf_optimized.md"
    if obsolete.exists() and args.overwrite:
        obsolete.unlink()
        outputs["removed_obsolete_ctf_optimized"] = "deleted"
    elif obsolete.exists():
        outputs["removed_obsolete_ctf_optimized"] = "present-not-deleted-without-overwrite"

    print(json.dumps({"root": str(ROOT), "outputs": outputs}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
