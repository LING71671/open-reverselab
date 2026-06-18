#!/usr/bin/env python3
"""Portable, no-popup health check for a ReverseLab checkout."""

from __future__ import annotations

import argparse
import json
import py_compile
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
REQUIRED_DIRS = [
    "boards", "cases", "exports", "kb", "logs", "notes", "patches",
    "projects", "reports", "samples", "scripts", "templates", "tools", "tmp",
]
CORE_FILES = [
    "AGENTS.md", "AI-USAGE.md", ".mcp.json",
    "tools/ai-tool-registry.json", "tools/ai-tool-playbook.json",
    "scripts/misc/ai_context.py", "scripts/misc/ai_tool.py",
    "tools/skills/mcp/ReverseLabToolsMCP/pyproject.toml",
]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--strict-tools", action="store_true", help="also require every registry tool")
    args = ap.parse_args()
    failures: list[str] = []

    for rel in REQUIRED_DIRS:
        if not (ROOT / rel).is_dir():
            failures.append(f"missing directory: {rel}/")
    for rel in CORE_FILES:
        if not (ROOT / rel).is_file():
            failures.append(f"missing core file: {rel}")

    for path in ROOT.rglob("*.py"):
        if any(part in {".git", ".venv", "venv", "node_modules"} for part in path.parts):
            continue
        try:
            py_compile.compile(str(path), doraise=True)
        except Exception as exc:
            failures.append(f"python syntax: {path.relative_to(ROOT)}: {exc}")

    for rel in [".mcp.json", "tools/ai-tool-registry.json", "tools/ai-tool-playbook.json"]:
        try:
            json.loads((ROOT / rel).read_text(encoding="utf-8"))
        except Exception as exc:
            failures.append(f"json parse: {rel}: {exc}")

    tool_result = None
    if args.strict_tools:
        tool_result = subprocess.run(
            [sys.executable, str(ROOT / "scripts/misc/ai_toolcheck.py")], cwd=ROOT
        ).returncode
        if tool_result:
            failures.append("strict tool availability check failed")

    payload = {
        "root": str(ROOT),
        "overall": "PASS" if not failures else "FAIL",
        "strict_tools": args.strict_tools,
        "failures": failures,
        "note": "External GUI/CLI tools are optional unless --strict-tools is used.",
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
