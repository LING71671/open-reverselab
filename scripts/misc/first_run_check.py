#!/usr/bin/env python3
"""First-run checklist for opening ReverseLab in an Agent workspace."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
MCP_NAME = "reverse_lab_tools"
MCP_ENTRY = "tools/skills/mcp/ReverseLabToolsMCP/reverse_lab_tools_mcp.py"
MCP_PROJECT = "tools/skills/mcp/ReverseLabToolsMCP"
REQUIRED_ROOT_FILES = ["README.md", "AI-USAGE.md", "AGENTS.md", ".mcp.json"]
REQUIRED_DIRS = ["boards", "kb", "scripts", "tools", "templates", "cases", "exports", "notes", "reports"]


@dataclass(frozen=True)
class Check:
    level: str
    name: str
    detail: str


def _load_json(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    try:
        return json.loads(path.read_text(encoding="utf-8")), None
    except Exception as exc:
        return None, str(exc)


def collect_checks(cwd: Path = Path.cwd()) -> list[Check]:
    checks: list[Check] = []

    if cwd.resolve() == ROOT:
        checks.append(Check("PASS", "workspace", f"current directory is repository root: {ROOT}"))
    else:
        checks.append(Check("WARN", "workspace", f"run Agent sessions from repository root: {ROOT}"))

    for rel in REQUIRED_ROOT_FILES:
        path = ROOT / rel
        checks.append(
            Check("PASS" if path.is_file() else "FAIL", rel, "found" if path.is_file() else "missing")
        )

    for rel in REQUIRED_DIRS:
        path = ROOT / rel
        checks.append(
            Check("PASS" if path.is_dir() else "FAIL", f"{rel}/", "found" if path.is_dir() else "missing")
        )

    mcp_path = ROOT / ".mcp.json"
    mcp_config, mcp_error = _load_json(mcp_path)
    if mcp_error:
        checks.append(Check("FAIL", ".mcp.json parse", mcp_error))
        return checks

    servers = (mcp_config or {}).get("mcpServers", {})
    reverse_lab_tools = servers.get(MCP_NAME)
    if not isinstance(reverse_lab_tools, dict):
        checks.append(Check("FAIL", "MCP reverse_lab_tools", "missing from .mcp.json mcpServers"))
        return checks

    checks.append(Check("PASS", "MCP reverse_lab_tools", "configured in .mcp.json"))
    command = reverse_lab_tools.get("command")
    args = reverse_lab_tools.get("args", [])
    checks.append(
        Check("PASS" if command else "FAIL", "MCP command", str(command) if command else "missing command")
    )
    checks.append(
        Check(
            "PASS" if (ROOT / MCP_ENTRY).is_file() else "FAIL",
            "MCP entry script",
            MCP_ENTRY,
        )
    )
    checks.append(
        Check(
            "PASS" if (ROOT / MCP_PROJECT / "pyproject.toml").is_file() else "FAIL",
            "MCP project",
            MCP_PROJECT,
        )
    )
    if command and shutil.which(str(command)) is None:
        checks.append(Check("WARN", f"{command} in PATH", "install uv or adjust .mcp.json command before starting MCP"))
    elif command:
        checks.append(Check("PASS", f"{command} in PATH", shutil.which(str(command)) or "found"))

    args_text = " ".join(str(arg) for arg in args)
    if MCP_ENTRY.replace("\\", "/") in args_text.replace("\\", "/"):
        checks.append(Check("PASS", "MCP args", "entry script is referenced"))
    else:
        checks.append(Check("FAIL", "MCP args", f"{MCP_ENTRY} is not referenced"))

    return checks


def print_human(checks: list[Check]) -> None:
    print("ReverseLab first-run check")
    print(f"Repository root: {ROOT}")
    print("")
    for check in checks:
        print(f"[{check.level}] {check.name}: {check.detail}")

    failures = [check for check in checks if check.level == "FAIL"]
    warnings = [check for check in checks if check.level == "WARN"]
    print("")
    if failures:
        print("Result: FAIL")
        print("Fix the FAIL items first, then restart Claude Code or reopen this folder in Codex APP.")
    elif warnings:
        print("Result: PASS with warnings")
        print("The repository layout is usable; resolve WARN items before relying on MCP tool execution.")
    else:
        print("Result: PASS")
        print("Open this folder in Codex APP, or run Claude Code from this repository root.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="print machine-readable check results")
    args = parser.parse_args()

    checks = collect_checks()
    payload = {
        "root": str(ROOT),
        "overall": "FAIL" if any(check.level == "FAIL" for check in checks) else "PASS",
        "checks": [check.__dict__ for check in checks],
    }
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print_human(checks)
    return 1 if payload["overall"] == "FAIL" else 0


if __name__ == "__main__":
    raise SystemExit(main())
