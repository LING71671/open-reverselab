#!/usr/bin/env python3
"""First-run checklist for opening ReverseLab in an Agent workspace."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
MCP_NAME = "reverse_lab_tools"
MCP_ENTRY = "tools/skills/mcp/ReverseLabToolsMCP/reverse_lab_tools_mcp.py"
MCP_PROJECT = "tools/skills/mcp/ReverseLabToolsMCP"
REQUIRED_ROOT_FILES = ["README.md", "AI-USAGE.md", "AGENTS.md", ".mcp.json"]
REQUIRED_DIRS = ["boards", "kb", "scripts", "tools", "templates", "cases", "exports", "notes", "reports"]
DEFAULT_REPORT = ROOT / "reports" / "misc" / "first-run-report.json"


def _is_windows() -> bool:
    return sys.platform.startswith("win")


def _python_install_hint() -> str:
    if _is_windows():
        return "Install Python 3.10+ from https://www.python.org/downloads/windows/ if this check cannot run."
    if sys.platform == "darwin":
        return "Install Python 3.10+ from https://www.python.org/downloads/macos/ or Homebrew if this check cannot run."
    return "Install Python 3.10+ with your distribution package manager or from https://www.python.org/downloads/ if this check cannot run."


def _git_install_hint() -> str:
    if _is_windows():
        return "Install Git for Windows from https://git-scm.com/download/win and reopen this window."
    if sys.platform == "darwin":
        return "Install Git with Xcode Command Line Tools or Homebrew, then reopen this shell."
    return "Install Git with your distribution package manager, then reopen this shell."


def _tool_install_hint() -> str:
    if _is_windows():
        return "If you need Web/APK/Windows tools, run the matching `scripts/misc/install_tools.ps1` option after this wizard passes."
    return "If you need optional CLI tools, add native macOS/Linux packages to PATH; Windows GUI tools are shipped in the Windows release."


def _restart_command() -> str:
    return "START_HERE.bat" if _is_windows() else "./START_HERE.sh"


@dataclass(frozen=True)
class Check:
    level: str
    name: str
    detail: str
    recommendation: str = ""


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
        checks.append(
            Check(
                "WARN",
                "workspace",
                f"run Agent sessions from repository root: {ROOT}",
                "Open this folder directly in Codex APP, or run `cd <repo>` before starting Claude Code.",
            )
        )

    checks.append(
        Check(
            "PASS",
            "Python",
            f"{sys.version.split()[0]} at {sys.executable}",
            _python_install_hint(),
        )
    )

    git_path = shutil.which("git")
    checks.append(
        Check(
            "PASS" if git_path else "FAIL",
            "Git",
            git_path or "not found in PATH",
            _git_install_hint(),
        )
    )

    uv_path = shutil.which("uv")
    checks.append(
        Check(
            "PASS" if uv_path else "WARN",
            "uv",
            uv_path or "not found in PATH",
            "Install uv from https://docs.astral.sh/uv/getting-started/installation/ or change `.mcp.json` to a Python command.",
        )
    )

    for rel in REQUIRED_ROOT_FILES:
        path = ROOT / rel
        checks.append(
            Check(
                "PASS" if path.is_file() else "FAIL",
                rel,
                "found" if path.is_file() else "missing",
                "Re-clone the repository or restore this file from Git.",
            )
        )

    for rel in REQUIRED_DIRS:
        path = ROOT / rel
        checks.append(
            Check(
                "PASS" if path.is_dir() else "FAIL",
                f"{rel}/",
                "found" if path.is_dir() else "missing",
                "Run `git sparse-checkout disable` or re-clone the repository if this skeleton directory is missing.",
            )
        )

    mcp_path = ROOT / ".mcp.json"
    mcp_config, mcp_error = _load_json(mcp_path)
    if mcp_error:
        checks.append(Check("FAIL", ".mcp.json parse", mcp_error, "Fix the JSON syntax in `.mcp.json`."))
        return checks

    servers = (mcp_config or {}).get("mcpServers", {})
    reverse_lab_tools = servers.get(MCP_NAME)
    if not isinstance(reverse_lab_tools, dict):
        checks.append(
            Check(
                "FAIL",
                "MCP reverse_lab_tools",
                "missing from .mcp.json mcpServers",
                "Restore the default `.mcp.json`; it must define `mcpServers.reverse_lab_tools`.",
            )
        )
        return checks

    checks.append(Check("PASS", "MCP reverse_lab_tools", "configured in .mcp.json"))
    command = reverse_lab_tools.get("command")
    args = reverse_lab_tools.get("args", [])
    checks.append(
        Check(
            "PASS" if command else "FAIL",
            "MCP command",
            str(command) if command else "missing command",
            "Set `mcpServers.reverse_lab_tools.command` in `.mcp.json`.",
        )
    )
    checks.append(
        Check(
            "PASS" if (ROOT / MCP_ENTRY).is_file() else "FAIL",
            "MCP entry script",
            MCP_ENTRY,
            "Restore `tools/skills/mcp/ReverseLabToolsMCP/` from Git.",
        )
    )
    checks.append(
        Check(
            "PASS" if (ROOT / MCP_PROJECT / "pyproject.toml").is_file() else "FAIL",
            "MCP project",
            MCP_PROJECT,
            "Run `git submodule update --init --recursive` if future versions move this to a submodule; otherwise re-clone.",
        )
    )
    if command and shutil.which(str(command)) is None:
        checks.append(
            Check(
                "WARN",
                f"{command} in PATH",
                "not found",
                f"Install `{command}` or adjust `.mcp.json`; Codex/Claude may not be able to start MCP yet.",
            )
        )
    elif command:
        checks.append(Check("PASS", f"{command} in PATH", shutil.which(str(command)) or "found"))

    args_text = " ".join(str(arg) for arg in args)
    if MCP_ENTRY.replace("\\", "/") in args_text.replace("\\", "/"):
        checks.append(Check("PASS", "MCP args", "entry script is referenced"))
    else:
        checks.append(
            Check(
                "FAIL",
                "MCP args",
                f"{MCP_ENTRY} is not referenced",
                "Restore the default `args` array in `.mcp.json`.",
            )
        )

    return checks


def build_payload(checks: list[Check], report_path: Path = DEFAULT_REPORT) -> dict[str, Any]:
    failures = [check for check in checks if check.level == "FAIL"]
    warnings = [check for check in checks if check.level == "WARN"]
    serialized_checks = []
    for check in checks:
        item = check.__dict__.copy()
        if check.level == "PASS":
            item["recommendation"] = ""
        serialized_checks.append(item)

    return {
        "schema": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "root": str(ROOT),
        "report_path": str(report_path),
        "overall": "FAIL" if failures else "PASS",
        "summary": {
            "pass": sum(1 for check in checks if check.level == "PASS"),
            "warn": len(warnings),
            "fail": len(failures),
        },
        "checks": serialized_checks,
        "recommendations": [
            {"name": check.name, "level": check.level, "recommendation": check.recommendation}
            for check in checks
            if check.level != "PASS" and check.recommendation
        ],
        "next_steps": [
            f"Codex APP: open this folder directly: {ROOT}",
            f"Claude Code: run `cd {ROOT}` before starting the session.",
            _tool_install_hint(),
        ],
    }


def write_report(payload: dict[str, Any], report_path: Path = DEFAULT_REPORT) -> Path:
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return report_path


def print_human(checks: list[Check]) -> None:
    payload = build_payload(checks)
    print("ReverseLab first-run wizard")
    print(f"Repository root: {ROOT}")
    print(f"Python: {sys.version.split()[0]} ({sys.executable})")
    print("")

    print("Status summary")
    print(f"  PASS: {payload['summary']['pass']}")
    print(f"  WARN: {payload['summary']['warn']}")
    print(f"  FAIL: {payload['summary']['fail']}")
    print("")

    for check in checks:
        print(f"[{check.level}] {check.name}: {check.detail}")
        if check.level != "PASS" and check.recommendation:
            print(f"      Fix: {check.recommendation}")

    failures = [check for check in checks if check.level == "FAIL"]
    warnings = [check for check in checks if check.level == "WARN"]
    print("")
    if failures:
        print("Result: FAIL")
        print(f"Fix the FAIL items above first, then run {_restart_command()} again.")
    elif warnings:
        print("Result: PASS with warnings")
        print("The repository layout is usable; resolve WARN items before relying on MCP tool execution.")
    else:
        print("Result: PASS")
        print("现在可以用 Codex APP 打开这个文件夹，或在 Claude Code 中 cd 到这里。")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="print machine-readable check results")
    parser.add_argument(
        "--write-report",
        nargs="?",
        const=str(DEFAULT_REPORT),
        help=f"write first-run report JSON; default path is {DEFAULT_REPORT.relative_to(ROOT)}",
    )
    args = parser.parse_args()

    checks = collect_checks()
    report_path = Path(args.write_report) if args.write_report else DEFAULT_REPORT
    if not report_path.is_absolute():
        report_path = ROOT / report_path
    payload = build_payload(checks, report_path)
    if args.write_report:
        write_report(payload, report_path)

    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print_human(checks)
        if args.write_report:
            print("")
            print(f"Report written: {report_path}")
    return 1 if payload["overall"] == "FAIL" else 0


if __name__ == "__main__":
    raise SystemExit(main())
