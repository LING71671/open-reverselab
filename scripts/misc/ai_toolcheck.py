#!/usr/bin/env python3
"""
No-popup AI tool registry checker for ReverseLab.

Reads tools/ai-tool-registry.json and verifies:
- CLI tools by safe version/help probes.
- GUI or target-side binaries by file existence/hash only.

This script intentionally never launches entries marked launch_mode=gui.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
REGISTRY = ROOT / "tools" / "ai-tool-registry.json"
REPORT_DIR = ROOT / "reports" / "misc" / "toolcheck"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def one_line(text: str, limit: int = 260) -> str:
    text = " ".join((text or "").replace("\r", "\n").split())
    return text[: limit - 3] + "..." if len(text) > limit else text


def check_file(tool: dict[str, Any], probe: dict[str, Any]) -> dict[str, Any]:
    path = Path(probe.get("path") or tool.get("command") or "")
    if not path.is_absolute():
        path = ROOT / path
    if not path.exists():
        return {"status": "MISSING", "detail": "file missing", "path": str(path)}
    expected = (probe.get("sha256") or "").upper()
    actual = ""
    if expected:
        actual = sha256_file(path)
        if actual != expected:
            return {
                "status": "FAIL",
                "detail": f"sha256 mismatch expected={expected} actual={actual}",
                "path": str(path),
            }
    return {
        "status": "FOUND",
        "detail": f"file exists size={path.stat().st_size}" + (f" sha256={actual}" if actual else ""),
        "path": str(path),
    }


def check_command(tool: dict[str, Any], probe: dict[str, Any]) -> dict[str, Any]:
    command = tool["command"]
    command_path = Path(command)
    if not command_path.is_absolute() and ("/" in command or "\\" in command):
        command = str((ROOT / command_path).resolve())
    args = list(tool.get("args") or [])
    timeout = int(probe.get("timeout_ms") or 10000) / 1000.0
    allow_nonzero = bool(probe.get("allow_nonzero"))
    env = os.environ.copy()
    env["PATH"] = str(ROOT / "tools" / "bin") + os.pathsep + str(ROOT / "tools" / "ctf-website" / "bin") + os.pathsep + env.get("PATH", "")
    try:
        cmd_path = Path(command)
        argv = [command, *args]
        if cmd_path.suffix.lower() in {".bat", ".cmd"}:
            argv = [os.environ.get("COMSPEC", "cmd.exe"), "/c", command, *args]
        proc = subprocess.run(
            argv,
            cwd=str(ROOT),
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            shell=False,
        )
    except FileNotFoundError as exc:
        return {"status": "MISSING", "detail": str(exc), "path": command}
    except subprocess.TimeoutExpired:
        return {"status": "TIMEOUT", "detail": f"probe timed out after {timeout:.1f}s", "path": command}
    output = one_line((proc.stdout or "") + " " + (proc.stderr or ""))
    if proc.returncode != 0 and not allow_nonzero:
        return {"status": "FAIL", "detail": f"exit={proc.returncode} {output}", "path": command}
    return {"status": "FOUND", "detail": f"exit={proc.returncode} {output}", "path": command}


def check_tool(tool: dict[str, Any]) -> dict[str, Any]:
    probe = tool.get("safe_probe") or {}
    ptype = probe.get("type")
    if tool.get("launch_mode") == "gui" and ptype != "file":
        return {
            "status": "SKIPPED",
            "detail": "GUI entry has no file-only safe probe; not launched by design",
            "path": tool.get("command", ""),
        }
    if ptype == "file":
        result = check_file(tool, probe)
    elif ptype == "command":
        result = check_command(tool, probe)
    else:
        result = {"status": "FAIL", "detail": f"unknown safe_probe type: {ptype}", "path": tool.get("command", "")}
    return {
        "id": tool.get("id"),
        "board": tool.get("board"),
        "name": tool.get("name"),
        "launch_mode": tool.get("launch_mode"),
        "ai_callable": bool(tool.get("ai_callable")),
        **result,
    }


def render_md(payload: dict[str, Any]) -> str:
    lines = [
        "# ReverseLab AI Toolcheck",
        "",
        f"- Time: {payload['time']}",
        f"- Registry: `{payload['registry']}`",
        f"- Overall: **{payload['overall']}**",
        f"- Found: {payload['found']}",
        f"- Missing/Fail/Timeout: {payload['bad']}",
        "",
        "| Status | Board | ID | Mode | AI Callable | Detail | Path |",
        "|---|---|---|---|---:|---|---|",
    ]
    for r in payload["results"]:
        detail = str(r.get("detail", "")).replace("|", "\\|")
        path = str(r.get("path", "")).replace("|", "\\|")
        lines.append(
            f"| {r.get('status')} | {r.get('board')} | {r.get('id')} | {r.get('launch_mode')} | {r.get('ai_callable')} | {detail} | `{path}` |"
        )
    lines += [
        "",
        "## No-popup rule",
        "",
        "Entries with `launch_mode=gui` are verified by file existence/hash only and are never launched by this check.",
    ]
    return "\n".join(lines) + "\n"


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--registry", default=str(REGISTRY))
    ap.add_argument("--out-dir", default=str(REPORT_DIR))
    ap.add_argument("--board", action="append", help="Limit to one board; can repeat")
    args = ap.parse_args(argv)

    registry_path = Path(args.registry)
    registry = json.loads(registry_path.read_text(encoding="utf-8"))
    tools = registry.get("tools") or []
    if args.board:
        boards = set(args.board)
        tools = [t for t in tools if t.get("board") in boards]

    results = [check_tool(t) for t in tools]
    bad_status = {"MISSING", "FAIL", "TIMEOUT"}
    found = sum(1 for r in results if r["status"] == "FOUND")
    bad = sum(1 for r in results if r["status"] in bad_status)
    overall = "PASS" if bad == 0 else "FAIL"

    payload = {
        "time": datetime.now().astimezone().isoformat(timespec="seconds"),
        "registry": str(registry_path),
        "overall": overall,
        "found": found,
        "bad": bad,
        "results": results,
    }

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = out_dir / f"ai_toolcheck_{stamp}.json"
    md_path = out_dir / f"ai_toolcheck_{stamp}.md"
    json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    md_path.write_text(render_md(payload), encoding="utf-8")

    print(json.dumps({"Overall": overall, "Found": found, "Bad": bad, "Json": str(json_path), "Markdown": str(md_path)}, ensure_ascii=False, indent=2))
    return 0 if overall == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
