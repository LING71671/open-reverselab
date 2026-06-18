#!/usr/bin/env python3
"""
ReverseLab AI tool router.

Purpose:
- Give agents one stable entrypoint to remember tools across CTF/Android/Windows/Misc.
- Avoid accidental GUI popups: GUI tools are denied unless --allow-gui is explicit.
- Do not log broad command usage by default. Reusable discoveries are recorded with ai_finding.py.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
REGISTRY = ROOT / "tools" / "ai-tool-registry.json"
PLAYBOOK = ROOT / "tools" / "ai-tool-playbook.json"
FINDINGS = ROOT / "kb" / "ai-findings" / "findings.jsonl"


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def registry_tools() -> list[dict[str, Any]]:
    return load_json(REGISTRY).get("tools", [])


def tool_by_id(tool_id: str) -> dict[str, Any]:
    for tool in registry_tools():
        if tool.get("id") == tool_id:
            return tool
    raise SystemExit(f"tool not found: {tool_id}")


def one_line(text: str, limit: int = 500) -> str:
    text = " ".join((text or "").replace("\r", "\n").split())
    return text[: limit - 3] + "..." if len(text) > limit else text


def cmd_for(tool: dict[str, Any], extra_args: list[str]) -> list[str]:
    command = str(tool["command"])
    command_path = Path(command)
    if not command_path.is_absolute() and ("/" in command or "\\" in command):
        command = str((ROOT / command_path).resolve())
    argv = [command, *extra_args]
    if Path(command).suffix.lower() in {".bat", ".cmd"}:
        argv = [os.environ.get("COMSPEC", "cmd.exe"), "/c", command, *extra_args]
    return argv


def list_tools(args: argparse.Namespace) -> int:
    tools = registry_tools()
    if args.board:
        tools = [t for t in tools if t.get("board") == args.board]
    if args.callable:
        tools = [t for t in tools if t.get("ai_callable")]
    for t in tools:
        print(f"{t.get('id')}\t{t.get('board')}\t{t.get('launch_mode')}\tai={t.get('ai_callable')}\t{t.get('name')}")
    return 0


def find_tools(args: argparse.Namespace) -> int:
    terms = [x.lower() for x in args.query]
    results: list[dict[str, Any]] = []
    for t in registry_tools():
        hay = json.dumps(t, ensure_ascii=False).lower()
        if all(term in hay for term in terms):
            results.append(t)
    for t in results:
        print(f"{t.get('id')}\t{t.get('board')}\t{t.get('launch_mode')}\tai={t.get('ai_callable')}\t{t.get('name')}")
    return 0 if results else 1


def plan_tools(args: argparse.Namespace) -> int:
    playbook = load_json(PLAYBOOK)
    task = " ".join(args.task).lower()
    plans = []
    for rule in playbook.get("rules", []):
        keywords = [k.lower() for k in rule.get("keywords", [])]
        score = sum(1 for k in keywords if k in task)
        if score:
            plans.append((score, rule))
    plans.sort(key=lambda x: (-x[0], x[1].get("id", "")))
    related_findings = []
    if FINDINGS.exists():
        terms = [t for t in task.split() if len(t) >= 3]
        for line in FINDINGS.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            item = json.loads(line)
            if item.get("status") == "superseded":
                continue
            hay = json.dumps(item, ensure_ascii=False).lower()
            score = sum(1 for term in terms if term in hay)
            if score:
                related_findings.append((score, item))
    related_findings.sort(key=lambda x: (x[0], x[1].get("time", "")), reverse=True)

    payload = {
        "task": " ".join(args.task),
        "matches": [
            {
                "id": r.get("id"),
                "score": s,
                "when": r.get("when"),
                "tools": r.get("tools"),
                "method": r.get("method"),
                "evidence": r.get("evidence"),
            }
            for s, r in plans[: args.limit]
        ],
        "related_findings": [
            {
                "score": s,
                "time": f.get("time"),
                "board": f.get("board"),
                "kind": f.get("kind"),
                "title": f.get("title"),
                "reuse": f.get("reuse"),
                "tools": f.get("tools"),
                "keywords": f.get("keywords"),
            }
            for s, f in related_findings[: args.findings_limit]
        ],
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0 if payload["matches"] else 1


def run_tool(args: argparse.Namespace) -> int:
    tool = tool_by_id(args.tool_id)
    mode = tool.get("launch_mode")
    if mode == "gui" and not args.allow_gui:
        raise SystemExit(f"refusing to launch GUI tool without --allow-gui: {args.tool_id}")
    if not tool.get("ai_callable") and not args.force:
        raise SystemExit(f"tool is not marked ai_callable; use --force only if you know why: {args.tool_id}")
    if mode == "file_probe":
        raise SystemExit(f"file_probe tool is not runnable through ai_tool.py: {args.tool_id}")

    env = os.environ.copy()
    env["PATH"] = str(ROOT / "tools" / "bin") + os.pathsep + str(ROOT / "tools" / "ctf-website" / "bin") + os.pathsep + env.get("PATH", "")
    extra_args = list(args.tool_args)
    if extra_args and extra_args[0] == "--":
        extra_args = extra_args[1:]
    argv = cmd_for(tool, extra_args)
    start = datetime.now()
    proc = subprocess.run(
        argv,
        cwd=str(ROOT),
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=args.timeout,
        shell=False,
    )
    elapsed = (datetime.now() - start).total_seconds()
    out = proc.stdout or ""
    err = proc.stderr or ""
    sys.stdout.write(out)
    sys.stderr.write(err)
    if args.record_finding:
        finding = {
            "time": datetime.now().astimezone().isoformat(timespec="seconds"),
            "kind": "tool-observation",
            "board": tool.get("board"),
            "title": args.record_finding,
            "trigger": "ai_tool.py run",
            "tools": [args.tool_id],
            "evidence": {
                "argv": argv,
                "exit": proc.returncode,
                "elapsed_sec": round(elapsed, 3),
                "stdout_preview": one_line(out),
                "stderr_preview": one_line(err),
            },
            "reuse": "Review this observation before repeating the same tool path.",
            "confidence": "medium",
        }
        findings = ROOT / "kb" / "ai-findings" / "findings.jsonl"
        findings.parent.mkdir(parents=True, exist_ok=True)
        with findings.open("a", encoding="utf-8") as f:
            f.write(json.dumps(finding, ensure_ascii=False) + "\n")
    return proc.returncode


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="ReverseLab AI tool router")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("list", help="List registered tools")
    p.add_argument("--board")
    p.add_argument("--callable", action="store_true")
    p.set_defaults(func=list_tools)

    p = sub.add_parser("find", help="Find tools by keyword")
    p.add_argument("query", nargs="+")
    p.set_defaults(func=find_tools)

    p = sub.add_parser("plan", help="Suggest tools for a task using playbook rules")
    p.add_argument("task", nargs="+")
    p.add_argument("--limit", type=int, default=5)
    p.add_argument("--findings-limit", type=int, default=5)
    p.set_defaults(func=plan_tools)

    p = sub.add_parser("run", help="Run an AI-callable CLI tool")
    p.add_argument("tool_id")
    p.add_argument("tool_args", nargs=argparse.REMAINDER)
    p.add_argument("--timeout", type=int, default=120)
    p.add_argument("--allow-gui", action="store_true")
    p.add_argument("--force", action="store_true")
    p.add_argument("--record-finding", default="", help="Optional title: persist this run as a reusable finding")
    p.set_defaults(func=run_tool)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
