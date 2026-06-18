#!/usr/bin/env python3
"""
Record and search practical AI findings for ReverseLab.

This is not a broad command log. Use it only when real work yields a reusable
discovery, pitfall, tool-routing rule, exploit-chain insight, or verified tactic.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any
from collections import Counter


ROOT = Path(__file__).resolve().parents[2]
KB_DIR = ROOT / "kb" / "ai-findings"
FINDINGS = KB_DIR / "findings.jsonl"
INDEX_MD = KB_DIR / "README.md"
PLAYBOOK = ROOT / "tools" / "ai-tool-playbook.json"


def load_findings() -> list[dict[str, Any]]:
    if not FINDINGS.exists():
        return []
    rows = []
    for line in FINDINGS.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def write_all_findings(rows: list[dict[str, Any]]) -> None:
    KB_DIR.mkdir(parents=True, exist_ok=True)
    FINDINGS.write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
        encoding="utf-8",
    )
    render_index()


def save_finding(item: dict[str, Any]) -> None:
    KB_DIR.mkdir(parents=True, exist_ok=True)
    with FINDINGS.open("a", encoding="utf-8") as f:
        f.write(json.dumps(item, ensure_ascii=False) + "\n")
    render_index()


def render_index() -> None:
    rows = load_findings()
    lines = [
        "# AI Findings",
        "",
        "这里不是命令流水账；只记录实战中可复用的发现、坑点、打法、工具选择经验。",
        "",
        "## Record rule",
        "",
        "当出现以下情况，AI 必须记录 finding：",
        "",
        "- 发现一个可复用攻击路径、分析路径、工具组合或排障方法。",
        "- 某工具在特定环境下失败/弹窗/阻塞，并找到稳定替代或 safe probe。",
        "- 某类目标的指纹能稳定触发某个 CVE/漏洞链/逆向流程。",
        "- 一条路径被证据排除，能避免以后重复踩坑。",
        "",
        "## Latest findings",
        "",
        "| Time | Board | Kind | Title | Keywords | Confidence |",
        "|---|---|---|---|---|---|",
    ]
    for r in sorted(rows, key=lambda x: x.get("time", ""), reverse=True)[:80]:
        kws = ", ".join(r.get("keywords") or [])
        title = r.get("title", "")
        if r.get("status") == "superseded":
            title = "[SUPERSEDED] " + title
        lines.append(
            f"| {r.get('time','')} | {r.get('board','')} | {r.get('kind','')} | {title.replace('|','/')} | {kws.replace('|','/')} | {r.get('confidence','')} |"
        )
    lines += [
        "",
        "## Commands",
        "",
        "```powershell",
        "python scripts\\misc\\ai_finding.py add --board ctf-website --kind tactic --title \"...\" --trigger \"...\" --finding \"...\" --evidence \"...\" --reuse \"...\" --keyword k1 --keyword k2",
        "python scripts\\misc\\ai_finding.py search cve geoserver chain",
        "python scripts\\misc\\ai_finding.py list --board ctf-website",
        "python scripts\\misc\\ai_finding.py review --min-count 2",
        "python scripts\\misc\\ai_finding.py promote geoserver cve --apply",
        "python scripts\\misc\\ai_finding.py supersede <old-finding-id> --by <new-finding-id-or-rule> --reason \"...\"",
        "```",
        "",
    ]
    INDEX_MD.write_text("\n".join(lines), encoding="utf-8")


def add(args: argparse.Namespace) -> int:
    item = {
        "id": str(uuid.uuid4()),
        "time": datetime.now().astimezone().isoformat(timespec="seconds"),
        "board": args.board,
        "kind": args.kind,
        "title": args.title,
        "trigger": args.trigger,
        "finding": args.finding,
        "evidence": args.evidence,
        "reuse": args.reuse,
        "tools": args.tool or [],
        "scripts": args.script or [],
        "keywords": args.keyword or [],
        "case": args.case,
        "confidence": args.confidence,
    }
    save_finding(item)
    print(json.dumps(item, ensure_ascii=False, indent=2))
    return 0


def matches(row: dict[str, Any], terms: list[str]) -> bool:
    hay = json.dumps(row, ensure_ascii=False).lower()
    return all(t.lower() in hay for t in terms)


def search(args: argparse.Namespace) -> int:
    rows = [r for r in load_findings() if matches(r, args.terms)]
    if not args.all:
        rows = [r for r in rows if r.get("status") != "superseded"]
    rows.sort(key=lambda x: x.get("time", ""), reverse=True)
    for r in rows[: args.limit]:
        print(f"[{r.get('time')}] {r.get('board')} / {r.get('kind')} / {r.get('title')}")
        print(f"  trigger: {r.get('trigger')}")
        print(f"  finding: {r.get('finding')}")
        print(f"  reuse:   {r.get('reuse')}")
        if r.get("tools"):
            print(f"  tools:   {', '.join(r.get('tools'))}")
        if r.get("keywords"):
            print(f"  keys:    {', '.join(r.get('keywords'))}")
        print()
    return 0 if rows else 1


def list_cmd(args: argparse.Namespace) -> int:
    rows = load_findings()
    if args.board:
        rows = [r for r in rows if r.get("board") == args.board]
    if not args.all:
        rows = [r for r in rows if r.get("status") != "superseded"]
    rows.sort(key=lambda x: x.get("time", ""), reverse=True)
    for r in rows[: args.limit]:
        print(f"{r.get('time')}\t{r.get('board')}\t{r.get('kind')}\t{r.get('title')}")
    return 0


def supersede(args: argparse.Namespace) -> int:
    rows = load_findings()
    changed = False
    for r in rows:
        if r.get("id") == args.finding_id or r.get("title") == args.finding_id:
            r["status"] = "superseded"
            r["superseded_by"] = args.by
            r["superseded_reason"] = args.reason
            changed = True
    if not changed:
        raise SystemExit(f"finding not found: {args.finding_id}")
    write_all_findings(rows)
    print(json.dumps({"status": "ok", "superseded": args.finding_id, "by": args.by}, ensure_ascii=False, indent=2))
    return 0


def promote(args: argparse.Namespace) -> int:
    """Print playbook-rule draft for matching findings; human/AI can paste into ai-tool-playbook.json."""
    rows = [r for r in load_findings() if matches(r, args.terms)]
    if not rows:
        return 1
    keywords = sorted({k for r in rows for k in (r.get("keywords") or [])})
    tools = sorted({t for r in rows for t in (r.get("tools") or [])})
    draft = {
        "id": re.sub(r"[^a-z0-9]+", "-", "-".join(args.terms).lower()).strip("-") or "finding-derived-rule",
        "keywords": keywords or args.terms,
        "when": rows[0].get("trigger"),
        "tools": tools,
        "method": rows[0].get("reuse"),
        "evidence": rows[0].get("evidence"),
        "derived_from_findings": [r.get("id") for r in rows[:10]],
    }
    if args.apply:
        playbook = json.loads(PLAYBOOK.read_text(encoding="utf-8"))
        rules = playbook.setdefault("rules", [])
        existing = next((i for i, r in enumerate(rules) if r.get("id") == draft["id"]), None)
        if existing is None:
            rules.append(draft)
            action = "added"
        else:
            rules[existing] = draft
            action = "replaced"
        PLAYBOOK.write_text(json.dumps(playbook, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"action": action, "playbook": str(PLAYBOOK), "rule": draft}, ensure_ascii=False, indent=2))
    else:
        print(json.dumps(draft, ensure_ascii=False, indent=2))
    return 0


def review(args: argparse.Namespace) -> int:
    rows = load_findings()
    if args.board:
        rows = [r for r in rows if r.get("board") == args.board]
    keyword_counts = Counter(k for r in rows for k in (r.get("keywords") or []))
    tool_counts = Counter(t for r in rows for t in (r.get("tools") or []))
    kind_counts = Counter(r.get("kind") for r in rows)
    payload = {
        "finding_count": len(rows),
        "board": args.board or "",
        "top_keywords": keyword_counts.most_common(args.limit),
        "top_tools": tool_counts.most_common(args.limit),
        "kinds": kind_counts.most_common(),
        "promotion_candidates": [
            {
                "keyword": key,
                "count": count,
                "command": f"python scripts\\misc\\ai_finding.py promote {key}",
            }
            for key, count in keyword_counts.most_common(args.limit)
            if count >= args.min_count
        ],
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("add")
    p.add_argument("--board", required=True)
    p.add_argument("--kind", default="tactic", choices=["tactic", "pitfall", "tool-rule", "dead-end", "cve-chain", "reversing-flow"])
    p.add_argument("--title", required=True)
    p.add_argument("--trigger", required=True)
    p.add_argument("--finding", required=True)
    p.add_argument("--evidence", required=True)
    p.add_argument("--reuse", required=True)
    p.add_argument("--tool", action="append")
    p.add_argument("--script", action="append")
    p.add_argument("--keyword", action="append")
    p.add_argument("--case", default="")
    p.add_argument("--confidence", default="medium", choices=["low", "medium", "high"])
    p.set_defaults(func=add)

    p = sub.add_parser("search")
    p.add_argument("terms", nargs="+")
    p.add_argument("--limit", type=int, default=10)
    p.add_argument("--all", action="store_true", help="Include superseded findings")
    p.set_defaults(func=search)

    p = sub.add_parser("list")
    p.add_argument("--board")
    p.add_argument("--limit", type=int, default=30)
    p.add_argument("--all", action="store_true", help="Include superseded findings")
    p.set_defaults(func=list_cmd)

    p = sub.add_parser("supersede")
    p.add_argument("finding_id", help="Finding id or exact title to supersede")
    p.add_argument("--by", required=True, help="New finding id/title/rule that supersedes it")
    p.add_argument("--reason", default="")
    p.set_defaults(func=supersede)

    p = sub.add_parser("promote")
    p.add_argument("terms", nargs="+")
    p.add_argument("--apply", action="store_true", help="Append/replace the generated rule in tools/ai-tool-playbook.json")
    p.set_defaults(func=promote)

    p = sub.add_parser("review")
    p.add_argument("--board")
    p.add_argument("--limit", type=int, default=12)
    p.add_argument("--min-count", type=int, default=2)
    p.set_defaults(func=review)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
