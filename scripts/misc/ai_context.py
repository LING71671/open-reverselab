#!/usr/bin/env python3
"""
Build a task-start context pack for ReverseLab agents.

Run this at the beginning of a real task. It answers:
- Which board/tool rules match this task?
- Which historical practical findings should be remembered?
- Which installed tools are AI-callable now?
- Which GUI/no-popup constraints apply?
- What should be recorded if a reusable discovery appears?
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
REGISTRY = ROOT / "tools" / "ai-tool-registry.json"
PLAYBOOK = ROOT / "tools" / "ai-tool-playbook.json"
FINDINGS = ROOT / "kb" / "ai-findings" / "findings.jsonl"
OUT_DIR = ROOT / "reports" / "misc" / "ai-context"


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_findings() -> list[dict[str, Any]]:
    if not FINDINGS.exists():
        return []
    rows = []
    for line in FINDINGS.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def score_text(hay: str, terms: list[str]) -> int:
    hay = hay.lower()
    return sum(1 for term in terms if term and term.lower() in hay)


def build_context(task: str, board: str = "", limit: int = 6) -> dict[str, Any]:
    registry = load_json(REGISTRY)
    playbook = load_json(PLAYBOOK)
    terms = [t for t in task.lower().split() if len(t) >= 3]

    rule_hits = []
    for rule in playbook.get("rules", []):
        if board and board not in {rule.get("board"), *(str(t).split(".")[0] for t in rule.get("tools", []))}:
            continue
        hay = json.dumps(rule, ensure_ascii=False)
        score = score_text(hay, terms)
        if score:
            rule_hits.append((score, rule))
    rule_hits.sort(key=lambda x: (-x[0], x[1].get("id", "")))

    finding_hits = []
    for item in load_findings():
        if item.get("status") == "superseded":
            continue
        if board and item.get("board") != board:
            # Keep cross-board findings only if they have an explicit strong task match.
            hay = json.dumps(item, ensure_ascii=False)
            if score_text(hay, terms) < 2:
                continue
        hay = json.dumps(item, ensure_ascii=False)
        score = score_text(hay, terms)
        if score:
            finding_hits.append((score, item))
    finding_hits.sort(key=lambda x: (x[0], x[1].get("time", "")), reverse=True)

    suggested_tool_ids: set[str] = set()
    for _, rule in rule_hits[:limit]:
        suggested_tool_ids.update(rule.get("tools") or [])
    for _, finding in finding_hits[:limit]:
        suggested_tool_ids.update(finding.get("tools") or [])

    tools_by_id = {t.get("id"): t for t in registry.get("tools", [])}
    suggested_tools = [tools_by_id[t] for t in sorted(suggested_tool_ids) if t in tools_by_id]
    if board:
        board_tools = [t for t in registry.get("tools", []) if t.get("board") == board and t.get("ai_callable")]
    else:
        boards = {t.get("board") for t in suggested_tools}
        board_tools = [t for t in registry.get("tools", []) if t.get("board") in boards and t.get("ai_callable")]

    return {
        "time": datetime.now().astimezone().isoformat(timespec="seconds"),
        "task": task,
        "board_filter": board,
        "no_popup_policy": registry.get("policy", {}).get("ai_default_rule"),
        "path_bootstrap_powershell": registry.get("policy", {}).get("path_bootstrap_powershell"),
        "matched_rules": [
            {
                "score": score,
                "id": rule.get("id"),
                "when": rule.get("when"),
                "tools": rule.get("tools"),
                "scripts": rule.get("scripts"),
                "method": rule.get("method"),
                "evidence": rule.get("evidence"),
            }
            for score, rule in rule_hits[:limit]
        ],
        "related_findings": [
            {
                "score": score,
                "time": item.get("time"),
                "board": item.get("board"),
                "kind": item.get("kind"),
                "title": item.get("title"),
                "trigger": item.get("trigger"),
                "finding": item.get("finding"),
                "reuse": item.get("reuse"),
                "tools": item.get("tools"),
                "keywords": item.get("keywords"),
            }
            for score, item in finding_hits[:limit]
        ],
        "suggested_tools": [
            {
                "id": t.get("id"),
                "board": t.get("board"),
                "name": t.get("name"),
                "mode": t.get("launch_mode"),
                "ai_callable": t.get("ai_callable"),
                "command": t.get("command"),
                "safe_probe": t.get("safe_probe"),
                "notes": t.get("notes", ""),
            }
            for t in suggested_tools
        ],
        "callable_tools_in_scope": [
            {"id": t.get("id"), "board": t.get("board"), "name": t.get("name"), "command": t.get("command")}
            for t in board_tools
        ],
        "finding_record_template": (
            'python scripts\\misc\\ai_finding.py add --board <board> --kind <tactic|pitfall|tool-rule|dead-end|cve-chain|reversing-flow> '
            '--title "..." --trigger "..." --finding "..." --evidence "..." --reuse "..." --keyword ...'
        ),
    }


def render_md(ctx: dict[str, Any]) -> str:
    lines = [
        "# ReverseLab AI Task Context",
        "",
        f"- Time: {ctx['time']}",
        f"- Task: {ctx['task']}",
        f"- Board filter: {ctx.get('board_filter') or '(auto)'}",
        "",
        "## No-popup policy",
        "",
        f"- {ctx.get('no_popup_policy')}",
        f"- PATH bootstrap: `{ctx.get('path_bootstrap_powershell')}`",
        "",
        "## Matched playbook rules",
        "",
    ]
    if not ctx["matched_rules"]:
        lines.append("- No playbook rule matched. Use `ai_tool.py find <keyword>` and record a finding if a new reusable route is discovered.")
    for r in ctx["matched_rules"]:
        lines += [
            f"### {r['id']} (score {r['score']})",
            "",
            f"- When: {r.get('when')}",
            f"- Tools: {', '.join(r.get('tools') or [])}",
            f"- Scripts: {', '.join(r.get('scripts') or [])}",
            f"- Method: {r.get('method')}",
            f"- Evidence: {r.get('evidence')}",
            "",
        ]

    lines += ["## Related practical findings", ""]
    if not ctx["related_findings"]:
        lines.append("- No related finding found. If this task yields a reusable insight, record it with `ai_finding.py add`.")
    for f in ctx["related_findings"]:
        lines += [
            f"### {f.get('title')} (score {f.get('score')})",
            "",
            f"- Board/kind: {f.get('board')} / {f.get('kind')}",
            f"- Trigger: {f.get('trigger')}",
            f"- Finding: {f.get('finding')}",
            f"- Reuse: {f.get('reuse')}",
            f"- Tools: {', '.join(f.get('tools') or [])}",
            f"- Keywords: {', '.join(f.get('keywords') or [])}",
            "",
        ]

    lines += ["## Suggested tools", ""]
    if not ctx["suggested_tools"]:
        lines.append("- No specific tool suggested.")
    for t in ctx["suggested_tools"]:
        lines.append(
            f"- `{t.get('id')}` [{t.get('board')}/{t.get('mode')}/ai={t.get('ai_callable')}]: {t.get('name')} -> `{t.get('command')}`"
        )
        if t.get("notes"):
            lines.append(f"  - Note: {t.get('notes')}")
    lines += ["", "## Callable tools in scope", ""]
    for t in ctx["callable_tools_in_scope"]:
        lines.append(f"- `{t.get('id')}`: {t.get('name')} -> `{t.get('command')}`")
    lines += [
        "",
        "## If you discover something reusable",
        "",
        f"`{ctx['finding_record_template']}`",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("task", nargs="+")
    ap.add_argument("--board", default="")
    ap.add_argument("--limit", type=int, default=6)
    ap.add_argument("--json", action="store_true", help="Print JSON instead of Markdown")
    ap.add_argument("--save", action="store_true", help="Save context under reports/misc/ai-context")
    args = ap.parse_args()

    ctx = build_context(" ".join(args.task), board=args.board, limit=args.limit)
    if args.save:
        OUT_DIR.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        (OUT_DIR / f"ai_context_{stamp}.json").write_text(json.dumps(ctx, ensure_ascii=False, indent=2), encoding="utf-8")
        (OUT_DIR / f"ai_context_{stamp}.md").write_text(render_md(ctx), encoding="utf-8")
        ctx["saved_json"] = str(OUT_DIR / f"ai_context_{stamp}.json")
        ctx["saved_md"] = str(OUT_DIR / f"ai_context_{stamp}.md")
    print(json.dumps(ctx, ensure_ascii=False, indent=2) if args.json else render_md(ctx))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
