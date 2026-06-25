#!/usr/bin/env python3
"""Audit ReverseLab technique documents for structure and broken local links."""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path


ROOTS = (
    Path("kb/ctf-website/techniques"),
    Path("kb/apk-reverse/techniques"),
    Path("kb/pe-reverse/techniques"),
    Path("kb/general/techniques"),
)
FLOW_RE = re.compile(r"^#{2,3}\s+.*(?:攻击链|攻击网|分析链|工作流|流程|管线|attack chain|workflow)", re.I | re.M)
EVIDENCE_RE = re.compile(r"^#{2,3}\s+.*(?:证据|验证|确认标准|判定标准|evidence)", re.I | re.M)
MCP_RE = re.compile(r"^#{2,3}\s+.*MCP\s*工具映射", re.I | re.M)
LINK_RE = re.compile(r"(?<!!)\[[^\]]*\]\(([^)]+)\)")


def technique_files() -> list[Path]:
    files: list[Path] = []
    for root in ROOTS:
        if root.exists():
            files.extend(
                p for p in root.rglob("*.md")
                if p.name.lower() != "readme.md" and p.name != "attack-network.md"
            )
    return sorted(files)


def local_link_errors(path: Path, text: str) -> list[str]:
    errors: list[str] = []
    prose = re.sub(r"```.*?```", "", text, flags=re.S)
    prose = re.sub(r"`[^`\n]+`", "", prose)
    for raw in LINK_RE.findall(prose):
        target = raw.strip().split(maxsplit=1)[0].strip("<>")
        if not target or target.startswith(("#", "http://", "https://", "mailto:", "data:")):
            continue
        target = target.split("#", 1)[0]
        if any(marker in target for marker in ("<", ">", "{", "}")):
            continue
        resolved = (path.parent / target).resolve()
        if not resolved.exists():
            errors.append(f"broken-link:{target}")
    return errors


def audit(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8", errors="replace")
    failures: list[str] = []
    if not text.lstrip().startswith("# "):
        failures.append("missing-h1")
    if len(text.strip()) < 800:
        failures.append("too-short")
    if "```" not in text:
        failures.append("missing-runnable-example")
    if not FLOW_RE.search(text):
        failures.append("missing-workflow")
    if not EVIDENCE_RE.search(text):
        failures.append("missing-evidence")
    if not MCP_RE.search(text):
        failures.append("missing-mcp-map")
    failures.extend(local_link_errors(path, text))
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", dest="json_path", help="write the full audit report")
    args = parser.parse_args()

    results = {str(path): audit(path) for path in technique_files()}
    failures = {path: items for path, items in results.items() if items}
    counts = Counter(item.split(":", 1)[0] for items in failures.values() for item in items)
    report = {
        "documents": len(results),
        "passed": len(results) - len(failures),
        "failed": len(failures),
        "failure_counts": dict(sorted(counts.items())),
        "failures": failures,
    }
    print(json.dumps({k: report[k] for k in ("documents", "passed", "failed", "failure_counts")},
                     ensure_ascii=False, indent=2))
    if args.json_path:
        out = Path(args.json_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
