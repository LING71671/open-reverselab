#!/usr/bin/env python3
"""Audit ReverseLab technique documents for structure and broken local links."""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path


ROOTS = tuple(Path("kb") / layer / board / "techniques"
              for layer in ("red", "blue", "shared")
              for board in ("ctf-website", "apk-reverse", "pe-reverse", "general"))

FLOW_RE = re.compile(r"^#{2,3}\s+.*(?:攻击链|攻击网|分析链|调用链|工作流|流程|管线|attack chain|workflow)", re.I | re.M)
EVIDENCE_RE = re.compile(r"^#{2,3}\s+.*(?:证据|验证|确认标准|判定标准|evidence)", re.I | re.M)
MCP_RE = re.compile(r"^#{2,3}\s+.*MCP\s*工具映射", re.I | re.M)
LINK_RE = re.compile(r"(?<!!)\[[^\]]*\]\(([^)]+)\)")
STYLE_PHRASES = (
    "脱敏",
    "修复验证",
    "修复建议",
    "低风险验证",
    "低风险探测",
    "保守探测",
    "安全约束",
    "是否安全",
    "授权测试",
    "仅限授权",
    "只读探针",
    "只读枚举",
    "原始样本只读保留",
    "从干净基线最小化复现",
    "从全新 session/重置状态最小化重放",
    "从全新浏览器 profile/session 最小化重放",
    "审计脚本",
    "审计清单",
    "白盒审计",
    "全面审计",
    "完整审计",
)


def technique_files() -> list[Path]:
    files: list[Path] = []
    for root in ROOTS:
        if root.exists():
            files.extend(
                p for p in root.rglob("*.md")
                if p.name.lower() != "readme.md" and p.name not in ("attack-network.md", "defense-network.md")
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


def _strip_frontmatter(text: str) -> str:
    """剥离 YAML frontmatter，返回正文。"""
    t = text.lstrip()
    if t.startswith("---"):
        end = t.find("---", 3)
        if end != -1:
            return t[end + 3:].lstrip()
    return text


def _has_frontmatter(text: str) -> bool:
    """检查是否有 YAML frontmatter。"""
    return text.lstrip().startswith("---")


def _check_frontmatter(text: str) -> list[str]:
    """检查 frontmatter 完整性（必填字段是否存在）。"""
    REQUIRED = ["id:", "title:", "title_en:", "summary:", "summary_en:",
                "board:", "category:", "signals:", "keywords:",
                "difficulty:", "tags:", "language:", "last_updated:"]
    t = text.lstrip()
    end = t.find("---", 3)
    if end == -1:
        return ["malformed-frontmatter"]
    fm = t[3:end]
    missing = [f"fm-missing:{f[:-1]}" for f in REQUIRED if f not in fm]
    return missing


def audit(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8", errors="replace")
    failures: list[str] = []

    # Frontmatter 检查（如果存在）
    if _has_frontmatter(text):
        failures.extend(_check_frontmatter(text))

    # 正文检查（剥离 frontmatter 后再做）
    body = _strip_frontmatter(text)
    if not body.startswith("# "):
        failures.append("missing-h1")
    if len(body.strip()) < 800:
        failures.append("too-short")
    if "```" not in body:
        failures.append("missing-runnable-example")
    if not FLOW_RE.search(body):
        failures.append("missing-workflow")
    if not EVIDENCE_RE.search(body):
        failures.append("missing-evidence")
    if not MCP_RE.search(body):
        failures.append("missing-mcp-map")
    for phrase in STYLE_PHRASES:
        if phrase in body:
            failures.append(f"style-phrase:{phrase}")
    failures.extend(local_link_errors(path, body))
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
