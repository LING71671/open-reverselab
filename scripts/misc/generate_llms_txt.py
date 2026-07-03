#!/usr/bin/env python3
"""生成 llms.txt (紧凑索引) 和 llms-full.txt (全文聚合) 供 LLM 爬虫使用。

llms.txt: 项目简介 + 每篇文章一行 (标题 + URL + 摘要)
llms-full.txt: 所有 KB 文章正文聚合，去隐私/案例内容

Usage:
    python scripts/misc/generate_llms_txt.py              # 生成两个文件到 docs/
    python scripts/misc/generate_llms_txt.py --check      # 检查是否过期
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs"
BOARDS = {
    "ctf-website": (ROOT / "kb/ctf-website/techniques", "https://ling71671.github.io/open-reverselab/kb/ctf-website/"),
    "apk-reverse": (ROOT / "kb/apk-reverse/techniques", "https://ling71671.github.io/open-reverselab/kb/apk-reverse/"),
    "pe-reverse": (ROOT / "kb/pe-reverse/techniques", "https://ling71671.github.io/open-reverselab/kb/pe-reverse/"),
    "general": (ROOT / "kb/general/techniques", "https://ling71671.github.io/open-reverselab/kb/general/"),
    "windows": (ROOT / "kb/windows/techniques", "https://ling71671.github.io/open-reverselab/kb/windows/"),
}

BOARD_NAMES = {
    "ctf-website": "CTF Website — Web 攻击全表面",
    "apk-reverse": "APK Reverse — Android 逆向工程",
    "pe-reverse": "PE Reverse — Windows 二进制分析",
    "general": "General — 跨领域逆向工程",
    "windows": "Windows — 系统安全专项",
}


def _strip_frontmatter(text: str) -> str:
    t = text.lstrip()
    if t.startswith("---"):
        end = t.find("---", 3)
        if end != -1:
            return t[end + 3:].lstrip()
    return text


def _get_frontmatter_field(text: str, field: str) -> str:
    """从 frontmatter 中提取字段值。"""
    t = text.lstrip()
    if not t.startswith("---"):
        return ""
    end = t.find("---", 3)
    if end == -1:
        return ""
    fm = t[3:end]
    for line in fm.splitlines():
        stripped = line.strip()
        if stripped.startswith(f"{field}:"):
            val = stripped[len(f"{field}:"):].strip().strip('"')
            return val
    # 多行字段 (summary: >)
    in_multiline = False
    lines_collected = []
    for line in fm.splitlines():
        stripped = line.strip()
        if stripped == f"{field}: >":
            in_multiline = True
            continue
        if in_multiline:
            if stripped.startswith("#") or stripped.startswith("-"):
                break
            if stripped:
                lines_collected.append(stripped)
    return " ".join(lines_collected)


def collect_articles() -> list[dict]:
    """收集所有技术文章的基本信息。"""
    articles = []
    for board, (root, base_url) in BOARDS.items():
        if not root.exists():
            continue
        for path in sorted(root.rglob("*.md")):
            name = path.name.lower()
            if name == "readme.md" or name == "attack-network.md":
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            title = _get_frontmatter_field(text, "title")
            title_en = _get_frontmatter_field(text, "title_en")
            summary = _get_frontmatter_field(text, "summary")
            summary_en = _get_frontmatter_field(text, "summary_en")

            # 如果没有 frontmatter，从正文提取
            if not title:
                body = _strip_frontmatter(text)
                for line in body.splitlines():
                    if line.startswith("# ") and not title:
                        title = line[2:].strip()
                        break

            rel = path.relative_to(root).as_posix()
            slug = rel.replace(".md", "")
            url = f"{base_url}techniques/{slug}/" if not base_url.endswith("/") else f"{base_url}{slug}/"

            articles.append({
                "board": board,
                "board_name": BOARD_NAMES.get(board, board),
                "title": title or path.stem,
                "title_en": title_en or "",
                "summary": summary or "",
                "summary_en": summary_en or "",
                "url": url,
                "github_url": f"https://github.com/LING71671/open-reverselab/blob/main/kb/{board}/techniques/{rel}",
                "path": str(path),
            })
    return articles


def generate_llms_txt(articles: list[dict]) -> str:
    """生成紧凑 llms.txt。"""
    lines = []
    lines.append("# ReverseLab — Open-Source Reverse Engineering Lab & MCP Tool Ecosystem")
    lines.append("")
    lines.append(f"> {len(articles)}-article knowledge base, 100+ MCP automation tools for reverse engineering.")
    lines.append("> Agent-native architecture. Covers CTF, APK, PE, cryptography, game cheating, and more.")
    lines.append("")
    lines.append("## Quick Links")
    lines.append(f"- Landing Page: https://ling71671.github.io/open-reverselab/")
    lines.append(f"- Knowledge Base: https://ling71671.github.io/open-reverselab/kb/")
    lines.append(f"- MCP Tools: https://ling71671.github.io/open-reverselab/mcp-tools/")
    lines.append(f"- FAQ: https://ling71671.github.io/open-reverselab/faq.html")
    lines.append(f"- GitHub: https://github.com/LING71671/open-reverselab")
    lines.append(f"- Full LLM dump: https://ling71671.github.io/open-reverselab/llms-full.txt")
    lines.append("")

    # 按板块分组
    from collections import defaultdict
    by_board = defaultdict(list)
    for a in articles:
        by_board[a["board"]].append(a)

    for board in ["ctf-website", "apk-reverse", "pe-reverse", "general", "windows"]:
        items = by_board.get(board, [])
        if not items:
            continue
        lines.append(f"## {BOARD_NAMES.get(board, board)} ({len(items)} articles)")
        lines.append("")
        for a in items:
            title = a["title_en"] or a["title"]
            summary = a["summary_en"] or a["summary"]
            lines.append(f"- [{title}]({a['url']})")
            if summary:
                lines.append(f"  {summary[:200]}")
        lines.append("")

    lines.append(f"---")
    lines.append(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d')}")
    lines.append(f"Total articles: {len(articles)}")
    return "\n".join(line.rstrip() for line in lines)


def generate_llms_full(articles: list[dict]) -> str:
    """生成全文 llms-full.txt。"""
    lines = []
    lines.append("# ReverseLab — Full Knowledge Base Dump for LLM Ingestion")
    lines.append("")
    lines.append(f"Total articles: {len(articles)}")
    lines.append(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d')}")
    lines.append("")

    for a in articles:
        lines.append(f"---")
        lines.append(f"## [{a['board']}] {a['title']}")
        if a["title_en"]:
            lines.append(f"### {a['title_en']}")
        lines.append(f"URL: {a['url']}")
        lines.append(f"Source: {a['github_url']}")
        if a["summary"]:
            lines.append(f"")
            lines.append(f"> {a['summary']}")
        lines.append("")

        # 读文章正文
        try:
            text = Path(a["path"]).read_text(encoding="utf-8", errors="replace")
            body = _strip_frontmatter(text)
            # 限制每篇文章 10000 字符（避免文件过大）
            if len(body) > 10000:
                body = body[:10000] + "\n\n[... content truncated for size ...]"
            body = "\n".join(line.rstrip() for line in body.splitlines())
            lines.append(body)
        except Exception:
            lines.append(f"[Error reading file: {a['path']}]")
        lines.append("")
        lines.append("")

    return "\n".join(line.rstrip() for line in lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="检查文件是否过期")
    args = parser.parse_args()

    articles = collect_articles()
    if not articles:
        print("No articles found!")
        return 1

    print(f"Found {len(articles)} articles across {len(set(a['board'] for a in articles))} boards")

    if args.check:
        llms_txt = DOCS / "llms.txt"
        llms_full = DOCS / "llms-full.txt"
        ok = True
        for f in [llms_txt, llms_full]:
            if not f.exists():
                print(f"MISSING: {f.name}")
                ok = False
        print("OK" if ok else "NEEDS REGENERATION")
        return 0 if ok else 1

    # 生成 llms.txt
    llms_content = generate_llms_txt(articles)
    (DOCS / "llms.txt").write_text(llms_content, encoding="utf-8")
    print(f"  ✓ docs/llms.txt ({len(llms_content)} chars)")

    # 生成 llms-full.txt
    full_content = generate_llms_full(articles)
    (DOCS / "llms-full.txt").write_text(full_content, encoding="utf-8")
    print(f"  ✓ docs/llms-full.txt ({len(full_content)} chars)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
