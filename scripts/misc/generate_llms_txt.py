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
BOARDS = ("ctf-website", "apk-reverse", "pe-reverse", "general", "windows")
LAYERS = ("red", "blue", "shared")
SITE_URL = "https://ling71671.github.io/open-reverselab/"

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
    """Read quoted scalars and folded/literal block scalars from frontmatter."""
    lines = text.lstrip("\ufeff").splitlines()
    if not lines or lines[0].strip() != "---":
        return ""
    for index, line in enumerate(lines[1:], 1):
        if line.strip() == "---":
            break
        if not line.startswith(f"{field}:"):
            continue
        value = line.split(":", 1)[1].strip()
        if value in (">", ">-", ">+", "|", "|-", "|+"):
            content = []
            for continuation in lines[index + 1:]:
                if continuation and not continuation[0].isspace():
                    break
                content.append(continuation.strip())
            return (" " if value.startswith(">") else "\n").join(content).strip()
        return value.strip("\"'")
    return ""


def collect_articles(*, networks: bool = False) -> list[dict]:
    """收集所有技术文章的基本信息。"""
    articles = []
    for layer, board in ((layer, board) for layer in LAYERS for board in BOARDS):
        root = ROOT / "kb" / layer / board / "techniques"
        if not root.exists():
            continue
        for path in sorted(root.rglob("*.md")):
            name = path.name.lower()
            if name == "readme.md" or (name in ("attack-network.md", "defense-network.md")) != networks:
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
            url = f"{SITE_URL}kb/{layer}/{board}/techniques/{slug}.html"

            articles.append({
                "board": board,
                "track": layer,
                "board_name": BOARD_NAMES.get(board, board),
                "title": title or path.stem,
                "title_en": title_en or "",
                "summary": summary or "",
                "summary_en": summary_en or "",
                "url": url,
                "github_url": f"https://github.com/LING71671/open-reverselab/blob/main/kb/{layer}/{board}/techniques/{rel}",
                "path": str(path),
            })
    return articles


def generate_llms_txt(articles: list[dict], networks: list[dict] | None = None) -> str:
    """生成紧凑 llms.txt。"""
    lines = []
    lines.append("# Open ReverseLab — AI reverse engineering workspace")
    lines.append("")
    lines.append(f"> {len(articles)} knowledge-base articles for reverse engineering and defensive analysis, with desktop and MCP integrations.")
    lines.append("> Desktop workspaces with red / blue / both strategies, parallel Goals, execution evidence and a searchable knowledge base.")
    lines.append("")
    lines.append("## Quick Links")
    lines.append(f"- Landing Page: https://ling71671.github.io/open-reverselab/")
    lines.append(f"- Knowledge Base: https://ling71671.github.io/open-reverselab/kb/README.html")
    lines.append(f"- MCP Tools: https://ling71671.github.io/open-reverselab/mcp-tools.html")
    lines.append(f"- FAQ: https://ling71671.github.io/open-reverselab/faq.html")
    lines.append(f"- GitHub: https://github.com/LING71671/open-reverselab")
    lines.append(f"- Full LLM dump: https://ling71671.github.io/open-reverselab/llms-full.txt")
    lines.append("")

    lines.extend(["## Attack and Defense Networks", ""])
    for article in networks or []:
        lines.append(f"- [{article['board']} · {article['track']}: {article['title']}]({article['url']})")
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
            lines.append(f"- [{a['track']} · {title}]({a['url']})")
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
    lines.append("# Open ReverseLab — Full Knowledge Base Dump for LLM Ingestion")
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
    parser.add_argument("--output", type=Path, default=DOCS, help="Output directory")
    args = parser.parse_args()
    output = args.output
    output.mkdir(parents=True, exist_ok=True)

    articles = collect_articles()
    if not articles:
        print("No articles found!")
        return 1

    print(f"Found {len(articles)} articles across {len(set(a['board'] for a in articles))} boards")

    if args.check:
        llms_txt = output / "llms.txt"
        llms_full = output / "llms-full.txt"
        ok = True
        for f in [llms_txt, llms_full]:
            if not f.exists():
                print(f"MISSING: {f.name}")
                ok = False
        print("OK" if ok else "NEEDS REGENERATION")
        return 0 if ok else 1

    # 生成 llms.txt
    llms_content = generate_llms_txt(articles, collect_articles(networks=True))
    (output / "llms.txt").write_text(llms_content, encoding="utf-8")
    print(f"  ✓ {output / 'llms.txt'} ({len(llms_content)} chars)")

    # 生成 llms-full.txt
    full_content = generate_llms_full(collect_articles(networks=True) + articles)
    (output / "llms-full.txt").write_text(full_content, encoding="utf-8")
    print(f"  ✓ {output / 'llms-full.txt'} ({len(full_content)} chars)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
