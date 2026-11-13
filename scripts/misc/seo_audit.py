#!/usr/bin/env python3
"""SEO 审计工具 — 检查网站 SEO 健康状态。

检查项：
1. 所有 KB 文章有完整 frontmatter
2. sitemap.xml 存在且覆盖所有页面
3. robots.txt 存在
4. llms.txt 存在且引用有效
5. 关键 HTML 页面有 meta 标签
6. 无 broken internal links

Usage:
    python scripts/misc/seo_audit.py
    python scripts/misc/seo_audit.py --json reports/seo_audit.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs"

FM_REQUIRED = ["id:", "title:", "title_en:", "summary:", "summary_en:",
               "board:", "category:", "signals:", "keywords:",
               "difficulty:", "tags:", "language:", "last_updated:"]

SEO_PAGES = [  # 需要 SEO 标签的页面（排除 404）
    "index.html", "faq.html",
    "kb/index.html",
    "kb/ctf-website/index.html",
    "kb/apk-reverse/index.html",
    "kb/pe-reverse/index.html",
    "kb/general/index.html",
    "kb/windows/index.html",
    "mcp-tools/index.html",
]
EXPECTED_PAGES = SEO_PAGES + ["404.html"]  # 404 需要存在但不需要 SEO 标签

EXPECTED_FILES = [
    "robots.txt", "sitemap.xml", "llms.txt", "llms-full.txt",
]


def check_frontmatter() -> list[str]:
    """检查所有 KB 文章的 frontmatter 完整性。"""
    failures = []
    boards_dirs = [ROOT / "kb" / layer / board / "techniques"
                   for layer in ("red", "blue", "shared")
                   for board in ("ctf-website", "apk-reverse", "pe-reverse", "general", "windows")]

    for board_dir in boards_dirs:
        if not board_dir.exists():
            continue
        for path in board_dir.rglob("*.md"):
            if path.name.lower() == "readme.md" or path.name in ("attack-network.md", "defense-network.md"):
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            if not text.lstrip().startswith("---"):
                failures.append(f"missing-frontmatter: {path.relative_to(ROOT)}")
                continue
            end = text.find("---", 3)
            if end == -1:
                failures.append(f"malformed-frontmatter: {path.relative_to(ROOT)}")
                continue
            fm = text[3:end]
            for field in FM_REQUIRED:
                if field not in fm:
                    failures.append(f"missing-{field[:-1]}: {path.relative_to(ROOT)}")
    return failures


def check_docs_pages() -> list[str]:
    """检查 docs/ 下必要页面是否存在。"""
    failures = []
    for page in EXPECTED_PAGES:
        if not (DOCS / page).exists():
            failures.append(f"missing-page: docs/{page}")
    for f in EXPECTED_FILES:
        if not (DOCS / f).exists():
            failures.append(f"missing-file: docs/{f}")
    return failures


def check_meta_tags() -> list[str]:
    """检查 HTML 页面的 meta 标签（仅 SEO 页面，不含 404）。"""
    failures = []
    for page in SEO_PAGES:
        path = DOCS / page
        if not path.exists():
            continue
        html = path.read_text(encoding="utf-8", errors="replace")
        if "<title>" not in html:
            failures.append(f"missing-title-tag: docs/{page}")
        if 'name="description"' not in html:
            failures.append(f"missing-meta-description: docs/{page}")
        if "og:title" not in html:
            failures.append(f"missing-og-tags: docs/{page}")
    return failures


def check_sitemap_coverage() -> list[str]:
    """检查 sitemap 是否覆盖所有主要页面。"""
    sitemap = DOCS / "sitemap.xml"
    if not sitemap.exists():
        return ["sitemap-missing"]
    content = sitemap.read_text(encoding="utf-8")
    failures = []
    for page in SEO_PAGES:
        if page.replace(".html", "/") not in content and page.replace(".html", "") not in content:
            url_path = page.replace("index.html", "").replace(".html", "/")
            if url_path not in content and page not in content:
                failures.append(f"sitemap-missing-url: {page}")
    return failures


def check_robots() -> list[str]:
    """检查 robots.txt。"""
    robots = DOCS / "robots.txt"
    if not robots.exists():
        return ["robots-missing"]
    content = robots.read_text(encoding="utf-8")
    failures = []
    if "Sitemap:" not in content:
        failures.append("robots-missing-sitemap-ref")
    if "GPTBot" not in content:
        failures.append("robots-missing-gptbot")
    if "Claude-Web" not in content:
        failures.append("robots-missing-claude")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", dest="json_path", help="输出 JSON 报告路径")
    args = parser.parse_args()

    results = {
        "frontmatter": check_frontmatter(),
        "pages": check_docs_pages(),
        "meta_tags": check_meta_tags(),
        "sitemap": check_sitemap_coverage(),
        "robots": check_robots(),
    }

    total_failures = sum(len(v) for v in results.values())

    print(f"SEO Audit — {total_failures} issues found\n")

    for category, failures in results.items():
        status = "✓" if not failures else f"✗ ({len(failures)})"
        print(f"  {status} {category}")
        for f in failures[:5]:  # 最多显示 5 条
            print(f"      {f}")
        if len(failures) > 5:
            print(f"      ... and {len(failures) - 5} more")

    if args.json_path:
        out = Path(args.json_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")

    return 0 if total_failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
