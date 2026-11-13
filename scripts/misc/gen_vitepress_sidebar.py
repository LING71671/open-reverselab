#!/usr/bin/env python3
"""
Generate VitePress sidebar + board data for the ReverseLab site.

Scans kb/<track>/<board>/**/*.md and emits:
  site/.vitepress/sidebar.ts      - navigation by track, board and category
  site/.vitepress/boards.json     - board metadata (name, counts, blurb, hue)

Run from the repository root:  python scripts/misc/gen_vitepress_sidebar.py
The site/ build expects these files to exist; re-run after kb/ changes.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
KB = ROOT / "kb"
OUT_DIR = ROOT / "site" / ".vitepress"

# Board order + display metadata. Blurbs are short one-liners for the homepage.
BOARDS: dict[str, dict] = {
    "ctf-website": {
        "name": "CTF Website",
        "zh": "Web 攻击全表面",
        "hue": "278",
        "blurb": "JWT / SQLi / SSRF / XSS / CORS / OAuth / CVE / 支付攻击，信号到闭环的攻击网。",
    },
    "apk-reverse": {
        "name": "APK Reverse",
        "zh": "Android 逆向",
        "hue": "190",
        "blurb": "DEX / Native / IL2CPP / Frida Hook / 脱壳 / 加密破解，从 APK 到内存。",
    },
    "pe-reverse": {
        "name": "PE Reverse",
        "zh": "Windows 二进制分析",
        "hue": "65",
        "blurb": "Ghidra / x64dbg / Triage / IOC / YARA / Patch / 免杀，二进制全流程。",
    },
    "general": {
        "name": "General",
        "zh": "跨领域",
        "hue": "150",
        "blurb": "密码学 / 协议逆向 / 内核利用 / 游戏作弊 / 固件 / SDR / AI 安全。",
    },
    "windows": {
        "name": "Windows",
        "zh": "Windows 专项",
        "hue": "280",
        "blurb": "配置注入 / 权限提升 / 进程注入等 Windows 平台专项。",
    },
}

CATEGORY_RE = re.compile(r"^(\d{2})-(.+)$")
FILE_RE = re.compile(r"^(\d{2})-?(.+)?\.md$")
TRACKS = {"red": "Red", "blue": "Blue", "shared": "共享方法"}


def title_of(path: Path) -> str:
    """Best-effort title: frontmatter title, first # heading, else filename."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")[:2000]
    except OSError:
        return path.stem
    m = re.search(r"^title:\s*(.+)$", text, re.M)
    if m:
        return m.group(1).strip().strip("\"'")
    m = re.search(r"^#\s+(.+)$", text, re.M)
    if m:
        return m.group(1).strip()
    return path.stem


def sort_key(name: str) -> tuple[int, str]:
    m = FILE_RE.match(name)
    if m and m.group(1).isdigit():
        return (int(m.group(1)), m.group(2) or "")
    return (10_000, name)


def document_item(md: Path, text: str | None = None) -> dict:
    return {"text": text or title_of(md), "link": "/kb/" + md.relative_to(KB).with_suffix("").as_posix()}


def build_navigation() -> list[dict]:
    """Only publish domains that have a landing page in that track."""
    groups = []
    for track, title in TRACKS.items():
        landing = KB / track / "README.md"
        if not landing.is_file():
            continue
        items = [document_item(landing, "策略总览")]
        for board, meta in BOARDS.items():
            board_landing = KB / track / board / "README.md"
            if board_landing.is_file():
                items.append(document_item(board_landing, meta["name"]))
        groups.append({"text": title, "items": items})
    return groups


def article_groups(directory: Path) -> list[dict]:
    groups = []
    if not directory.is_dir():
        return groups
    for category in sorted(directory.iterdir(), key=lambda p: p.name):
        if not category.is_dir():
            continue
        articles = [md for md in sorted(category.rglob("*.md"), key=lambda p: (p.parent.as_posix(), sort_key(p.name))) if md.name != "README.md"]
        items = [document_item(md) for md in articles]
        if (category / "README.md").is_file():
            items.insert(0, document_item(category / "README.md", "分类索引"))
        if items:
            match = CATEGORY_RE.match(category.name)
            label = match.group(2) if match else category.name
            groups.append({"text": f"{label}（{len(articles)}）", "collapsed": True, "items": items})
    return groups


def build_sidebar() -> dict[str, list]:
    navigation = build_navigation()
    overview = {"text": "知识库总览", "link": "/kb/README"}
    sidebar = {"/kb/": [overview, *navigation]}
    for track, title in TRACKS.items():
        track_nav = next((group for group in navigation if group["text"] == title), None)
        if not track_nav:
            continue
        sidebar[f"/kb/{track}/"] = [overview, *navigation]
        for board, meta in BOARDS.items():
            directory = KB / track / board
            landing = directory / "README.md"
            if not landing.is_file():
                continue
            techniques = directory / "techniques"
            items = [document_item(landing, "板块总览")]
            for filename, label in (("attack-network", "攻击网"), ("defense-network", "防御网"), ("README", "技术索引")):
                md = techniques / f"{filename}.md"
                if md.is_file():
                    items.append(document_item(md, label))
            for md in sorted(directory.glob("*.md"), key=lambda p: sort_key(p.name)):
                if md.name != "README.md":
                    items.append(document_item(md))
            bare = [document_item(md) for md in sorted(techniques.glob("*.md"), key=lambda p: sort_key(p.name)) if md.stem not in {"README", "attack-network", "defense-network"}]
            if bare:
                items.append({"text": "板块文章", "items": bare})
            # Shared checklists, methodology and reference directories are also browsable.
            extra_groups = [group for group in article_groups(directory) if not group["text"].startswith("techniques（")]
            sidebar[f"/kb/{track}/{board}/"] = [
                overview,
                {**track_nav, "collapsed": True},
                {"text": f"{title} / {meta['name']}", "items": items},
                *article_groups(techniques),
                *extra_groups,
            ]
    return sidebar


def board_counts() -> dict:
    """{ board: { articles, categories, total } } with real numbers."""
    out = {}
    for board in BOARDS:
        tracks = {}
        for track in TRACKS:
            techniques = KB / track / board / "techniques"
            articles = [md for md in techniques.rglob("*.md") if md.stem not in {"README", "attack-network", "defense-network"}]
            categories = {md.relative_to(techniques).parts[0] for md in articles if md.parent != techniques}
            tracks[track] = {"articles": len(articles), "categories": len(categories)}
        out[board] = {"articles": sum(item["articles"] for item in tracks.values()), "categories": sum(item["categories"] for item in tracks.values()), "tracks": tracks}
    return out


def build_mcp_tools() -> list[dict]:
    """Group ai-tool-registry.json tools by board with full metadata for the tools page."""
    registry = json.loads((ROOT / "tools" / "ai-tool-registry.json").read_text(encoding="utf-8"))
    grouped: dict[str, list[dict]] = {}
    for tool in registry.get("tools") or []:
        board = str(tool.get("board") or "misc")
        grouped.setdefault(board, []).append(
            {
                "id": str(tool.get("id") or ""),
                "name": str(tool.get("name") or ""),
                "launch_mode": str(tool.get("launch_mode") or "cli"),
                "ai_callable": bool(tool.get("ai_callable")),
                "notes": str(tool.get("notes") or ""),
            }
        )
    return [
        {"board": board, "tools": sorted(ids, key=lambda t: t["id"])}
        for board, ids in grouped.items()
        if ids
    ]


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    sidebar = build_sidebar()

    ts_lines = ["// Auto-generated by scripts/misc/gen_vitepress_sidebar.py. Do not edit.", "// Regenerate with: python scripts/misc/gen_vitepress_sidebar.py", ""]
    ts_lines.append("export const sidebar: Record<string, any> = " + json.dumps(sidebar, ensure_ascii=False, indent=2) + ";")
    ts_lines.append("export const knowledgeNav = " + json.dumps(build_navigation(), ensure_ascii=False, indent=2) + ";")
    (OUT_DIR / "sidebar.ts").write_text("\n".join(ts_lines) + "\n", encoding="utf-8")

    counts = board_counts()
    boards_out = {}
    for board, meta in BOARDS.items():
        boards_out[board] = {**meta, **counts[board]}
    (OUT_DIR / "boards.json").write_text(
        json.dumps(boards_out, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    (OUT_DIR / "mcp-tools.json").write_text(
        json.dumps(build_mcp_tools(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    total_articles = sum(c["articles"] for c in counts.values())
    print(f"boards={len(BOARDS)} articles={total_articles} -> {OUT_DIR / 'sidebar.ts'}, {OUT_DIR / 'boards.json'}, {OUT_DIR / 'mcp-tools.json'}")


if __name__ == "__main__":
    main()
