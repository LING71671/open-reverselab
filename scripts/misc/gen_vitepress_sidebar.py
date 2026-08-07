#!/usr/bin/env python3
"""
Generate VitePress sidebar + board data for the ReverseLab site.

Scans kb/<board>/techniques/<category>/*.md and emits:
  site/.vitepress/sidebar.ts      - sidebar tree per board (grouped by category)
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


def build_sidebar() -> dict[str, list]:
    """Return { board: [ { text, link, collapsed, items } ] }."""
    sidebar: dict[str, list] = {}
    for board, meta in BOARDS.items():
        techniques = KB / board / "techniques"
        groups: list[dict] = []
        bare_articles: list[dict] = []
        if techniques.is_dir():
            for cat in sorted(techniques.iterdir(), key=lambda p: p.name):
                if not cat.is_dir():
                    continue
                cat_m = CATEGORY_RE.match(cat.name)
                items = []
                for md in sorted(cat.glob("*.md"), key=lambda p: sort_key(p.name)):
                    rel = f"/kb/{board}/techniques/{cat.name}/{md.name}"
                    items.append({"text": title_of(md), "link": rel})
                if not items:
                    continue
                label = cat_m.group(2) if cat_m else cat.name
                groups.append(
                    {
                        "text": f"{label}（{len(items)}）",
                        "collapsed": True,
                        "items": items,
                    }
                )
            # Articles sitting directly under techniques/ (no category dir),
            # e.g. kb/windows/techniques/*.md. README/attack-network are
            # landing pages, not articles.
            for md in sorted(techniques.glob("*.md"), key=lambda p: sort_key(p.name)):
                if md.stem in {"README", "attack-network"}:
                    continue
                bare_articles.append(
                    {
                        "text": title_of(md),
                        "link": f"/kb/{board}/techniques/{md.name}",
                    }
                )
        # Board README as the board landing page
        landing = f"/kb/{board}/README"
        root_items = [
            {"text": "板块总览", "link": landing},
            {"text": "攻击网", "link": f"/kb/{board}/techniques/attack-network"},
        ]
        if bare_articles:
            root_items.append({"text": "板块文章", "items": bare_articles})
        sidebar[board] = [{"text": meta["name"], "items": root_items}, *groups]
    return sidebar


def board_counts() -> dict:
    """{ board: { articles, categories, total } } with real numbers."""
    out = {}
    for board in BOARDS:
        techniques = KB / board / "techniques"
        articles = 0
        categories = 0
        if techniques.is_dir():
            for cat in techniques.iterdir():
                if cat.is_dir():
                    n = len(list(cat.glob("*.md")))
                    if n:
                        categories += 1
                        articles += n
            # bare articles under techniques/ root
            for md in techniques.glob("*.md"):
                if md.stem not in {"README", "attack-network"}:
                    articles += 1
        out[board] = {"articles": articles, "categories": categories}
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
