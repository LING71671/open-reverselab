#!/usr/bin/env python3
"""Generate the 1200x630 social preview image for the ReverseLab site.

Uses the DESIGN.md palette (pure white bg, indigo primary, amber accent,
board hue bars). Output: site/public/assets/social-preview.png
"""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "site" / "public" / "assets" / "social-preview.png"

W, H = 1200, 630
BG = (255, 255, 255)
INK = (32, 30, 58)          # oklch(0.16 0.02 280) ~ near-black indigo
PRIMARY = (64, 58, 115)     # oklch(0.42 0.14 278) indigo
MUTED = (118, 116, 136)     # oklch(0.5 0.015 280)
ACCENT = (168, 110, 28)     # oklch(0.58 0.15 65) amber
LINE = (226, 225, 233)      # oklch(0.9 0.004 280)

BOARD_BARS = [  # hue-coded board colors (light variants)
    (74, 68, 128),    # CTF indigo
    (40, 118, 138),   # APK cyan
    (168, 110, 28),   # PE amber
    (46, 120, 82),    # General green
    (96, 90, 128),    # Windows purple-gray
]

FONT_DIR = Path("C:/Windows/Fonts")
FONT_BOLD = FONT_DIR / "msyhbd.ttc"   # Microsoft YaHei Bold (zh + latin)
FONT_REG = FONT_DIR / "msyh.ttc"


def font(size: int, bold: bool = True) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(str(FONT_BOLD if bold else FONT_REG), size)


def main() -> None:
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)

    # left accent rule
    d.rectangle([0, 0, 10, H], fill=PRIMARY)

    # title
    title_f = font(96)
    d.text((72, 150), "ReverseLab", font=title_f, fill=INK)

    # tagline
    tag_f = font(34, bold=False)
    d.text(
        (74, 276),
        "开源逆向工程实验环境 · 173 篇文章 · 100+ MCP 工具",
        font=tag_f,
        fill=MUTED,
    )

    # sub note
    note_f = font(26, bold=False)
    d.text(
        (74, 336),
        "Agent 原生，目录即约定。CTF / APK / PE / 加密 / 游戏作弊全领域。",
        font=note_f,
        fill=MUTED,
    )

    # board bars at the bottom
    bar_w = 4
    gap = 12
    x = 74
    y = H - 96
    labels = ["CTF Website", "APK Reverse", "PE Reverse", "General", "Windows"]
    lab_f = font(24, bold=False)
    for color, name in zip(BOARD_BARS, labels):
        d.rectangle([x, y, x + bar_w, y + 40], fill=color)
        d.text((x + bar_w + 10, y + 6), name, font=lab_f, fill=INK)
        x += bar_w + 10 + d.textlength(name, font=lab_f) + 28
        if x > W - 120:
            break

    # footer line + url
    d.line([72, H - 52, W - 72, H - 52], fill=LINE, width=1)
    url_f = font(24, bold=False)
    d.text((74, H - 42), "reverselab.int0.cc", font=url_f, fill=ACCENT)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    img.save(OUT, format="PNG", optimize=True)
    print(f"wrote {OUT} ({img.size[0]}x{img.size[1]})")


if __name__ == "__main__":
    main()
