#!/usr/bin/env python3
"""
Knowledge Base Router (ctf-website compatibility wrapper) — 按信号搜索相关技术文件。

Usage:
    python scripts/ctf-website/kb_router.py "jwt"
    python scripts/ctf-website/kb_router.py "sql injection" --track red
"""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
from typing import Any

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, "..", ".."))
KB_INDEX = os.path.join(ROOT, "kb", "ctf-website", "techniques", "kb-index.json")
TECHNIQUES_DIR = os.path.join(ROOT, "kb", "ctf-website", "techniques")

_MISC_ROUTER_PATH = Path(ROOT) / "scripts" / "misc" / "kb_router.py"
_SPEC = importlib.util.spec_from_file_location("reverselab_misc_kb_router", _MISC_ROUTER_PATH)
assert _SPEC and _SPEC.loader
_MISC_ROUTER = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MISC_ROUTER)

SCORE_SIGNAL = _MISC_ROUTER.SCORE_SIGNAL
SCORE_SIGNAL_EXACT = _MISC_ROUTER.SCORE_SIGNAL_EXACT
SCORE_ID = _MISC_ROUTER.SCORE_ID
SCORE_FILE = _MISC_ROUTER.SCORE_FILE


def load_index(board: str = "ctf-website") -> list[dict[str, Any]]:
    return _MISC_ROUTER.load_index(board=board)


def search(query: str, entries: list[dict[str, Any]], track: str = "") -> list[dict[str, Any]]:
    return _MISC_ROUTER.search(query, entries, track=track)


def main(argv: list[str] | None = None) -> int:
    return _MISC_ROUTER.main(argv=argv, default_board="ctf-website")


if __name__ == "__main__":
    raise SystemExit(main())
