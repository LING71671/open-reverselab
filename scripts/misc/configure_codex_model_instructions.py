#!/usr/bin/env python3
"""
Configure the project-local Codex model_instructions_file to point at CODEX.md.

Updates `.codex/config.toml` and `.codex/ctf.config.toml` while preserving any
existing keys (MCP servers, approval_policy, etc.).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CODEX_MD = ROOT / "CODEX.md"
CODEX_DIR = ROOT / ".codex"
CONFIG_FILES = (
    CODEX_DIR / "config.toml",
    CODEX_DIR / "ctf.config.toml",
)
MODEL_INSTRUCTIONS_VALUE = "../CODEX.md"
MODEL_INSTRUCTIONS_LINE = f'model_instructions_file = "{MODEL_INSTRUCTIONS_VALUE}"\n'
LINE_RE = re.compile(r"^\s*model_instructions_file\s*=", re.MULTILINE)


def upsert_model_instructions(text: str) -> str:
    if LINE_RE.search(text):
        return LINE_RE.sub(MODEL_INSTRUCTIONS_LINE.rstrip("\n"), text, count=1)
    if text and not text.endswith("\n"):
        text += "\n"
    if text and not text.endswith("\n\n") and text != "\n":
        # Keep a blank line before following tables when inserting at top.
        return MODEL_INSTRUCTIONS_LINE + ("\n" if text.strip() else "") + text.lstrip("\n")
    return MODEL_INSTRUCTIONS_LINE + text


def read_current_value(path: Path) -> str | None:
    if not path.exists():
        return None
    for line in path.read_text(encoding="utf-8").splitlines():
        if LINE_RE.match(line):
            return line.split("=", 1)[1].strip().strip('"').strip("'")
    return None


def configure_file(path: Path, overwrite_key: bool) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        current = read_current_value(path)
        if current == MODEL_INSTRUCTIONS_VALUE and not overwrite_key:
            return "unchanged"
        text = path.read_text(encoding="utf-8")
        if current is not None and current != MODEL_INSTRUCTIONS_VALUE and not overwrite_key:
            # Still update to the repo standard; flag as replaced.
            path.write_text(upsert_model_instructions(text), encoding="utf-8")
            return f"replaced:{current}->{MODEL_INSTRUCTIONS_VALUE}"
        path.write_text(upsert_model_instructions(text), encoding="utf-8")
        return "updated" if current else "inserted"
    path.write_text(MODEL_INSTRUCTIONS_LINE, encoding="utf-8")
    return "created"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Point Codex model_instructions_file at ../CODEX.md for this repo."
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Rewrite the key even when it already equals ../CODEX.md.",
    )
    args = parser.parse_args()

    if not CODEX_MD.is_file():
        print(f"ERROR: missing {CODEX_MD}", file=sys.stderr)
        return 1

    outputs: dict[str, str] = {}
    for path in CONFIG_FILES:
        outputs[str(path.relative_to(ROOT))] = configure_file(path, overwrite_key=args.force)

    payload = {
        "root": str(ROOT),
        "model_instructions_file": MODEL_INSTRUCTIONS_VALUE,
        "codex_md": str(CODEX_MD),
        "outputs": outputs,
        "verify_hint": "powershell -File scripts/misc/verify_codex_ctf_profile.ps1",
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
