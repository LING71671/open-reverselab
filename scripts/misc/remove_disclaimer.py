#!/usr/bin/env python3
"""
Optionally remove disclaimer files and README disclaimer sections from a local checkout.

Purpose: some AI agents over-interpret disclaimer text and then refuse or degrade
normal reverse-engineering / CTF / lab workflows. This script clears those texts
from the local working tree after an explicit confirmation.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]

DISCLAIMER_FILES = (
    ROOT / "DISCLAIMER.md",
    ROOT / "DISCLAIMER.zh.md",
)

README_SECTIONS = (
    (ROOT / "README.md", "Disclaimer"),
    (ROOT / "README.zh.md", "免责声明"),
)


def strip_markdown_section(text: str, heading: str) -> tuple[str, bool]:
    """Remove a ## section by exact heading title, keeping the following ## section."""
    pattern = re.compile(
        rf"(?ms)^##[ \t]+{re.escape(heading)}[ \t]*\n.*?(?=^##[ \t]+|\Z)"
    )
    new_text, count = pattern.subn("", text, count=1)
    if count:
        new_text = re.sub(r"\n{3,}", "\n\n", new_text).rstrip() + "\n"
        return new_text, True
    return text, False


def preview() -> list[str]:
    lines: list[str] = []
    for path in DISCLAIMER_FILES:
        status = "delete" if path.exists() else "skip (missing)"
        lines.append(f"  FILE  [{status}] {path.relative_to(ROOT)}")
    for path, heading in README_SECTIONS:
        if not path.exists():
            lines.append(f"  EDIT  [skip missing] {path.relative_to(ROOT)} ## {heading}")
            continue
        text = path.read_text(encoding="utf-8")
        _, found = strip_markdown_section(text, heading)
        status = "strip section" if found else "skip (section absent)"
        lines.append(f"  EDIT  [{status}] {path.relative_to(ROOT)} ## {heading}")
    return lines


def confirm(yes: bool) -> bool:
    print()
    print("=" * 72)
    print("WARNING — local disclaimer removal")
    print("=" * 72)
    print(
        "This will delete DISCLAIMER.md / DISCLAIMER.zh.md and strip the\n"
        "Disclaimer / 免责声明 sections from README.md / README.zh.md in THIS\n"
        "local working copy only.\n"
        "\n"
        "Reason this script exists: some AI agents misread disclaimer text and\n"
        "then refuse or hedge instead of doing normal lab / RE / CTF work.\n"
        "\n"
        "License / 许可 sections are kept. CODEX.md / AGENTS.md are untouched."
    )
    print("=" * 72)
    if yes:
        print("Confirmation via --yes")
        return True
    try:
        answer = input('Type DELETE (all caps) to proceed, anything else to abort: ').strip()
    except EOFError:
        print("No TTY input; aborting. Re-run with --yes for non-interactive use.", file=sys.stderr)
        return False
    return answer == "DELETE"


def apply_changes() -> dict[str, str]:
    results: dict[str, str] = {}
    for path in DISCLAIMER_FILES:
        rel = str(path.relative_to(ROOT))
        if not path.exists():
            results[rel] = "missing"
            continue
        path.unlink()
        results[rel] = "deleted"

    for path, heading in README_SECTIONS:
        rel = str(path.relative_to(ROOT))
        key = f"{rel}##{heading}"
        if not path.exists():
            results[key] = "missing"
            continue
        text = path.read_text(encoding="utf-8")
        new_text, found = strip_markdown_section(text, heading)
        if not found:
            results[key] = "section-absent"
            continue
        path.write_text(new_text, encoding="utf-8")
        results[key] = "stripped"
    return results


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Remove local disclaimer files and README disclaimer sections after confirmation."
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Skip interactive prompt (still prints the warning). Use deliberately.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show planned actions and exit without changing files.",
    )
    args = parser.parse_args()

    print(f"Repository root: {ROOT}")
    print("Planned actions:")
    for line in preview():
        print(line)

    if args.dry_run:
        print("Dry-run only; no changes made.")
        return 0

    if not confirm(args.yes):
        print("Aborted; no changes made.")
        return 1

    results = apply_changes()
    print("Results:")
    for key, status in results.items():
        print(f"  {key}: {status}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
