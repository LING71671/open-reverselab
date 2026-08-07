#!/usr/bin/env python3
"""
Fix extension-less relative Markdown links in kb/ by appending .md.

kb/ articles use links like [x](techniques/README) or [x](./01-recon/foo)
without a .md suffix. Those are broken both on GitHub and in the built
site. This script rewrites them to include .md when the target file
exists (checked relative to the article's directory, then to kb/ root).

Usage:
  python scripts/misc/fix_kb_links.py            # apply fixes
  python scripts/misc/fix_kb_links.py --dry-run  # report only
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
KB = ROOT / "kb"

# [text](target) and ![alt](target); capture up to whitespace or ')'
LINK_RE = re.compile(r"(!?\[[^\]]*\]\()([^)\s]+)")
SCHEME_RE = re.compile(r"^(?:[a-zA-Z][a-zA-Z0-9+.-]*:|#|/)")


def fix_target(target: str, md_file: Path) -> str | None:
    """Return target + '.md' if that resolves to an existing file, else None."""
    body = target
    anchor = ""
    if "#" in target:
        body, anchor = target.split("#", 1)
    if not body or body.endswith("/"):
        return None
    if SCHEME_RE.match(body):
        return None
    suffix = Path(body).suffix
    if suffix:
        return None  # already has an extension (.md/.py/.png/...)
    candidates = [
        md_file.parent / body,
        KB / body,
    ]
    for base in candidates:
        if (base.parent / f"{base.name}.md").is_file():
            return f"{body}.md" + (f"#{anchor}" if anchor else "")
    return None


def process(file: Path, dry_run: bool) -> int:
    text = file.read_text(encoding="utf-8", errors="replace")
    original = text
    changed = 0

    def repl(m: re.Match) -> str:
        nonlocal changed
        prefix, target = m.group(1), m.group(2)
        fixed = fix_target(target, file)
        if fixed and fixed != target:
            changed += 1
            return f"{prefix}{fixed}"
        return m.group(0)

    new_text = LINK_RE.sub(repl, text)
    if changed:
        if dry_run:
            print(f"  {file.relative_to(ROOT)}: {changed} link(s)")
        else:
            file.write_text(new_text, encoding="utf-8")
    return changed


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true", help="report only, do not write")
    args = ap.parse_args()

    total = 0
    files_changed = 0
    for md in sorted(KB.rglob("*.md")):
        n = process(md, args.dry_run)
        if n:
            files_changed += 1
            total += n
    print(f"{'[dry-run] ' if args.dry_run else ''}{files_changed} files, {total} links fixed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
