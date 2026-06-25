#!/usr/bin/env python3
"""
Merge multiple proxy source configurations into one unified config.

Usage:
  python tools/proxy_pool/merge_sources.py config1.json config2.json --output merged.json
  python tools/proxy_pool/merge_sources.py config1.json --override test_url=https://example.com/ip
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Merge proxy source config files")
    ap.add_argument("inputs", nargs="+", help="Source config JSON files to merge")
    ap.add_argument("--output", "-o", default="tools/proxy_pool/proxy_sources.merged.json")
    ap.add_argument("--override", nargs="*", default=[], help="key=value overrides for top-level fields")
    ap.add_argument("--dedup", action="store_true", default=True, help="Deduplicate sources by id")
    args = ap.parse_args(argv)

    merged: dict = {"schema": "reverselab.proxy_sources.v1", "test_url": "", "validation": {}, "pool": {}, "sources": []}
    seen_ids: set[str] = set()

    for input_path in args.inputs:
        p = Path(input_path)
        if not p.exists():
            print(f"[warn] skipping missing file: {p}", file=sys.stderr)
            continue
        cfg = json.loads(p.read_text(encoding="utf-8"))
        # Merge top-level fields
        for key in ("test_url", "validation", "pool"):
            if key in cfg and cfg[key]:
                if isinstance(cfg[key], dict) and isinstance(merged.get(key), dict):
                    merged[key] = {**merged[key], **cfg[key]}
                else:
                    merged[key] = cfg[key]
        # Merge sources
        for src in cfg.get("sources", []):
            sid = src.get("id", "")
            if args.dedup and sid in seen_ids:
                print(f"[info] dedup: skipped duplicate source '{sid}'", file=sys.stderr)
                continue
            seen_ids.add(sid)
            merged["sources"].append(src)

    # Apply overrides
    for ov in args.override:
        if "=" not in ov:
            print(f"[warn] bad override format: {ov} (use key=value)", file=sys.stderr)
            continue
        key, val = ov.split("=", 1)
        # Try to parse as JSON, fall back to string
        try:
            val = json.loads(val)
        except (json.JSONDecodeError, ValueError):
            pass
        merged[key] = val

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(merged, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[info] merged {len(args.inputs)} file(s) → {out_path} ({len(merged['sources'])} sources)", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
