#!/usr/bin/env python3
"""
Knowledge Base Router — 按信号搜索相关技术文件。

Usage:
    python scripts/ctf-website/kb_router.py "jwt"
    python scripts/ctf-website/kb_router.py "sql injection"
"""

import sys
import json
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, "..", ".."))
KB_INDEX = os.path.join(ROOT, "kb", "ctf-website", "techniques", "kb-index.json")
TECHNIQUES_DIR = os.path.join(ROOT, "kb", "ctf-website", "techniques")

SCORE_SIGNAL = 10
SCORE_ID = 5
SCORE_FILE = 3


def load_index():
    if not os.path.exists(KB_INDEX):
        print(f"kb-index.json not found at {KB_INDEX}")
        return []
    with open(KB_INDEX, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data.get("entries", [])


def search(query, entries):
    query_lower = query.lower()
    results = []
    for entry in entries:
        score = 0
        # Match against entry id
        if query_lower in entry.get("id", "").lower():
            score += SCORE_ID
        # Match against signals
        for sig in entry.get("signals", []):
            if sig.lower() in query_lower or query_lower in sig.lower():
                score += SCORE_SIGNAL
        # Match against file paths
        for f in entry.get("files", []):
            if query_lower in f.lower():
                score += SCORE_FILE
        if score > 0:
            results.append((score, entry))
    results.sort(key=lambda x: x[0], reverse=True)
    return [r[1] for r in results]


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return

    query = sys.argv[1]
    entries = load_index()
    if not entries:
        return

    results = search(query, entries)
    if not results:
        print(f"\nNo matches for '{query}'.")
        print("Try broader keywords, or check kb/ctf-website/techniques/attack-network.md")
        return

    print(f"\nResults for '{query}' ({len(results)} found):\n")
    for i, entry in enumerate(results[:10], 1):
        print(f"  {i}. [{entry.get('id', '')}] priority={entry.get('priority', 0)}")
        print(f"     Signals: {', '.join(entry.get('signals', [])[:5])}")
        for f in entry.get("files", []):
            full = os.path.join(TECHNIQUES_DIR, f)
            exists = "✓" if os.path.exists(full) else "✗"
            print(f"     {exists} kb/ctf-website/techniques/{f}")
        print()


if __name__ == "__main__":
    main()
