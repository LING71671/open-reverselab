#!/usr/bin/env python3
"""
Knowledge Base Router — 按信号与双轨模式检索逆向技术文档（支持 general / pe-reverse / apk-reverse / ctf-website）。

Usage:
    python scripts/misc/kb_router.py "rsa"
    python scripts/misc/kb_router.py "jwt" --board ctf-website --track red
    python scripts/misc/kb_router.py "jwt" --board ctf-website --track both
    python scripts/misc/kb_router.py "signature" --board general --track blue
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
_SPEC = importlib.util.spec_from_file_location("kb_layout", Path(__file__).with_name("kb_layout.py"))
assert _SPEC and _SPEC.loader
layout = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(layout)
BOARDS: tuple[str, ...] = ("general", "pe-reverse", "apk-reverse", "ctf-website")
VALID_TRACKS: tuple[str, ...] = ("blue", "red", "both")
DEFAULT_TRACK = "blue"
TRACK_ENV_VAR = "REVERSELAB_MODE"

SCORE_SIGNAL = 10
SCORE_SIGNAL_EXACT = 30
SCORE_ID = 5
SCORE_FILE = 3


def index_path_for(board: str) -> Path:
    return layout.index_path(board, ROOT)


def resolve_track(track: str = "") -> str:
    norm = (track or "").strip().lower()
    if not norm or norm == "auto":
        env_val = os.environ.get(TRACK_ENV_VAR, DEFAULT_TRACK).strip().lower()
        return env_val if env_val in VALID_TRACKS else DEFAULT_TRACK
    if norm not in VALID_TRACKS:
        raise ValueError(
            f"Invalid track '{track}'. Must be one of: {', '.join(VALID_TRACKS)} or 'auto'."
        )
    return norm


def _as_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value] if value.strip() else []
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    return []


def entry_track(entry: dict[str, Any]) -> str:
    raw = str(entry.get("track", "")).strip().lower()
    if raw in VALID_TRACKS:
        return raw
    files = entry.get("files") or []
    if files and all(str(f).endswith("-defense.md") for f in files):
        return "blue"
    return "both"


def entry_matches_track(entry: dict[str, Any], active_track: str) -> bool:
    e_track = entry_track(entry)
    if active_track == "both":
        return True
    if active_track == "blue":
        return e_track in ("blue", "both")
    if active_track == "red":
        return e_track in ("red", "both")
    return True


def score_entry(query_lower: str, entry: dict[str, Any]) -> int:
    if not query_lower:
        return 0
    score = 0
    if query_lower in str(entry.get("id", "")).lower():
        score += SCORE_ID
    # Exact equality scores higher than substring: substring matching is
    # bidirectional so short queries can match longer signals without letting
    # accidental substrings outrank exact signal hits.
    for sig in entry.get("signals", []):
        s = str(sig).lower()
        if s == query_lower:
            score += SCORE_SIGNAL_EXACT
        elif s in query_lower or query_lower in s:
            score += SCORE_SIGNAL
    for f in entry.get("files", []):
        if query_lower in str(f).lower():
            score += SCORE_FILE
    return score


def _build_pair_map(entries: list[dict[str, Any]]) -> dict[tuple[str, str], list[dict[str, Any]]]:
    by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for e in entries:
        eid = str(e.get("id", ""))
        if eid:
            by_key[(str(e.get("_board", "general")), eid)] = e

    pairs: dict[tuple[str, str], list[dict[str, Any]]] = {}

    def _add_link(src_key: tuple[str, str], dst_key: tuple[str, str], relation: str) -> None:
        if src_key == dst_key or dst_key not in by_key:
            return
        dst = by_key[dst_key]
        bucket = pairs.setdefault(src_key, [])
        if any(item["id"] == dst_key[1] and item["relation"] == relation for item in bucket):
            return
        bucket.append(
            {
                "board": dst_key[0],
                "id": dst_key[1],
                "track": entry_track(dst),
                "relation": relation,
                "files": list(dst.get("files", [])),
            }
        )

    for entry in entries:
        board = str(entry.get("_board", "general"))
        eid = str(entry.get("id", ""))
        if not eid:
            continue
        src_key = (board, eid)

        for target in _as_list(entry.get("defends")):
            target_id = target if (board, target) in by_key else target.split("/")[-1]
            dst_key = (board, target_id)
            _add_link(src_key, dst_key, "defends")
            _add_link(dst_key, src_key, "defended_by")

        for blue_target in _as_list(entry.get("defended_by")):
            blue_id = blue_target if (board, blue_target) in by_key else blue_target.split("/")[-1]
            dst_key = (board, blue_id)
            _add_link(src_key, dst_key, "defended_by")
            _add_link(dst_key, src_key, "defends")

        if eid.endswith("-defense"):
            base_id = eid[: -len("-defense")]
            dst_key = (board, base_id)
            if dst_key in by_key:
                _add_link(src_key, dst_key, "defends")
                _add_link(dst_key, src_key, "defended_by")

    return pairs


def load_index(board: str = "all") -> list[dict[str, Any]]:
    boards = BOARDS if board in ("all", "") else (board,)
    entries: list[dict[str, Any]] = []
    for b in boards:
        idx = index_path_for(b)
        if not idx.is_file():
            continue
        data = json.loads(idx.read_text(encoding="utf-8"))
        for entry in data.get("entries", []):
            item = dict(entry)
            item.setdefault("_board", b)
            entries.append(item)
    return entries


def search(query: str, entries: list[dict[str, Any]], track: str = "") -> list[dict[str, Any]]:
    query_lower = query.lower().strip()
    if not query_lower:
        return []

    active_track = resolve_track(track)
    pair_map = _build_pair_map(entries)
    scored: list[tuple[int, int, int, dict[str, Any]]] = []

    for entry in entries:
        e_track = entry_track(entry)
        if not entry_matches_track(entry, active_track):
            continue
        score = score_entry(query_lower, entry)
        if score <= 0:
            continue

        item = dict(entry)
        item["_score"] = score
        item["_track"] = e_track
        if active_track == "both":
            board = str(entry.get("_board", "general"))
            eid = str(entry.get("id", ""))
            paired = pair_map.get((board, eid), [])
            if paired:
                item["_paired"] = paired

        scored.append(
            (
                score,
                1 if e_track == active_track else 0,
                int(entry.get("priority", 0)),
                item,
            )
        )

    scored.sort(key=lambda x: (x[0], x[1], x[2]), reverse=True)
    return [r[3] for r in scored]


def main(argv: list[str] | None = None, default_board: str = "all") -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("query", help="Signal or keyword to search")
    parser.add_argument("--board", default=default_board, choices=("all", *BOARDS))
    parser.add_argument("--track", default="auto", choices=("auto", *VALID_TRACKS))
    parser.add_argument("--json", action="store_true", help="Print JSON output")
    args = parser.parse_args(argv)

    active_track = resolve_track(args.track)
    entries = load_index(args.board)
    if not entries:
        print("No kb-index.json entries found.")
        return 1

    results = search(args.query, entries, track=active_track)
    if args.json:
        payload = {
            "query": args.query,
            "board": args.board,
            "track": active_track,
            "total": len(results),
            "results": results[:10],
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0

    if not results:
        print(f"\nNo matches for '{args.query}' (track={active_track}).")
        return 0

    print(f"\nResults for '{args.query}' (track={active_track}, {len(results)} found):\n")
    for i, entry in enumerate(results[:10], 1):
        board = entry.get("_board", "general")
        e_track = entry.get("_track", entry_track(entry))
        print(
            f"  {i}. [{board}:{entry.get('id', '')}] track={e_track} "
            f"score={entry.get('_score', 0)} priority={entry.get('priority', 0)}"
        )
        print(f"     Signals: {', '.join(entry.get('signals', [])[:5])}")
        for f in entry.get("files", []):
            full = layout.resolve_file(f, board, ROOT)
            exists = "✓" if full.is_file() else "✗"
            print(f"     {exists} {full.relative_to(ROOT).as_posix()}")
        for paired in entry.get("_paired", []):
            p_files = ", ".join(layout.resolve_file(pf, paired['board'], ROOT).relative_to(ROOT).as_posix() for pf in paired.get("files", []))
            print(f"     ⇄ {paired['relation']}: [{paired['id']}] ({paired['track']}) -> {p_files}")
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
