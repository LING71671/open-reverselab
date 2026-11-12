"""Knowledge base routing, reading, and catalog tools for ReverseLabToolsMCP."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .. import track as track_mod
from ..config import REVERSE_ROOT
from ..paths import ensure_under

KB_ROOTS: dict[str, Path] = {
    "ctf-website": REVERSE_ROOT / "kb" / "ctf-website" / "techniques",
    "apk-reverse": REVERSE_ROOT / "kb" / "apk-reverse" / "techniques",
    "pe-reverse": REVERSE_ROOT / "kb" / "pe-reverse" / "techniques",
    "general": REVERSE_ROOT / "kb" / "general" / "techniques",
}

SCORE_SIGNAL = 10
SCORE_SIGNAL_EXACT = 30
SCORE_ID = 5
SCORE_FILE = 3

_FRONTMATTER_RE = re.compile(r"\A---\s*\n(.*?)\n---", re.S)


def _as_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value] if value.strip() else []
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    return []


def _entry_track(entry: dict[str, Any]) -> str:
    raw = str(entry.get("track", "")).strip().lower()
    if raw in track_mod.VALID_TRACKS:
        return raw
    files = entry.get("files") or []
    if files and all(str(f).endswith("-defense.md") for f in files):
        return "blue"
    return "both"


def _entry_matches_track(entry_track: str, active_track: str) -> bool:
    if active_track == "both":
        return True
    if active_track == "blue":
        return entry_track in ("blue", "both")
    if active_track == "red":
        return entry_track in ("red", "both")
    return True


def _score_entry(query_lower: str, entry: dict[str, Any]) -> int:
    if not query_lower:
        return 0
    score = 0
    if query_lower in str(entry.get("id", "")).lower():
        score += SCORE_ID
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


def _build_pair_map(
    entries: list[dict[str, Any]],
    techniques_dir: Path,
) -> dict[str, list[dict[str, Any]]]:
    """Build bidirectional offense <-> defense pair map keyed by entry id."""
    by_id: dict[str, dict[str, Any]] = {
        str(e.get("id", "")): e for e in entries if e.get("id")
    }
    pairs: dict[str, list[dict[str, Any]]] = {}

    def _add_link(src_id: str, target_id: str, relation: str) -> None:
        if not src_id or not target_id or src_id == target_id:
            return
        target = by_id.get(target_id)
        if target is None:
            return
        bucket = pairs.setdefault(src_id, [])
        if any(item["id"] == target_id and item["relation"] == relation for item in bucket):
            return
        bucket.append(
            {
                "id": target_id,
                "track": _entry_track(target),
                "relation": relation,
                "files": [
                    (techniques_dir / f).as_posix() for f in target.get("files", [])
                ],
            }
        )

    for entry in entries:
        eid = str(entry.get("id", ""))
        if not eid:
            continue
        for target_id in _as_list(entry.get("defends")):
            resolved_id = target_id if target_id in by_id else target_id.split("/")[-1]
            _add_link(eid, resolved_id, "defends")
            _add_link(resolved_id, eid, "defended_by")
        for blue_id in _as_list(entry.get("defended_by")):
            resolved_id = blue_id if blue_id in by_id else blue_id.split("/")[-1]
            _add_link(eid, resolved_id, "defended_by")
            _add_link(resolved_id, eid, "defends")

        if eid.endswith("-defense"):
            base_id = eid[: -len("-defense")]
            if base_id in by_id:
                _add_link(eid, base_id, "defends")
                _add_link(base_id, eid, "defended_by")

    return pairs


def _search_kb(query: str, board: str, active_track: str) -> list[dict[str, Any]]:
    """Search a single KB board's index and return scored, track-filtered results."""
    techniques_dir = KB_ROOTS[board]
    index_path = techniques_dir / "kb-index.json"
    if not index_path.exists():
        return []

    with open(index_path, encoding="utf-8") as f:
        data = json.load(f)

    entries = data.get("entries", [])
    query_lower = query.lower().strip()
    if not query_lower:
        return []

    pair_map = _build_pair_map(entries, techniques_dir)
    results: list[dict[str, Any]] = []

    for entry in entries:
        e_track = _entry_track(entry)
        if not _entry_matches_track(e_track, active_track):
            continue

        score = _score_entry(query_lower, entry)
        if score <= 0:
            continue

        eid = entry["id"]
        item: dict[str, Any] = {
            "board": board,
            "id": eid,
            "track": e_track,
            "priority": entry.get("priority", 0),
            "score": score,
            "signals": entry.get("signals", [])[:8],
            "files": [
                (techniques_dir / f).as_posix() for f in entry.get("files", [])
            ],
        }
        if "defends" in entry:
            item["defends"] = entry["defends"]
        if "defense_files" in entry:
            item["defense_files"] = [
                (techniques_dir / df).as_posix() for df in _as_list(entry["defense_files"])
            ]

        paired = pair_map.get(eid, [])
        if paired and active_track == "both":
            item["paired_entries"] = paired
            paired_files: list[str] = []
            for p in paired:
                for pf in p["files"]:
                    if pf not in paired_files:
                        paired_files.append(pf)
            if "defense_files" in item:
                for df in item["defense_files"]:
                    if df not in paired_files:
                        paired_files.append(df)
            item["paired_files"] = paired_files

        results.append(item)

    results.sort(
        key=lambda r: (
            r["score"],
            1 if r["track"] == active_track else 0,
            r["priority"],
        ),
        reverse=True,
    )
    return results


def kb_router(query: str, board: str = "", track: str = "") -> dict[str, Any]:
    """按攻击/防御信号搜索知识库（支持全部 4 个板块与 blue/red/both 三轨），返回匹配技术文件与配对关系。

    board 可选：'ctf-website' | 'apk-reverse' | 'pe-reverse' | 'general' | ''（全部搜索）
    track 可选：'blue' | 'red' | 'both' | ''（默认跟随当前活动轨道）
    """
    try:
        active_track = track_mod.resolve_track(track)
    except ValueError as exc:
        return {"error": str(exc), "valid_tracks": list(track_mod.VALID_TRACKS)}

    if board and board not in KB_ROOTS:
        return {
            "error": f"Unknown board '{board}'. Valid boards: {', '.join(KB_ROOTS.keys())}",
            "valid_boards": list(KB_ROOTS.keys()),
        }

    boards = [board] if board else list(KB_ROOTS.keys())
    all_results: list[dict[str, Any]] = []
    for b in boards:
        all_results.extend(_search_kb(query, b, active_track))

    all_results.sort(
        key=lambda r: (
            r["score"],
            1 if r["track"] == active_track else 0,
            r["priority"],
        ),
        reverse=True,
    )

    by_board: dict[str, list[dict[str, Any]]] = {}
    for r in all_results[:15]:
        by_board.setdefault(r["board"], []).append(r)

    top = all_results[:10]
    payload: dict[str, Any] = {
        "query": query,
        "track": active_track,
        "boards_searched": boards,
        "total": len(all_results),
        "by_board": by_board,
        "top": top,
    }

    if active_track == "both":
        paired_links: list[dict[str, Any]] = []
        for item in top:
            if item.get("paired_entries") or item.get("defense_files"):
                paired_links.append(
                    {
                        "board": item["board"],
                        "id": item["id"],
                        "track": item["track"],
                        "paired_entries": item.get("paired_entries", []),
                        "paired_files": item.get("paired_files", item.get("defense_files", [])),
                    }
                )
        payload["paired_links"] = paired_links

    return payload


def _normalize_technique_path(technique_path: str, board: str) -> str:
    norm = technique_path.replace("\\", "/")
    prefix = f"kb/{board}/techniques/"
    if norm.startswith(prefix):
        return norm[len(prefix):]
    return technique_path


def _parse_frontmatter_track(content: str) -> dict[str, str]:
    match = _FRONTMATTER_RE.match(content.lstrip())
    if not match:
        return {}
    meta: dict[str, str] = {}
    for line in match.group(1).splitlines():
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        key = k.strip()
        if key in ("track", "defends", "id"):
            meta[key] = v.strip().strip('"').strip("'")
    return meta


def kb_read_file(technique_path: str, board: str = "") -> dict[str, Any]:
    """读取知识库技术文件内容。自动检测板块或通过 board 参数指定。

    支持板块：ctf-website / apk-reverse / pe-reverse / general。
    """
    if not board:
        for b, root in KB_ROOTS.items():
            rel_path = _normalize_technique_path(technique_path, b)
            candidate = (root / rel_path).resolve()
            try:
                ensure_under(candidate, [root], "technique path")
                if candidate.exists() and candidate.is_file():
                    board = b
                    technique_path = rel_path
                    break
            except ValueError:
                continue
        else:
            for b, root in KB_ROOTS.items():
                rel_path = _normalize_technique_path(technique_path, b)
                candidate = root / rel_path
                if candidate.exists() and candidate.is_file():
                    board = b
                    technique_path = rel_path
                    break

    if not board or board not in KB_ROOTS:
        return {
            "error": f"Cannot resolve board for '{technique_path}'. "
            f"Specify board: {', '.join(KB_ROOTS.keys())}"
        }

    rel_path = _normalize_technique_path(technique_path, board)
    resolved = (KB_ROOTS[board] / rel_path).resolve()
    try:
        ensure_under(resolved, [KB_ROOTS[board]], "technique path")
    except ValueError as e:
        return {"error": str(e)}

    if not resolved.exists():
        return {"error": f"file not found: {resolved}"}
    if not resolved.is_file():
        return {"error": f"not a file: {resolved}"}

    content = resolved.read_text(encoding="utf-8", errors="replace")
    meta = _parse_frontmatter_track(content)
    result: dict[str, Any] = {
        "board": board,
        "path": str(resolved.relative_to(REVERSE_ROOT)),
        "size": len(content),
        "lines": content.count("\n"),
        "content": content[:16384],
        "truncated": len(content) > 16384,
    }
    if meta.get("track"):
        result["track"] = meta["track"]
    if meta.get("defends"):
        result["defends"] = meta["defends"]
    return result


def kb_catalog(board: str = "", track: str = "") -> dict[str, Any]:
    """列出知识库所有板块、分类、条目数、文件数与轨道分布。

    board 可选：不传则列出所有板块；track 可选：'blue' | 'red' | 'both' | ''。
    """
    filter_track = (track or "").strip().lower()
    if filter_track and filter_track not in (*track_mod.VALID_TRACKS, "auto"):
        return {"error": f"Invalid track '{track}'. Must be one of: blue, red, both."}
    if filter_track == "auto":
        filter_track = track_mod.get_track()

    if board and board not in KB_ROOTS:
        return {
            "error": f"Unknown board '{board}'. Valid boards: {', '.join(KB_ROOTS.keys())}",
            "valid_boards": list(KB_ROOTS.keys()),
        }

    boards = [board] if board else list(KB_ROOTS.keys())
    all_catalogs: dict[str, Any] = {}

    for b in boards:
        index_path = KB_ROOTS[b] / "kb-index.json"
        if not index_path.exists():
            all_catalogs[b] = {"error": "kb-index.json not found"}
            continue

        with open(index_path, encoding="utf-8") as f:
            data = json.load(f)

        entries = data.get("entries", [])
        track_counts = {"blue": 0, "red": 0, "both": 0}
        filtered_entries: list[dict[str, Any]] = []
        for entry in entries:
            e_track = _entry_track(entry)
            track_counts[e_track] = track_counts.get(e_track, 0) + 1
            if not filter_track or _entry_matches_track(e_track, filter_track):
                filtered_entries.append(entry)

        categories: dict[str, dict[str, Any]] = {}
        for entry in filtered_entries:
            for f_path in entry.get("files", []):
                cat = f_path.split("/")[0]
                categories.setdefault(cat, {"files": set(), "entry_ids": []})
                categories[cat]["files"].add(f_path)
                if entry["id"] not in categories[cat]["entry_ids"]:
                    categories[cat]["entry_ids"].append(entry["id"])

        all_catalogs[b] = {
            "version": data.get("version", ""),
            "techniques_dir": str(KB_ROOTS[b].relative_to(REVERSE_ROOT)),
            "total_entries": len(filtered_entries),
            "total_files": sum(len(e.get("files", [])) for e in filtered_entries),
            "track_counts": track_counts,
            "categories": {
                cat: {
                    "entry_count": len(info["entry_ids"]),
                    "file_count": len(info["files"]),
                    "entries": info["entry_ids"],
                }
                for cat, info in sorted(categories.items())
            },
        }

    return {
        "active_track": track_mod.get_track(),
        "track_filter": filter_track or "all",
        "boards": all_catalogs,
    }
