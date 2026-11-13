#!/usr/bin/env python3
"""Shared knowledge catalog and document reader for the desktop and Vite server."""

from __future__ import annotations

import argparse
import ast
import importlib.util
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
_SPEC = importlib.util.spec_from_file_location("desktop_kb_router", Path(__file__).with_name("kb_router.py"))
assert _SPEC and _SPEC.loader
router = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(router)


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if isinstance(value, list):
        return list(dict.fromkeys(str(item).strip() for item in value if str(item).strip()))
    return []


def _frontmatter(content: str) -> dict[str, Any]:
    """Read the scalar/inline-list fields used by KB documents without a YAML dependency."""
    lines = content.lstrip("\ufeff").splitlines()
    if not lines or lines[0].strip() != "---":
        return {}
    metadata: dict[str, Any] = {}
    list_key = ""
    for line in lines[1:]:
        if line.strip() == "---":
            break
        if list_key and re.match(r"^\s+-\s+", line):
            value = re.sub(r"^\s+-\s+", "", line).strip()
            metadata[list_key].append(value.strip("\"'"))
            continue
        match = re.match(r"^([\w-]+):\s*(.*)$", line)
        if not match:
            continue
        key, value = match.groups()
        list_key = ""
        if not value:
            metadata[key] = []
            list_key = key
        else:
            try:
                metadata[key] = json.loads(value)
            except (ValueError, TypeError):
                try:
                    metadata[key] = ast.literal_eval(value)
                except (ValueError, SyntaxError):
                    metadata[key] = value.strip("\"'")
    return metadata


def _canonical_doc(repo_root: Path, candidate: Path) -> Path:
    kb_root = (repo_root / "kb").resolve(strict=True)
    resolved = candidate.resolve(strict=True)
    if not resolved.is_relative_to(kb_root) or not resolved.is_file() or resolved.suffix != ".md":
        raise ValueError("Only Markdown documents inside kb/ can be read")
    return resolved


def read_document(relative_path: str, repo_root: Path = ROOT) -> str:
    # Require the canonical form sent by the catalog. Resolve again to reject links
    # that point outside kb/, including Windows junctions and symbolic links.
    parts = relative_path.split("/")
    if (
        not relative_path
        or "\\" in relative_path
        or ":" in relative_path
        or "\x00" in relative_path
        or parts[0] != "kb"
        or any(part in ("", ".", "..") for part in parts)
    ):
        raise ValueError("Expected a canonical kb/.../*.md path")
    path = _canonical_doc(repo_root, repo_root / router.layout.canonical_path(relative_path, repo_root))
    return path.read_text(encoding="utf-8-sig")


def build_catalog(track: str = "both", repo_root: Path = ROOT) -> list[dict[str, Any]]:
    if track not in router.VALID_TRACKS:
        raise ValueError("Track must be red, blue, or both")
    repo_root = repo_root.resolve(strict=True)
    entries: list[dict[str, Any]] = []
    paths_by_entry: dict[tuple[str, str], list[str]] = {}
    owners: dict[str, list[dict[str, Any]]] = defaultdict(list)
    documents: dict[str, Path] = {}

    for board in router.BOARDS:
        index_path = router.layout.index_path(board, repo_root)
        if not index_path.is_file():
            continue
        index = json.loads(index_path.read_text(encoding="utf-8-sig"))
        for raw in index.get("entries", []):
            entry = {**raw, "_board": board}
            entries.append(entry)
            entry_paths = paths_by_entry.setdefault((board, str(entry.get("id", ""))), [])
            for filename in _strings(entry.get("files")):
                try:
                    # Index references can cross boards; normalize these trusted
                    # references while keeping public reader input traversal-free.
                    path = _canonical_doc(repo_root, router.layout.resolve_file(filename, board, repo_root))
                except (OSError, ValueError):
                    continue
                relative = path.relative_to(repo_root).as_posix()
                if not router.layout.document_parts(relative):
                    continue
                documents[relative] = path
                owners[relative].append(entry)
                if relative not in entry_paths:
                    entry_paths.append(relative)
        for path in (path for folder in router.layout.technique_dirs(board, repo_root) for path in folder.rglob("*.md")):
            if path.name == "README.md":
                continue
            try:
                path = _canonical_doc(repo_root, path)
            except (OSError, ValueError):
                continue
            relative = path.relative_to(repo_root).as_posix()
            if router.layout.document_parts(relative):
                documents[relative] = path

    pair_map = router._build_pair_map(entries)
    items: dict[str, dict[str, Any]] = {}
    for relative, path in sorted(documents.items()):
        board, technique, folder_track = router.layout.document_parts(relative)
        content = path.read_text(encoding="utf-8-sig")
        metadata = _frontmatter(content)
        # The owning board is authoritative when another index cross-references it.
        indexed = [entry for entry in owners[relative] if entry["_board"] == board] or owners[relative]
        tracks = {router.entry_track(entry) for entry in indexed}
        article_track = folder_track or (next(iter(tracks)) if len(tracks) == 1 else "both")
        heading = re.search(r"^#\s+(.+)$", content, flags=re.MULTILINE)
        title = str(metadata.get("title") or (heading.group(1).strip() if heading else path.stem))
        signals = list(dict.fromkeys(signal for entry in indexed for signal in _strings(entry.get("signals"))))
        mcp_tools = list(dict.fromkeys(tool for entry in indexed for tool in _strings(entry.get("mcp_tools"))))
        related: list[str] = []
        for entry in owners[relative]:
            key = (entry["_board"], str(entry.get("id", "")))
            for pair in pair_map.get(key, []):
                related.extend(paths_by_entry.get((pair["board"], pair["id"]), []))
        items[relative] = {
            "id": f"{board}:{technique[:-3]}",
            "board": board,
            "title": title,
            "category": str(metadata.get("category") or (technique.split('/')[0] if '/' in technique else "general")),
            "signals": signals if indexed else _strings(metadata.get("signals")),
            "mcp_tools": mcp_tools or _strings(metadata.get("mcp_tools")),
            "path": relative,
            "track": article_track,
            "related_paths": list(dict.fromkeys(p for p in related if p != relative and p in documents)),
        }

    for relative, item in items.items():
        counterpart = (relative[:-11] + ".md").replace("kb/blue/", "kb/red/", 1) if relative.endswith("-defense.md") else (relative[:-3] + "-defense.md").replace("kb/red/", "kb/blue/", 1)
        # Multi-document index groups (e.g. JWT) link to the exact sibling article
        # when present, instead of presenting every article in the paired group.
        if counterpart in items:
            item["related_paths"] = [counterpart]
    return [item for item in items.values() if router.entry_matches_track(item, track)]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    catalog = commands.add_parser("list")
    catalog.add_argument("--track", default="both")
    reader = commands.add_parser("read")
    reader.add_argument("--path", required=True)
    args = parser.parse_args(argv)
    try:
        result = build_catalog(args.track) if args.command == "list" else {"content": read_document(args.path)}
    except (OSError, ValueError) as error:
        status = 404 if isinstance(error, FileNotFoundError) else 400
        print(json.dumps({"error": str(error), "status": status}, ensure_ascii=True))
        return 1
    print(json.dumps(result, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
