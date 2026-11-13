"""Canonical KB paths shared by readers, routers and publication generators."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LAYERS = ("red", "blue", "shared")


def aliases(root: Path = ROOT) -> dict[str, str]:
    path = root / "kb" / "path-aliases.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}


def canonical_path(path: str, root: Path = ROOT) -> str:
    return aliases(root).get(path, path)


def index_path(board: str, root: Path = ROOT) -> Path:
    path = root / "kb" / "catalog" / f"{board}.json"
    return path if path.is_file() else root / "kb" / board / "techniques" / "kb-index.json"


def technique_dirs(board: str, root: Path = ROOT) -> list[Path]:
    paths = [root / "kb" / layer / board / "techniques" for layer in LAYERS]
    paths.append(root / "kb" / board / "techniques")
    return [path for path in paths if path.is_dir()]


def resolve_file(filename: str, board: str, root: Path = ROOT) -> Path:
    candidate = root / filename if filename.startswith("kb/") else root / "kb" / board / "techniques" / filename
    normalized = candidate.resolve().relative_to(root.resolve()).as_posix()
    return root / canonical_path(normalized, root)


def document_parts(relative: str) -> tuple[str, str, str] | None:
    """Return board, technique-relative path and track for either path format."""
    parts = relative.split("/")
    if len(parts) >= 5 and parts[0] == "kb" and parts[1] in LAYERS and parts[3] == "techniques":
        return parts[2], "/".join(parts[4:]), "both" if parts[1] == "shared" else parts[1]
    if len(parts) >= 4 and parts[0] == "kb" and parts[2] == "techniques":
        return parts[1], "/".join(parts[3:]), ""
    return None
