from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from ..audit import append_audit, audit_log_path
from ..config import ALLOWED_ROOTS, SAMPLES_DIR, SAMPLE_QUARANTINE_DIR
from ..errors import ToolError
from ..paths import ensure_under, is_relative_to
from ..utils import slug
from .triage import hashes


def _resolve_any_file(path: str) -> Path:
    if not path:
        raise ToolError("file path is required")
    resolved = Path(path).expanduser().resolve(strict=True)
    if not resolved.is_file():
        raise ToolError(f"not a file: {resolved}")
    ensure_under(resolved, ALLOWED_ROOTS, "source file")
    return resolved


def _resolve_sample_path(path: str) -> Path:
    if not path:
        raise ToolError("sample path is required")
    resolved = Path(path).expanduser().resolve(strict=True)
    if not resolved.is_file():
        raise ToolError(f"not a file: {resolved}")
    ensure_under(resolved, [SAMPLES_DIR], "sample path")
    return resolved


def _sample_destination(name: str, subdir: str = "") -> Path:
    parts = [segment for segment in subdir.replace("\\", "/").split("/") if segment.strip()]
    safe_parts = [slug(segment) for segment in parts]
    destination = SAMPLES_DIR.joinpath(*safe_parts, slug(name))
    ensure_under(destination, [SAMPLES_DIR], "sample destination")
    return destination


def _copy_or_move(source: Path, destination: Path, overwrite: bool, move: bool) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        if not overwrite:
            raise ToolError(f"destination already exists: {destination}")
        if destination.is_dir():
            raise ToolError(f"destination must be a file path: {destination}")
        destination.unlink()
    if move:
        shutil.move(str(source), str(destination))
    else:
        shutil.copy2(source, destination)


def import_sample(
    source_path: str,
    destination_name: str = "",
    destination_subdir: str = "",
    overwrite: bool = False,
    move_source: bool = False,
) -> dict[str, Any]:
    source = _resolve_any_file(source_path)
    destination = _sample_destination(destination_name or source.name, destination_subdir)
    if source.resolve() == destination.resolve():
        raise ToolError("source and destination are identical")

    before_hashes = hashes(source)
    _copy_or_move(source, destination, overwrite=overwrite, move=move_source)
    after_hashes = hashes(destination)
    audit_record = append_audit(
        {
            "action": "import_sample",
            "status": "ok",
            "source_path": str(source),
            "destination_path": str(destination),
            "move_source": move_source,
            "overwrite": overwrite,
            "source_hashes": before_hashes,
            "destination_hashes": after_hashes,
        }
    )
    return {
        "operation_id": audit_record["operation_id"],
        "source_path": str(source),
        "destination_path": str(destination),
        "move_source": move_source,
        "overwrite": overwrite,
        "source_hashes": before_hashes,
        "destination_hashes": after_hashes,
        "audit_log": str(audit_log_path()),
    }


def list_samples(limit: int = 200, subdir: str = "") -> dict[str, Any]:
    base = SAMPLES_DIR
    if subdir.strip():
        base = SAMPLES_DIR.joinpath(*[slug(part) for part in subdir.replace("\\", "/").split("/") if part.strip()])
    base.mkdir(parents=True, exist_ok=True)
    ensure_under(base, [SAMPLES_DIR], "samples subdir")

    items = []
    for path in sorted(base.rglob("*"), key=lambda item: item.stat().st_mtime if item.exists() else 0, reverse=True):
        if len(items) >= max(0, limit):
            break
        if path.is_dir():
            continue
        stat = path.stat()
        items.append(
            {
                "path": str(path),
                "relative_path": str(path.relative_to(SAMPLES_DIR)),
                "name": path.name,
                "size": stat.st_size,
                "mtime": stat.st_mtime,
                "sha256": hashes(path)["sha256"],
            }
        )
    return {
        "root": str(base),
        "samples": items,
        "samples_returned": len(items),
    }


def rename_sample(path: str, new_name: str, overwrite: bool = False) -> dict[str, Any]:
    source = _resolve_sample_path(path)
    destination = source.with_name(slug(new_name))
    ensure_under(destination, [SAMPLES_DIR], "renamed sample")
    if source.resolve() == destination.resolve():
        raise ToolError("new_name resolves to the same path")
    _copy_or_move(source, destination, overwrite=overwrite, move=True)
    audit_record = append_audit(
        {
            "action": "rename_sample",
            "status": "ok",
            "source_path": str(source),
            "destination_path": str(destination),
            "overwrite": overwrite,
        }
    )
    return {
        "operation_id": audit_record["operation_id"],
        "source_path": str(source),
        "destination_path": str(destination),
        "overwrite": overwrite,
        "audit_log": str(audit_log_path()),
    }


def copy_sample(path: str, destination_name: str = "", destination_subdir: str = "", overwrite: bool = False) -> dict[str, Any]:
    source = _resolve_sample_path(path)
    destination = _sample_destination(destination_name or source.name, destination_subdir)
    if source.resolve() == destination.resolve():
        raise ToolError("source and destination are identical")
    _copy_or_move(source, destination, overwrite=overwrite, move=False)
    audit_record = append_audit(
        {
            "action": "copy_sample",
            "status": "ok",
            "source_path": str(source),
            "destination_path": str(destination),
            "overwrite": overwrite,
            "source_hashes": hashes(source),
            "destination_hashes": hashes(destination),
        }
    )
    return {
        "operation_id": audit_record["operation_id"],
        "source_path": str(source),
        "destination_path": str(destination),
        "overwrite": overwrite,
        "audit_log": str(audit_log_path()),
    }


def move_sample(path: str, destination_name: str = "", destination_subdir: str = "", overwrite: bool = False) -> dict[str, Any]:
    source = _resolve_sample_path(path)
    destination = _sample_destination(destination_name or source.name, destination_subdir)
    if source.resolve() == destination.resolve():
        raise ToolError("source and destination are identical")
    _copy_or_move(source, destination, overwrite=overwrite, move=True)
    audit_record = append_audit(
        {
            "action": "move_sample",
            "status": "ok",
            "source_path": str(source),
            "destination_path": str(destination),
            "overwrite": overwrite,
        }
    )
    return {
        "operation_id": audit_record["operation_id"],
        "source_path": str(source),
        "destination_path": str(destination),
        "overwrite": overwrite,
        "audit_log": str(audit_log_path()),
    }


def quarantine_sample(path: str, overwrite: bool = False) -> dict[str, Any]:
    source = _resolve_sample_path(path)
    relative_parent = source.parent.relative_to(SAMPLES_DIR)
    destination = (SAMPLE_QUARANTINE_DIR / relative_parent / source.name).resolve()
    ensure_under(destination, [SAMPLES_DIR], "quarantine path")
    _copy_or_move(source, destination, overwrite=overwrite, move=True)
    audit_record = append_audit(
        {
            "action": "quarantine_sample",
            "status": "ok",
            "source_path": str(source),
            "destination_path": str(destination),
            "overwrite": overwrite,
        }
    )
    return {
        "operation_id": audit_record["operation_id"],
        "source_path": str(source),
        "destination_path": str(destination),
        "overwrite": overwrite,
        "audit_log": str(audit_log_path()),
    }


def delete_sample(path: str, dry_run: bool = True) -> dict[str, Any]:
    source = _resolve_sample_path(path)
    if is_relative_to(source, SAMPLE_QUARANTINE_DIR.resolve()):
        target_class = "quarantine_sample"
    else:
        target_class = "sample"
    sha256 = hashes(source)["sha256"]
    if not dry_run:
        source.unlink()
    audit_record = append_audit(
        {
            "action": "delete_sample",
            "status": "dry_run" if dry_run else "ok",
            "source_path": str(source),
            "target_class": target_class,
            "sha256": sha256,
        }
    )
    return {
        "operation_id": audit_record["operation_id"],
        "source_path": str(source),
        "dry_run": dry_run,
        "deleted": not dry_run,
        "target_class": target_class,
        "sha256": sha256,
        "audit_log": str(audit_log_path()),
    }
