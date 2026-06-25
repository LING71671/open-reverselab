from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from ..audit import append_audit, audit_log_path
from ..config import EXPORTS_ROOT, NOTES_DIR, PATCHES_DIR, PROJECTS_DIR, REPORTS_DIR, SCRIPTS_DIR
from ..errors import ToolError
from ..paths import ensure_under
from ..utils import read_text


TEXT_ROOTS = [
    NOTES_DIR,
    REPORTS_DIR,
    SCRIPTS_DIR,
    EXPORTS_ROOT,
]

ARTIFACT_ROOTS = [
    NOTES_DIR,
    REPORTS_DIR,
    SCRIPTS_DIR,
    EXPORTS_ROOT,
    PATCHES_DIR,
    PROJECTS_DIR,
]

TEXT_EXTENSIONS = {
    ".cmd",
    ".csv",
    ".java",
    ".json",
    ".md",
    ".ps1",
    ".py",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
    ".yar",
}


def _resolve_text_target(path: str, must_exist: bool = False) -> Path:
    if not path:
        raise ToolError("path is required")
    resolved = Path(path).expanduser().resolve(strict=must_exist)
    ensure_under(resolved, TEXT_ROOTS, "workspace text path")
    if resolved.suffix.lower() not in TEXT_EXTENSIONS:
        allowed = ", ".join(sorted(TEXT_EXTENSIONS))
        raise ToolError(f"unsupported text extension: {resolved.suffix}; allowed: {allowed}")
    if must_exist and not resolved.is_file():
        raise ToolError(f"not a file: {resolved}")
    return resolved


def _resolve_artifact_target(path: str, must_exist: bool = False) -> Path:
    if not path:
        raise ToolError("path is required")
    resolved = Path(path).expanduser().resolve(strict=must_exist)
    ensure_under(resolved, ARTIFACT_ROOTS, "workspace artifact path")
    if must_exist and not resolved.exists():
        raise ToolError(f"path does not exist: {resolved}")
    return resolved


def workspace_read_text(path: str, max_chars: int = 12000) -> dict[str, Any]:
    target = _resolve_text_target(path, must_exist=True)
    stat = target.stat()
    return {
        "path": str(target),
        "size": stat.st_size,
        "mtime": stat.st_mtime,
        "content": read_text(target, max_chars=max(1, max_chars)),
        "truncated": stat.st_size > max(1, max_chars),
    }


def workspace_write_text(
    path: str,
    content: str,
    mode: str = "replace",
    create_dirs: bool = True,
    overwrite: bool = True,
) -> dict[str, Any]:
    target = _resolve_text_target(path, must_exist=False)
    normalized_mode = mode.strip().lower()
    if normalized_mode not in {"replace", "append", "prepend"}:
        raise ToolError("mode must be one of: replace, append, prepend")

    existed_before = target.exists()
    if existed_before and not target.is_file():
        raise ToolError(f"target exists and is not a file: {target}")
    if existed_before and not overwrite and normalized_mode == "replace":
        raise ToolError(f"target already exists and overwrite=False: {target}")

    if create_dirs:
        target.parent.mkdir(parents=True, exist_ok=True)
    elif not target.parent.exists():
        raise ToolError(f"parent directory does not exist: {target.parent}")

    before_content = target.read_text(encoding="utf-8", errors="replace") if existed_before else ""
    if normalized_mode == "replace":
        final_content = content
    elif normalized_mode == "append":
        final_content = before_content + content
    else:
        final_content = content + before_content

    target.write_text(final_content, encoding="utf-8")
    stat = target.stat()
    audit_record = append_audit(
        {
            "action": "workspace_write_text",
            "status": "ok",
            "path": str(target),
            "mode": normalized_mode,
            "existed_before": existed_before,
            "size_before": len(before_content.encode("utf-8")),
            "size_after": stat.st_size,
        }
    )
    return {
        "operation_id": audit_record["operation_id"],
        "path": str(target),
        "mode": normalized_mode,
        "existed_before": existed_before,
        "size_after": stat.st_size,
        "audit_log": str(audit_log_path()),
    }


def workspace_copy_artifact(path: str, destination_path: str, overwrite: bool = False) -> dict[str, Any]:
    source = _resolve_artifact_target(path, must_exist=True)
    destination = _resolve_artifact_target(destination_path, must_exist=False)
    if destination.exists() and not overwrite:
        raise ToolError(f"destination already exists: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)

    if source.is_dir():
        if destination.exists() and overwrite:
            shutil.rmtree(destination)
        shutil.copytree(source, destination)
        kind = "directory"
    else:
        shutil.copy2(source, destination)
        kind = "file"

    audit_record = append_audit(
        {
            "action": "workspace_copy_artifact",
            "status": "ok",
            "source_path": str(source),
            "destination_path": str(destination),
            "kind": kind,
            "overwrite": overwrite,
        }
    )
    return {
        "operation_id": audit_record["operation_id"],
        "source_path": str(source),
        "destination_path": str(destination),
        "kind": kind,
        "audit_log": str(audit_log_path()),
    }


def workspace_move_artifact(path: str, destination_path: str, overwrite: bool = False) -> dict[str, Any]:
    source = _resolve_artifact_target(path, must_exist=True)
    destination = _resolve_artifact_target(destination_path, must_exist=False)
    if destination.exists():
        if not overwrite:
            raise ToolError(f"destination already exists: {destination}")
        if destination.is_dir():
            shutil.rmtree(destination)
        else:
            destination.unlink()
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(source), str(destination))
    kind = "directory" if destination.is_dir() else "file"

    audit_record = append_audit(
        {
            "action": "workspace_move_artifact",
            "status": "ok",
            "source_path": str(source),
            "destination_path": str(destination),
            "kind": kind,
            "overwrite": overwrite,
        }
    )
    return {
        "operation_id": audit_record["operation_id"],
        "source_path": str(source),
        "destination_path": str(destination),
        "kind": kind,
        "audit_log": str(audit_log_path()),
    }


def workspace_delete_artifact(path: str, dry_run: bool = True) -> dict[str, Any]:
    target = _resolve_artifact_target(path, must_exist=True)
    kind = "directory" if target.is_dir() else "file"
    if not dry_run:
        if target.is_dir():
            shutil.rmtree(target)
        else:
            target.unlink()

    audit_record = append_audit(
        {
            "action": "workspace_delete_artifact",
            "status": "dry_run" if dry_run else "ok",
            "target_path": str(target),
            "kind": kind,
        }
    )
    return {
        "operation_id": audit_record["operation_id"],
        "target_path": str(target),
        "kind": kind,
        "dry_run": dry_run,
        "deleted": not dry_run,
        "audit_log": str(audit_log_path()),
    }
