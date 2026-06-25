from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from ..audit import append_audit, audit_log_path, read_audit_tail
from ..config import GENERATED_ROOTS, PATCHES_DIR, PROJECTS_DIR, REPORTS_DIR
from ..errors import ToolError
from ..paths import resolve_file, resolve_generated_artifact, resolve_patch_output
from ..pe import address_to_offset
from ..utils import slug
from .triage import hashes


def _hash_or_none(path: Path) -> dict[str, Any] | None:
    if path.exists() and path.is_file():
        return hashes(path)
    return None


def _case_dir(source: Path, case_name: str = "") -> Path:
    source_hash = hashes(source)["sha256"][:12]
    name = slug(case_name) if case_name else f"{slug(source.stem)}_{source_hash}"
    return PATCHES_DIR / name


def _copy_file(source: Path, destination: Path, overwrite: bool) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() and not overwrite:
        raise ToolError(f"destination already exists: {destination}")
    shutil.copy2(source, destination)


def copy_sample_to_patches(path: str, case_name: str = "", output_name: str = "", overwrite: bool = False) -> dict[str, Any]:
    source = resolve_file(path)
    destination_dir = _case_dir(source, case_name)
    destination = destination_dir / (slug(output_name) if output_name else source.name)
    _copy_file(source, destination, overwrite=overwrite)

    source_hashes = hashes(source)
    destination_hashes = hashes(destination)
    audit_record = append_audit(
        {
            "action": "copy_sample_to_patches",
            "status": "ok",
            "source_path": str(source),
            "destination_path": str(destination),
            "source_hashes": source_hashes,
            "destination_hashes": destination_hashes,
            "overwrite": overwrite,
        }
    )
    return {
        "operation_id": audit_record["operation_id"],
        "source_path": str(source),
        "destination_path": str(destination),
        "source_hashes": source_hashes,
        "destination_hashes": destination_hashes,
        "audit_log": str(audit_log_path()),
    }


def patch_bytes(
    path: str,
    offset: int,
    new_bytes_hex: str,
    output_path: str = "",
    case_name: str = "",
    overwrite: bool = False,
) -> dict[str, Any]:
    source = resolve_file(path)
    if offset < 0:
        raise ToolError("offset must be >= 0")

    compact_hex = "".join(new_bytes_hex.split())
    if not compact_hex or len(compact_hex) % 2 != 0:
        raise ToolError("new_bytes_hex must contain an even number of hex digits")
    try:
        new_bytes = bytes.fromhex(compact_hex)
    except ValueError as exc:
        raise ToolError(f"invalid hex bytes: {new_bytes_hex}") from exc

    source_size = source.stat().st_size
    if offset + len(new_bytes) > source_size:
        raise ToolError(f"patch exceeds file size: offset={offset}, length={len(new_bytes)}, size={source_size}")

    if output_path:
        destination = resolve_patch_output(output_path)
    else:
        destination_dir = _case_dir(source, case_name or f"{source.stem}_patch_{offset:x}")
        destination = destination_dir / f"{source.stem}.patched{source.suffix}"

    _copy_file(source, destination, overwrite=overwrite)

    with destination.open("r+b") as f:
        f.seek(offset)
        old_bytes = f.read(len(new_bytes))
        f.seek(offset)
        f.write(new_bytes)

    source_hashes = hashes(source)
    patched_hashes = hashes(destination)
    audit_record = append_audit(
        {
            "action": "patch_bytes",
            "status": "ok",
            "source_path": str(source),
            "destination_path": str(destination),
            "offset": offset,
            "old_bytes_hex": old_bytes.hex().upper(),
            "new_bytes_hex": new_bytes.hex().upper(),
            "source_hashes": source_hashes,
            "patched_hashes": patched_hashes,
            "overwrite": overwrite,
        }
    )
    return {
        "operation_id": audit_record["operation_id"],
        "source_path": str(source),
        "destination_path": str(destination),
        "offset": offset,
        "old_bytes_hex": old_bytes.hex().upper(),
        "new_bytes_hex": new_bytes.hex().upper(),
        "source_hashes": source_hashes,
        "patched_hashes": patched_hashes,
        "audit_log": str(audit_log_path()),
    }


def _parse_pattern(pattern: str) -> tuple[list[int], list[bool]]:
    tokens = pattern.replace(",", " ").split()
    if not tokens:
        raise ToolError("pattern is required")
    values = []
    masks = []
    for token in tokens:
        if token in ("?", "??", "**"):
            values.append(0)
            masks.append(False)
            continue
        if len(token) != 2:
            raise ToolError(f"invalid pattern token: {token}")
        try:
            values.append(int(token, 16))
        except ValueError as exc:
            raise ToolError(f"invalid pattern token: {token}") from exc
        masks.append(True)
    return values, masks


def _parse_hex_bytes(hex_text: str) -> bytes:
    compact_hex = "".join(hex_text.split())
    if not compact_hex or len(compact_hex) % 2 != 0:
        raise ToolError("hex bytes must contain an even number of hex digits")
    try:
        return bytes.fromhex(compact_hex)
    except ValueError as exc:
        raise ToolError(f"invalid hex bytes: {hex_text}") from exc


def _pattern_matches(data: bytes, start: int, values: list[int], masks: list[bool]) -> bool:
    for index, expected in enumerate(values):
        if masks[index] and data[start + index] != expected:
            return False
    return True


def search_pattern(path: str, pattern: str, start_offset: int = 0, max_matches: int = 50) -> dict[str, Any]:
    source = resolve_file(path)
    if start_offset < 0:
        raise ToolError("start_offset must be >= 0")
    values, masks = _parse_pattern(pattern)
    pattern_len = len(values)

    data = source.read_bytes()
    matches = []
    end = len(data) - pattern_len
    if end < start_offset:
        end = start_offset - 1
    for offset in range(start_offset, end + 1):
        if _pattern_matches(data, offset, values, masks):
            matches.append(
                {
                    "offset": offset,
                    "offset_hex": f"0x{offset:X}",
                    "matched_bytes_hex": data[offset:offset + pattern_len].hex().upper(),
                }
            )
            if len(matches) >= max(0, max_matches):
                break

    return {
        "path": str(source),
        "pattern": pattern,
        "pattern_length": pattern_len,
        "start_offset": start_offset,
        "matches": matches,
        "matches_returned": len(matches),
    }


def patch_pattern(
    path: str,
    pattern: str,
    new_bytes_hex: str,
    occurrence: int = 0,
    require_unique: bool = False,
    start_offset: int = 0,
    output_path: str = "",
    case_name: str = "",
    overwrite: bool = False,
) -> dict[str, Any]:
    source = resolve_file(path)
    values, _ = _parse_pattern(pattern)
    new_bytes = _parse_hex_bytes(new_bytes_hex)
    if len(new_bytes) != len(values):
        raise ToolError(f"new bytes length ({len(new_bytes)}) must equal pattern length ({len(values)})")
    if occurrence < 0:
        raise ToolError("occurrence must be >= 0")

    matches_result = search_pattern(str(source), pattern, start_offset=start_offset, max_matches=occurrence + 2 if require_unique else occurrence + 1)
    matches = matches_result["matches"]
    if require_unique:
        all_matches = search_pattern(str(source), pattern, start_offset=start_offset, max_matches=2)["matches"]
        if len(all_matches) != 1:
            raise ToolError(f"require_unique=True expected exactly 1 match, got {len(all_matches)}")
        match = all_matches[0]
    else:
        if len(matches) <= occurrence:
            raise ToolError(f"pattern occurrence not found: occurrence={occurrence}, matches={len(matches)}")
        match = matches[occurrence]

    result = patch_bytes(
        str(source),
        offset=match["offset"],
        new_bytes_hex=new_bytes_hex,
        output_path=output_path,
        case_name=case_name or f"{source.stem}_pattern_{match['offset']:x}",
        overwrite=overwrite,
    )
    if "error" in result:
        return result

    audit_record = append_audit(
        {
            "action": "patch_pattern",
            "status": "ok",
            "source_path": str(source),
            "destination_path": result.get("destination_path"),
            "pattern": pattern,
            "occurrence": occurrence,
            "require_unique": require_unique,
            "offset": match["offset"],
            "matched_bytes_hex": match["matched_bytes_hex"],
            "old_bytes_hex": result.get("old_bytes_hex"),
            "new_bytes_hex": result.get("new_bytes_hex"),
            "patch_bytes_operation_id": result.get("operation_id"),
        }
    )
    return {
        **result,
        "operation_id": audit_record["operation_id"],
        "patch_bytes_operation_id": result.get("operation_id"),
        "pattern": pattern,
        "occurrence": occurrence,
        "require_unique": require_unique,
        "offset": match["offset"],
        "offset_hex": match["offset_hex"],
        "matched_bytes_hex": match["matched_bytes_hex"],
        "audit_log": str(audit_log_path()),
    }


def pe_address_to_offset(path: str, address: int | str, address_type: str = "auto") -> dict[str, Any]:
    source = resolve_file(path)
    mapping = address_to_offset(source, address, address_type)
    return {
        "path": str(source),
        **mapping,
        "file_offset_hex": f"0x{mapping['file_offset']:X}",
        "rva_hex": f"0x{mapping['rva']:X}" if "rva" in mapping else "",
        "image_base_hex": f"0x{mapping['image_base']:X}",
    }


def patch_pe_bytes(
    path: str,
    address: int | str,
    new_bytes_hex: str,
    address_type: str = "auto",
    output_path: str = "",
    case_name: str = "",
    overwrite: bool = False,
) -> dict[str, Any]:
    source = resolve_file(path)
    mapping = address_to_offset(source, address, address_type)
    result = patch_bytes(
        str(source),
        offset=mapping["file_offset"],
        new_bytes_hex=new_bytes_hex,
        output_path=output_path,
        case_name=case_name or f"{source.stem}_{mapping['address_type']}_{mapping['address']:x}",
        overwrite=overwrite,
    )
    if "error" in result:
        return result

    audit_record = append_audit(
        {
            "action": "patch_pe_bytes",
            "status": "ok",
            "source_path": str(source),
            "destination_path": result.get("destination_path"),
            "address": mapping["address"],
            "address_type": mapping["address_type"],
            "rva": mapping.get("rva"),
            "file_offset": mapping["file_offset"],
            "section": mapping.get("section", ""),
            "new_bytes_hex": result.get("new_bytes_hex"),
            "old_bytes_hex": result.get("old_bytes_hex"),
            "patch_bytes_operation_id": result.get("operation_id"),
        }
    )
    return {
        **result,
        "operation_id": audit_record["operation_id"],
        "patch_bytes_operation_id": result.get("operation_id"),
        "address": mapping["address"],
        "address_type": mapping["address_type"],
        "address_hex": f"0x{mapping['address']:X}",
        "rva": mapping.get("rva"),
        "rva_hex": f"0x{mapping['rva']:X}" if "rva" in mapping else "",
        "file_offset": mapping["file_offset"],
        "file_offset_hex": f"0x{mapping['file_offset']:X}",
        "section": mapping.get("section", ""),
        "image_base": mapping["image_base"],
        "image_base_hex": f"0x{mapping['image_base']:X}",
        "audit_log": str(audit_log_path()),
    }


def list_generated_artifacts(root: str = "patches", limit: int = 100) -> dict[str, Any]:
    root_map = {
        "exports": GENERATED_ROOTS[0],
        "patches": PATCHES_DIR,
        "projects": PROJECTS_DIR,
        "reports": REPORTS_DIR,
    }
    base = root_map.get(root.lower())
    if base is None:
        raise ToolError(f"unknown root: {root}; expected one of: {', '.join(root_map)}")
    base.mkdir(parents=True, exist_ok=True)

    items = []
    for path in sorted(base.rglob("*"), key=lambda item: item.stat().st_mtime if item.exists() else 0, reverse=True):
        if len(items) >= max(0, limit):
            break
        stat = path.stat()
        items.append(
            {
                "path": str(path),
                "name": path.name,
                "type": "directory" if path.is_dir() else "file",
                "size": stat.st_size if path.is_file() else None,
                "mtime": stat.st_mtime,
            }
        )
    return {
        "root": str(base),
        "artifacts": items,
        "artifacts_returned": len(items),
    }


def delete_generated_artifact(path: str, dry_run: bool = True) -> dict[str, Any]:
    target = resolve_generated_artifact(path)
    before_hashes = _hash_or_none(target)
    target_type = "directory" if target.is_dir() else "file"

    if not dry_run:
        if target.is_dir():
            shutil.rmtree(target)
        else:
            target.unlink()

    audit_record = append_audit(
        {
            "action": "delete_generated_artifact",
            "status": "dry_run" if dry_run else "ok",
            "target_path": str(target),
            "target_type": target_type,
            "before_hashes": before_hashes,
        }
    )
    return {
        "operation_id": audit_record["operation_id"],
        "target_path": str(target),
        "target_type": target_type,
        "dry_run": dry_run,
        "deleted": not dry_run,
        "before_hashes": before_hashes,
        "audit_log": str(audit_log_path()),
    }


def audit_tail(limit: int = 50) -> dict[str, Any]:
    return read_audit_tail(limit)
