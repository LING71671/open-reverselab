"""Native .NET (PE/CLI) tools.

`dotnet_metadata` is dependency-free: it walks the PE headers, the COM descriptor data directory,
and the CLI metadata root. `dotnet_list_types` / `dotnet_decompile_type` shell out to `ilspycmd`
when available.
"""

from __future__ import annotations

import os
import shutil
import struct
from pathlib import Path
from typing import Any

from ..contracts.envelope import Coverage, fail, ok
from ..errors import ToolError
from ..paths import resolve_file
from ..runner import run

_MAX_READ = 64 * 1024 * 1024
_BSJB = b"BSJB"


def _u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _u64(data: bytes, offset: int) -> int:
    return struct.unpack_from("<Q", data, offset)[0]


def _layout(data: bytes) -> dict[str, Any]:
    if len(data) < 0x100 or data[:2] != b"MZ":
        raise ToolError("not a PE/MZ file")
    pe_offset = _u32(data, 0x3C)
    if pe_offset + 0x108 > len(data) or data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
        raise ToolError("invalid PE signature")
    file_header = pe_offset + 4
    section_count = _u16(data, file_header + 2)
    optional_size = _u16(data, file_header + 16)
    optional = file_header + 20
    magic = _u16(data, optional)
    if magic == 0x10B:
        bits = 32
        directories = optional + 96
    elif magic == 0x20B:
        bits = 64
        directories = optional + 112
    else:
        raise ToolError(f"unsupported PE optional header magic 0x{magic:X}")

    sections = []
    table = optional + optional_size
    for index in range(section_count):
        entry = table + index * 40
        if entry + 40 > len(data):
            raise ToolError("section table exceeds readable range")
        sections.append(
            {
                "name": data[entry:entry + 8].split(b"\x00", 1)[0].decode("latin-1"),
                "virtual_size": _u32(data, entry + 8),
                "virtual_address": _u32(data, entry + 12),
                "raw_size": _u32(data, entry + 16),
                "raw_pointer": _u32(data, entry + 20),
            }
        )
    return {"bits": bits, "directories": directories, "sections": sections}


def _rva_to_offset(layout: dict[str, Any], rva: int) -> int | None:
    for section in layout["sections"]:
        start = section["virtual_address"]
        span = max(section["virtual_size"], section["raw_size"])
        if start <= rva < start + span:
            delta = rva - start
            if delta >= section["raw_size"]:
                return None
            return section["raw_pointer"] + delta
    return None


def _read(path: Path) -> bytes:
    size = path.stat().st_size
    with path.open("rb") as handle:
        return handle.read(min(size, _MAX_READ))


def _ilspycmd() -> str | None:
    explicit = os.environ.get("ILSPYCMD_COMMAND")
    if explicit:
        return explicit
    return shutil.which("ilspycmd") or shutil.which("ilspycmd.exe")


def dotnet_metadata(path: str) -> dict[str, Any]:
    """Report whether a PE is a managed assembly and read its CLI metadata header."""

    try:
        target = resolve_file(path)
        data = _read(target)
        layout = _layout(data)
    except (ToolError, OSError, struct.error) as exc:
        return fail("dotnet_metadata", kind="invalid_argument", message=str(exc))

    cli_rva = _u32(data, layout["directories"] + 14 * 8)
    cli_size = _u32(data, layout["directories"] + 14 * 8 + 4)
    if not cli_rva or not cli_size:
        return ok(
            "dotnet_metadata",
            target={"path": str(target), "format": "pe"},
            findings={"is_managed": False, "reason": "COM descriptor directory is empty"},
            coverage=Coverage(scope="cli header", complete=True),
        )

    cli_offset = _rva_to_offset(layout, cli_rva)
    if cli_offset is None or cli_offset + 0x48 > len(data):
        return fail(
            "dotnet_metadata",
            kind="unsupported",
            message="CLI header points outside the readable image",
        )
    cli_magic = _u32(data, cli_offset)
    entry_value = _u32(data, cli_offset + 20)
    metadata_rva = _u32(data, cli_offset + 8)
    metadata_size = _u32(data, cli_offset + 12)
    metadata_offset = _rva_to_offset(layout, metadata_rva)
    if metadata_offset is None or metadata_offset + 16 > len(data):
        return fail("dotnet_metadata", kind="unsupported", message="metadata root is outside the image")

    signature = data[metadata_offset:metadata_offset + 4]
    version = ""
    if signature == _BSJB:
        version_length = _u32(data, metadata_offset + 12)
        if 0 < version_length <= 256 and metadata_offset + 16 + version_length <= len(data):
            version = data[metadata_offset + 16:metadata_offset + 16 + version_length].split(b"\x00", 1)[0].decode(
                "latin-1", errors="replace"
            )

    return ok(
        "dotnet_metadata",
        target={"path": str(target), "format": "pe"},
        findings={
            "is_managed": signature == _BSJB,
            "cli_header": {
                "magic": hex(cli_magic),
                "metadata_rva": hex(metadata_rva),
                "metadata_size": metadata_size,
                "entry_point_token": hex(entry_value),
            },
            "metadata_root": {
                "signature": signature.decode("latin-1"),
                "runtime_version": version,
            },
            "bits": layout["bits"],
            "sections": [section["name"] for section in layout["sections"]],
        },
        coverage=Coverage(scope="cli metadata header", complete=True),
    )


def _run_ilspy(arguments: list[str], operation: str, target: Path) -> dict[str, Any]:
    ilspy = _ilspycmd()
    if not ilspy:
        return fail(
            operation,
            kind="missing_engine",
            message="ilspycmd was not found.",
            remedy="Install it with `dotnet tool install -g ilspycmd`, or set ILSPYCMD_COMMAND.",
        )
    try:
        code, out, err = run([ilspy, *arguments], timeout=300)
    except (OSError, RuntimeError, ValueError) as exc:
        return fail(operation, kind="internal", message=f"ilspycmd failed to start: {exc}", retryable=True)
    if code != 0:
        return fail(
            operation,
            kind="unsupported",
            message=f"ilspycmd exited {code}: {(err or out).strip()[:500]}",
            remedy="Check the assembly and type name.",
        )
    return ok(
        operation,
        target={"path": str(target), "format": "dotnet"},
        findings={"output": out[:200_000], "truncated": len(out) > 200_000},
        coverage=Coverage(scope="assembly", complete=True),
        metadata={"ilspycmd": ilspy},
    )


def dotnet_list_types(path: str, kind: str = "classes") -> dict[str, Any]:
    """List declared types in a managed assembly (`classes`, `interfaces`, `structs`, `enums`)."""

    try:
        target = resolve_file(path)
    except (ToolError, OSError) as exc:
        return fail("dotnet_list_types", kind="invalid_argument", message=str(exc))
    mapping = {
        "classes": "c",
        "interfaces": "i",
        "structs": "s",
        "enums": "e",
        "delegates": "d",
    }
    key = (kind or "classes").strip().lower()
    if key not in mapping:
        return fail(
            "dotnet_list_types",
            kind="invalid_argument",
            message=f"kind must be one of: {', '.join(mapping)}",
        )
    return _run_ilspy(["-l", mapping[key], str(target)], "dotnet_list_types", target)


def dotnet_decompile_type(path: str, type_name: str) -> dict[str, Any]:
    """Decompile one type from a managed assembly to C# source."""

    if not type_name.strip():
        return fail("dotnet_decompile_type", kind="invalid_argument", message="type_name is required")
    try:
        target = resolve_file(path)
    except (ToolError, OSError) as exc:
        return fail("dotnet_decompile_type", kind="invalid_argument", message=str(exc))
    return _run_ilspy(["-t", type_name.strip(), str(target)], "dotnet_decompile_type", target)
