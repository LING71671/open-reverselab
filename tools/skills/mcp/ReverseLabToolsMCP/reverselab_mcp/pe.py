from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

from .errors import ToolError


def _u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _u64(data: bytes, offset: int) -> int:
    return struct.unpack_from("<Q", data, offset)[0]


def _parse_int(value: int | str) -> int:
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if not text:
        raise ToolError("address is required")
    return int(text, 16) if text.lower().startswith("0x") else int(text, 0)


def _read_header(path: Path) -> bytes:
    with path.open("rb") as f:
        return f.read(0x10000)


def pe_info(path: Path) -> dict[str, Any]:
    data = _read_header(path)
    if len(data) < 0x100:
        raise ToolError(f"file too small for PE header: {path}")
    if data[:2] != b"MZ":
        raise ToolError(f"not a PE/MZ file: {path}")

    pe_offset = _u32(data, 0x3C)
    if pe_offset + 0x108 > len(data):
        raise ToolError(f"PE header is outside readable header range: {path}")
    if data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
        raise ToolError(f"invalid PE signature at 0x{pe_offset:X}: {path}")

    file_header = pe_offset + 4
    machine = _u16(data, file_header)
    number_of_sections = _u16(data, file_header + 2)
    size_of_optional_header = _u16(data, file_header + 16)
    optional_header = file_header + 20
    magic = _u16(data, optional_header)
    if magic == 0x10B:
        bits = 32
        image_base = _u32(data, optional_header + 28)
    elif magic == 0x20B:
        bits = 64
        image_base = _u64(data, optional_header + 24)
    else:
        raise ToolError(f"unsupported PE optional header magic: 0x{magic:X}")

    section_table = optional_header + size_of_optional_header
    sections = []
    for index in range(number_of_sections):
        entry = section_table + index * 40
        if entry + 40 > len(data):
            raise ToolError("section table exceeds readable header range")
        name = data[entry:entry + 8].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
        virtual_size = _u32(data, entry + 8)
        virtual_address = _u32(data, entry + 12)
        size_of_raw_data = _u32(data, entry + 16)
        pointer_to_raw_data = _u32(data, entry + 20)
        characteristics = _u32(data, entry + 36)
        sections.append(
            {
                "index": index,
                "name": name,
                "virtual_size": virtual_size,
                "virtual_address": virtual_address,
                "size_of_raw_data": size_of_raw_data,
                "pointer_to_raw_data": pointer_to_raw_data,
                "characteristics": characteristics,
            }
        )

    return {
        "path": str(path),
        "pe_offset": pe_offset,
        "machine": machine,
        "bits": bits,
        "image_base": image_base,
        "number_of_sections": number_of_sections,
        "size_of_optional_header": size_of_optional_header,
        "sections": sections,
    }


def rva_to_offset(path: Path, rva: int) -> dict[str, Any]:
    info = pe_info(path)
    if rva < 0:
        raise ToolError("RVA must be >= 0")

    # Header RVAs usually map 1:1 to file offsets before the first section.
    first_section_rva = min((section["virtual_address"] for section in info["sections"]), default=0)
    if rva < first_section_rva:
        return {
            "file_offset": rva,
            "rva": rva,
            "section": "Headers",
            "image_base": info["image_base"],
        }

    for section in info["sections"]:
        start = section["virtual_address"]
        span = max(section["virtual_size"], section["size_of_raw_data"])
        end = start + span
        if start <= rva < end:
            delta = rva - start
            if delta >= section["size_of_raw_data"]:
                raise ToolError(
                    f"RVA 0x{rva:X} is inside virtual tail of section {section['name']} but has no raw file bytes"
                )
            return {
                "file_offset": section["pointer_to_raw_data"] + delta,
                "rva": rva,
                "section": section["name"],
                "image_base": info["image_base"],
            }

    raise ToolError(f"RVA is not mapped to file bytes: 0x{rva:X}")


def address_to_offset(path: Path, address: int | str, address_type: str = "auto") -> dict[str, Any]:
    parsed = _parse_int(address)
    kind = address_type.lower().strip()
    info = pe_info(path)

    if kind in ("file", "file_offset", "offset", "fo"):
        return {
            "file_offset": parsed,
            "address": parsed,
            "address_type": "file_offset",
            "image_base": info["image_base"],
            "section": "",
        }
    if kind == "rva":
        mapped = rva_to_offset(path, parsed)
        mapped["address"] = parsed
        mapped["address_type"] = "rva"
        return mapped
    if kind == "va":
        if parsed < info["image_base"]:
            raise ToolError(f"VA 0x{parsed:X} is below image base 0x{info['image_base']:X}")
        rva = parsed - info["image_base"]
        mapped = rva_to_offset(path, rva)
        mapped["address"] = parsed
        mapped["address_type"] = "va"
        return mapped
    if kind != "auto":
        raise ToolError("address_type must be one of: auto, file_offset, rva, va")

    if parsed >= info["image_base"]:
        mapped = rva_to_offset(path, parsed - info["image_base"])
        mapped["address"] = parsed
        mapped["address_type"] = "va"
        return mapped

    try:
        mapped = rva_to_offset(path, parsed)
        mapped["address"] = parsed
        mapped["address_type"] = "rva"
        return mapped
    except ToolError:
        return {
            "file_offset": parsed,
            "address": parsed,
            "address_type": "file_offset",
            "image_base": info["image_base"],
            "section": "",
        }
