from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from ..audit import append_audit, audit_log_path
from ..config import CUTTER_ROOT, PATCHES_DIR
from ..errors import ToolError
from ..paths import check_tool, resolve_file, resolve_patch_output
from ..runner import run
from ..utils import slug
from .triage import hashes


RIZIN_EXE = CUTTER_ROOT / "rizin.exe"
RZ_ASM_EXE = CUTTER_ROOT / "rz-asm.exe"


def _case_output(source: Path, case_name: str, suffix: str = "") -> Path:
    name = slug(case_name) if case_name else f"{slug(source.stem)}_rizin_patch"
    filename = f"{source.stem}{suffix or '.patched'}{source.suffix}"
    return PATCHES_DIR / name / filename


def _copy_to_output(source: Path, output_path: str, case_name: str, overwrite: bool, suffix: str = "") -> Path:
    destination = resolve_patch_output(output_path) if output_path else _case_output(source, case_name, suffix)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() and not overwrite:
        raise ToolError(f"destination already exists: {destination}")
    shutil.copy2(source, destination)
    return destination


def _normalize_hex_bytes(new_bytes_hex: str) -> str:
    compact = "".join(new_bytes_hex.split()).upper()
    if not compact or len(compact) % 2 != 0:
        raise ToolError("new_bytes_hex must contain an even number of hex digits")
    try:
        bytes.fromhex(compact)
    except ValueError as exc:
        raise ToolError(f"invalid hex bytes: {new_bytes_hex}") from exc
    return compact


def _read_old_bytes(path: Path, offset: int, size: int) -> str:
    with path.open("rb") as f:
        f.seek(offset)
        return f.read(size).hex().upper()


def _run_rizin_write(path: Path, offset: int, command: str, timeout: int) -> dict[str, Any]:
    check_tool(RIZIN_EXE, "rizin")
    if offset < 0:
        raise ToolError("offset must be >= 0")
    args = [str(RIZIN_EXE), "-n", "-q", "-w", "-c", f"s {offset}; {command}", str(path)]
    code, stdout, stderr = run(args, timeout=max(5, timeout))
    if code != 0 or "ERROR:" in stderr.upper():
        raise ToolError(f"rizin write failed: returncode={code}; stderr={stderr or stdout}")
    return {
        "args": args,
        "returncode": code,
        "stdout": stdout,
        "stderr": stderr,
    }


def rizin_write_bytes(
    path: str,
    offset: int,
    new_bytes_hex: str,
    output_path: str = "",
    case_name: str = "",
    overwrite: bool = False,
    timeout: int = 30,
) -> dict[str, Any]:
    source = resolve_file(path)
    compact = _normalize_hex_bytes(new_bytes_hex)
    destination = _copy_to_output(source, output_path, case_name or f"{source.stem}_rizin_wx_{offset:x}", overwrite)
    old_bytes_hex = _read_old_bytes(destination, offset, len(compact) // 2)
    run_result = _run_rizin_write(destination, offset, f"wx {compact}", timeout)
    patched_hashes = hashes(destination)
    audit_record = append_audit(
        {
            "action": "rizin_write_bytes",
            "status": "ok",
            "source_path": str(source),
            "destination_path": str(destination),
            "offset": offset,
            "old_bytes_hex": old_bytes_hex,
            "new_bytes_hex": compact,
            "patched_hashes": patched_hashes,
        }
    )
    return {
        "operation_id": audit_record["operation_id"],
        "source_path": str(source),
        "destination_path": str(destination),
        "offset": offset,
        "offset_hex": f"0x{offset:X}",
        "old_bytes_hex": old_bytes_hex,
        "new_bytes_hex": compact,
        "patched_hashes": patched_hashes,
        "rizin": run_result,
        "audit_log": str(audit_log_path()),
    }


def rizin_assemble_bytes(
    assembly: str,
    arch: str = "x86",
    bits: int = 64,
    cpu: str = "",
    syntax: str = "",
) -> dict[str, Any]:
    check_tool(RZ_ASM_EXE, "rz-asm")
    if not assembly.strip():
        raise ToolError("assembly is required")
    args = [str(RZ_ASM_EXE), "-a", arch, "-b", str(bits)]
    if cpu.strip():
        args.extend(["-c", cpu.strip()])
    if syntax.strip():
        args.extend(["-s", syntax.strip()])
    args.append(assembly)
    code, stdout, stderr = run(args, timeout=30)
    if code != 0 or not stdout.strip():
        raise ToolError(f"rz-asm failed: returncode={code}; stderr={stderr or stdout}")
    hex_bytes = "".join(stdout.split()).upper()
    try:
        raw = bytes.fromhex(hex_bytes)
    except ValueError as exc:
        raise ToolError(f"rz-asm returned non-hex output: {stdout}") from exc
    return {
        "arch": arch,
        "bits": bits,
        "cpu": cpu,
        "syntax": syntax,
        "assembly": assembly,
        "hex_bytes": hex_bytes,
        "size": len(raw),
        "args": args,
    }


def rizin_assemble_patch(
    path: str,
    offset: int,
    assembly: str,
    arch: str = "x86",
    bits: int = 64,
    cpu: str = "",
    syntax: str = "",
    output_path: str = "",
    case_name: str = "",
    overwrite: bool = False,
    timeout: int = 30,
) -> dict[str, Any]:
    assembled = rizin_assemble_bytes(assembly=assembly, arch=arch, bits=bits, cpu=cpu, syntax=syntax)
    result = rizin_write_bytes(
        path=path,
        offset=offset,
        new_bytes_hex=assembled["hex_bytes"],
        output_path=output_path,
        case_name=case_name or f"{Path(path).stem}_rizin_asm_{offset:x}",
        overwrite=overwrite,
        timeout=timeout,
    )
    audit_record = append_audit(
        {
            "action": "rizin_assemble_patch",
            "status": "ok",
            "source_path": result["source_path"],
            "destination_path": result["destination_path"],
            "offset": offset,
            "assembly": assembly,
            "arch": arch,
            "bits": bits,
            "cpu": cpu,
            "syntax": syntax,
            "assembled_hex": assembled["hex_bytes"],
            "rizin_write_operation_id": result["operation_id"],
        }
    )
    return {
        **result,
        "operation_id": audit_record["operation_id"],
        "rizin_write_operation_id": result["operation_id"],
        "assembly": assembly,
        "arch": arch,
        "bits": bits,
        "cpu": cpu,
        "syntax": syntax,
        "assembled_hex": assembled["hex_bytes"],
        "assembled_size": assembled["size"],
        "audit_log": str(audit_log_path()),
    }
