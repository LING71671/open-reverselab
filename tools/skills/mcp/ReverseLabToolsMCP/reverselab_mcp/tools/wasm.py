"""Native WebAssembly inspection using WABT when it is installed.

This wrapper answers basic WASM questions through WABT and returns a structured
`missing_engine` envelope when the tool is absent. WABT is optional.
"""

from __future__ import annotations

import os
import shutil
from typing import Any

from ..contracts.envelope import Coverage, fail, ok
from ..errors import ToolError
from ..paths import resolve_file
from ..runner import run


def _find(env_name: str, names: list[str]) -> str | None:
    explicit = os.environ.get(env_name)
    if explicit:
        return explicit
    for name in names:
        found = shutil.which(name)
        if found:
            return found
    return None


def wasm_info(path: str, wat_bytes: int = 8192) -> dict[str, Any]:
    """Dump WASM section/code structure and the start of the WAT text form."""

    try:
        target = resolve_file(path)
    except (ToolError, OSError) as exc:
        return fail("wasm_info", kind="invalid_argument", message=str(exc))

    objdump = _find("WASM_OBJDUMP", ["wasm-objdump", "wasm-objdump.exe"])
    wat = _find("WASM2WAT", ["wasm2wat", "wasm2wat.exe"])
    if not objdump and not wat:
        return fail(
            "wasm_info",
            kind="missing_engine",
            message="No WABT tool was found (wasm-objdump / wasm2wat).",
            remedy="Install WABT and put it on PATH, or set WASM_OBJDUMP / WASM2WAT to absolute paths.",
        )

    findings: dict[str, Any] = {"path": str(target)}
    if objdump:
        try:
            code, out, err = run([objdump, "-x", str(target)], timeout=120)
        except (OSError, RuntimeError, ValueError) as exc:
            findings["objdump"] = {"error": str(exc)}
        else:
            findings["objdump"] = {"exit": code, "output": (out or err)[:200_000]}
    if wat:
        try:
            code, out, err = run([wat, "--enable-all", str(target)], timeout=120)
        except (OSError, RuntimeError, ValueError) as exc:
            findings["wat"] = {"error": str(exc)}
        else:
            findings["wat"] = {
                "exit": code,
                "preview": (out or err)[: max(0, wat_bytes)],
                "truncated": len(out or err) > wat_bytes,
            }

    errors = [value.get("error") for value in findings.values() if isinstance(value, dict) and value.get("error")]
    if errors and not any(isinstance(value, dict) and value.get("output") for value in findings.values()):
        return fail(
            "wasm_info",
            kind="internal",
            message="; ".join(str(item) for item in errors)[:500],
            retryable=True,
        )

    return ok(
        "wasm_info",
        target={"path": str(target), "format": "wasm"},
        findings=findings,
        coverage=Coverage(scope="module", complete=True),
        metadata={"wabt": {"objdump": objdump, "wasm2wat": wat}},
    )
