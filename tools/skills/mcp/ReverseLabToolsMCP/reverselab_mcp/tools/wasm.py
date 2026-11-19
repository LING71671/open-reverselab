"""Native WebAssembly inspection using WABT when it is installed.

This wrapper answers basic WASM questions through WABT and returns a structured
`missing_engine` envelope when the tool is absent. WABT is optional.
"""

from __future__ import annotations

import os
import shutil
from typing import Any

from ..contracts.envelope import Coverage, component_failure, fail, ok
from ..errors import ToolError
from ..paths import resolve_file
from ..runner import run_component


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
    components = []
    if objdump:
        components.append("objdump")
        out, failure = run_component([objdump, "-x", str(target)], timeout=120)
        findings["objdump"] = failure or {"exit": 0, "output": out[:200_000]}
    if wat:
        components.append("wat")
        out, failure = run_component([wat, "--enable-all", str(target)], timeout=120)
        limit = max(0, wat_bytes)
        findings["wat"] = failure or {"exit": 0, "preview": out[:limit], "truncated": len(out) > limit}

    descriptor = {"path": str(target), "format": "wasm"}
    failure = component_failure("wasm_info", descriptor, findings, components)
    if failure:
        return failure

    return ok(
        "wasm_info",
        target=descriptor,
        findings=findings,
        coverage=Coverage(scope="module", complete=True),
        metadata={"wabt": {"objdump": objdump, "wasm2wat": wat}},
    )
