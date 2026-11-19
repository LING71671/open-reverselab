"""IDA-first routing with an explicit, auditable Ghidra fallback."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from ..config import GHIDRA_HEADLESS_BAT
from ..errors import ToolError
from ..paths import resolve_file
from ..static_config import find_ida_executable
from . import ghidra_headless, ida_headless


def static_backend_status() -> dict[str, Any]:
    ida = find_ida_executable()
    return {
        "default_backend": os.environ.get("REVERSELAB_STATIC_BACKEND", "auto"),
        "auto_order": ["ida", "ghidra"],
        "ida": {"available": bool(ida and ida.is_file()), "executable": str(ida) if ida else "", "probe": "file_exists_only"},
        "ghidra": {"available": GHIDRA_HEADLESS_BAT.is_file(), "executable": str(GHIDRA_HEADLESS_BAT), "probe": "file_exists_only"},
        "note": "Availability does not confirm IDAPython, Hex-Rays, Java or license readiness; run a synthetic smoke test.",
    }


def static_headless_analyze(
    path: str, backend: str = "", project_name: str = "", overwrite: bool = True,
    analysis_timeout_seconds: int = 600, process_timeout_seconds: int = 1800,
    function_limit: int = 300, string_limit: int = 300, import_limit: int = 300,
) -> dict[str, Any]:
    requested = (backend or os.environ.get("REVERSELAB_STATIC_BACKEND", "auto")).strip().lower()
    if requested not in {"auto", "ida", "ghidra"}:
        raise ToolError("backend must be auto, ida or ghidra")
    target = resolve_file(path)  # Invalid input never triggers either backend.
    order = ["ida", "ghidra"] if requested == "auto" else [requested]
    attempts = []
    for selected in order:
        result = {}
        try:
            analyzer = ida_headless.ida_headless_analyze if selected == "ida" else ghidra_headless.ghidra_headless_analyze
            result = analyzer(str(target), project_name, overwrite, analysis_timeout_seconds,
                              process_timeout_seconds, function_limit, string_limit, import_limit)
            if result.get("returncode") != 0 or result.get("analysis_timed_out") or result.get("error") or result.get("status") == "error":
                raise ToolError(str(result.get("error") or result.get("stderr") or f"{selected} failed or timed out"))
            summary_path = Path(str(result.get("summary_path", "")))
            if not summary_path.is_file() or not isinstance(result.get("summary"), dict):
                raise ToolError(f"{selected} did not export a fresh summary")
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            if not isinstance(summary, dict) or not isinstance(summary.get("program"), dict) or any(not isinstance(summary.get(k), list) for k in ["functions", "imports", "strings"]):
                raise ToolError(f"{selected} produced an invalid summary contract")
            attempts.append({"backend": selected, "status": "ok"})
            return {**result, "status": "ok", "backend": selected, "requested_backend": requested,
                    "fallback_used": len(attempts) > 1, "attempts": attempts}
        except Exception as exc:
            evidence = {k: result[k] for k in ["returncode", "summary_path", "headless_log_path", "analysis_timed_out"] if k in result}
            attempts.append({"backend": selected, "status": "error", "error": str(exc), **evidence})
    return {"status": "error", "error": "All selected static-analysis backends failed", "target": str(target),
            "backend": "", "requested_backend": requested, "fallback_used": len(attempts) > 1,
            "summary_path": "", "summary": None, "attempts": attempts}
