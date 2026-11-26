"""IDA-first routing with an explicit, auditable Ghidra fallback."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

from ..config import GHIDRA_HEADLESS_BAT
from ..contracts.envelope import Coverage, fail
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


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _valid_summary(summary: Any, *, run_id: str, target_sha256: str) -> bool:
    if not isinstance(summary, dict) or summary.get("run_id") != run_id:
        return False
    program = summary.get("program")
    if not isinstance(program, dict):
        return False
    actual_sha256 = summary.get("target_sha256") or program.get("sha256")
    if not target_sha256 or actual_sha256 != target_sha256:
        return False
    return all(isinstance(summary.get(key), list) for key in ("functions", "imports", "strings"))


def static_headless_analyze(
    path: str, backend: str = "", project_name: str = "", overwrite: bool = False,
    analysis_timeout_seconds: int = 600, process_timeout_seconds: int = 1800,
    function_limit: int = 300, string_limit: int = 300, import_limit: int = 300,
) -> dict[str, Any]:
    requested = (backend or os.environ.get("REVERSELAB_STATIC_BACKEND", "auto")).strip().lower()
    if requested not in {"auto", "ida", "ghidra"}:
        raise ToolError("backend must be auto, ida or ghidra")
    target = resolve_file(path)  # Invalid input never triggers either backend.
    target_sha256 = _sha256_file(target)
    order = ["ida", "ghidra"] if requested == "auto" else [requested]
    attempts = []
    partial_result: dict[str, Any] | None = None
    for selected in order:
        result = {}
        try:
            analyzer = ida_headless.ida_headless_analyze if selected == "ida" else ghidra_headless.ghidra_headless_analyze
            result = analyzer(str(target), project_name, overwrite, analysis_timeout_seconds,
                              process_timeout_seconds, function_limit, string_limit, import_limit)
            if result.get("error") or result.get("status") == "error":
                raise ToolError(str(result.get("error") or result.get("stderr") or f"{selected} failed"))
            if result.get("returncode") != 0 and result.get("status") != "partial":
                raise ToolError(str(result.get("stderr") or f"{selected} exited {result.get('returncode')}"))
            if result.get("analysis_timed_out") and result.get("status") != "partial":
                raise ToolError(str(result.get("stderr") or f"{selected} timed out"))
            summary_path = Path(str(result.get("summary_path", "")))
            summary = result.get("summary")
            if not summary_path.is_file() or not isinstance(summary, dict):
                raise ToolError(f"{selected} did not export a fresh summary")
            if not _valid_summary(summary, run_id=str(result.get("run_id", "")), target_sha256=target_sha256):
                raise ToolError(f"{selected} returned a summary that does not match this run and target")
            on_disk = json.loads(summary_path.read_text(encoding="utf-8"))
            if not _valid_summary(on_disk, run_id=str(result.get("run_id", "")), target_sha256=target_sha256):
                raise ToolError(f"{selected} published a summary that does not match this run and target")
            if on_disk != summary:
                raise ToolError(f"{selected} returned a different summary than it published")
            status = "partial" if result.get("status") == "partial" or summary.get("analysis_complete") is False else "ok"
            if status == "partial":
                partial_result = {**result, "status": status, "backend": selected, "requested_backend": requested}
                reason = "analysis timed out" if result.get("analysis_timed_out") else "analysis incomplete"
                attempts.append({"backend": selected, "status": status, "error": result.get("stderr") or reason})
                if requested == "auto" and selected != order[-1]:
                    continue
                return {**partial_result, "attempts": attempts, "fallback_used": len(attempts) > 1}
            attempts.append({"backend": selected, "status": status})
            return {**result, "status": status, "backend": selected, "requested_backend": requested,
                    "fallback_used": len(attempts) > 1, "attempts": attempts}
        except Exception as exc:
            evidence = {k: result[k] for k in ["returncode", "summary_path", "headless_log_path", "analysis_timed_out"] if k in result}
            attempts.append({"backend": selected, "status": "error", "error": str(exc), **evidence})
    if partial_result is not None:
        return {**partial_result, "attempts": attempts, "fallback_used": len(attempts) > 1}
    last_attempt = attempts[-1] if attempts else {}
    failure_kind = "missing_engine" if all(
        attempt.get("status") == "error" and any(token in str(attempt.get("error", "")).lower() for token in ("not found", "not installed", "missing", "no such file"))
        for attempt in attempts
    ) else "internal"
    failure = fail(
        "static_headless_analyze",
        kind=failure_kind,
        message="All selected static-analysis backends failed: " + "; ".join(
            f"{attempt.get('backend')}: {attempt.get('error', 'failed')}" for attempt in attempts
        ),
        remedy="Install/configure IDA or Ghidra, or retry after correcting the backend error.",
        retryable=True,
        target={"path": str(target), "format": "binary"},
        findings={"attempts": attempts},
        coverage=Coverage(scope="static analysis", complete=False, reason="all backends failed"),
        metadata={"backend": "", "requested_backend": requested, "fallback_used": len(attempts) > 1, "last_attempt": last_attempt},
    )
    failure.update({"status": "error", "summary_path": "", "summary": None, "attempts": attempts})
    return failure
