from __future__ import annotations

import hashlib
import json
import subprocess
import uuid
from typing import Any

from ..config import GHIDRA_EXPORTS_DIR, GHIDRA_HEADLESS_BAT, GHIDRA_PROJECTS_DIR, GHIDRA_SCRIPT_DIR
from ..paths import check_tool, resolve_file
from ..runner import run
from ..utils import read_text, slug


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def ghidra_headless_analyze(
    path: str,
    project_name: str = "",
    overwrite: bool = False,
    analysis_timeout_seconds: int = 600,
    process_timeout_seconds: int = 1800,
    function_limit: int = 300,
    string_limit: int = 300,
    import_limit: int = 300,
) -> dict[str, Any]:
    target = resolve_file(path)
    check_tool(GHIDRA_HEADLESS_BAT, GHIDRA_HEADLESS_BAT.name)

    script_path = GHIDRA_SCRIPT_DIR / "ReverseLabExportSummary.java"
    check_tool(script_path, "ReverseLabExportSummary.java")

    sample_slug = slug(target.stem)
    run_id = uuid.uuid4().hex[:12]
    project = slug(project_name) if project_name else f"mcp_{sample_slug}_{run_id}"
    GHIDRA_PROJECTS_DIR.mkdir(parents=True, exist_ok=True)
    GHIDRA_EXPORTS_DIR.mkdir(parents=True, exist_ok=True)

    # Every run owns its output and log paths, so concurrent same-stem analyses cannot
    # accept each other's summary or infer a timeout from another run's log.
    output_json = GHIDRA_EXPORTS_DIR / f"{sample_slug}-{run_id}-ghidra-summary.json"
    headless_log = GHIDRA_EXPORTS_DIR / f"{sample_slug}-{run_id}-headless.log"
    script_log = GHIDRA_EXPORTS_DIR / f"{sample_slug}-{run_id}-script.log"

    target_sha256 = _sha256_file(target)
    args = [
        str(GHIDRA_HEADLESS_BAT),
        str(GHIDRA_PROJECTS_DIR),
        project,
        "-import",
        str(target),
        "-scriptPath",
        str(GHIDRA_SCRIPT_DIR),
        "-log",
        str(headless_log),
        "-scriptlog",
        str(script_log),
        "-analysisTimeoutPerFile",
        str(max(1, analysis_timeout_seconds)),
    ]
    if overwrite:
        args.append("-overwrite")
    args.extend(
        [
            "-postScript",
            "ReverseLabExportSummary.java",
            str(output_json),
            str(max(0, function_limit)),
            str(max(0, string_limit)),
            str(max(0, import_limit)),
            run_id,
            target_sha256,
        ]
    )

    code, stdout, stderr = 0, "", ""
    process_timed_out = False
    try:
        code, stdout, stderr = run(args, timeout=max(1, process_timeout_seconds))
    except subprocess.TimeoutExpired as exc:
        code = -1
        process_timed_out = True
        stdout = exc.stdout.decode("utf-8", errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode("utf-8", errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        stderr += f"\nGhidra exceeded its {process_timeout_seconds} second process deadline."

    summary = None
    if output_json.is_file():
        try:
            candidate = json.loads(output_json.read_text(encoding="utf-8", errors="replace"))
            program = candidate.get("program") if isinstance(candidate, dict) else None
            if (
                isinstance(candidate, dict)
                and candidate.get("run_id") == run_id
                and candidate.get("target_sha256") == target_sha256
                and isinstance(program, dict)
                and isinstance(candidate.get("functions"), list)
                and isinstance(candidate.get("imports"), list)
                and isinstance(candidate.get("strings"), list)
            ):
                summary = candidate
        except (OSError, ValueError):
            summary = None

    headless_log_text = read_text(headless_log)
    script_log_text = read_text(script_log)
    timed_out = process_timed_out or "Analysis timed out" in headless_log_text or "analysis timed out" in stdout
    is_complete = isinstance(summary, dict) and summary.get("analysis_complete") is True and not timed_out
    status = "ok" if code == 0 and is_complete else ("partial" if isinstance(summary, dict) else "error")
    if status == "partial" and isinstance(summary, dict):
        summary["analysis_complete"] = False

    return {
        "tool": "ghidra_analyzeHeadless",
        "backend": "ghidra",
        "run_id": run_id,
        "target_sha256": target_sha256,
        "status": status,
        "returncode": code,
        "target": str(target),
        "project_location": str(GHIDRA_PROJECTS_DIR),
        "project_name": project,
        "summary_path": str(output_json) if isinstance(summary, dict) else "",
        "headless_log_path": str(headless_log),
        "script_log_path": str(script_log),
        "summary": summary,
        "analysis_timed_out": timed_out,
        "stdout": stdout[-12000:],
        "stderr": stderr[-12000:],
        "headless_log_tail": headless_log_text,
        "script_log_tail": script_log_text,
    }
