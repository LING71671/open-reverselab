from __future__ import annotations

import json
from typing import Any

from ..config import GHIDRA_EXPORTS_DIR, GHIDRA_HEADLESS_BAT, GHIDRA_PROJECTS_DIR, GHIDRA_SCRIPT_DIR
from ..paths import check_tool, resolve_file
from ..runner import run
from ..utils import read_text, slug


def ghidra_headless_analyze(
    path: str,
    project_name: str = "",
    overwrite: bool = True,
    analysis_timeout_seconds: int = 600,
    process_timeout_seconds: int = 1800,
    function_limit: int = 300,
    string_limit: int = 300,
    import_limit: int = 300,
) -> dict[str, Any]:
    target = resolve_file(path)
    check_tool(GHIDRA_HEADLESS_BAT, "analyzeHeadless.bat")

    script_path = GHIDRA_SCRIPT_DIR / "ReverseLabExportSummary.java"
    check_tool(script_path, "ReverseLabExportSummary.java")

    sample_slug = slug(target.stem)
    project = slug(project_name) if project_name else f"mcp_{sample_slug}"
    GHIDRA_PROJECTS_DIR.mkdir(parents=True, exist_ok=True)
    GHIDRA_EXPORTS_DIR.mkdir(parents=True, exist_ok=True)

    output_json = GHIDRA_EXPORTS_DIR / f"{sample_slug}-ghidra-summary.json"
    headless_log = GHIDRA_EXPORTS_DIR / f"{sample_slug}-headless.log"
    script_log = GHIDRA_EXPORTS_DIR / f"{sample_slug}-script.log"

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
        ]
    )

    code, stdout, stderr = run(args, timeout=max(1, process_timeout_seconds))

    summary = None
    if output_json.exists():
        summary = json.loads(output_json.read_text(encoding="utf-8", errors="replace"))

    headless_log_text = read_text(headless_log)
    script_log_text = read_text(script_log)

    return {
        "tool": "ghidra_analyzeHeadless",
        "returncode": code,
        "target": str(target),
        "project_location": str(GHIDRA_PROJECTS_DIR),
        "project_name": project,
        "summary_path": str(output_json),
        "headless_log_path": str(headless_log),
        "script_log_path": str(script_log),
        "summary": summary,
        "analysis_timed_out": "Analysis timed out" in headless_log_text or "analysis timed out" in stdout,
        "stdout": stdout[-12000:],
        "stderr": stderr[-12000:],
        "headless_log_tail": headless_log_text,
        "script_log_tail": script_log_text,
    }
