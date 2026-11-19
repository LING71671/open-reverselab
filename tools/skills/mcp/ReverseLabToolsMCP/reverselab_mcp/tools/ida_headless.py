"""Run IDAPython in a private per-run database, never in the sample directory."""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import uuid
from typing import Any

from ..errors import ToolError
from ..paths import resolve_file
from ..runner import run
from ..static_config import IDA_EXPORTS_DIR, IDA_PROJECTS_DIR, IDA_SCRIPT, find_ida_executable
from ..utils import slug, read_text


def ida_headless_analyze(
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
    executable = find_ida_executable()
    if executable is None or not executable.is_file():
        raise ToolError("IDA Pro not found; set REVERSELAB_IDA_EXE to idat/ida, or set IDA_HOME. auto mode can use Ghidra instead.")
    if not IDA_SCRIPT.is_file():
        raise ToolError(f"IDA summary exporter missing: {IDA_SCRIPT}")
    # Both overwrite values preserve old databases: each invocation is isolated.
    run_id = uuid.uuid4().hex[:12]
    name = slug(project_name or target.stem) or "sample"
    project = IDA_PROJECTS_DIR / f"{name}-{run_id}"
    project.mkdir(parents=True, exist_ok=False)
    IDA_EXPORTS_DIR.mkdir(parents=True, exist_ok=True)
    staged_input = project / "input" / target.name
    staged_input.parent.mkdir()
    shutil.copy2(target, staged_input)
    output = IDA_EXPORTS_DIR / f"{name}-{run_id}-ida-summary.json"
    log = IDA_EXPORTS_DIR / f"{name}-{run_id}-ida.log"
    database = project / "analysis.i64"
    options = project / "export-options.json"
    digest = hashlib.sha256()
    with staged_input.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    options.write_text(json.dumps({
        "target": str(target), "sha256": digest.hexdigest(), "output": str(output),
        "run_id": run_id, "function_limit": max(0, function_limit),
        "string_limit": max(0, string_limit), "import_limit": max(0, import_limit),
    }, ensure_ascii=False), encoding="utf-8")
    args = [str(executable), "-A", "-c", f"-o{database}", f"-L{log}",
            f'-S"{IDA_SCRIPT}" "{options}"', str(staged_input)]
    timed_out = False
    try:
        code, stdout, stderr = run(args, timeout=min(max(1, process_timeout_seconds), max(1, analysis_timeout_seconds)))
    except subprocess.TimeoutExpired:
        code, stdout, stderr, timed_out = -1, "", "IDA analysis exceeded the configured timeout", True
    summary = None
    if output.is_file():
        try:
            summary = json.loads(output.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            stderr += f"\nInvalid IDA summary: {exc}"
    error_output = output.with_suffix(".error.json")
    if summary is None and error_output.is_file():
        try:
            stderr += "\n" + str(json.loads(error_output.read_text(encoding="utf-8")).get("error", "IDA export failed"))
        except (OSError, ValueError):
            stderr += "\nIDA export failed; inspect the headless log"
    valid = isinstance(summary, dict) and summary.get("run_id") == run_id and not summary.get("error")
    result = {
        "tool": "ida_headless", "backend": "ida", "returncode": code,
        "target": str(target), "project_location": str(project), "project_name": project.name,
        "database_path": str(database), "summary_path": str(output), "summary": summary,
        "headless_log_path": str(log), "analysis_timed_out": timed_out,
        "stdout": stdout[-12000:], "stderr": stderr[-12000:], "headless_log_tail": read_text(log),
        "status": "ok" if code == 0 and valid and not timed_out else "error",
    }
    if result["status"] == "error":
        result["error"] = (summary.get("error") if isinstance(summary, dict) else None) or stderr or "IDA did not produce a fresh summary"
    return result
