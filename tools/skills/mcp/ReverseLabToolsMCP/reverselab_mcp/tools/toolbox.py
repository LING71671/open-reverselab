from __future__ import annotations

import csv
import shlex
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from ..config import (
    CUTTER_ROOT,
    DIE_ROOT,
    GHIDRA_HEADLESS_BAT,
    GHIDRA_ROOT,
    PE_BEAR_EXE,
    PROCMON_EXPORTS_DIR,
    PROCMON_ROOT,
    RZ_BIN_EXE,
    RZ_HASH_EXE,
    X64DBG_ROOT,
)
from ..errors import ToolError
from ..paths import check_tool, ensure_under, resolve_file
from ..runner import launch, run


@dataclass(frozen=True)
class ToolSpec:
    tool_id: str
    path: Path
    category: str
    kind: str
    launchable: bool
    supports_target: bool = False
    version_args: tuple[str, ...] = ()
    notes: str = ""


TOOLBOX: dict[str, ToolSpec] = {
    "cutter": ToolSpec("cutter", CUTTER_ROOT / "cutter.exe", "disassembler", "gui", True, True, notes="Cutter GUI，可直接打开样本。"),
    "rizin": ToolSpec("rizin", CUTTER_ROOT / "rizin.exe", "disassembler", "cli", False, True, ("-v",), "Rizin interactive CLI；当前只做版本探测。"),
    "rz_asm": ToolSpec("rz_asm", CUTTER_ROOT / "rz-asm.exe", "rizin", "cli", False, False, ("-v",), "Assembler/disassembler helper。"),
    "rz_ax": ToolSpec("rz_ax", CUTTER_ROOT / "rz-ax.exe", "rizin", "cli", False, False, ("-v",), "数字、base、地址换算 helper。"),
    "rz_bin": ToolSpec("rz_bin", RZ_BIN_EXE, "rizin", "cli", False, True, ("-v",), "PE/ELF/Mach-O 结构解析；已有专用 triage wrapper。"),
    "rz_diff": ToolSpec("rz_diff", CUTTER_ROOT / "rz-diff.exe", "rizin", "cli", False, True, ("-v",), "二进制 diff helper，后续可封装 patch diff。"),
    "rz_find": ToolSpec("rz_find", CUTTER_ROOT / "rz-find.exe", "rizin", "cli", False, True, ("-v",), "二进制搜索 helper。"),
    "rz_hash": ToolSpec("rz_hash", RZ_HASH_EXE, "rizin", "cli", False, True, ("-v",), "Rizin hash helper。"),
    "rz_run": ToolSpec("rz_run", CUTTER_ROOT / "rz-run.exe", "rizin", "cli", False, False, ("-v",), "运行配置 helper；默认不用于启动样本。"),
    "rz_sign": ToolSpec("rz_sign", CUTTER_ROOT / "rz-sign.exe", "rizin", "cli", False, False, ("-v",), "signature helper。"),
    "die_gui": ToolSpec("die_gui", DIE_ROOT / "die.exe", "triage", "gui", True, True, notes="Detect It Easy GUI。"),
    "die_cli": ToolSpec("die_cli", DIE_ROOT / "diec.exe", "triage", "cli", False, True, ("-v",), "Detect It Easy CLI；已有 die_scan wrapper。"),
    "diel": ToolSpec("diel", DIE_ROOT / "diel.exe", "triage", "gui", True, True, notes="DiE Lite GUI。"),
    "ghidra_gui": ToolSpec("ghidra_gui", GHIDRA_ROOT / "ghidraRun.bat", "decompiler", "gui", True, False, notes="Ghidra GUI。"),
    "ghidra_headless": ToolSpec("ghidra_headless", GHIDRA_HEADLESS_BAT, "decompiler", "cli", False, True, notes="已有 ghidra_headless_analyze wrapper。"),
    "pe_bear": ToolSpec("pe_bear", PE_BEAR_EXE, "pe", "gui", True, True, notes="PE-bear GUI。"),
    "procmon": ToolSpec("procmon", PROCMON_ROOT / "Procmon.exe", "dynamic", "gui", True, False, notes="Process Monitor GUI。"),
    "procmon64": ToolSpec("procmon64", PROCMON_ROOT / "Procmon64.exe", "dynamic", "gui", True, False, notes="Process Monitor x64；支持 capture start/stop。"),
    "procmon64a": ToolSpec("procmon64a", PROCMON_ROOT / "Procmon64a.exe", "dynamic", "gui", True, False, notes="Process Monitor ARM64。"),
    "x32dbg": ToolSpec("x32dbg", X64DBG_ROOT / "x32" / "x32dbg.exe", "debugger", "gui", True, True, notes="x32dbg GUI。"),
    "x64dbg": ToolSpec("x64dbg", X64DBG_ROOT / "x64" / "x64dbg.exe", "debugger", "gui", True, True, notes="x64dbg GUI。"),
    "x96dbg": ToolSpec("x96dbg", X64DBG_ROOT / "x96dbg.exe", "debugger", "gui", True, True, notes="x96dbg launcher。"),
    "x32dbg_unsigned": ToolSpec("x32dbg_unsigned", X64DBG_ROOT / "x32" / "x32dbg-unsigned.exe", "debugger", "gui", True, True, notes="x32dbg unsigned build。"),
    "x64dbg_unsigned": ToolSpec("x64dbg_unsigned", X64DBG_ROOT / "x64" / "x64dbg-unsigned.exe", "debugger", "gui", True, True, notes="x64dbg unsigned build。"),
}


def _split_extra_args(extra_args: str) -> list[str]:
    if not extra_args.strip():
        return []
    return [arg.strip("\"'") for arg in shlex.split(extra_args, posix=False)]


def _spec(tool_id: str) -> ToolSpec:
    normalized = tool_id.strip().lower()
    if normalized not in TOOLBOX:
        known = ", ".join(sorted(TOOLBOX))
        raise ToolError(f"unknown tool_id: {tool_id}; known tool ids: {known}")
    return TOOLBOX[normalized]


def toolbox_list() -> dict[str, Any]:
    tools: list[dict[str, Any]] = []
    for spec in sorted(TOOLBOX.values(), key=lambda item: (item.category, item.tool_id)):
        tools.append(
            {
                "tool_id": spec.tool_id,
                "path": str(spec.path),
                "exists": spec.path.exists(),
                "category": spec.category,
                "kind": spec.kind,
                "launchable": spec.launchable,
                "supports_target": spec.supports_target,
                "has_version_probe": bool(spec.version_args),
                "notes": spec.notes,
            }
        )
    return {
        "tool_count": len(tools),
        "available_count": sum(1 for item in tools if item["exists"]),
        "tools": tools,
    }


def toolbox_version(tool_id: str, timeout: int = 30) -> dict[str, Any]:
    spec = _spec(tool_id)
    check_tool(spec.path, spec.tool_id)
    if not spec.version_args:
        raise ToolError(f"tool has no safe version probe: {spec.tool_id}")
    code, stdout, stderr = run([str(spec.path), *spec.version_args], timeout=max(1, timeout))
    return {
        "tool_id": spec.tool_id,
        "path": str(spec.path),
        "args": list(spec.version_args),
        "returncode": code,
        "stdout": stdout,
        "stderr": stderr,
    }


def toolbox_launch(tool_id: str, target_path: str = "", extra_args: str = "", visible: bool = True) -> dict[str, Any]:
    spec = _spec(tool_id)
    check_tool(spec.path, spec.tool_id)
    if not spec.launchable:
        raise ToolError(f"tool is not configured for interactive launch: {spec.tool_id}")

    args = [str(spec.path), *_split_extra_args(extra_args)]
    target = ""
    if target_path:
        if not spec.supports_target:
            raise ToolError(f"tool does not support target_path launch: {spec.tool_id}")
        target = str(resolve_file(target_path))
        args.append(target)

    pid = launch(args, visible=visible, cwd=spec.path.parent)
    return {
        "tool_id": spec.tool_id,
        "path": str(spec.path),
        "target_path": target,
        "args": args,
        "pid": pid,
        "visible": visible,
    }


def _procmon_output_path(pml_path: str) -> Path:
    PROCMON_EXPORTS_DIR.mkdir(parents=True, exist_ok=True)
    if pml_path:
        path = Path(pml_path).expanduser().resolve()
        ensure_under(path, [PROCMON_EXPORTS_DIR], "procmon backing file")
        if path.suffix.lower() != ".pml":
            raise ToolError(f"Procmon backing file must use .pml suffix: {path}")
        path.parent.mkdir(parents=True, exist_ok=True)
        return path
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return PROCMON_EXPORTS_DIR / f"procmon-{stamp}.pml"


def _resolve_procmon_log(path: str) -> Path:
    if not path:
        raise ToolError("procmon log path is required")
    resolved = Path(path).expanduser().resolve(strict=True)
    if not resolved.is_file():
        raise ToolError(f"not a file: {resolved}")
    ensure_under(resolved, [PROCMON_EXPORTS_DIR], "procmon log path")
    if resolved.suffix.lower() != ".pml":
        raise ToolError(f"procmon log must use .pml suffix: {resolved}")
    return resolved


def _resolve_procmon_config(path: str) -> Path:
    if not path:
        raise ToolError("procmon config path is required")
    resolved = resolve_file(path)
    if resolved.suffix.lower() not in {".pmc", ".pmf"}:
        raise ToolError(f"procmon config must use .pmc or .pmf suffix: {resolved}")
    return resolved


def _default_procmon_csv_output(source_log: Path) -> Path:
    PROCMON_EXPORTS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return PROCMON_EXPORTS_DIR / f"{source_log.stem}-export-{stamp}.csv"


def _resolve_procmon_csv_output(output_path: str, source_log: Path) -> Path:
    if not output_path:
        return _default_procmon_csv_output(source_log)
    resolved = Path(output_path).expanduser().resolve()
    ensure_under(resolved, [PROCMON_EXPORTS_DIR], "procmon csv output")
    if resolved.suffix.lower() != ".csv":
        raise ToolError(f"procmon csv output must use .csv suffix: {resolved}")
    resolved.parent.mkdir(parents=True, exist_ok=True)
    return resolved


def _procmon_processes() -> list[dict[str, str]]:
    code, stdout, _stderr = run(["tasklist", "/FO", "CSV", "/NH", "/FI", "IMAGENAME eq Procmon64.exe"], timeout=15)
    if code != 0 or not stdout.strip():
        return []
    rows: list[dict[str, str]] = []
    for row in csv.reader(stdout.splitlines()):
        if len(row) < 2:
            continue
        image_name = row[0].strip().strip('"')
        if image_name.lower() != "procmon64.exe":
            continue
        rows.append(
            {
                "image_name": image_name,
                "pid": row[1].strip().strip('"'),
            }
        )
    return rows


def procmon_start_capture(pml_path: str = "", quiet: bool = True) -> dict[str, Any]:
    spec = _spec("procmon64")
    check_tool(spec.path, spec.tool_id)
    output = _procmon_output_path(pml_path)
    args = [str(spec.path), "/AcceptEula", "/BackingFile", str(output)]
    if quiet:
        args.insert(2, "/Quiet")
    pid = launch(args, visible=not quiet, cwd=spec.path.parent)
    return {
        "tool_id": spec.tool_id,
        "path": str(spec.path),
        "backing_file": str(output),
        "args": args,
        "pid": pid,
        "quiet": quiet,
        "note": "Procmon capture 已启动；停止时调用 procmon_stop_capture。若权限不足，Procmon 可能弹出 UAC 或启动失败。",
    }


def procmon_stop_capture(timeout: int = 30) -> dict[str, Any]:
    spec = _spec("procmon64")
    check_tool(spec.path, spec.tool_id)
    args = [str(spec.path), "/Terminate"]
    timed_out = False
    try:
        code, stdout, stderr = run(args, timeout=max(1, timeout))
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        code = None
        stdout = str(exc.stdout or "").strip()
        stderr = str(exc.stderr or "").strip()
    return {
        "tool_id": spec.tool_id,
        "path": str(spec.path),
        "args": args,
        "returncode": code,
        "stdout": stdout,
        "stderr": stderr,
        "timed_out": timed_out,
    }


def procmon_export_csv(
    pml_path: str,
    output_path: str = "",
    load_config_path: str = "",
    apply_filter: bool = False,
    terminate_when_done: bool = True,
    wait_timeout: int = 60,
) -> dict[str, Any]:
    spec = _spec("procmon64")
    check_tool(spec.path, spec.tool_id)

    source_log = _resolve_procmon_log(pml_path)
    output = _resolve_procmon_csv_output(output_path, source_log)
    config = str(_resolve_procmon_config(load_config_path)) if load_config_path else ""

    existing_before = _procmon_processes()
    args = [
        str(spec.path),
        "/AcceptEula",
        "/Quiet",
        "/Minimized",
        "/NoConnect",
        "/OpenLog",
        str(source_log),
    ]
    if config:
        args.extend(["/LoadConfig", config])
    args.extend(["/SaveAs", str(output)])
    if apply_filter:
        args.append("/SaveApplyFilter")

    if output.exists():
        output.unlink()

    timed_out = False
    try:
        code, stdout, stderr = run(args, timeout=max(15, min(max(1, wait_timeout), 120)))
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        code = None
        stdout = str(exc.stdout or "").strip()
        stderr = str(exc.stderr or "").strip()

    deadline = time.time() + max(1, wait_timeout)
    exported = False
    observed_size = 0
    while time.time() < deadline:
        if output.exists():
            observed_size = output.stat().st_size
            exported = True
            break
        time.sleep(0.5)

    auto_terminated = False
    terminate_result: dict[str, Any] | None = None
    force_kill_result: dict[str, Any] | None = None
    existing_after = _procmon_processes()
    if terminate_when_done and not existing_before:
        time.sleep(1.0)
        terminate_result = procmon_stop_capture(timeout=30)
        auto_terminated = terminate_result.get("returncode") == 0
        time.sleep(5.0)
        kill_code, kill_stdout, kill_stderr = run(["taskkill", "/IM", "Procmon64.exe", "/F"], timeout=30)
        force_kill_result = {
            "returncode": kill_code,
            "stdout": kill_stdout,
            "stderr": kill_stderr,
        }
        time.sleep(1.0)
        existing_after = _procmon_processes()

    note = (
        "Procmon CSV export completed."
        if exported
        else "Procmon export command was dispatched, but CSV was not observed before timeout."
    )
    if timed_out:
        note = "Procmon export command timed out before CLI returned."
        if not exported:
            note += " No CSV was observed during the wait window."
    if not exported and not existing_before:
        note += " Procmon may still have required UI interaction or the source log may be invalid."

    return {
        "tool_id": spec.tool_id,
        "path": str(spec.path),
        "pml_path": str(source_log),
        "output_path": str(output),
        "load_config_path": config,
        "apply_filter": apply_filter,
        "args": args,
        "returncode": code,
        "stdout": stdout,
        "stderr": stderr,
        "timed_out": timed_out,
        "exported": exported,
        "output_exists": output.exists(),
        "output_size": output.stat().st_size if output.exists() else observed_size,
        "procmon_instances_before": existing_before,
        "procmon_instances_after": existing_after,
        "auto_terminated": auto_terminated,
        "terminate_when_done": terminate_when_done,
        "terminate_result": terminate_result,
        "force_kill_result": force_kill_result,
        "note": note,
    }
