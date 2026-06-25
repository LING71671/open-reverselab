from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from ..config import DEBUG_SCRIPTS_DIR, REPORTS_DIR
from ..paths import resolve_file
from ..utils import slug
from . import (
    analysis_notes,
    crypto_unpack,
    debug_scripts,
    ghidra_headless,
    ghidra_summary,
    ioc_extract,
    procmon_filters,
    sigma_stub,
    triage,
    yara_stub,
)


DEFAULT_DEBUG_PRESETS = "loader,file,registry,network,process,crypto,antidebug,ui"
UNPACKING_APIS = (
    "VirtualAlloc,VirtualAllocEx,VirtualProtect,VirtualProtectEx,"
    "WriteProcessMemory,ReadProcessMemory,CreateRemoteThread,NtCreateThreadEx,"
    "LoadLibraryA,LoadLibraryW,GetProcAddress,CreateFileW,MapViewOfFile"
)
CRYPTO_AUTOPILOT_APIS = tuple(api.lower() for api in crypto_unpack.CRYPTO_APIS + crypto_unpack.CRT_CRYPTO_HINTS)
UNPACK_AUTOPILOT_APIS = tuple(api.lower() for api in crypto_unpack.UNPACK_APIS)


def _safe_step(name: str, func: Callable[..., dict[str, Any]], *args: Any, **kwargs: Any) -> dict[str, Any]:
    try:
        result = func(*args, **kwargs)
        if not isinstance(result, dict):
            return {"status": "ok", "result": result}
        return {"status": "ok", **result}
    except Exception as exc:
        return {"status": "error", "error": str(exc)}


def _artifact_paths(result: dict[str, Any]) -> list[str]:
    paths: list[str] = []
    generated_keys = {
        "output_path",
        "csv_path",
        "json_path",
        "markdown_path",
        "rule_path",
        "yaml_path",
        "manifest_path",
        "battleplan_path",
        "headless_log_path",
        "script_log_path",
    }
    for key, value in result.items():
        if not isinstance(value, str):
            continue
        lowered = key.lower()
        if value and lowered in generated_keys:
            paths.append(value)
    return paths


def _triage_highlights(triage_result: dict[str, Any]) -> dict[str, Any]:
    hashes = triage_result.get("hashes", {}) if isinstance(triage_result.get("hashes"), dict) else {}
    info = (((triage_result.get("rizin_info", {}) or {}).get("stdout", {}) or {}).get("info", {}) or {})
    sections = (((triage_result.get("sections", {}) or {}).get("stdout", {}) or {}).get("sections", []) or [])
    imports = (((triage_result.get("imports", {}) or {}).get("stdout", {}) or {}).get("imports", []) or [])
    strings = (((triage_result.get("strings", {}) or {}).get("stdout", {}) or {}).get("strings", []) or [])
    return {
        "name": hashes.get("name", ""),
        "size": hashes.get("size", ""),
        "md5": hashes.get("md5", ""),
        "sha1": hashes.get("sha1", ""),
        "sha256": hashes.get("sha256", ""),
        "file_type": f"{info.get('bintype', '')}/{info.get('class', '')}".strip("/"),
        "arch": f"{info.get('arch', '')} {info.get('bits', '')}".strip(),
        "entry": info.get("entry", ""),
        "subsystem": info.get("subsys", ""),
        "section_count": len(sections),
        "import_count": len(imports),
        "string_count": len(strings),
    }


def _summary_path_from_step(step: dict[str, Any], fallback: str) -> str:
    if step.get("status") != "ok":
        return fallback
    value = str(step.get("summary_path", "")).strip()
    return value or fallback


def _write_battleplan_report(
    sample_path: str,
    steps: dict[str, dict[str, Any]],
    output_path: str = "",
) -> Path:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    sample_name = Path(sample_path).name
    if output_path:
        path = Path(output_path).expanduser().resolve()
        if not str(path).lower().startswith(str(REPORTS_DIR.resolve()).lower()):
            raise ValueError(f"battleplan report must be under {REPORTS_DIR}: {path}")
        path.parent.mkdir(parents=True, exist_ok=True)
    else:
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        path = REPORTS_DIR / f"{slug(Path(sample_name).stem)}-battleplan-{stamp}.md"

    triage_result = steps.get("triage", {})
    highlights = _triage_highlights(triage_result) if triage_result.get("status") == "ok" else {}
    focus = steps.get("ghidra_call_focus", {})
    focus_items = focus.get("items", []) if isinstance(focus.get("items"), list) else []
    if not focus_items and isinstance(focus.get("suggested_functions"), list):
        focus_items = focus["suggested_functions"]

    lines = [
        f"# ReverseLab Battleplan: {sample_name}",
        "",
        f"生成时间：{datetime.now().isoformat(timespec='seconds')}",
        "",
        "## 1. Triage Highlights",
        "",
    ]
    if highlights:
        for key, value in highlights.items():
            lines.append(f"- `{key}`: `{value}`")
    else:
        lines.append("- triage 阶段失败，见 Steps。")

    lines.extend(["", "## 2. Generated Artifacts", ""])
    artifacts: list[str] = []
    for step_name, result in steps.items():
        if result.get("status") != "ok":
            continue
        for artifact in _artifact_paths(result):
            if artifact and artifact not in artifacts:
                artifacts.append(artifact)
                lines.append(f"- `{step_name}`: `{artifact}`")
    if not artifacts:
        lines.append("- 暂无产物。")

    lines.extend(["", "## 3. Static Focus Queue", ""])
    if focus_items:
        lines.append("| Rank | Address | Name | Reason | Score |")
        lines.append("|---:|---|---|---|---:|")
        for index, item in enumerate(focus_items[:20], start=1):
            if not isinstance(item, dict):
                continue
            reasons = ", ".join(str(reason) for reason in item.get("reasons", [])[:4]) if isinstance(item.get("reasons"), list) else ""
            lines.append(
                f"| {index} | `{item.get('entry', '')}` | `{item.get('name', '')}` | `{reasons}` | `{item.get('score', '')}` |"
            )
    else:
        lines.append("- 没有 Ghidra focus queue。可运行 `ghidra_headless_analyze` 后重跑此工作流。")

    lines.extend(["", "## 4. Dynamic Plan", ""])
    debug_step = steps.get("x64dbg_breakpoints", {})
    procmon_step = steps.get("procmon_filters", {})
    if debug_step.get("status") == "ok":
        lines.append(f"- x64dbg 脚本：`{debug_step.get('output_path', '')}`")
        lines.append(f"- API breakpoints: `{len(debug_step.get('api_breakpoints', []))}`")
        lines.append(f"- Function breakpoints: `{len(debug_step.get('function_breakpoints', []))}`")
    else:
        lines.append(f"- x64dbg 脚本生成失败：`{debug_step.get('error', '')}`")
    if procmon_step.get("status") == "ok":
        lines.append(f"- Procmon 过滤计划：`{procmon_step.get('output_path', '')}`")
        lines.append(f"- Effective presets: `{', '.join(procmon_step.get('effective_presets', []))}`")
    else:
        lines.append(f"- Procmon 过滤计划生成失败：`{procmon_step.get('error', '')}`")

    lines.extend(["", "## 5. Detection Drafts", ""])
    for step_name in ["ioc_extract", "ioc_refine", "yara_stub", "sigma_stub"]:
        step = steps.get(step_name, {})
        if step.get("status") == "ok":
            lines.append(f"- `{step_name}`: ok")
            for artifact in _artifact_paths(step):
                lines.append(f"  - `{artifact}`")
        else:
            lines.append(f"- `{step_name}`: error `{step.get('error', '')}`")

    lines.extend(["", "## 6. Steps", ""])
    for step_name, result in steps.items():
        status = result.get("status", "unknown")
        lines.append(f"- `{step_name}`: `{status}`")
        if status != "ok":
            lines.append(f"  - error: `{result.get('error', '')}`")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def sample_full_workup(
    sample_path: str,
    summary_path: str = "",
    run_ghidra: bool = False,
    generate_rules: bool = True,
    overwrite_note: bool = True,
    report_path: str = "",
    ghidra_timeout_seconds: int = 1800,
) -> dict[str, Any]:
    """Run an evidence-producing reverse-engineering workflow for one sample."""
    sample = str(resolve_file(sample_path))
    steps: dict[str, dict[str, Any]] = {}

    steps["triage"] = _safe_step("triage", triage.triage_pe, sample, True)

    effective_summary = summary_path
    if run_ghidra:
        steps["ghidra_headless"] = _safe_step(
            "ghidra_headless",
            ghidra_headless.ghidra_headless_analyze,
            sample,
            "",
            True,
            600,
            ghidra_timeout_seconds,
            500,
            600,
            500,
        )
        effective_summary = _summary_path_from_step(steps["ghidra_headless"], effective_summary)

    if effective_summary:
        steps["ghidra_overview"] = _safe_step("ghidra_overview", ghidra_summary.ghidra_summary_overview, effective_summary)
        steps["ghidra_call_focus"] = _safe_step("ghidra_call_focus", ghidra_summary.ghidra_summary_call_focus, effective_summary, "", "", 32, 40)
    else:
        steps["ghidra_call_focus"] = {"status": "skipped", "reason": "no summary_path and run_ghidra=False"}

    steps["analysis_note"] = _safe_step(
        "analysis_note",
        analysis_notes.triage_to_notes,
        sample,
        effective_summary,
        "",
        overwrite_note,
        25,
        30,
        30,
    )
    note_path = str(steps["analysis_note"].get("output_path", "")) if steps["analysis_note"].get("status") == "ok" else ""

    steps["x64dbg_breakpoints"] = _safe_step(
        "x64dbg_breakpoints",
        debug_scripts.make_x64dbg_breakpoint_script,
        sample,
        effective_summary,
        "",
        DEFAULT_DEBUG_PRESETS,
        "",
        "",
        "",
        12,
    )
    steps["procmon_filters"] = _safe_step(
        "procmon_filters",
        procmon_filters.make_procmon_filters,
        sample,
        effective_summary,
        "",
        "",
        "",
        True,
        10,
    )
    steps["ioc_extract"] = _safe_step(
        "ioc_extract",
        ioc_extract.extract_iocs_from_summary,
        effective_summary,
        sample,
        note_path,
        "",
    )
    ioc_json = str(steps["ioc_extract"].get("json_path", "")) if steps["ioc_extract"].get("status") == "ok" else ""
    if ioc_json:
        steps["ioc_refine"] = _safe_step("ioc_refine", ioc_extract.refine_ioc_sources, ioc_json, "")
    else:
        steps["ioc_refine"] = {"status": "skipped", "reason": "ioc_extract did not produce json_path"}

    if generate_rules:
        steps["yara_stub"] = _safe_step("yara_stub", yara_stub.make_yara_stub, sample, effective_summary, ioc_json, "", "", 14, 8)
        steps["sigma_stub"] = _safe_step("sigma_stub", sigma_stub.make_sigma_stub, sample, effective_summary, ioc_json, "", "")
    else:
        steps["yara_stub"] = {"status": "skipped", "reason": "generate_rules=False"}
        steps["sigma_stub"] = {"status": "skipped", "reason": "generate_rules=False"}

    battleplan = _write_battleplan_report(sample, steps, report_path)
    ok_count = sum(1 for result in steps.values() if result.get("status") == "ok")
    error_count = sum(1 for result in steps.values() if result.get("status") == "error")
    skipped_count = sum(1 for result in steps.values() if result.get("status") == "skipped")
    artifact_paths: list[str] = [str(battleplan)]
    for result in steps.values():
        if result.get("status") == "ok":
            artifact_paths.extend(path for path in _artifact_paths(result) if path not in artifact_paths)

    manifest_path = battleplan.with_suffix(".json")
    manifest = {
        "sample_path": sample,
        "summary_path": effective_summary,
        "battleplan_path": str(battleplan),
        "ok_count": ok_count,
        "error_count": error_count,
        "skipped_count": skipped_count,
        "artifact_paths": artifact_paths,
        "steps": steps,
    }
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")

    return {
        "sample_path": sample,
        "summary_path": effective_summary,
        "battleplan_path": str(battleplan),
        "manifest_path": str(manifest_path),
        "ok_count": ok_count,
        "error_count": error_count,
        "skipped_count": skipped_count,
        "artifact_paths": artifact_paths,
        "steps": steps,
    }


def _latest_manifest() -> Path:
    candidates = sorted(REPORTS_DIR.glob("*-battleplan-*.json"), key=lambda item: item.stat().st_mtime, reverse=True)
    if not candidates:
        raise FileNotFoundError(f"no battleplan manifest found under {REPORTS_DIR}")
    return candidates[0]


def _load_manifest(manifest_path: str = "") -> tuple[Path, dict[str, Any]]:
    path = Path(manifest_path).expanduser().resolve() if manifest_path else _latest_manifest()
    data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    if not isinstance(data, dict):
        raise ValueError(f"manifest root is not an object: {path}")
    return path, data


def _behavior_tags(manifest: dict[str, Any]) -> list[str]:
    steps = manifest.get("steps", {}) if isinstance(manifest.get("steps"), dict) else {}
    for key in ("ioc_extract", "sigma_stub", "yara_stub", "procmon_filters"):
        step = steps.get(key, {}) if isinstance(steps.get(key), dict) else {}
        tags = step.get("behavior_tags") or step.get("effective_presets") or step.get("inferred_presets")
        if isinstance(tags, list) and tags:
            return [str(item) for item in tags if str(item).strip()]
    return []


def _triage_step(manifest: dict[str, Any]) -> dict[str, Any]:
    steps = manifest.get("steps", {}) if isinstance(manifest.get("steps"), dict) else {}
    triage_step = steps.get("triage", {})
    return triage_step if isinstance(triage_step, dict) else {}


def _looks_packed(manifest: dict[str, Any]) -> tuple[bool, list[str]]:
    triage_step = _triage_step(manifest)
    reasons: list[str] = []
    entropy = (((triage_step.get("die_entropy", {}) or {}).get("stdout", {}) or {}))
    if str(entropy.get("status", "")).lower() == "packed":
        reasons.append("DiE entropy status is packed")
    for record in entropy.get("records", []) if isinstance(entropy.get("records"), list) else []:
        if not isinstance(record, dict):
            continue
        record_name = str(record.get("name", "")).lower()
        if any(noisy in record_name for noisy in [".rsrc", "resource", ".reloc"]):
            continue
        if str(record.get("status", "")).lower() == "packed":
            reasons.append(f"packed section: {record.get('name', '')} entropy={record.get('entropy', '')}")
    imports = (((triage_step.get("imports", {}) or {}).get("stdout", {}) or {}).get("imports", []) or [])
    names = {str(item.get("name", "")).lower() for item in imports if isinstance(item, dict)}
    if {"virtualalloc", "virtualprotect", "writeprocessmemory"}.intersection(names):
        reasons.append("memory allocation/protection APIs imported")
    return bool(reasons), reasons


def _crypto_unpack_mode(manifest: dict[str, Any]) -> tuple[str, list[str]]:
    triage_step = _triage_step(manifest)
    steps = manifest.get("steps", {}) if isinstance(manifest.get("steps"), dict) else {}
    imports = (((triage_step.get("imports", {}) or {}).get("stdout", {}) or {}).get("imports", []) or [])
    names = {str(item.get("name", "")).lower() for item in imports if isinstance(item, dict)}

    summary_focus = steps.get("ghidra_call_focus", {}) if isinstance(steps.get("ghidra_call_focus"), dict) else {}
    for item in summary_focus.get("suggested_functions", []) if isinstance(summary_focus.get("suggested_functions"), list) else []:
        if not isinstance(item, dict):
            continue
        for ref in item.get("import_refs", []) if isinstance(item.get("import_refs"), list) else []:
            if isinstance(ref, dict):
                names.add(str(ref.get("name", "")).lower())

    crypto_hits = sorted(api for api in CRYPTO_AUTOPILOT_APIS if api.lower() in names)
    unpack_hits = sorted(api for api in UNPACK_AUTOPILOT_APIS if api.lower() in names)
    reasons: list[str] = []
    if crypto_hits:
        reasons.append("crypto APIs imported/referenced: " + ", ".join(crypto_hits[:8]))
    if unpack_hits:
        reasons.append("unpack/loader APIs imported/referenced: " + ", ".join(unpack_hits[:8]))
    packed, packed_reasons = _looks_packed(manifest)
    if packed:
        reasons.extend(packed_reasons)

    if crypto_hits and (unpack_hits or packed):
        return "both", reasons
    if crypto_hits:
        return "crypto", reasons
    if unpack_hits or packed:
        return "unpack", reasons
    return "both", ["default ReverseLab priority: prepare decrypt/unpack probes"]


def _focus_functions_from_summary(summary_path: str, behaviors: list[str], limit: int) -> list[dict[str, Any]]:
    combined: list[dict[str, Any]] = []
    seen: set[str] = set()
    query_behaviors = behaviors or [""]
    for behavior in query_behaviors:
        result = ghidra_summary.ghidra_summary_call_focus(summary_path, "", behavior if behavior in {"file", "registry", "process", "network", "image"} else "", 32, limit)
        for item in result.get("suggested_functions", []) if isinstance(result.get("suggested_functions"), list) else []:
            if not isinstance(item, dict):
                continue
            entry = str(item.get("entry", "")).strip()
            if not entry or entry in seen:
                continue
            seen.add(entry)
            combined.append(item)
            if len(combined) >= limit:
                return combined
    return combined


def _autopilot_report_path(sample_path: str) -> Path:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return REPORTS_DIR / f"{slug(Path(sample_path).stem)}-autopilot-{stamp}.json"


def _action(action_id: str, kind: str, priority: int, reason: str, params: dict[str, Any], executable: bool = True) -> dict[str, Any]:
    return {
        "id": action_id,
        "kind": kind,
        "priority": priority,
        "reason": reason,
        "params": params,
        "executable": executable,
    }


def _build_action_queue(manifest: dict[str, Any], max_actions: int) -> list[dict[str, Any]]:
    sample_path = str(manifest.get("sample_path", "")).strip()
    summary_path = str(manifest.get("summary_path", "")).strip()
    behaviors = _behavior_tags(manifest)
    packed, packed_reasons = _looks_packed(manifest)
    crypto_unpack_mode, crypto_unpack_reasons = _crypto_unpack_mode(manifest)
    actions: list[dict[str, Any]] = []

    if sample_path:
        actions.append(
            _action(
                f"make_pe_{crypto_unpack_mode}_plan",
                "make_pe_crypto_unpack_plan",
                98 if crypto_unpack_reasons and "default ReverseLab priority" not in crypto_unpack_reasons[0] else 75,
                "; ".join(crypto_unpack_reasons),
                {
                    "sample_path": sample_path,
                    "summary_path": summary_path,
                    "mode": crypto_unpack_mode,
                    "include_frida": True,
                    "focus_limit": 12,
                },
            )
        )

    if not summary_path:
        actions.append(
            _action(
                "run_ghidra_full_workup",
                "sample_full_workup",
                100,
                "No Ghidra summary is attached; function-level automation needs one.",
                {
                    "sample_path": sample_path,
                    "summary_path": "",
                    "run_ghidra": True,
                    "generate_rules": True,
                    "overwrite_note": True,
                },
            )
        )
    else:
        focus_functions = _focus_functions_from_summary(summary_path, behaviors, 12)
        addresses = ",".join(str(item.get("entry", "")) for item in focus_functions[:8] if item.get("entry"))
        if addresses:
            actions.append(
                _action(
                    "make_focus_function_breakpoints",
                    "make_x64dbg_breakpoint_script",
                    95,
                    "Ghidra summary has focus functions; generate module-relative function breakpoints.",
                    {
                        "sample_path": sample_path,
                        "summary_path": summary_path,
                        "presets": "",
                        "api_names": "",
                        "function_addresses": addresses,
                        "function_limit": 8,
                    },
                )
            )
        for behavior in behaviors[:4]:
            if behavior in {"file", "registry", "process", "network", "image"}:
                actions.append(
                    _action(
                        f"make_{behavior}_breakpoints",
                        "make_x64dbg_breakpoint_script",
                        70,
                        f"Behavior tag `{behavior}` is present; generate targeted API breakpoints.",
                        {
                            "sample_path": sample_path,
                            "summary_path": summary_path,
                            "presets": behavior,
                            "api_names": "",
                            "function_addresses": "",
                            "function_limit": 0,
                        },
                    )
                )

    if packed:
        actions.append(
            _action(
                "make_unpacking_breakpoints",
                "make_x64dbg_breakpoint_script",
                90,
                "; ".join(packed_reasons),
                {
                    "sample_path": sample_path,
                    "summary_path": summary_path,
                    "presets": "",
                    "api_names": UNPACKING_APIS,
                    "function_addresses": "",
                    "function_limit": 0,
                },
            )
        )

    actions.append(
        _action(
            "refresh_procmon_views",
            "make_procmon_filters",
            45,
            "Refresh behavior-specific Procmon views from current import/string evidence.",
            {
                "sample_path": sample_path,
                "summary_path": summary_path,
                "presets": ",".join(behaviors),
            },
        )
    )

    actions.sort(key=lambda item: item["priority"], reverse=True)
    return actions[: max(1, max_actions)]


def _execute_action(action: dict[str, Any]) -> dict[str, Any]:
    kind = action.get("kind")
    params = action.get("params", {}) if isinstance(action.get("params"), dict) else {}
    if kind == "sample_full_workup":
        return _safe_step("sample_full_workup", sample_full_workup, **params)
    if kind == "make_x64dbg_breakpoint_script":
        sample_name = Path(params.get("sample_path", "sample")).name or "sample"
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        output_path = DEBUG_SCRIPTS_DIR / f"{slug(sample_name)}-{slug(str(action.get('id', 'breakpoints')))}-{stamp}.txt"
        return _safe_step(
            "make_x64dbg_breakpoint_script",
            debug_scripts.make_x64dbg_breakpoint_script,
            params.get("sample_path", ""),
            params.get("summary_path", ""),
            str(output_path),
            params.get("presets", ""),
            params.get("api_names", ""),
            "",
            params.get("function_addresses", ""),
            int(params.get("function_limit", 10) or 0),
        )
    if kind == "make_procmon_filters":
        return _safe_step(
            "make_procmon_filters",
            procmon_filters.make_procmon_filters,
            params.get("sample_path", ""),
            params.get("summary_path", ""),
            "",
            params.get("presets", ""),
            "",
            True,
            10,
        )
    if kind == "make_pe_crypto_unpack_plan":
        return _safe_step(
            "make_pe_crypto_unpack_plan",
            crypto_unpack.make_pe_crypto_unpack_plan,
            params.get("sample_path", ""),
            params.get("summary_path", ""),
            params.get("mode", "both"),
            "",
            bool(params.get("include_frida", True)),
            int(params.get("focus_limit", 12) or 12),
        )
    return {"status": "skipped", "reason": f"unsupported action kind: {kind}"}


def sample_autopilot_round(
    manifest_path: str = "",
    max_actions: int = 4,
    execute: bool = False,
) -> dict[str, Any]:
    """Plan or execute the next AI reverse-engineering round from a battleplan manifest."""
    resolved_manifest, manifest = _load_manifest(manifest_path)
    action_queue = _build_action_queue(manifest, max_actions)
    executed: list[dict[str, Any]] = []
    if execute:
        for action in action_queue:
            if action.get("executable", True):
                executed.append({"action": action, "result": _execute_action(action)})

    output_path = _autopilot_report_path(str(manifest.get("sample_path", "sample")))
    payload = {
        "manifest_path": str(resolved_manifest),
        "sample_path": manifest.get("sample_path", ""),
        "summary_path": manifest.get("summary_path", ""),
        "behaviors": _behavior_tags(manifest),
        "execute": execute,
        "action_queue": action_queue,
        "executed": executed,
    }
    output_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    payload["output_path"] = str(output_path)
    return payload
