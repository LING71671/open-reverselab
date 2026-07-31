from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from ..config import NOTES_DIR
from ..errors import ToolError
from ..paths import ensure_under, resolve_file, resolve_summary
from ..utils import slug
from . import ghidra_summary, triage
from .procmon_filters import PRESET_FILTERS


def _default_output_path(sample_name: str) -> Path:
    NOTES_DIR.mkdir(parents=True, exist_ok=True)
    stem = Path(sample_name).stem if sample_name else "sample"
    return NOTES_DIR / f"{slug(stem)}_analysis.md"


def _resolve_output_path(output_path: str, sample_name: str, overwrite: bool) -> Path:
    if not output_path:
        path = _default_output_path(sample_name)
    else:
        path = Path(output_path).expanduser().resolve()
        ensure_under(path, [NOTES_DIR], "analysis note output")
        path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not overwrite:
        raise ToolError(f"output note already exists, pass overwrite=True or choose another output_path: {path}")
    return path


def _fmt_hex(value: Any) -> str:
    if isinstance(value, int):
        return f"0x{value:X}"
    text = str(value or "").strip()
    if not text:
        return ""
    if text.lower().startswith("0x"):
        return text
    try:
        if all(ch in "0123456789abcdefABCDEF" for ch in text):
            return f"0x{text.upper()}"
        return f"0x{int(text):X}"
    except ValueError:
        return text


def _collect_import_names(items: list[dict[str, Any]]) -> set[str]:
    return {
        str(item.get("name", "")).strip().lower()
        for item in items
        if isinstance(item, dict) and item.get("name")
    }


def _infer_focuses(import_names: set[str]) -> list[str]:
    focuses: list[str] = []
    for preset, spec in PRESET_FILTERS.items():
        markers = {str(item).lower() for item in spec.get("api_markers", [])}
        if import_names.intersection(markers):
            focuses.append(preset)
    return focuses


def _top_imports(triage_imports: list[dict[str, Any]], summary_imports: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if triage_imports:
        return triage_imports[:20]
    if summary_imports:
        return summary_imports[:20]
    return triage_imports[:20]


def _top_strings(summary_strings: list[dict[str, Any]], triage_strings: list[str]) -> list[str]:
    noisy = {"mz", "pe", ".text", ".data", ".rdata", ".pdata", ".didat", ".rsrc", ".reloc", "fothk"}
    values: list[str] = []
    for item in summary_strings[:20]:
        if not isinstance(item, dict):
            continue
        value = str(item.get("value", "")).strip()
        if value and len(value) >= 4 and value.lower() not in noisy:
            values.append(value)
    if values:
        return values
    filtered = []
    for item in triage_strings:
        text = str(item)[:220].strip()
        if len(text) < 4:
            continue
        filtered.append(text)
        if len(filtered) >= 20:
            break
    return filtered


def _proposed_function_name(function: dict[str, Any]) -> str:
    name = str(function.get("name", "")).strip()
    if name.startswith("entry"):
        return "entry"
    if name.startswith("__") or name.startswith("thunk_"):
        return name
    if name.startswith("FUN_"):
        return f"candidate_{name.lower()}"
    return name or "review_me"


def _function_evidence_cue(function: dict[str, Any]) -> str:
    cues: list[str] = []
    if str(function.get("signature", "")).strip():
        cues.append("signature")
    if isinstance(function.get("import_refs"), list) and function["import_refs"]:
        cues.append(f"imports:{len(function['import_refs'])}")
    if isinstance(function.get("string_refs"), list) and function["string_refs"]:
        cues.append(f"strings:{len(function['string_refs'])}")
    if isinstance(function.get("callers"), list) and function["callers"]:
        cues.append(f"callers:{len(function['callers'])}")
    if isinstance(function.get("callees"), list) and function["callees"]:
        cues.append(f"callees:{len(function['callees'])}")
    decompile = function.get("decompile")
    if isinstance(decompile, dict) and str(decompile.get("status", "")).lower() == "ok":
        cues.append("decompile")
    return ", ".join(cues) if cues else "review xrefs/decompile"


def triage_to_notes(
    sample_path: str,
    summary_path: str = "",
    output_path: str = "",
    overwrite: bool = False,
    max_functions: int = 15,
    max_imports: int = 20,
    max_strings: int = 20,
) -> dict[str, Any]:
    resolved_sample = resolve_file(sample_path)
    triage_result = triage.triage_pe(str(resolved_sample), write_markdown=False)

    summary_data: dict[str, Any] = {}
    resolved_summary = ""
    if summary_path:
        resolved_summary = str(resolve_summary(summary_path))
        _summary_path_obj, summary_data = ghidra_summary.load_summary(resolved_summary)

    output = _resolve_output_path(output_path, resolved_sample.name, overwrite)

    hashes = triage_result.get("hashes", {})
    rizin_info = ((triage_result.get("rizin_info", {}) or {}).get("stdout", {}) or {}).get("info", {}) or {}
    die_scan = (triage_result.get("die_scan", {}) or {}).get("stdout", {}) or {}
    die_entropy = (triage_result.get("die_entropy", {}) or {}).get("stdout", {}) or {}
    sections = ((triage_result.get("sections", {}) or {}).get("stdout", {}) or {}).get("sections", []) or []
    triage_imports = ((triage_result.get("imports", {}) or {}).get("stdout", {}) or {}).get("imports", []) or []
    triage_strings = ((triage_result.get("strings", {}) or {}).get("stdout", {}) or {}).get("strings", []) or []

    functions = summary_data.get("functions", []) if isinstance(summary_data.get("functions"), list) else []
    summary_imports = summary_data.get("imports", []) if isinstance(summary_data.get("imports"), list) else []
    summary_strings = summary_data.get("strings", []) if isinstance(summary_data.get("strings"), list) else []
    program = summary_data.get("program", {}) if isinstance(summary_data.get("program"), dict) else {}

    import_names = _collect_import_names(triage_imports) | _collect_import_names(summary_imports)
    focuses = _infer_focuses(import_names)
    top_imports = _top_imports(triage_imports, summary_imports)[: max(0, max_imports)]
    top_strings = _top_strings(summary_strings, triage_strings)[: max(0, max_strings)]

    lines = [
        f"# Sample Analysis: {resolved_sample.name}",
        "",
        f"生成时间：{datetime.now().isoformat(timespec='seconds')}",
        "",
        "## 1. Basic Info",
        "",
        f"- Path: `{resolved_sample}`",
        f"- Size: `{hashes.get('size', '')}` bytes",
        f"- MD5: `{hashes.get('md5', '')}`",
        f"- SHA1: `{hashes.get('sha1', '')}`",
        f"- SHA256: `{hashes.get('sha256', '')}`",
        f"- File Type: `{rizin_info.get('bintype', '')}` / `{rizin_info.get('class', '')}`",
        f"- Architecture: `{rizin_info.get('arch', '')}` `{rizin_info.get('bits', '')}`",
        f"- Compiler/Packer: `{rizin_info.get('compiler', '')}` / `{die_scan.get('detects', [{}])[0].get('values', [{}])[0].get('name', '') if isinstance(die_scan.get('detects'), list) and die_scan.get('detects') else ''}`",
        f"- Entry Point: `{_fmt_hex(rizin_info.get('entry', ''))}`",
        f"- Base Address: `{_fmt_hex(rizin_info.get('baddr', '')) or _fmt_hex(program.get('image_base', ''))}`",
        f"- Subsystem: `{rizin_info.get('subsys', '')}`",
        f"- PDB: `{rizin_info.get('dbg_file', '')}`",
        f"- Summary Path: `{resolved_summary}`" if resolved_summary else "- Summary Path: ``",
        "",
        "## 2. Initial Triage",
        "",
        f"- DiE status: `{die_entropy.get('status', '')}`",
        f"- Entropy total: `{die_entropy.get('total', '')}`",
        f"- Imports total: `{((triage_result.get('imports', {}) or {}).get('stdout', {}) or {}).get('imports_total', len(triage_imports))}`",
        f"- Strings total: `{((triage_result.get('strings', {}) or {}).get('stdout', {}) or {}).get('strings_total', len(triage_strings))}`",
        f"- Ghidra functions total: `{summary_data.get('functions_total', 0)}`" if summary_data else "- Ghidra functions total: ``",
        f"- Ghidra imports total: `{summary_data.get('imports_total', 0)}`" if summary_data else "- Ghidra imports total: ``",
        f"- Ghidra strings total: `{summary_data.get('strings_total', 0)}`" if summary_data else "- Ghidra strings total: ``",
        f"- Suggested behavior focus: `{', '.join(focuses)}`" if focuses else "- Suggested behavior focus: `review manually`",
        "",
        "## 3. Strings",
        "",
    ]

    if top_strings:
        for item in top_strings:
            lines.append(f"- `{item}`")
    else:
        lines.append("- 暂无字符串快照。")

    lines.extend(
        [
            "",
            "## 4. Imports / Exports",
            "",
        ]
    )
    if top_imports:
        for item in top_imports:
            if isinstance(item, dict):
                lib = item.get("libname", item.get("namespace", ""))
                name = item.get("name", "")
                addr = item.get("plt", item.get("address", ""))
                addr_text = _fmt_hex(addr)
                suffix = f" @ {addr_text}" if addr_text else ""
                lines.append(f"- `{lib}!{name}`{suffix}")
    else:
        lines.append("- 暂无导入快照。")

    lines.extend(
        [
            "",
            "## 5. Sections / PE Structure",
            "",
            "| Name | PAddr | VAddr | Size | VSize | Perm | Flags |",
            "|---|---:|---:|---:|---:|---|---|",
        ]
    )
    for sec in sections:
        if not isinstance(sec, dict):
            continue
        flags = ", ".join(sec.get("flags", [])) if isinstance(sec.get("flags"), list) else str(sec.get("flags", ""))
        lines.append(
            f"| `{sec.get('name', '')}` | `{_fmt_hex(sec.get('paddr', ''))}` | `{_fmt_hex(sec.get('vaddr', ''))}` | "
            f"`{sec.get('size', '')}` | `{sec.get('vsize', '')}` | `{sec.get('perm', '')}` | `{flags}` |"
        )

    lines.extend(
        [
            "",
            "## 6. Static Analysis",
            "",
            "### Function Map",
            "",
            "| Address | Current Name | Proposed Name | Purpose / Evidence | Confidence | Review Status |",
            "|---|---|---|---|---|---|",
        ]
    )
    for function in functions[: max(0, max_functions)]:
        if not isinstance(function, dict):
            continue
        lines.append(
            f"| `{_fmt_hex(function.get('entry', ''))}` | `{function.get('name', '')}` | `{_proposed_function_name(function)}` | "
            f"`{_function_evidence_cue(function)}` | `Low` | `Needs review` |"
        )

    lines.extend(
        [
            "",
            "### Symbol / Struct Evidence Ledger",
            "",
            "Use this ledger to keep observed evidence separate from hypotheses. A proposed name or field type is not confirmed until its listed static and dynamic evidence agree.",
            "",
            "| Kind | Function / Address | Offset | Width / Access | Candidate Name or Meaning | Static Evidence | Dynamic Evidence | Confidence |",
            "|---|---|---:|---|---|---|---|---|",
            "| symbol |  |  |  |  | signature / strings / imports / callers / callees |  | Low / Medium / High |",
            "| field |  |  |  |  | decompile / xref / instruction | runtime observation (if authorized) | Low / Medium / High |",
            "",
            "Evidence level: **Observed** records tool output; **Inferred** records a reasoned hypothesis; **Confirmed** requires corroborating static and, where safe, dynamic evidence.",
            "",
            "### Key Functions",
            "",
        ]
    )
    if functions:
        for function in functions[: min(max(0, max_functions), 8)]:
            if not isinstance(function, dict):
                continue
            lines.extend(
                [
                    f"#### `{function.get('name', '')}` @ `{_fmt_hex(function.get('entry', ''))}`",
                    "",
                    f"- Signature: `{function.get('signature', '')}`",
                    f"- Body Size: `{function.get('body_size', '')}`",
                    f"- Parameter Count: `{function.get('parameter_count', '')}`",
                    "- Purpose: 待结合 xrefs / decompile 补充。",
                    "- Inputs: 待确认。",
                    "- Outputs: 待确认。",
                    "- Side Effects: 待确认。",
                    "- Callers / Callees: 待确认。",
                    "",
                ]
            )
    else:
        lines.append("- 暂无 Ghidra 函数摘要，可先运行 `ghidra_headless_analyze`。")

    lines.extend(
        [
            "",
            "## 7. Dynamic Analysis Plan",
            "",
        ]
    )
    if focuses:
        if "file" in focuses:
            lines.append("- 文件行为：优先观察 `CreateFileW`、`ReadFile`、`WriteFile`、`SetRenameInformationFile`。")
        if "registry" in focuses:
            lines.append("- 注册表行为：优先观察 `RegOpenKeyExW`、`RegSetValueExW`、`RegQueryValueExW`。")
        if "process" in focuses:
            lines.append("- 进程行为：优先观察 `CreateProcessW`、`ShellExecuteW`、`Load Image`。")
        if "network" in focuses:
            lines.append("- 网络行为：优先观察 `TCP Connect/Send/Receive` 和 WinHTTP/WinINet API。")
        if "image" in focuses:
            lines.append("- 模块加载：重点看 `LoadLibrary*`、`GetProcAddress`、异常 DLL 路径。")
    else:
        lines.append("- 先从 `Process Name` 基线、`Load Image`、`CreateFileW` 和 `RegSetValueExW` 开始。")
    lines.extend(
        [
            "- 推荐工具：`make_x64dbg_breakpoint_script` 生成断点脚本。",
            "- 推荐工具：`make_procmon_filters` 生成 Procmon baseline + preset views。",
            "",
            "## 8. Dynamic Findings",
            "",
            "- 待填充。",
            "",
            "## 9. Algorithm Reconstruction",
            "",
            "- 待确认是否存在校验、编码、加解密或序列号逻辑。",
            "",
            "## 10. Patch / Bypass Notes",
            "",
            "- 如需 patch，优先复制到 `patches/` 后再修改。",
            "",
            "## 11. IOC / Behavior",
            "",
        ]
    )
    if focuses:
        lines.append(f"- 初步行为面：`{', '.join(focuses)}`")
    else:
        lines.append("- 初步行为面：待补充。")
    lines.extend(
        [
            "",
            "## 12. Open Questions",
            "",
            "- 哪些函数是真正的业务入口，而不是 CRT / thunk / 初始化包装？",
            "- 是否存在需要动态验证的关键分支、错误处理或资源访问路径？",
            "- 是否需要补充更完整的 Ghidra summary、xrefs 或字符串筛选？",
            "",
            "## 13. Final Conclusion",
            "",
            "- 当前为自动生成的分析骨架，已整合 triage 与可选的 Ghidra summary，可直接继续人工补充。",
        ]
    )

    output.write_text("\n".join(lines) + "\n", encoding="utf-8")

    return {
        "output_path": str(output),
        "sample_path": str(resolved_sample),
        "summary_path": resolved_summary,
        "focuses": focuses,
        "sections_count": len(sections),
        "function_rows": min(len(functions), max(0, max_functions)),
        "import_rows": len(top_imports),
        "string_rows": len(top_strings),
    }
