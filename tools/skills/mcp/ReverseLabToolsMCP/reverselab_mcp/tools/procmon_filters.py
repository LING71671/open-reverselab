from __future__ import annotations

import csv
from datetime import datetime
from pathlib import Path
from typing import Any

from ..config import PROCMON_FILTERS_DIR
from ..errors import ToolError
from ..paths import ensure_under, resolve_file, resolve_summary
from ..utils import slug
from . import ghidra_summary, triage


PRESET_FILTERS: dict[str, dict[str, Any]] = {
    "file": {
        "operations": [
            "CreateFile",
            "ReadFile",
            "WriteFile",
            "QueryOpen",
            "SetDispositionInformationFile",
            "SetRenameInformationFile",
            "CreateFileMapping",
        ],
        "api_markers": [
            "CreateFileA",
            "CreateFileW",
            "ReadFile",
            "WriteFile",
            "DeleteFileA",
            "DeleteFileW",
            "MoveFileExA",
            "MoveFileExW",
            "CopyFileA",
            "CopyFileW",
            "FindFirstFileA",
            "FindFirstFileW",
        ],
        "note": "重点看用户目录、临时目录、Startup 目录、文件落地与改名删除行为。",
    },
    "registry": {
        "operations": [
            "RegOpenKey",
            "RegCreateKey",
            "RegQueryValue",
            "RegSetValue",
            "RegDeleteValue",
            "RegDeleteKey",
            "RegRenameKey",
        ],
        "api_markers": [
            "RegOpenKeyA",
            "RegOpenKeyW",
            "RegOpenKeyExA",
            "RegOpenKeyExW",
            "RegCreateKeyA",
            "RegCreateKeyW",
            "RegCreateKeyExA",
            "RegCreateKeyExW",
            "RegSetValueA",
            "RegSetValueW",
            "RegSetValueExA",
            "RegSetValueExW",
            "RegQueryValueExA",
            "RegQueryValueExW",
            "RegDeleteKeyA",
            "RegDeleteKeyW",
            "RegDeleteValueA",
            "RegDeleteValueW",
        ],
        "note": "重点看 Run/RunOnce、Services、IFEO、Explorer Shell/Open 命令、策略键位。",
    },
    "process": {
        "operations": [
            "Process Create",
            "Process Start",
            "Process Exit",
            "Thread Create",
            "Thread Exit",
            "Load Image",
        ],
        "api_markers": [
            "CreateProcessA",
            "CreateProcessW",
            "ShellExecuteA",
            "ShellExecuteW",
            "WinExec",
            "CreateRemoteThread",
            "CreateRemoteThreadEx",
            "OpenProcess",
            "WriteProcessMemory",
            "ReadProcessMemory",
            "VirtualAllocEx",
            "VirtualProtectEx",
            "NtCreateThreadEx",
        ],
        "note": "重点看子进程、命令行、父子关系、可疑模块加载和注入痕迹。",
    },
    "network": {
        "operations": [
            "TCP Connect",
            "TCP Reconnect",
            "TCP Send",
            "TCP Receive",
            "UDP Send",
            "UDP Receive",
        ],
        "api_markers": [
            "InternetOpenA",
            "InternetOpenW",
            "InternetOpenUrlA",
            "InternetOpenUrlW",
            "InternetConnectA",
            "InternetConnectW",
            "HttpOpenRequestA",
            "HttpOpenRequestW",
            "HttpSendRequestA",
            "HttpSendRequestW",
            "WinHttpOpen",
            "WinHttpConnect",
            "WinHttpOpenRequest",
            "WinHttpSendRequest",
            "WinHttpReceiveResponse",
            "WinHttpReadData",
            "connect",
            "send",
            "recv",
            "WSAConnect",
            "WSASend",
            "WSARecv",
        ],
        "note": "重点看远端地址、端口、发送接收时序，以及与 DNS/代理相关的路径字段。",
    },
    "image": {
        "operations": [
            "Load Image",
        ],
        "api_markers": [
            "LoadLibraryA",
            "LoadLibraryW",
            "LoadLibraryExA",
            "LoadLibraryExW",
            "GetProcAddress",
            "FreeLibrary",
        ],
        "note": "重点看额外 DLL、延迟加载模块、非系统目录模块和同名伪装模块。",
    },
}


STRING_HINT_RULES: list[tuple[str, str]] = [
    (r"\currentversion\run", r"CurrentVersion\Run"),
    (r"\currentversion\runonce", r"CurrentVersion\RunOnce"),
    (r"\image file execution options", r"Image File Execution Options"),
    ("\\services\\", r"Services"),
    (r"\startup", r"Startup"),
    ("\\appdata\\", r"AppData"),
    ("\\programdata\\", r"ProgramData"),
    (r"\temp", r"Temp"),
    ("\\tasks\\", r"Tasks"),
    (r"http://", r"http://"),
    (r"https://", r"https://"),
]


def _parse_csv(text: str) -> list[str]:
    items: list[str] = []
    for raw in text.replace("\r", "\n").replace(",", "\n").split("\n"):
        value = raw.strip()
        if value:
            items.append(value)
    return items


def _default_output_path(sample_name: str) -> Path:
    PROCMON_FILTERS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return PROCMON_FILTERS_DIR / f"{slug(sample_name)}-procmon-filters-{stamp}.md"


def _resolve_output_path(output_path: str, sample_name: str) -> Path:
    if not output_path:
        return _default_output_path(sample_name)
    path = Path(output_path).expanduser().resolve()
    ensure_under(path, [PROCMON_FILTERS_DIR], "procmon filter output")
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _load_import_names(sample_path: str = "", summary_path: str = "") -> tuple[set[str], str]:
    names: set[str] = set()
    sources: list[str] = []

    if summary_path:
        path, data = ghidra_summary.load_summary(summary_path)
        items = data.get("imports", [])
        names.update(str(item.get("name", "")).strip().lower() for item in items if isinstance(item, dict) and item.get("name"))
        sources.append(str(path))

    if sample_path:
        result = triage.rizin_imports(sample_path, limit=5000)
        stdout = result.get("stdout", {})
        items = stdout.get("imports", []) if isinstance(stdout, dict) else []
        names.update(str(item.get("name", "")).strip().lower() for item in items if isinstance(item, dict) and item.get("name"))
        sources.append("rizin_imports")

    return names, ", ".join(sources)


def _load_string_values(summary_path: str) -> list[str]:
    if not summary_path:
        return []
    _path, data = ghidra_summary.load_summary(summary_path)
    items = data.get("strings", [])
    if not isinstance(items, list):
        return []
    values: list[str] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        value = str(item.get("value", "")).strip()
        if value:
            values.append(value)
    return values


def _infer_presets(imported_names: set[str]) -> list[str]:
    inferred: list[str] = []
    for preset, spec in PRESET_FILTERS.items():
        markers = {str(item).lower() for item in spec.get("api_markers", [])}
        if imported_names.intersection(markers):
            inferred.append(preset)
    return inferred


def _filter_item(column: str, relation: str, value: str, action: str, reason: str) -> dict[str, str]:
    return {
        "column": column,
        "relation": relation,
        "value": value,
        "action": action,
        "reason": reason,
    }


def _build_baseline_filters(
    sample_name: str,
    include_excludes: bool,
) -> list[dict[str, str]]:
    filters: list[dict[str, str]] = [
        _filter_item("Process Name", "is", sample_name, "Include", "只看目标样本主进程。"),
    ]

    if include_excludes:
        filters.extend(
            [
                _filter_item("Process Name", "is", "Procmon.exe", "Exclude", "排除 Procmon 自身噪音。"),
                _filter_item("Process Name", "is", "Procmon64.exe", "Exclude", "排除 Procmon 自身噪音。"),
            ]
        )

    deduped: list[dict[str, str]] = []
    seen: set[tuple[str, str, str, str]] = set()
    for item in filters:
        key = (item["column"], item["relation"], item["value"], item["action"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped


def _build_preset_views(
    presets: list[str],
    path_hints: list[str],
) -> list[dict[str, Any]]:
    views: list[dict[str, Any]] = []
    for preset in presets:
        spec = PRESET_FILTERS[preset]
        rows: list[dict[str, str]] = []
        for operation in spec.get("operations", []):
            rows.append(
                _filter_item(
                    "Operation",
                    "is",
                    str(operation),
                    "Include",
                    f"{preset} preset: {spec.get('note', '')}",
                )
            )

        if preset == "registry":
            for hint in path_hints:
                lowered = hint.lower()
                if "run" in lowered or "services" in lowered or "image file execution options" in lowered:
                    rows.append(_filter_item("Path", "contains", hint, "Include", "注册表相关路径聚焦。"))
        elif preset == "file":
            for hint in path_hints:
                lowered = hint.lower()
                if any(token in lowered for token in ["startup", "appdata", "programdata", "temp", "tasks"]):
                    rows.append(_filter_item("Path", "contains", hint, "Include", "文件系统相关路径聚焦。"))
        elif preset == "network":
            for hint in path_hints:
                if hint.lower().startswith("http"):
                    rows.append(_filter_item("Path", "contains", hint, "Include", "网络相关路径或 URL 线索聚焦。"))

        deduped: list[dict[str, str]] = []
        seen: set[tuple[str, str, str, str]] = set()
        for item in rows:
            key = (item["column"], item["relation"], item["value"], item["action"])
            if key in seen:
                continue
            seen.add(key)
            deduped.append(item)

        views.append(
            {
                "preset": preset,
                "note": str(spec.get("note", "")),
                "filters": deduped,
            }
        )
    return views


def _extract_path_hints(summary_path: str, max_hints: int) -> list[str]:
    hints: list[str] = []
    for value in _load_string_values(summary_path):
        lowered = value.lower()
        for needle, normalized in STRING_HINT_RULES:
            if needle in lowered:
                hints.append(normalized)
                break
    deduped: list[str] = []
    seen: set[str] = set()
    for item in hints:
        key = item.lower()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
        if len(deduped) >= max(0, max_hints):
            break
    return deduped


def _build_observation_points(presets: list[str], path_hints: list[str]) -> list[str]:
    points: list[str] = []
    for preset in presets:
        note = str(PRESET_FILTERS[preset].get("note", "")).strip()
        if note:
            points.append(note)
    if any("run" in hint.lower() for hint in path_hints):
        points.append("重点核对 Run/RunOnce 是否有写入或查询，确认是否存在用户态持久化。")
    if any("startup" in hint.lower() for hint in path_hints):
        points.append("重点核对 Startup 目录的 CreateFile/WriteFile/SetRenameInformationFile。")
    if any(hint.lower().startswith("http") for hint in path_hints):
        points.append("静态字符串中出现 URL，动态时可结合 Procmon Network 类事件与抓包工具交叉验证。")

    deduped: list[str] = []
    seen: set[str] = set()
    for item in points:
        if item in seen:
            continue
        seen.add(item)
        deduped.append(item)
    return deduped


def _write_csv(path: Path, rows: list[dict[str, str]]) -> Path:
    csv_path = path.with_suffix(".csv")
    with csv_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["view", "column", "relation", "value", "action", "reason"])
        writer.writeheader()
        writer.writerows(rows)
    return csv_path


def _write_markdown(
    path: Path,
    sample_name: str,
    sample_path: str,
    summary_path: str,
    requested_presets: list[str],
    inferred_presets: list[str],
    baseline_filters: list[dict[str, str]],
    preset_views: list[dict[str, Any]],
    path_hints: list[str],
    observation_points: list[str],
) -> None:
    lines = [
        f"# Procmon Filter Plan: {sample_name}",
        "",
        f"生成时间：{datetime.now().isoformat(timespec='seconds')}",
        "",
        "## 1. Inputs",
        "",
        f"- Sample: `{sample_name}`",
        f"- Sample Path: `{sample_path}`" if sample_path else "- Sample Path: ``",
        f"- Summary Path: `{summary_path}`" if summary_path else "- Summary Path: ``",
        f"- Requested Presets: `{', '.join(requested_presets)}`" if requested_presets else "- Requested Presets: ``",
        f"- Inferred Presets: `{', '.join(inferred_presets)}`" if inferred_presets else "- Inferred Presets: ``",
        "",
        "## 2. Baseline Filters",
        "",
        "说明：Procmon 的 include 规则更适合按视图分批应用，下面的 baseline 规则建议长期保留。",
        "",
        "| Column | Relation | Value | Action | Reason |",
        "|---|---|---|---|---|",
    ]

    for item in baseline_filters:
        lines.append(
            f"| `{item['column']}` | `{item['relation']}` | `{item['value']}` | `{item['action']}` | {item['reason']} |"
        )

    lines.extend(["", "## 3. Preset Views", ""])
    for view in preset_views:
        lines.extend(
            [
                "",
                f"### {view['preset']}",
                "",
                f"- 说明：{view['note']}",
                "- 用法：保留 baseline 规则，再单独启用这一组 include 规则；不要把多个大类视图一次性全开。",
                "",
                "| Column | Relation | Value | Action | Reason |",
                "|---|---|---|---|---|",
            ]
        )
        for item in view["filters"]:
            lines.append(
                f"| `{item['column']}` | `{item['relation']}` | `{item['value']}` | `{item['action']}` | {item['reason']} |"
            )

    lines.extend(["", "## 4. Path Hints", ""])
    if path_hints:
        for hint in path_hints:
            lines.append(f"- `{hint}`")
    else:
        lines.append("- 暂无额外路径线索。")

    lines.extend(["", "## 5. Observation Points", ""])
    if observation_points:
        for point in observation_points:
            lines.append(f"- {point}")
    else:
        lines.append("- 先从 Process Name + Operation 组合开始，按结果逐步收缩范围。")

    lines.extend(
        [
            "",
            "## 6. Usage",
            "",
            "- 先在 Procmon 中清空旧过滤器。",
            "- 先应用 baseline 规则，确认只剩目标进程和少量噪音。",
            "- 之后一次只启用一个 preset view 的 include 规则。",
            "- 如果日志量仍大，再叠加该 view 下的 `Path contains ...` 规则。",
            "- 观察完成后切换到下一组视图，不建议把多个大类视图同时 include。",
        ]
    )

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def make_procmon_filters(
    sample_path: str = "",
    summary_path: str = "",
    output_path: str = "",
    presets: str = "",
    extra_path_contains: str = "",
    include_noise_excludes: bool = True,
    max_path_hints: int = 8,
) -> dict[str, Any]:
    if not sample_path and not summary_path:
        raise ToolError("sample_path or summary_path is required")

    resolved_sample = str(resolve_file(sample_path)) if sample_path else ""
    resolved_summary = ""
    sample_name = Path(resolved_sample).name if resolved_sample else "sample"

    if summary_path:
        resolved_summary = str(resolve_summary(summary_path))
        if sample_name == "sample":
            _path, data = ghidra_summary.load_summary(resolved_summary)
            program = data.get("program", {})
            sample_name = str(program.get("name", "")).strip() or sample_name

    imported_names, import_source = _load_import_names(resolved_sample, resolved_summary)
    requested_presets = [item.lower() for item in _parse_csv(presets)]
    unknown = [item for item in requested_presets if item not in PRESET_FILTERS]
    if unknown:
        known = ", ".join(sorted(PRESET_FILTERS))
        raise ToolError(f"unknown presets: {', '.join(unknown)}; known presets: {known}")

    inferred_presets = _infer_presets(imported_names)
    effective_presets = requested_presets or inferred_presets
    if not effective_presets:
        effective_presets = ["file", "process"]

    path_hints = _extract_path_hints(resolved_summary, max_path_hints) if resolved_summary else []
    extra_paths = _parse_csv(extra_path_contains)
    for hint in extra_paths:
        if hint not in path_hints:
            path_hints.append(hint)

    baseline_filters = _build_baseline_filters(sample_name, include_noise_excludes)
    preset_views = _build_preset_views(effective_presets, path_hints)
    observation_points = _build_observation_points(effective_presets, path_hints)

    out_path = _resolve_output_path(output_path, sample_name)
    _write_markdown(
        out_path,
        sample_name,
        resolved_sample,
        resolved_summary,
        requested_presets,
        inferred_presets,
        baseline_filters,
        preset_views,
        path_hints,
        observation_points,
    )
    csv_rows = [{"view": "baseline", **item} for item in baseline_filters]
    for view in preset_views:
        csv_rows.extend({"view": view["preset"], **item} for item in view["filters"])
    csv_path = _write_csv(out_path, csv_rows)

    return {
        "output_path": str(out_path),
        "csv_path": str(csv_path),
        "sample_name": sample_name,
        "sample_path": resolved_sample,
        "summary_path": resolved_summary,
        "requested_presets": requested_presets,
        "inferred_presets": inferred_presets,
        "effective_presets": effective_presets,
        "import_source": import_source,
        "imports_considered_total": len(imported_names),
        "path_hints": path_hints,
        "baseline_filters": baseline_filters,
        "baseline_filter_count": len(baseline_filters),
        "preset_views": preset_views,
        "preset_view_count": len(preset_views),
        "csv_row_count": len(csv_rows),
        "observation_points": observation_points,
    }
