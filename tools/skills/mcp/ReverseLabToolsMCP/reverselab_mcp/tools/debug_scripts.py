from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from ..config import DEBUG_SCRIPTS_DIR
from ..errors import ToolError
from ..paths import ensure_under, resolve_file, resolve_summary
from ..utils import match_any, slug
from . import ghidra_summary, triage


PRESET_APIS: dict[str, list[str]] = {
    "loader": [
        "LoadLibraryA",
        "LoadLibraryW",
        "LoadLibraryExA",
        "LoadLibraryExW",
        "GetProcAddress",
        "FreeLibrary",
    ],
    "file": [
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
        "SetFilePointer",
        "SetFilePointerEx",
        "GetFileSize",
        "GetFileSizeEx",
        "FindFirstFileA",
        "FindFirstFileW",
    ],
    "registry": [
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
    "network": [
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
    "process": [
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
    "crypto": [
        "CryptAcquireContextA",
        "CryptAcquireContextW",
        "CryptCreateHash",
        "CryptHashData",
        "CryptDeriveKey",
        "CryptEncrypt",
        "CryptDecrypt",
        "BCryptOpenAlgorithmProvider",
        "BCryptGenerateSymmetricKey",
        "BCryptEncrypt",
        "BCryptDecrypt",
        "BCryptHashData",
    ],
    "antidebug": [
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess",
        "OutputDebugStringA",
        "OutputDebugStringW",
        "GetTickCount",
        "GetTickCount64",
        "QueryPerformanceCounter",
    ],
    "ui": [
        "MessageBoxA",
        "MessageBoxW",
        "DialogBoxParamA",
        "DialogBoxParamW",
        "GetDlgItemTextA",
        "GetDlgItemTextW",
    ],
}


def _parse_csv(text: str) -> list[str]:
    items: list[str] = []
    for raw in text.replace("\r", "\n").replace(",", "\n").split("\n"):
        value = raw.strip()
        if value:
            items.append(value)
    return items


def _normalize_api(value: str) -> str:
    return value.strip()


def _import_name_set(sample_path: str, summary_path: str) -> tuple[set[str], str]:
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


def _load_summary_data(summary_path: str) -> tuple[Path, dict[str, Any]]:
    path = resolve_summary(summary_path)
    actual_path, data = ghidra_summary.load_summary(str(path))
    return Path(actual_path), data


def _default_output_path(sample_name: str, variant: str = "") -> Path:
    DEBUG_SCRIPTS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    suffix = f"-{slug(variant)}" if variant else ""
    return DEBUG_SCRIPTS_DIR / f"{slug(sample_name)}-x64dbg-breakpoints{suffix}-{stamp}.txt"


def _resolve_output_path(output_path: str, sample_name: str, variant: str = "") -> Path:
    if not output_path:
        return _default_output_path(sample_name, variant)
    path = Path(output_path).expanduser().resolve()
    ensure_under(path, [DEBUG_SCRIPTS_DIR], "debug script output")
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _script_variant(requested_presets: list[str], api_names: str, function_query: str, function_addresses: str) -> str:
    if requested_presets:
        return "preset-" + "-".join(requested_presets[:4])
    if api_names.strip():
        return "apis-" + "-".join(name.strip() for name in api_names.split(",")[:3] if name.strip())
    if function_addresses.strip():
        return "functions"
    if function_query.strip():
        return "query-" + function_query.strip()[:32]
    return ""


def _sample_name(sample_path: str, summary: dict[str, Any] | None) -> str:
    if sample_path:
        return resolve_file(sample_path).name
    if summary:
        program = summary.get("program", {})
        name = str(program.get("name", "")).strip()
        if name:
            return name
    return "sample"


def _build_api_breakpoints(
    presets_text: str,
    api_names_text: str,
    imported_names: set[str],
) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    requested_presets = [item.lower() for item in _parse_csv(presets_text)]
    unknown_presets = [item for item in requested_presets if item not in PRESET_APIS]
    if unknown_presets:
        known = ", ".join(sorted(PRESET_APIS))
        raise ToolError(f"unknown presets: {', '.join(unknown_presets)}; known presets: {known}")

    breakpoints: list[dict[str, Any]] = []
    seen: set[str] = set()

    for preset in requested_presets:
        for api in PRESET_APIS[preset]:
            if imported_names and api.lower() not in imported_names:
                continue
            expression = f"bp {api}"
            if expression.lower() in seen:
                continue
            seen.add(expression.lower())
            breakpoints.append({"expression": expression, "api": api, "source": f"preset:{preset}"})

    for raw in _parse_csv(api_names_text):
        api = _normalize_api(raw)
        expression = f"bp {api}"
        if expression.lower() in seen:
            continue
        seen.add(expression.lower())
        breakpoints.append({"expression": expression, "api": api, "source": "explicit"})

    return breakpoints, requested_presets, sorted(imported_names)


def _build_function_breakpoints(
    summary_path: str,
    function_query: str,
    function_addresses: str,
    function_limit: int,
) -> tuple[list[dict[str, Any]], str]:
    if not summary_path and not function_query and not function_addresses:
        return [], ""

    path, data = _load_summary_data(summary_path)
    items = data.get("functions", [])
    if not isinstance(items, list):
        items = []

    program = data.get("program", {})
    image_base_text = str(program.get("image_base", "")).strip().lower().replace("0x", "")
    if not image_base_text:
        raise ToolError(f"summary has no image_base: {path}")
    image_base = int(image_base_text, 16)

    requested_addresses = {
        value.lower().replace("0x", "")
        for value in _parse_csv(function_addresses)
    }

    matches: list[dict[str, Any]] = []
    seen_entries: set[str] = set()
    for item in items:
        if not isinstance(item, dict):
            continue
        entry_text = str(item.get("entry", "")).strip().lower().replace("0x", "")
        if not entry_text:
            continue
        query_ok = match_any(item, function_query, ["name", "entry", "signature", "calling_convention"])
        address_ok = not requested_addresses or entry_text in requested_addresses
        if requested_addresses and not address_ok and not function_query:
            continue
        if function_query and not query_ok and entry_text not in requested_addresses:
            continue
        if entry_text in seen_entries:
            continue
        seen_entries.add(entry_text)
        matches.append(item)

    if function_limit > 0:
        matches = matches[:function_limit]

    breakpoints: list[dict[str, Any]] = []
    for item in matches:
        entry_value = int(str(item.get("entry")).replace("0x", ""), 16)
        if entry_value < image_base:
            continue
        rva = entry_value - image_base
        breakpoints.append(
            {
                "expression": f"bp mod.main()+0x{rva:X}",
                "name": item.get("name", ""),
                "entry": f"0x{entry_value:X}",
                "rva": f"0x{rva:X}",
                "signature": item.get("signature", ""),
            }
        )

    return breakpoints, str(path)


def make_x64dbg_breakpoint_script(
    sample_path: str = "",
    summary_path: str = "",
    output_path: str = "",
    presets: str = "",
    api_names: str = "",
    function_query: str = "",
    function_addresses: str = "",
    function_limit: int = 10,
) -> dict[str, Any]:
    if not any([sample_path, summary_path, presets, api_names, function_query, function_addresses]):
        raise ToolError("at least one of sample_path, summary_path, presets, api_names, function_query, function_addresses is required")

    summary_data: dict[str, Any] | None = None
    resolved_summary_path = ""
    if summary_path:
        summary_obj_path, summary_data = _load_summary_data(summary_path)
        resolved_summary_path = str(summary_obj_path)

    sample_name = _sample_name(sample_path, summary_data)
    imported_names, import_source = _import_name_set(sample_path, resolved_summary_path)
    api_breakpoints, requested_presets, imported_name_list = _build_api_breakpoints(presets, api_names, imported_names)
    function_breakpoints, function_source = _build_function_breakpoints(
        resolved_summary_path or summary_path,
        function_query,
        function_addresses,
        function_limit,
    )

    if not api_breakpoints and not function_breakpoints:
        raise ToolError("no breakpoints generated; adjust presets/api_names/function_query/function_addresses")

    variant = _script_variant(requested_presets, api_names, function_query, function_addresses)
    out_path = _resolve_output_path(output_path, sample_name, variant)
    lines = [
        "// ReverseLab x64dbg breakpoint script",
        f"// Generated: {datetime.now().isoformat(timespec='seconds')}",
        f"// Sample: {sample_name}",
        "// Usage: load the sample in x64dbg, open this script in Script tab, then run it.",
    ]
    if sample_path:
        lines.append(f"// Sample path: {resolve_file(sample_path)}")
    if resolved_summary_path:
        lines.append(f"// Summary: {resolved_summary_path}")
    if requested_presets:
        lines.append(f"// Presets: {', '.join(requested_presets)}")
    lines.append("")

    if api_breakpoints:
        lines.append("// API breakpoints")
        for item in api_breakpoints:
            lines.append(item["expression"])
        lines.append("")

    if function_breakpoints:
        lines.append("// Internal function breakpoints (module-relative RVA)")
        for item in function_breakpoints:
            lines.append(item["expression"])
        lines.append("")

    content = "\n".join(lines).rstrip() + "\n"
    out_path.write_text(content, encoding="utf-8")

    return {
        "output_path": str(out_path),
        "sample_name": sample_name,
        "sample_path": str(resolve_file(sample_path)) if sample_path else "",
        "summary_path": resolved_summary_path,
        "presets": requested_presets,
        "import_source": import_source,
        "imports_considered_total": len(imported_name_list),
        "api_breakpoints": api_breakpoints,
        "function_breakpoints": function_breakpoints,
        "function_query": function_query,
        "function_source": function_source,
        "function_limit": function_limit,
        "line_count": len(lines),
        "script_preview": lines[:20],
    }
