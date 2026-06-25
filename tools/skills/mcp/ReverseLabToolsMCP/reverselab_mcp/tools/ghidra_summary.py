from __future__ import annotations

import json
from typing import Any

from ..config import GHIDRA_EXPORTS_DIR
from ..errors import ToolError
from ..paths import resolve_summary
from ..utils import contains, match_any
from .procmon_filters import PRESET_FILTERS


def load_summary(summary_path: str = "") -> tuple[Any, dict[str, Any]]:
    path = resolve_summary(summary_path)
    data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    if not isinstance(data, dict):
        raise ToolError(f"summary JSON root is not an object: {path}")
    return path, data


def ghidra_summary_list(limit: int = 20) -> dict[str, Any]:
    GHIDRA_EXPORTS_DIR.mkdir(parents=True, exist_ok=True)
    items = []
    for path in sorted(GHIDRA_EXPORTS_DIR.glob("*-ghidra-summary.json"), key=lambda item: item.stat().st_mtime, reverse=True):
        items.append(
            {
                "path": str(path),
                "name": path.name,
                "size": path.stat().st_size,
                "mtime": path.stat().st_mtime,
            }
        )
    return {
        "summaries": items[: max(0, limit)],
        "summaries_total": len(items),
    }


def ghidra_summary_overview(summary_path: str = "") -> dict[str, Any]:
    path, data = load_summary(summary_path)
    return {
        "summary_path": str(path),
        "export_schema": data.get("export_schema", "legacy"),
        "program": data.get("program", {}),
        "memory_blocks": data.get("memory_blocks", []),
        "functions_total": data.get("functions_total", 0),
        "functions_returned": len(data.get("functions", [])) if isinstance(data.get("functions"), list) else 0,
        "imports_total": data.get("imports_total", 0),
        "imports_returned": data.get("imports_returned", len(data.get("imports", [])) if isinstance(data.get("imports"), list) else 0),
        "strings_total": data.get("strings_total", 0),
        "strings_returned": data.get("strings_returned", len(data.get("strings", [])) if isinstance(data.get("strings"), list) else 0),
    }


def ghidra_summary_function_detail(
    summary_path: str = "",
    address: str = "",
    name: str = "",
    include_decompile: bool = True,
    max_decompile_chars: int = 12000,
) -> dict[str, Any]:
    path, data = load_summary(summary_path)
    items = data.get("functions", [])
    if not isinstance(items, list):
        items = []

    normalized_address = address.lower().replace("0x", "").strip()
    normalized_name = name.lower().strip()
    for item in items:
        if not isinstance(item, dict):
            continue
        entry = str(item.get("entry", "")).lower().replace("0x", "")
        item_name = str(item.get("name", "")).lower()
        if normalized_address and normalized_address not in entry:
            continue
        if normalized_name and normalized_name not in item_name:
            continue
        result = dict(item)
        if not include_decompile:
            result.pop("decompile", None)
        else:
            decompile = result.get("decompile")
            if isinstance(decompile, dict):
                preview = str(decompile.get("preview", ""))
                if len(preview) > max(0, max_decompile_chars):
                    decompile = dict(decompile)
                    decompile["preview"] = preview[: max(0, max_decompile_chars)] + "..."
                    result["decompile"] = decompile
        return {
            "summary_path": str(path),
            "query": {"address": address, "name": name},
            "function": result,
        }

    return {
        "summary_path": str(path),
        "query": {"address": address, "name": name},
        "function": None,
        "error": "function not found",
    }


def ghidra_summary_functions(summary_path: str = "", query: str = "", address: str = "", limit: int = 50) -> dict[str, Any]:
    path, data = load_summary(summary_path)
    items = data.get("functions", [])
    if not isinstance(items, list):
        items = []

    normalized_address = address.lower().replace("0x", "").strip()
    matches = []
    for item in items:
        if not isinstance(item, dict):
            continue
        entry = str(item.get("entry", "")).lower().replace("0x", "")
        if normalized_address and normalized_address not in entry:
            continue
        if not match_any(item, query, ["name", "entry", "signature", "calling_convention"]):
            continue
        matches.append(item)

    return {
        "summary_path": str(path),
        "query": query,
        "address": address,
        "matches": matches[: max(0, limit)],
        "matches_total": len(matches),
        "exported_functions": len(items),
        "functions_total": data.get("functions_total", 0),
    }


def ghidra_summary_imports(
    summary_path: str = "",
    query: str = "",
    library: str = "",
    min_refs: int = 0,
    limit: int = 50,
) -> dict[str, Any]:
    path, data = load_summary(summary_path)
    items = data.get("imports", [])
    if not isinstance(items, list):
        items = []

    matches = []
    for item in items:
        if not isinstance(item, dict):
            continue
        if library and not contains(item.get("namespace"), library):
            continue
        if int(item.get("reference_count", 0) or 0) < max(0, min_refs):
            continue
        if not match_any(item, query, ["name", "namespace", "address"]):
            continue
        matches.append(item)

    return {
        "summary_path": str(path),
        "query": query,
        "library": library,
        "min_refs": min_refs,
        "matches": matches[: max(0, limit)],
        "matches_total": len(matches),
        "exported_imports": len(items),
        "imports_total": data.get("imports_total", 0),
    }


def ghidra_summary_strings(
    summary_path: str = "",
    query: str = "",
    min_length: int = 0,
    limit: int = 50,
) -> dict[str, Any]:
    path, data = load_summary(summary_path)
    items = data.get("strings", [])
    if not isinstance(items, list):
        items = []

    matches = []
    for item in items:
        if not isinstance(item, dict):
            continue
        if int(item.get("length", 0) or 0) < max(0, min_length):
            continue
        if not match_any(item, query, ["value", "address"]):
            continue
        matches.append(item)

    return {
        "summary_path": str(path),
        "query": query,
        "min_length": min_length,
        "matches": matches[: max(0, limit)],
        "matches_total": len(matches),
        "exported_strings": len(items),
        "strings_total": data.get("strings_total", 0),
    }


def _parse_terms(text: str) -> list[str]:
    terms: list[str] = []
    for raw in text.replace(",", "\n").replace("\r", "\n").split("\n"):
        value = raw.strip()
        if value:
            terms.append(value)
    return terms


def _behavior_terms(behavior: str) -> tuple[list[str], list[str]]:
    normalized = behavior.strip().lower()
    if not normalized:
        return [], []
    if normalized not in PRESET_FILTERS:
        known = ", ".join(sorted(PRESET_FILTERS))
        raise ToolError(f"unknown behavior preset: {behavior}; known presets: {known}")
    spec = PRESET_FILTERS[normalized]
    markers = [str(item).strip() for item in spec.get("api_markers", []) if str(item).strip()]
    hint_map = {
        "file": ["appdata", "programdata", "temp", "startup", "tasks"],
        "registry": ["hklm", "hkcu", "currentversion\\run", "runonce", "services", "image file execution options"],
        "process": ["cmd.exe", "powershell", "rundll32", "createprocess", "shell execute"],
        "network": ["http://", "https://", "winhttp", "internetopen", "connect", "user-agent"],
        "image": [".dll", "loadlibrary", "getprocaddress"],
    }
    return markers, hint_map.get(normalized, [])


BOILERPLATE_NAME_MARKERS = [
    "__scrt",
    "__security",
    "__gs",
    "__chkstk",
    "_onexit",
    "atexit",
    "memcpy",
    "memmove",
    "memcmp",
    "wcscmp",
    "operator_new",
    "guard_check",
]


HIGH_SIGNAL_IMPORT_TERMS = [
    "CreateFile",
    "WriteFile",
    "ReadFile",
    "DeleteFile",
    "RegSetValue",
    "RegCreateKey",
    "RegOpenKey",
    "CreateProcess",
    "ShellExecute",
    "WinHttp",
    "Internet",
    "connect",
    "send",
    "recv",
    "VirtualAlloc",
    "VirtualProtect",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "LoadLibrary",
    "GetProcAddress",
    "Crypt",
    "BCrypt",
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
]


HIGH_SIGNAL_STRING_TERMS = [
    "http://",
    "https://",
    "runonce",
    "currentversion\\run",
    "powershell",
    "cmd.exe",
    "appdata",
    "programdata",
    "\\temp\\",
    ".dll",
    ".exe",
    "user-agent",
]


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _ref_text(refs: list[Any], keys: list[str]) -> str:
    parts: list[str] = []
    for ref in refs:
        if not isinstance(ref, dict):
            continue
        for key in keys:
            value = str(ref.get(key, "")).strip()
            if value:
                parts.append(value)
    return " ".join(parts)


def _score_function(item: dict[str, Any], terms: list[str]) -> tuple[int, list[str]]:
    name = str(item.get("name", "")).strip()
    signature = str(item.get("signature", "")).strip()
    body_size = int(item.get("body_size", 0) or 0)
    import_refs = _as_list(item.get("import_refs"))
    string_refs = _as_list(item.get("string_refs"))
    callers = _as_list(item.get("callers"))
    callees = _as_list(item.get("callees"))
    decompile = item.get("decompile") if isinstance(item.get("decompile"), dict) else {}
    decompile_preview = str(decompile.get("preview", ""))
    score = 0
    reasons: list[str] = []

    if item.get("thunk"):
        score -= 60
        reasons.append("thunk")
    if item.get("external"):
        score -= 80
        reasons.append("external")
    if any(token in name.lower() for token in BOILERPLATE_NAME_MARKERS):
        score -= 55
        reasons.append("compiler/runtime boilerplate")
    if any(token in name.lower() for token in ["entry", "winmain", "main", "dllmain", "init", "start"]):
        score += 70
        reasons.append("entry/init naming")
    if body_size >= 256:
        score += 35
        reasons.append("large body")
    elif body_size >= 96:
        score += 18
        reasons.append("medium body")

    haystack = f"{name} {signature}".lower()
    for term in terms:
        normalized = term.lower()
        if normalized and normalized in haystack:
            score += 45
            reasons.append(f"matched term:{term}")

    import_text = _ref_text(import_refs, ["name", "namespace"]).lower()
    if import_refs:
        score += min(140, 25 * len(import_refs))
        reasons.append(f"import refs:{len(import_refs)}")
    for marker in HIGH_SIGNAL_IMPORT_TERMS:
        if marker.lower() in import_text:
            score += 45
            reasons.append(f"high-signal import:{marker}")
    for term in terms:
        normalized = term.lower()
        if normalized and normalized in import_text:
            score += 65
            reasons.append(f"behavior import match:{term}")

    string_text = _ref_text(string_refs, ["value"]).lower()
    if string_refs:
        score += min(110, 18 * len(string_refs))
        reasons.append(f"string refs:{len(string_refs)}")
    for marker in HIGH_SIGNAL_STRING_TERMS:
        if marker.lower() in string_text:
            score += 35
            reasons.append(f"high-signal string:{marker}")
    for term in terms:
        normalized = term.lower()
        if normalized and normalized in string_text:
            score += 55
            reasons.append(f"behavior string match:{term}")

    if callers:
        score += min(40, 4 * len(callers))
        reasons.append(f"callers:{len(callers)}")
    if callees:
        score += min(50, 5 * len(callees))
        reasons.append(f"callees:{len(callees)}")

    decompile_haystack = decompile_preview.lower()
    if decompile.get("status") == "ok" and decompile_preview:
        score += 12
        reasons.append("decompile available")
    for term in terms:
        normalized = term.lower()
        if normalized and normalized in decompile_haystack:
            score += 35
            reasons.append(f"decompile term:{term}")

    if name.startswith("FUN_") and body_size >= 128:
        score += 10
        reasons.append("generic name but sizable")

    return score, reasons


def ghidra_summary_call_focus(
    summary_path: str = "",
    query: str = "",
    behavior: str = "",
    min_body_size: int = 32,
    limit: int = 12,
) -> dict[str, Any]:
    path, data = load_summary(summary_path)
    functions = data.get("functions", [])
    imports = data.get("imports", [])
    strings = data.get("strings", [])
    if not isinstance(functions, list):
        functions = []
    if not isinstance(imports, list):
        imports = []
    if not isinstance(strings, list):
        strings = []

    query_terms = _parse_terms(query)
    behavior_markers, behavior_hints = _behavior_terms(behavior)
    all_terms = query_terms + behavior_markers + behavior_hints

    matched_imports: list[dict[str, Any]] = []
    for item in imports:
        if not isinstance(item, dict):
            continue
        text = " ".join(
            [
                str(item.get("name", "")),
                str(item.get("namespace", "")),
                str(item.get("address", "")),
            ]
        ).lower()
        if not all_terms or any(term.lower() in text for term in all_terms):
            matched_imports.append(item)
    matched_imports.sort(key=lambda item: int(item.get("reference_count", 0) or 0), reverse=True)

    matched_strings: list[dict[str, Any]] = []
    for item in strings:
        if not isinstance(item, dict):
            continue
        value = str(item.get("value", "")).strip()
        if not value:
            continue
        lowered = value.lower()
        if not all_terms or any(term.lower() in lowered for term in all_terms):
            matched_strings.append(item)
    matched_strings.sort(key=lambda item: (int(item.get("length", 0) or 0), str(item.get("value", "")).lower()), reverse=True)

    ranked_functions: list[dict[str, Any]] = []
    for item in functions:
        if not isinstance(item, dict):
            continue
        body_size = int(item.get("body_size", 0) or 0)
        if body_size < max(0, min_body_size):
            continue
        score, reasons = _score_function(item, query_terms + behavior_hints)
        if score <= 0 and all_terms:
            continue
        ranked_functions.append(
            {
                "name": item.get("name", ""),
                "entry": item.get("entry", ""),
                "body_size": body_size,
                "parameter_count": item.get("parameter_count", 0),
                "calling_convention": item.get("calling_convention", ""),
                "signature": item.get("signature", ""),
                "caller_count": len(_as_list(item.get("callers"))),
                "callee_count": len(_as_list(item.get("callees"))),
                "import_ref_count": len(_as_list(item.get("import_refs"))),
                "string_ref_count": len(_as_list(item.get("string_refs"))),
                "import_refs": _as_list(item.get("import_refs"))[:8],
                "string_refs": _as_list(item.get("string_refs"))[:8],
                "decompile_status": (item.get("decompile") or {}).get("status", "") if isinstance(item.get("decompile"), dict) else "",
                "score": score,
                "reasons": reasons,
            }
        )
    ranked_functions.sort(key=lambda item: (item["score"], item["body_size"]), reverse=True)

    return {
        "summary_path": str(path),
        "query": query,
        "behavior": behavior,
        "matched_imports": matched_imports[: max(0, limit)],
        "matched_imports_total": len(matched_imports),
        "matched_strings": matched_strings[: max(0, limit)],
        "matched_strings_total": len(matched_strings),
        "suggested_functions": ranked_functions[: max(0, limit)],
        "suggested_functions_total": len(ranked_functions),
        "evidence_mode": "semantic_xrefs" if any(isinstance(item, dict) and ("import_refs" in item or "string_refs" in item or "callees" in item) for item in functions) else "legacy_heuristic",
    }
