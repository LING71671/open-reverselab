from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from ..config import IOC_EXPORTS_DIR, YARA_EXPORTS_DIR
from ..errors import ToolError
from ..paths import ensure_under, resolve_file, resolve_summary
from ..utils import slug
from . import ghidra_summary, triage
from .debug_scripts import PRESET_APIS


DEFAULT_NOISY_STRINGS = {
    "mz",
    "this program cannot be run in dos mode",
    ".text",
    "text",
    ".data",
    "data",
    ".rdata",
    "rdata",
    ".pdata",
    "pdata",
    ".didat",
    "didat",
    ".rsrc",
    "rsrc",
    ".reloc",
    "reloc",
    "fothk",
    "richt",
}
TRIAGE_STRING_RE = re.compile(
    r"^\s*\d+\s+0x[0-9a-fA-F]+\s+0x[0-9a-fA-F]+\s+\d+\s+\d+\s+\([^)]+\)\s+\S+\s+(.*)$"
)
LOW_SIGNAL_LIBRARIES = {
    "gdi32.dll",
    "user32.dll",
    "comdlg32.dll",
}
HIGH_SIGNAL_LIBRARIES = {
    "advapi32.dll",
    "bcrypt.dll",
    "crypt32.dll",
    "kernel32.dll",
    "ntdll.dll",
    "urlmon.dll",
    "winhttp.dll",
    "wininet.dll",
    "ws2_32.dll",
}


def _default_output_base(sample_name: str, rule_name: str) -> Path:
    YARA_EXPORTS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    base_name = slug(rule_name or Path(sample_name or "sample").stem)
    return YARA_EXPORTS_DIR / f"{base_name}-yara-{stamp}"


def _resolve_output_base(output_path: str, sample_name: str, rule_name: str) -> Path:
    if not output_path:
        return _default_output_base(sample_name, rule_name)
    path = Path(output_path).expanduser().resolve()
    ensure_under(path, [YARA_EXPORTS_DIR], "yara output path")
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.suffix:
        return path.with_suffix("")
    return path


def _resolve_ioc_path(ioc_json_path: str) -> Path:
    resolved = Path(ioc_json_path).expanduser().resolve(strict=True)
    if not resolved.is_file():
        raise ToolError(f"not a file: {resolved}")
    if resolved.suffix.lower() != ".json":
        raise ToolError(f"IOC path is not JSON: {resolved}")
    ensure_under(resolved, [IOC_EXPORTS_DIR], "ioc json path")
    return resolved


def _safe_text(value: Any) -> str:
    return str(value or "").strip()


def _sample_name(sample_path: str, summary_data: dict[str, Any], ioc_data: dict[str, Any]) -> str:
    if sample_path:
        return resolve_file(sample_path).name
    program = summary_data.get("program", {}) if isinstance(summary_data.get("program"), dict) else {}
    name = _safe_text(program.get("name"))
    if name:
        return name
    return _safe_text(ioc_data.get("sample_name")) or "sample"


def _load_summary_data(summary_path: str) -> tuple[str, dict[str, Any]]:
    resolved = str(resolve_summary(summary_path))
    _path, data = ghidra_summary.load_summary(resolved)
    return resolved, data


def _load_ioc_data(ioc_json_path: str) -> tuple[str, dict[str, Any]]:
    resolved = str(_resolve_ioc_path(ioc_json_path))
    data = json.loads(Path(resolved).read_text(encoding="utf-8", errors="replace"))
    if not isinstance(data, dict):
        raise ToolError(f"IOC JSON root is not an object: {resolved}")
    return resolved, data


def _hashes_from_sample(sample_path: str) -> dict[str, Any]:
    if not sample_path:
        return {}
    return triage.hash_file(sample_path)


def _collect_imports(summary_data: dict[str, Any], triage_result: dict[str, Any]) -> list[dict[str, str]]:
    combined: list[dict[str, str]] = []
    raw_items: list[dict[str, Any]] = []
    if isinstance(summary_data.get("imports"), list):
        raw_items.extend(item for item in summary_data.get("imports", []) if isinstance(item, dict))
    triage_imports = ((triage_result.get("imports", {}) or {}).get("stdout", {}) or {}).get("imports", []) or []
    raw_items.extend(item for item in triage_imports if isinstance(item, dict))

    seen: set[tuple[str, str]] = set()
    for item in raw_items:
        library = _safe_text(item.get("libname", item.get("namespace", "")))
        name = _safe_text(item.get("name"))
        if not library or not name:
            continue
        key = (library.lower(), name.lower())
        if key in seen:
            continue
        seen.add(key)
        combined.append({"library": library, "name": name})
    return combined


def _string_score(value: str, source: str) -> int:
    lower = value.lower()
    score = 0
    if source in {"url", "registry_path", "file_path", "email"}:
        score += 90
    elif source == "domain":
        score += 75
    elif source == "file_artifact":
        score += 45
    elif source == "summary_string":
        score += 35
    elif source == "triage_string":
        score += 25

    if "\\" in value or "/" in value:
        score += 15
    if any(ch.isdigit() for ch in value):
        score += 8
    if len(value) >= 12:
        score += 8
    if lower.endswith((".dll", ".exe", ".sys", ".drv")):
        score -= 10
    if lower in DEFAULT_NOISY_STRINGS:
        score -= 100
    return score


def _clean_string_candidate(text: str) -> str:
    cleaned = text.replace("\r", " ").replace("\n", " ").strip().strip("`")
    cleaned = re.sub(r"\s+", " ", cleaned)
    return cleaned[:120]


def _is_good_string(value: str) -> bool:
    if not value or len(value) < 4:
        return False
    lower = value.lower()
    lower_clean = lower.strip("!@#$%^&*()[]{};:'\"`~.,<>/?\\|+-=_ ")
    if lower in DEFAULT_NOISY_STRINGS or lower_clean in DEFAULT_NOISY_STRINGS:
        return False
    if "this program cannot be run in dos mode" in lower:
        return False
    if re.match(r"^\d+\s+0x[0-9a-f]+\s+0x[0-9a-f]+", lower):
        return False
    if value.count(" ") > 10:
        return False
    if any(ord(ch) < 32 for ch in value):
        return False
    if "\\x" in value:
        return False
    alnum_count = sum(ch.isalnum() for ch in value)
    if alnum_count < max(4, len(value) // 5):
        return False
    return True


def _parse_triage_string(text: str) -> str:
    match = TRIAGE_STRING_RE.match(text)
    if match:
        return match.group(1).strip()
    marker_match = re.search(r"\s(?:ascii|utf8|wide|utf16le|utf16be)\s+(.+)$", text, re.IGNORECASE)
    if marker_match:
        return marker_match.group(1).strip()
    if re.search(r"\s(?:ascii|utf8|wide|utf16le|utf16be)\s*$", text, re.IGNORECASE):
        return ""
    for marker in (" ascii ", " utf8 ", " wide ", " utf16le ", " utf16be "):
        if marker in text:
            return text.split(marker, 1)[1].strip()
    return text.strip()


def _collect_ioc_strings(ioc_data: dict[str, Any]) -> list[dict[str, str]]:
    category_map = {
        "urls": "url",
        "domains": "domain",
        "emails": "email",
        "registry_paths": "registry_path",
        "file_paths": "file_path",
        "file_artifacts": "file_artifact",
    }
    candidates: list[dict[str, str]] = []
    categories = ioc_data.get("categories", {}) if isinstance(ioc_data.get("categories"), dict) else {}
    for category, source in category_map.items():
        items = categories.get(category, [])
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            sources = item.get("sources", [])
            source_types = {
                str(source.get("source_type", "")).strip().lower()
                for source in sources
                if isinstance(source, dict)
            }
            if source_types and source_types == {"note"}:
                continue
            value = _clean_string_candidate(_safe_text(item.get("value")))
            if _is_good_string(value):
                candidates.append({"value": value, "source": source})
    return candidates


def _collect_summary_strings(summary_data: dict[str, Any], triage_result: dict[str, Any]) -> list[dict[str, str]]:
    candidates: list[dict[str, str]] = []
    summary_strings = summary_data.get("strings", []) if isinstance(summary_data.get("strings"), list) else []
    for item in summary_strings:
        if not isinstance(item, dict):
            continue
        value = _clean_string_candidate(_safe_text(item.get("value")))
        if len(value) >= 6 and _is_good_string(value):
            candidates.append({"value": value, "source": "summary_string"})

    triage_strings = ((triage_result.get("strings", {}) or {}).get("stdout", {}) or {}).get("strings", []) or []
    for item in triage_strings:
        value = _clean_string_candidate(_parse_triage_string(_safe_text(item)))
        if not re.search(r"[a-z]{3,}", value):
            continue
        if len(value) >= 6 and _is_good_string(value):
            candidates.append({"value": value, "source": "triage_string"})
    return candidates


def _pick_strings(ioc_data: dict[str, Any], summary_data: dict[str, Any], triage_result: dict[str, Any], limit: int) -> list[dict[str, Any]]:
    ranked: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in _collect_ioc_strings(ioc_data) + _collect_summary_strings(summary_data, triage_result):
        value = item["value"]
        key = value.lower()
        if key in seen:
            continue
        seen.add(key)
        ranked.append(
            {
                "value": value,
                "source": item["source"],
                "score": _string_score(value, item["source"]),
            }
        )
    ranked.sort(key=lambda item: (-item["score"], -len(item["value"]), item["value"].lower()))
    return ranked[: max(0, limit)]


def _import_score(item: dict[str, str]) -> int:
    library = item["library"].lower()
    name = item["name"]
    score = 10
    if library in HIGH_SIGNAL_LIBRARIES:
        score += 20
    if library in LOW_SIGNAL_LIBRARIES:
        score -= 10
    for preset_name, apis in PRESET_APIS.items():
        if name in apis:
            score += 40
            if preset_name in {"network", "crypto", "registry", "process", "antidebug"}:
                score += 10
            break
    if name.startswith(("Nt", "Zw", "Crypt", "BCrypt", "WinHttp", "Internet", "CreateProcess", "Reg")):
        score += 12
    return score


def _pick_imports(summary_data: dict[str, Any], triage_result: dict[str, Any], limit: int) -> list[dict[str, Any]]:
    items = _collect_imports(summary_data, triage_result)
    ranked = [
        {
            "library": item["library"],
            "name": item["name"],
            "score": _import_score(item),
        }
        for item in items
    ]
    ranked.sort(key=lambda item: (-item["score"], item["library"].lower(), item["name"].lower()))
    return ranked[: max(0, limit)]


def _escape_yara_string(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\"", "\\\"")


def _rule_name(sample_name: str, explicit_rule_name: str) -> str:
    base = slug(explicit_rule_name or Path(sample_name).stem).replace(".", "_")
    if not base or not (base[0].isalpha() or base[0] == "_"):
        base = f"sample_{base}" if base else "sample_rule"
    return f"reverselab_{base}"


def _build_condition_clauses(strings: list[dict[str, Any]], imports: list[dict[str, Any]]) -> list[str]:
    clauses = ["uint16(0) == 0x5A4D"]
    if strings:
        threshold = 2 if len(strings) >= 4 else 1
        clauses.append(f"{threshold} of ($s*)")
    if imports:
        import_checks = [f'pe.imports("{item["library"]}", "{item["name"]}")' for item in imports[:6]]
        if len(import_checks) == 1:
            clauses.append(import_checks[0])
        else:
            clauses.append("(\n      " + " or\n      ".join(import_checks) + "\n    )")
    return clauses


def _write_rule(path: Path, payload: dict[str, Any]) -> None:
    strings = payload["selected_strings"]
    imports = payload["selected_imports"]
    hashes = payload.get("hashes", {})
    behavior_tags = payload.get("behavior_tags", [])
    condition_clauses = _build_condition_clauses(strings, imports)

    lines = [
        'import "pe"',
        "",
        f"rule {payload['rule_name']}",
        "{",
        "  meta:",
        '    author = "ReverseLabToolsMCP"',
        f'    generated = "{payload["generated_at"]}"',
        f'    sample_name = "{_escape_yara_string(payload["sample_name"])}"',
    ]
    if hashes.get("sha256"):
        lines.append(f'    sha256 = "{hashes["sha256"]}"')
    if hashes.get("md5"):
        lines.append(f'    md5 = "{hashes["md5"]}"')
    if payload.get("summary_path"):
        lines.append(f'    summary_path = "{_escape_yara_string(payload["summary_path"])}"')
    if payload.get("ioc_json_path"):
        lines.append(f'    ioc_json_path = "{_escape_yara_string(payload["ioc_json_path"])}"')
    if behavior_tags:
        lines.append(f'    behavior_tags = "{_escape_yara_string(", ".join(behavior_tags))}"')

    lines.extend(["", "  strings:"])
    if strings:
        for index, item in enumerate(strings, start=1):
            lines.append(f'    $s{index} = "{_escape_yara_string(item["value"])}" ascii wide nocase')
    else:
        lines.append('    $fallback = "MZ" ascii')

    lines.extend(["", "  condition:"])
    if len(condition_clauses) == 1:
        lines.append(f"    {condition_clauses[0]}")
    else:
        for index, clause in enumerate(condition_clauses):
            suffix = " and" if index < len(condition_clauses) - 1 else ""
            if "\n" in clause:
                block_lines = clause.splitlines()
                lines.append(f"    {block_lines[0]}")
                for inner in block_lines[1:-1]:
                    lines.append(inner)
                lines.append(f"{block_lines[-1]}{suffix}")
            else:
                lines.append(f"    {clause}{suffix}")
    lines.append("}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_manifest(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def make_yara_stub(
    sample_path: str = "",
    summary_path: str = "",
    ioc_json_path: str = "",
    rule_name: str = "",
    output_path: str = "",
    max_strings: int = 10,
    max_imports: int = 6,
) -> dict[str, Any]:
    if not any([sample_path, summary_path, ioc_json_path]):
        raise ToolError("at least one of sample_path, summary_path, ioc_json_path is required")

    resolved_sample = str(resolve_file(sample_path)) if sample_path else ""
    resolved_summary = ""
    summary_data: dict[str, Any] = {}
    if summary_path:
        resolved_summary, summary_data = _load_summary_data(summary_path)

    resolved_ioc = ""
    ioc_data: dict[str, Any] = {}
    if ioc_json_path:
        resolved_ioc, ioc_data = _load_ioc_data(ioc_json_path)

    triage_result: dict[str, Any] = {}
    hashes: dict[str, Any] = {}
    if resolved_sample:
        triage_result = triage.triage_pe(resolved_sample, write_markdown=False)
        hashes = triage_result.get("hashes", {})

    sample_name = _sample_name(resolved_sample, summary_data, ioc_data)
    output_base = _resolve_output_base(output_path, sample_name, rule_name)
    selected_strings = _pick_strings(ioc_data, summary_data, triage_result, max_strings)
    selected_imports = _pick_imports(summary_data, triage_result, max_imports)
    behavior_tags = ioc_data.get("behavior_tags", []) if isinstance(ioc_data.get("behavior_tags"), list) else []

    payload = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "sample_name": sample_name,
        "sample_path": resolved_sample,
        "summary_path": resolved_summary,
        "ioc_json_path": resolved_ioc,
        "rule_name": _rule_name(sample_name, rule_name),
        "hashes": hashes,
        "behavior_tags": behavior_tags,
        "selected_strings": selected_strings,
        "selected_imports": selected_imports,
        "string_count": len(selected_strings),
        "import_count": len(selected_imports),
    }

    rule_path = output_base.with_suffix(".yar")
    manifest_path = output_base.with_suffix(".json")
    _write_rule(rule_path, payload)
    _write_manifest(manifest_path, payload)

    return {
        "rule_path": str(rule_path),
        "manifest_path": str(manifest_path),
        "sample_name": sample_name,
        "summary_path": resolved_summary,
        "ioc_json_path": resolved_ioc,
        "selected_strings": selected_strings,
        "selected_imports": selected_imports,
        "behavior_tags": behavior_tags,
    }
