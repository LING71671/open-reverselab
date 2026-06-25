from __future__ import annotations

import json
import ipaddress
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from ..config import IOC_EXPORTS_DIR, SIGMA_EXPORTS_DIR
from ..errors import ToolError
from ..paths import ensure_under, resolve_file, resolve_summary
from ..utils import slug
from . import ghidra_summary, triage
from .ioc_extract import _extract_import_artifacts


RULE_TAGS: dict[str, list[str]] = {
    "sample_exec": ["reverselab.auto_stub", "reverselab.behavior.execution"],
    "file": ["reverselab.auto_stub", "reverselab.behavior.file"],
    "registry": ["reverselab.auto_stub", "reverselab.behavior.registry"],
    "process": ["reverselab.auto_stub", "reverselab.behavior.process"],
    "network": ["reverselab.auto_stub", "reverselab.behavior.network"],
    "image": ["reverselab.auto_stub", "reverselab.behavior.image"],
}

COMMON_IMAGE_NAMES = {
    "advapi32.dll",
    "comdlg32.dll",
    "gdi32.dll",
    "kernel32.dll",
    "ntdll.dll",
    "shell32.dll",
    "user32.dll",
}


def _default_output_base(sample_name: str, rule_name: str) -> Path:
    SIGMA_EXPORTS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    stem = slug(rule_name or Path(sample_name or "sample").stem)
    return SIGMA_EXPORTS_DIR / f"{stem}-sigma-{stamp}"


def _resolve_output_base(output_path: str, sample_name: str, rule_name: str) -> Path:
    if not output_path:
        return _default_output_base(sample_name, rule_name)
    path = Path(output_path).expanduser().resolve()
    ensure_under(path, [SIGMA_EXPORTS_DIR], "sigma output path")
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


def _sample_name(sample_path: str, summary_data: dict[str, Any], ioc_data: dict[str, Any]) -> str:
    if sample_path:
        return resolve_file(sample_path).name
    program = summary_data.get("program", {}) if isinstance(summary_data.get("program"), dict) else {}
    name = _safe_text(program.get("name"))
    if name:
        return name
    return _safe_text(ioc_data.get("sample_name")) or "sample"


def _hashes_from_sample(sample_path: str) -> dict[str, Any]:
    if not sample_path:
        return {}
    return triage.hash_file(sample_path)


def _ioc_items(ioc_data: dict[str, Any], category: str) -> list[dict[str, Any]]:
    categories = ioc_data.get("categories", {}) if isinstance(ioc_data.get("categories"), dict) else {}
    items = categories.get(category, [])
    if not isinstance(items, list):
        return []
    return [item for item in items if isinstance(item, dict)]


def _source_types(item: dict[str, Any]) -> set[str]:
    sources = item.get("sources", [])
    if not isinstance(sources, list):
        return set()
    return {str(src.get("source_type", "")).strip().lower() for src in sources if isinstance(src, dict)}


def _note_only(item: dict[str, Any]) -> bool:
    types = _source_types(item)
    return bool(types) and types == {"note"}


def _is_local_network_indicator(value: str) -> bool:
    lowered = value.lower()
    if lowered in {"localhost", "::1", "127.0.0.1"}:
        return True
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_private or ip.is_link_local


def _yaml_scalar(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    text = str(value)
    if text == "" or any(ch in text for ch in "\\:#{}[]&,*>!%@`\"") or text.strip() != text:
        return "'" + text.replace("'", "''") + "'"
    return text


def _dump_yaml(value: Any, indent: int = 0) -> list[str]:
    prefix = " " * indent
    if isinstance(value, dict):
        lines: list[str] = []
        for key, item in value.items():
            if isinstance(item, (dict, list)):
                lines.append(f"{prefix}{key}:")
                lines.extend(_dump_yaml(item, indent + 2))
            else:
                lines.append(f"{prefix}{key}: {_yaml_scalar(item)}")
        return lines
    if isinstance(value, list):
        lines = []
        for item in value:
            if isinstance(item, (dict, list)):
                nested = _dump_yaml(item, indent + 2)
                if nested:
                    lines.append(f"{prefix}- {nested[0].lstrip()}")
                    lines.extend(nested[1:])
                else:
                    lines.append(f"{prefix}-")
            else:
                lines.append(f"{prefix}- {_yaml_scalar(item)}")
        return lines
    return [f"{prefix}{_yaml_scalar(value)}"]


def _rule_id(sample_name: str, rule_kind: str, values: list[str]) -> str:
    material = "|".join([sample_name.lower(), rule_kind.lower(), *sorted(value.lower() for value in values)])
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"reverselab:{material}"))


def _append_condition_block(detection: dict[str, Any], name: str, field: str, values: list[str]) -> None:
    cleaned = [item for item in values if item]
    if not cleaned:
        return
    key = f"{name}_{len(detection)}"
    if len(cleaned) == 1:
        detection[key] = {field: cleaned[0]}
    else:
        detection[key] = {field: cleaned}


def _sample_exec_rule(sample_name: str, level: str = "low") -> dict[str, Any]:
    values = [sample_name]
    return {
        "title": f"ReverseLab Auto Stub - Sample Execution - {sample_name}",
        "id": _rule_id(sample_name, "sample_exec", values),
        "status": "experimental",
        "description": "Auto-generated execution anchor rule. Review and tighten before production use.",
        "author": "ReverseLabToolsMCP",
        "date": datetime.now().strftime("%Y/%m/%d"),
        "logsource": {
            "product": "windows",
            "category": "process_creation",
        },
        "detection": {
            "selection_image": {
                "Image|endswith": f"\\{sample_name}",
            },
            "condition": "selection_image",
        },
        "falsepositives": [
            "Benign execution of the same binary path or filename.",
        ],
        "level": level,
        "tags": RULE_TAGS["sample_exec"],
        "fields": [
            "Image",
            "CommandLine",
            "ParentImage",
            "ParentCommandLine",
            "User",
        ],
    }


def _rule_for_file(sample_name: str, ioc_data: dict[str, Any]) -> tuple[dict[str, Any] | None, str]:
    indicators: list[str] = []
    for item in _ioc_items(ioc_data, "file_paths"):
        if _note_only(item):
            continue
        value = _safe_text(item.get("value"))
        if value and value.lower().endswith(sample_name.lower()):
            continue
        indicators.append(value)
    for item in _ioc_items(ioc_data, "file_artifacts"):
        value = _safe_text(item.get("value"))
        if _note_only(item) or not value:
            continue
        lowered = value.lower()
        if lowered.endswith((".dll", ".drv")):
            continue
        indicators.append(value)
    deduped = []
    seen: set[str] = set()
    for value in indicators:
        key = value.lower()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(value)
    if not deduped:
        return None, "no non-note file indicators"

    detection: dict[str, Any] = {}
    path_values = [value for value in deduped if "\\" in value or "/" in value][:6]
    name_values = [Path(value).name for value in deduped if Path(value).name][:6]
    _append_condition_block(detection, "selection_path", "TargetFilename|contains", path_values)
    _append_condition_block(detection, "selection_name", "TargetFilename|endswith", [f"\\{value}" for value in name_values])
    detection["condition"] = "1 of selection_*"
    return (
        {
            "title": f"ReverseLab Auto Stub - File Activity - {sample_name}",
            "id": _rule_id(sample_name, "file", deduped),
            "status": "experimental",
            "description": "Auto-generated file activity stub from IOC and string evidence. Review target paths before production use.",
            "author": "ReverseLabToolsMCP",
            "date": datetime.now().strftime("%Y/%m/%d"),
            "logsource": {
                "product": "windows",
                "category": "file_event",
            },
            "detection": detection,
            "falsepositives": [
                "Installers, updaters, or admin scripts touching the same filenames.",
            ],
            "level": "medium",
            "tags": RULE_TAGS["file"],
            "fields": [
                "Image",
                "TargetFilename",
                "User",
            ],
        },
        "",
    )


def _rule_for_registry(sample_name: str, ioc_data: dict[str, Any]) -> tuple[dict[str, Any] | None, str]:
    indicators = []
    for item in _ioc_items(ioc_data, "registry_paths"):
        if _note_only(item):
            continue
        value = _safe_text(item.get("value"))
        if value:
            indicators.append(value)
    if not indicators:
        return None, "no registry path indicators"
    indicators = indicators[:8]
    detection = {
        "selection_registry": {
            "TargetObject|contains": indicators if len(indicators) > 1 else indicators[0],
        },
        "condition": "selection_registry",
    }
    return (
        {
            "title": f"ReverseLab Auto Stub - Registry Activity - {sample_name}",
            "id": _rule_id(sample_name, "registry", indicators),
            "status": "experimental",
            "description": "Auto-generated registry activity stub from extracted registry indicators.",
            "author": "ReverseLabToolsMCP",
            "date": datetime.now().strftime("%Y/%m/%d"),
            "logsource": {
                "product": "windows",
                "category": "registry_event",
            },
            "detection": detection,
            "falsepositives": [
                "Administrative tooling, software installers, or policy updates.",
            ],
            "level": "medium",
            "tags": RULE_TAGS["registry"],
            "fields": [
                "Image",
                "TargetObject",
                "Details",
                "User",
            ],
        },
        "",
    )


def _rule_for_network(sample_name: str, ioc_data: dict[str, Any]) -> tuple[dict[str, Any] | None, str]:
    domains = []
    for item in _ioc_items(ioc_data, "domains"):
        value = _safe_text(item.get("value"))
        if not value or _note_only(item) or _is_local_network_indicator(value):
            continue
        domains.append(value)
    ips = []
    for item in _ioc_items(ioc_data, "ipv4s"):
        value = _safe_text(item.get("value"))
        if not value or _note_only(item) or _is_local_network_indicator(value):
            continue
        ips.append(value)
    if not domains and not ips:
        return None, "no external network indicators"
    detection: dict[str, Any] = {}
    _append_condition_block(detection, "selection_host", "DestinationHostname|contains", domains[:6])
    _append_condition_block(detection, "selection_ip", "DestinationIp", ips[:6])
    detection["condition"] = "1 of selection_*"
    values = domains[:6] + ips[:6]
    return (
        {
            "title": f"ReverseLab Auto Stub - Network Activity - {sample_name}",
            "id": _rule_id(sample_name, "network", values),
            "status": "experimental",
            "description": "Auto-generated network activity stub from extracted domain and IP indicators.",
            "author": "ReverseLabToolsMCP",
            "date": datetime.now().strftime("%Y/%m/%d"),
            "logsource": {
                "product": "windows",
                "category": "network_connection",
            },
            "detection": detection,
            "falsepositives": [
                "Benign software contacting the same domains, CDNs, or shared infrastructure.",
            ],
            "level": "medium",
            "tags": RULE_TAGS["network"],
            "fields": [
                "Image",
                "DestinationIp",
                "DestinationHostname",
                "DestinationPort",
                "Protocol",
                "User",
            ],
        },
        "",
    )


def _rule_for_image(sample_name: str, ioc_data: dict[str, Any]) -> tuple[dict[str, Any] | None, str]:
    indicators = []
    for item in _ioc_items(ioc_data, "file_artifacts"):
        value = _safe_text(item.get("value"))
        lowered = value.lower()
        if _note_only(item) or not lowered.endswith(".dll") or lowered in COMMON_IMAGE_NAMES:
            continue
        indicators.append(value)
    if not indicators:
        return None, "no non-common dll indicators"
    indicators = indicators[:6]
    detection = {
        "selection_image_load": {
            "ImageLoaded|endswith": [f"\\{value}" for value in indicators] if len(indicators) > 1 else f"\\{indicators[0]}",
        },
        "condition": "selection_image_load",
    }
    return (
        {
            "title": f"ReverseLab Auto Stub - Image Load - {sample_name}",
            "id": _rule_id(sample_name, "image", indicators),
            "status": "experimental",
            "description": "Auto-generated image load stub from extracted DLL indicators.",
            "author": "ReverseLabToolsMCP",
            "date": datetime.now().strftime("%Y/%m/%d"),
            "logsource": {
                "product": "windows",
                "category": "image_load",
            },
            "detection": detection,
            "falsepositives": [
                "Legitimate software loading the same modules.",
            ],
            "level": "medium",
            "tags": RULE_TAGS["image"],
            "fields": [
                "Image",
                "ImageLoaded",
                "User",
            ],
        },
        "",
    )


def _rule_for_process(sample_name: str, ioc_data: dict[str, Any]) -> tuple[dict[str, Any] | None, str]:
    indicators = []
    for item in _ioc_items(ioc_data, "file_artifacts"):
        value = _safe_text(item.get("value"))
        lowered = value.lower()
        if _note_only(item) or not lowered.endswith(".exe") or lowered == sample_name.lower():
            continue
        indicators.append(value)
    if not indicators:
        return None, "no child process indicators"
    indicators = indicators[:6]
    detection = {
        "selection_parent": {
            "ParentImage|endswith": f"\\{sample_name}",
        },
        "selection_child": {
            "Image|endswith": [f"\\{Path(value).name}" for value in indicators] if len(indicators) > 1 else f"\\{Path(indicators[0]).name}",
        },
        "condition": "all of selection_*",
    }
    return (
        {
            "title": f"ReverseLab Auto Stub - Child Process - {sample_name}",
            "id": _rule_id(sample_name, "process", indicators),
            "status": "experimental",
            "description": "Auto-generated child process stub from executable artifact indicators.",
            "author": "ReverseLabToolsMCP",
            "date": datetime.now().strftime("%Y/%m/%d"),
            "logsource": {
                "product": "windows",
                "category": "process_creation",
            },
            "detection": detection,
            "falsepositives": [
                "Benign parent-child execution chains using the same filenames.",
            ],
            "level": "medium",
            "tags": RULE_TAGS["process"],
            "fields": [
                "Image",
                "CommandLine",
                "ParentImage",
                "ParentCommandLine",
                "User",
            ],
        },
        "",
    )


def _write_yaml(path: Path, rules: list[dict[str, Any]]) -> None:
    documents: list[str] = []
    for rule in rules:
        documents.append("\n".join(_dump_yaml(rule)))
    path.write_text("\n---\n".join(documents) + "\n", encoding="utf-8")


def _write_manifest(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def make_sigma_stub(
    sample_path: str = "",
    summary_path: str = "",
    ioc_json_path: str = "",
    rule_name: str = "",
    output_path: str = "",
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

    behavior_tags = ioc_data.get("behavior_tags", []) if isinstance(ioc_data.get("behavior_tags"), list) else []
    if not behavior_tags:
        _imports, behavior_tags = _extract_import_artifacts(summary_data, triage_result)

    sample_name = _sample_name(resolved_sample, summary_data, ioc_data)
    output_base = _resolve_output_base(output_path, sample_name, rule_name)

    rules: list[dict[str, Any]] = [_sample_exec_rule(sample_name)]
    skipped: list[dict[str, str]] = []

    builders = {
        "file": _rule_for_file,
        "registry": _rule_for_registry,
        "process": _rule_for_process,
        "network": _rule_for_network,
        "image": _rule_for_image,
    }
    for tag in behavior_tags:
        builder = builders.get(str(tag).lower())
        if not builder:
            continue
        rule, reason = builder(sample_name, ioc_data)
        if rule:
            rules.append(rule)
        else:
            skipped.append({"tag": str(tag), "reason": reason or "no indicators"})

    payload = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "sample_name": sample_name,
        "sample_path": resolved_sample,
        "summary_path": resolved_summary,
        "ioc_json_path": resolved_ioc,
        "hashes": hashes,
        "behavior_tags": behavior_tags,
        "rule_count": len(rules),
        "generated_rule_titles": [rule.get("title", "") for rule in rules],
        "skipped": skipped,
    }

    yaml_path = output_base.with_suffix(".yml")
    manifest_path = output_base.with_suffix(".json")
    _write_yaml(yaml_path, rules)
    _write_manifest(manifest_path, payload)

    return {
        "yaml_path": str(yaml_path),
        "manifest_path": str(manifest_path),
        "sample_name": sample_name,
        "summary_path": resolved_summary,
        "ioc_json_path": resolved_ioc,
        "behavior_tags": behavior_tags,
        "rule_count": len(rules),
        "generated_rule_titles": payload["generated_rule_titles"],
        "skipped": skipped,
    }
