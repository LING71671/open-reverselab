from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from ..config import IOC_EXPORTS_DIR, NOTES_DIR
from ..errors import ToolError
from ..paths import ensure_under, resolve_file, resolve_summary
from ..utils import slug
from . import ghidra_summary, triage
from .procmon_filters import PRESET_FILTERS


URL_RE = re.compile(r"https?://[^\s\"'<>`]+", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[A-Za-z]{2,}\b")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[A-Za-z]{2,24}\b")
REGISTRY_RE = re.compile(
    r"\b(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU|HKCC)\\[^\r\n\"']+",
    re.IGNORECASE,
)
WIN_PATH_RE = re.compile(r"\b[A-Za-z]:\\[^\r\n\"'<>|?*]+")
ENV_PATH_RE = re.compile(r"%(?:APPDATA|LOCALAPPDATA|PROGRAMDATA|TEMP|TMP|USERPROFILE|PUBLIC)%\\[^\r\n\"']*", re.IGNORECASE)
DLL_RE = re.compile(r"\b[a-zA-Z0-9._-]+\.(?:dll|drv|exe|sys)\b", re.IGNORECASE)


def _default_base_path(sample_name: str) -> Path:
    IOC_EXPORTS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    stem = Path(sample_name).stem if sample_name else "sample"
    return IOC_EXPORTS_DIR / f"{slug(stem)}-iocs-{stamp}"


def _resolve_output_base(output_path: str, sample_name: str) -> Path:
    if not output_path:
        return _default_base_path(sample_name)
    path = Path(output_path).expanduser().resolve()
    ensure_under(path, [IOC_EXPORTS_DIR], "ioc output path")
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.suffix:
        return path.with_suffix("")
    return path


def _resolve_text_path(path: str) -> Path:
    resolved = Path(path).expanduser().resolve(strict=True)
    if not resolved.is_file():
        raise ToolError(f"not a file: {resolved}")
    ensure_under(resolved, [NOTES_DIR], "note path")
    return resolved


def _sample_name(sample_path: str, summary_data: dict[str, Any]) -> str:
    if sample_path:
        return resolve_file(sample_path).name
    program = summary_data.get("program", {}) if isinstance(summary_data.get("program"), dict) else {}
    return str(program.get("name", "")).strip() or "sample"


def _valid_ipv4(text: str) -> bool:
    parts = text.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False


def _normalize_url(url: str) -> str:
    return url.rstrip(").,;]")


def _url_host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").strip()
    except ValueError:
        return ""


def _collect_text_sources(
    summary_data: dict[str, Any],
    triage_result: dict[str, Any],
    note_text: str,
) -> list[dict[str, str]]:
    sources: list[dict[str, str]] = []

    for item in summary_data.get("strings", []) if isinstance(summary_data.get("strings"), list) else []:
        if not isinstance(item, dict):
            continue
        value = str(item.get("value", "")).strip()
        if value:
            sources.append(
                {
                    "source_type": "summary_string",
                    "source_ref": str(item.get("address", "")),
                    "text": value,
                }
            )

    triage_strings = ((triage_result.get("strings", {}) or {}).get("stdout", {}) or {}).get("strings", []) or []
    for index, item in enumerate(triage_strings[:500]):
        text = str(item).strip()
        if text:
            sources.append(
                {
                    "source_type": "triage_string",
                    "source_ref": str(index),
                    "text": text,
                }
            )

    if note_text.strip():
        sources.append(
            {
                "source_type": "note",
                "source_ref": "note",
                "text": note_text,
            }
        )

    return sources


def _push_match(store: dict[str, dict[str, Any]], category: str, value: str, source: dict[str, str]) -> None:
    bucket = store.setdefault(category, {})
    normalized = value.strip()
    if not normalized:
        return
    key = normalized.lower()
    if key not in bucket:
        bucket[key] = {
            "value": normalized,
            "sources": [],
        }
    bucket[key]["sources"].append(
        {
            "source_type": source["source_type"],
            "source_ref": source["source_ref"],
        }
    )


def _extract_from_texts(text_sources: list[dict[str, str]]) -> dict[str, dict[str, Any]]:
    found: dict[str, dict[str, Any]] = {}
    for source in text_sources:
        text = source["text"]

        for raw in URL_RE.findall(text):
            normalized_url = _normalize_url(raw)
            _push_match(found, "urls", normalized_url, source)
            host = _url_host(normalized_url)
            if host:
                _push_match(found, "domains", host, source)

        for raw in EMAIL_RE.findall(text):
            _push_match(found, "emails", raw, source)
            domain = raw.split("@", 1)[-1].strip()
            if domain:
                _push_match(found, "domains", domain, source)

        for raw in IPV4_RE.findall(text):
            if _valid_ipv4(raw):
                _push_match(found, "ipv4s", raw, source)

        for raw in REGISTRY_RE.findall(text):
            _push_match(found, "registry_paths", raw, source)

        for raw in WIN_PATH_RE.findall(text):
            _push_match(found, "file_paths", raw.rstrip(").,;]`"), source)

        for raw in ENV_PATH_RE.findall(text):
            _push_match(found, "file_paths", raw.rstrip(").,;]`"), source)

        for raw in DLL_RE.findall(text):
            _push_match(found, "file_artifacts", raw, source)

    return found


def _extract_import_artifacts(summary_data: dict[str, Any], triage_result: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str]]:
    imports: list[dict[str, Any]] = []
    if isinstance(summary_data.get("imports"), list):
        imports.extend(item for item in summary_data.get("imports", []) if isinstance(item, dict))
    triage_imports = ((triage_result.get("imports", {}) or {}).get("stdout", {}) or {}).get("imports", []) or []
    imports.extend(item for item in triage_imports if isinstance(item, dict))

    import_entries: list[dict[str, Any]] = []
    import_names: set[str] = set()
    seen_entries: set[tuple[str, str, str]] = set()
    for item in imports:
        lib = str(item.get("libname", item.get("namespace", ""))).strip()
        name = str(item.get("name", "")).strip()
        addr = item.get("plt", item.get("address", ""))
        key = (lib.lower(), name.lower(), str(addr).lower())
        if key in seen_entries:
            continue
        seen_entries.add(key)
        import_entries.append({"library": lib, "name": name, "address": addr})
        if name:
            import_names.add(name.lower())
    behavior_tags: list[str] = []
    for preset, spec in PRESET_FILTERS.items():
        markers = {str(item).lower() for item in spec.get("api_markers", [])}
        if import_names.intersection(markers):
            behavior_tags.append(preset)
    return import_entries, behavior_tags


def _serialize_categories(found: dict[str, dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = {}
    for category, values in found.items():
        ordered = sorted(values.values(), key=lambda item: item["value"].lower())
        result[category] = ordered
    return result


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _write_markdown(path: Path, payload: dict[str, Any]) -> None:
    lines = [
        f"# IOC Extraction: {payload['sample_name']}",
        "",
        f"生成时间：{datetime.now().isoformat(timespec='seconds')}",
        "",
        "## 1. Inputs",
        "",
        f"- Sample Path: `{payload.get('sample_path', '')}`",
        f"- Summary Path: `{payload.get('summary_path', '')}`",
        f"- Note Path: `{payload.get('note_path', '')}`",
        f"- Behavior Tags: `{', '.join(payload.get('behavior_tags', []))}`" if payload.get("behavior_tags") else "- Behavior Tags: ``",
        "",
        "## 2. Categories",
        "",
    ]

    for category, items in payload.get("categories", {}).items():
        lines.extend([f"### {category}", ""])
        if not items:
            lines.append("- 无匹配。")
            lines.append("")
            continue
        for item in items:
            refs = ", ".join(f"{src['source_type']}:{src['source_ref']}" for src in item.get("sources", [])[:5])
            lines.append(f"- `{item['value']}`")
            lines.append(f"  来源：`{refs}`")
        lines.append("")

    lines.extend(["## 3. Import Artifacts", ""])
    imports = payload.get("top_imports", [])
    if imports:
        for item in imports:
            addr = item.get("address", "")
            addr_text = f" @ {addr}" if str(addr).strip() else ""
            lines.append(f"- `{item.get('library', '')}!{item.get('name', '')}`{addr_text}")
    else:
        lines.append("- 无导入快照。")

    lines.extend(["", "## 4. Summary", ""])
    counts = payload.get("counts", {})
    for key, value in counts.items():
        lines.append(f"- `{key}`: `{value}`")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _resolve_ioc_json_path(path: str) -> Path:
    resolved = Path(path).expanduser().resolve(strict=True)
    if not resolved.is_file():
        raise ToolError(f"not a file: {resolved}")
    if resolved.suffix.lower() != ".json":
        raise ToolError(f"ioc json path is not a .json file: {resolved}")
    ensure_under(resolved, [IOC_EXPORTS_DIR], "ioc json path")
    return resolved


def _default_refined_base(ioc_json_path: Path) -> Path:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    stem = ioc_json_path.stem
    if stem.endswith(".json"):
        stem = Path(stem).stem
    return IOC_EXPORTS_DIR / f"{stem}-refined-{stamp}"


def _source_class(item: dict[str, Any]) -> tuple[str, list[str]]:
    source_types = sorted(
        {
            str(src.get("source_type", "")).strip()
            for src in item.get("sources", [])
            if isinstance(src, dict) and str(src.get("source_type", "")).strip()
        }
    )
    static_types = {"summary_string", "triage_string"}
    has_static = any(source in static_types for source in source_types)
    has_note = "note" in source_types
    if has_static and has_note:
        return "mixed", source_types
    if has_static:
        return "static_confirmed", source_types
    if has_note:
        return "note_only", source_types
    return "other", source_types


def _write_refined_markdown(path: Path, payload: dict[str, Any]) -> None:
    lines = [
        f"# IOC Source Refinement: {payload['sample_name']}",
        "",
        f"生成时间：{datetime.now().isoformat(timespec='seconds')}",
        "",
        f"- Input IOC JSON: `{payload.get('ioc_json_path', '')}`",
        f"- Static Confirmed: `{payload.get('counts', {}).get('static_confirmed', 0)}`",
        f"- Mixed: `{payload.get('counts', {}).get('mixed', 0)}`",
        f"- Note Only: `{payload.get('counts', {}).get('note_only', 0)}`",
        "",
    ]

    for category, items in payload.get("refined_categories", {}).items():
        lines.extend([f"## {category}", ""])
        if not items:
            lines.append("- 无条目。")
            lines.append("")
            continue
        for item in items:
            lines.append(f"- `{item.get('value', '')}`")
            lines.append(f"  分类：`{item.get('source_class', '')}`")
            lines.append(f"  来源类型：`{', '.join(item.get('source_types', []))}`")
        lines.append("")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def extract_iocs_from_summary(
    summary_path: str = "",
    sample_path: str = "",
    note_path: str = "",
    output_path: str = "",
) -> dict[str, Any]:
    summary_data: dict[str, Any] = {}
    resolved_summary = ""
    if summary_path:
        resolved_summary = str(resolve_summary(summary_path))
        _summary_path_obj, summary_data = ghidra_summary.load_summary(resolved_summary)

    triage_result: dict[str, Any] = {}
    resolved_sample = ""
    if sample_path:
        resolved_sample = str(resolve_file(sample_path))
        triage_result = triage.triage_pe(resolved_sample, write_markdown=False)

    resolved_note = ""
    note_text = ""
    if note_path:
        resolved_note = str(_resolve_text_path(note_path))
        note_text = Path(resolved_note).read_text(encoding="utf-8", errors="replace")

    if not resolved_summary and not resolved_sample and not resolved_note:
        raise ToolError("at least one of summary_path, sample_path, note_path is required")

    sample_name = _sample_name(resolved_sample, summary_data)
    output_base = _resolve_output_base(output_path, sample_name)

    text_sources = _collect_text_sources(summary_data, triage_result, note_text)
    found = _extract_from_texts(text_sources)
    categories = _serialize_categories(found)
    import_entries, behavior_tags = _extract_import_artifacts(summary_data, triage_result)

    counts = {
        category: len(items)
        for category, items in categories.items()
    }
    counts["imports"] = len(import_entries)
    counts["text_sources"] = len(text_sources)

    payload = {
        "sample_name": sample_name,
        "sample_path": resolved_sample,
        "summary_path": resolved_summary,
        "note_path": resolved_note,
        "behavior_tags": behavior_tags,
        "categories": categories,
        "counts": counts,
        "top_imports": import_entries[:30],
    }

    json_path = output_base.with_suffix(".json")
    md_path = output_base.with_suffix(".md")
    _write_json(json_path, payload)
    _write_markdown(md_path, payload)

    return {
        "json_path": str(json_path),
        "markdown_path": str(md_path),
        "sample_name": sample_name,
        "summary_path": resolved_summary,
        "sample_path": resolved_sample,
        "note_path": resolved_note,
        "behavior_tags": behavior_tags,
        "counts": counts,
    }


def refine_ioc_sources(ioc_json_path: str, output_path: str = "") -> dict[str, Any]:
    source_path = _resolve_ioc_json_path(ioc_json_path)
    data = json.loads(source_path.read_text(encoding="utf-8", errors="replace"))
    if not isinstance(data, dict):
        raise ToolError(f"ioc json root is not an object: {source_path}")

    if output_path:
        output_base = _resolve_output_base(output_path, str(data.get("sample_name", "sample")))
    else:
        output_base = _default_refined_base(source_path)

    refined_categories: dict[str, list[dict[str, Any]]] = {}
    counts = {
        "static_confirmed": 0,
        "mixed": 0,
        "note_only": 0,
        "other": 0,
    }

    categories = data.get("categories", {}) if isinstance(data.get("categories"), dict) else {}
    for category, items in categories.items():
        refined_items: list[dict[str, Any]] = []
        if not isinstance(items, list):
            refined_categories[category] = refined_items
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            source_class, source_types = _source_class(item)
            counts[source_class] = counts.get(source_class, 0) + 1
            refined_items.append(
                {
                    "value": item.get("value", ""),
                    "source_class": source_class,
                    "source_types": source_types,
                    "sources": item.get("sources", []),
                }
            )
        refined_categories[category] = refined_items

    payload = {
        "sample_name": data.get("sample_name", "sample"),
        "ioc_json_path": str(source_path),
        "summary_path": data.get("summary_path", ""),
        "sample_path": data.get("sample_path", ""),
        "note_path": data.get("note_path", ""),
        "behavior_tags": data.get("behavior_tags", []),
        "counts": counts,
        "refined_categories": refined_categories,
    }

    json_path = output_base.with_suffix(".json")
    md_path = output_base.with_suffix(".md")
    _write_json(json_path, payload)
    _write_refined_markdown(md_path, payload)

    return {
        "json_path": str(json_path),
        "markdown_path": str(md_path),
        "sample_name": str(payload.get("sample_name", "")),
        "ioc_json_path": str(source_path),
        "counts": counts,
    }
