"""Operation registry, tool profiles, and capability metadata.

Why this exists
---------------
The server used to register every tool unconditionally. That is fine for a 20-tool server and
bad for one with 118 native tools plus an optional 255-tool external engine. Profiles let an
agent load only the surface it needs, and the registry gives the capability matrix and the KB
router a single source of truth.

Nothing here changes tool behaviour. `legacy` is the default profile and preserves the old
catalog exactly.
"""

from __future__ import annotations

import ast
import os
from pathlib import Path
from typing import Any, Iterable

from .contracts.operations import OperationSpec

PROFILE_ENV = "REVERSELAB_PROFILE"
DEFAULT_PROFILE = "legacy"

PROFILE_DESCRIPTIONS: dict[str, str] = {
    "legacy": "Every registered tool. Backward-compatible default during migration.",
    "common": "Intake, triage, workspace, toolbox, engine status.",
    "ctf": "Web/HTTP/CTF surface plus common.",
    "pe": "PE/ELF static, dynamic, patch, IOC surface plus common.",
    "apk": "Android static, Frida, and crypto surface plus common.",
    "general": "Crypto, protocol, pcap, .NET, WASM surface plus common.",
}

PROFILES = tuple(PROFILE_DESCRIPTIONS)

# Tools always present in every non-legacy profile.
COMMON_TOOLS = frozenset(
    {
        "kb_router",
        "kb_read_file",
        "hash_file",
        "triage_pe",
        "die_scan",
        "static_backend_status",
        "sample_full_workup",
        "sample_autopilot_round",
        "import_sample",
        "list_samples",
        "rename_sample",
        "copy_sample",
        "move_sample",
        "quarantine_sample",
        "delete_sample",
        "workspace_read_text",
        "workspace_write_text",
        "workspace_copy_artifact",
        "workspace_move_artifact",
        "workspace_delete_artifact",
        "toolbox_list",
        "toolbox_version",
        "toolbox_launch",
        "mcp_update_audit",
        "project_skills_status",
        "list_generated_artifacts",
        "delete_generated_artifact",
        "python_re_tool_status",
        "python_re_tool_install",
        "python_re_tool_version",
    }
)

WEB_TOOLS = frozenset(
    {
        "http_probe",
        "kb_catalog",
        "ctf_new_challenge",
        "ctf_autopilot_round",
        "run_ctf_tool",
        "ctf_tool_status",
        "ctf_save_request",
        "run_sqlmap_request",
        "burp_status",
        "burp_launch",
    }
)

ANDROID_PREFIXES = ("android_",)

CRYPTO_TOOLS = frozenset(
    {
        "parse_android_crypto_unpack_result",
        "extract_frida_buffers",
        "make_crypto_replay_scaffold",
        "solve_crypto_from_evidence",
        "postprocess_frida_crypto_result",
        "make_pe_crypto_unpack_plan",
    }
)

PE_PREFIXES = (
    "rizin_",
    "ghidra_",
    "static_summary_",
    "static_headless_",
    "ida_headless_",
    "patch_",
    "pe_",
    "procmon_",
    "make_x64dbg_",
    "make_procmon_",
    "make_yara_",
    "make_sigma_",
    "mutation_",
    "debug_script",
    "carve_payloads_",
    "extract_iocs_",
    "refine_ioc_",
    "triage_to_notes",
    "search_pattern",
    "generate_patch_report",
    "copy_sample_to_patches",
)

PE_TOOLS = frozenset(
    {
        "triage_to_notes",
        "extract_iocs_from_summary",
        "refine_ioc_sources",
        "make_yara_stub",
        "make_sigma_stub",
        "make_procmon_filters",
        "make_pe_crypto_unpack_plan",
        "make_x64dbg_breakpoint_script",
        "carve_payloads_from_dump",
        "rizin_write_bytes",
        "rizin_assemble_bytes",
        "rizin_assemble_patch",
        "procmon_start_capture",
        "procmon_stop_capture",
        "procmon_export_csv",
        "mutation_audit_tail",
    }
)

GENERAL_TOOLS = frozenset(
    {
        "pcap_summary",
        "pcap_extract_http",
        "dotnet_metadata",
        "dotnet_list_types",
        "dotnet_decompile_type",
        "wasm_info",
    }
)

# Formats the general profile owns natively.
TOOL_FORMATS: dict[str, tuple[str, ...]] = {
    "pcap_summary": ("pcap",),
    "pcap_extract_http": ("pcap",),
    "dotnet_metadata": ("dotnet",),
    "dotnet_list_types": ("dotnet",),
    "dotnet_decompile_type": ("dotnet",),
    "wasm_info": ("wasm",),
}

FAMILY_FORMATS: dict[str, tuple[str, ...]] = {
    "common": ("pe", "elf", "directory"),
    "web": ("web",),
    "android": ("apk", "dex"),
    "crypto": ("binary", "apk"),
    "pe": ("pe", "elf"),
    "general-format": ("pcap", "dotnet", "wasm"),
}


def entrypoint_path() -> Path:
    """Path to the MCP entrypoint that declares the native tools."""

    return Path(__file__).resolve().parents[1] / "reverse_lab_tools_mcp.py"


def discover_native_tools(path: Path | None = None) -> list[tuple[str, str]]:
    """Return `(name, summary)` for every `@mcp.tool()` function, without importing the module."""

    target = path or entrypoint_path()
    tree = ast.parse(target.read_text(encoding="utf-8"), filename=str(target))
    found: list[tuple[str, str]] = []
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not any(_is_mcp_tool(decorator) for decorator in node.decorator_list):
            continue
        summary = ""
        doc = ast.get_docstring(node) or ""
        if doc:
            summary = doc.strip().splitlines()[0][:200]
        found.append((node.name, summary))
    return found


def _is_mcp_tool(decorator: ast.expr) -> bool:
    if isinstance(decorator, ast.Call):
        decorator = decorator.func
    return (
        isinstance(decorator, ast.Attribute)
        and decorator.attr == "tool"
        and isinstance(decorator.value, ast.Name)
        and decorator.value.id == "mcp"
    )


_NON_LEGACY_PROFILES = tuple(profile for profile in PROFILES if profile != "legacy")


def classify(name: str) -> tuple[str, tuple[str, ...]]:
    """Return `(family, profiles)` for a native tool name.

    Common tools are present in every non-legacy profile; format-specific tools are present only
    in the profiles that own that format.
    """

    if name in COMMON_TOOLS:
        return "common", _NON_LEGACY_PROFILES
    if name in WEB_TOOLS:
        return "web", ("ctf",)
    if name in GENERAL_TOOLS:
        return "general-format", ("general",)
    if name in CRYPTO_TOOLS:
        return "crypto", ("apk", "general", "pe")
    if name.startswith(ANDROID_PREFIXES):
        return "android", ("apk",)
    if name in PE_TOOLS or name.startswith(PE_PREFIXES):
        return "pe", ("pe",)
    return "pe", ("pe",)


def native_specs(path: Path | None = None) -> list[OperationSpec]:
    specs: list[OperationSpec] = []
    for name, summary in discover_native_tools(path):
        family, profiles = classify(name)
        specs.append(
            OperationSpec(
                name=name,
                family=family,
                profiles=profiles,
                target_formats=TOOL_FORMATS.get(name, FAMILY_FORMATS.get(family, ())),
                engine="native",
                description=summary,
            )
        )
    return specs


def allowed_tools(profile: str, path: Path | None = None) -> set[str] | None:
    """Return the allowed tool names for a profile, or `None` for `legacy` (no pruning)."""

    if profile == "legacy":
        return None
    if profile not in PROFILES:
        raise ValueError(f"unknown profile: {profile}; choose from {', '.join(PROFILES)}")
    return {spec.name for spec in native_specs(path) if profile in spec.profiles}


def apply_profile(mcp: Any, profile: str | None = None) -> dict[str, Any]:
    """Prune the FastMCP registry to the selected profile.

    The MCP object is duck-typed (`_tool_manager._tools` / `remove_tool`) so this module stays
    importable without the MCP dependency in tests.
    """

    selected = (profile or os.environ.get(PROFILE_ENV) or DEFAULT_PROFILE).strip()
    if selected not in PROFILES:
        return {
            "ok": False,
            "profile": selected,
            "error": f"unknown profile {selected!r}; choose from {', '.join(PROFILES)}",
            "removed": [],
            "kept": 0,
        }
    if selected == "legacy":
        return {
            "ok": True,
            "profile": selected,
            "removed": [],
            "kept": len(mcp._tool_manager._tools),
        }

    allowed = allowed_tools(selected) or set()
    removed: list[str] = []
    for name in list(mcp._tool_manager._tools):
        if name not in allowed:
            mcp.remove_tool(name)
            removed.append(name)
    return {
        "ok": True,
        "profile": selected,
        "removed": removed,
        "kept": len(mcp._tool_manager._tools),
    }


def profile_report(profile: str, path: Path | None = None) -> dict[str, Any]:
    """Summarize a profile without mutating a server."""

    if profile not in PROFILES:
        return {"ok": False, "profile": profile, "error": "unknown profile"}
    specs = native_specs(path)
    if profile == "legacy":
        selected = specs
    else:
        selected = [spec for spec in specs if profile in spec.profiles]
    families: dict[str, int] = {}
    for spec in selected:
        families[spec.family] = families.get(spec.family, 0) + 1
    return {
        "ok": True,
        "profile": profile,
        "description": PROFILE_DESCRIPTIONS[profile],
        "total": len(selected),
        "families": dict(sorted(families.items())),
        "tools": sorted(spec.name for spec in selected),
    }


def all_profiles_report(path: Path | None = None) -> dict[str, Any]:
    return {profile: profile_report(profile, path) for profile in PROFILES}


def iter_specs(specs: Iterable[OperationSpec]) -> Iterable[OperationSpec]:
    return specs
