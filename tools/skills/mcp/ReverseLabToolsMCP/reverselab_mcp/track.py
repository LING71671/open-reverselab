"""Dual-track (BLUE / RED / BOTH) state, routing, and RED tool gating."""

from __future__ import annotations

import os
import re
from typing import Any

VALID_TRACKS: tuple[str, ...] = ("blue", "red", "both")
DEFAULT_TRACK = "blue"
TRACK_ENV_VAR = "REVERSELAB_MODE"

RED_GATED_TOOLS: frozenset[str] = frozenset(
    {
        "http_probe",
        "ctf_new_challenge",
        "ctf_autopilot_round",
        "run_ctf_tool",
        "run_sqlmap_request",
        "burp_launch",
        "android_frida_run_script",
        "patch_bytes",
        "patch_pe_bytes",
        "patch_pattern",
        "rizin_write_bytes",
        "rizin_assemble_patch",
    }
)

_runtime_track: str | None = None

_APK_MARKERS = (
    ".apk", ".dex", ".smali", "apk", "dex", "smali", "jadx", "android",
    "frida", "adb", "jni", "il2cpp", "libil2cpp", "mumu", "webview", "okhttp",
)
_PE_MARKERS = (
    ".exe", ".dll", ".sys", ".pdb", "pe", "win32", "win64", "x64dbg",
    "ghidra", "asar", "electron", "upx", "iat", "rva", "procmon", "yara",
    "sigma", "authenticode", "syscall", "detour",
)
_WEB_MARKERS = (
    "http://", "https://", "url", "jwt", "sqli", "sql", "xss", "ssrf",
    "ssti", "csrf", "idor", "oauth", "saml", "burp", "sqlmap", "dirsearch",
    "tplmap", "web", "ctf", "cookie", "header", "graphql", "cors", "csp",
)
_GENERAL_MARKERS = (
    "crypto", "rsa", "aes", "prng", "lcg", "mt19937", "protobuf", "grpc",
    "signature", "hmac", "kernel", "seccomp", "cheat", "protocol", "firmware",
    "jtag", "uart", "ble", "radio",
)

_RED_INTENT_MARKERS = (
    "exploit", "attack", "bypass", "crack", "keygen", "patch", "inject",
    "sqli", "sqlmap", "fuzz", "bruteforce", "brute", "probe", "burp",
    "frida", "hook", "tamper", "pwn", "payload", "offensive", "red",
    "利用", "攻击", "绕过", "破解", "注入", "爆破", "补丁", "探测", "渗透",
)
_BLUE_INTENT_MARKERS = (
    "defend", "defense", "harden", "hardening", "detect", "detection",
    "mitigate", "mitigation", "remediate", "remediation", "protect",
    "yara", "sigma", "ioc", "triage", "verify", "integrity", "blue",
    "防御", "加固", "检测", "缓解", "防护", "取证", "研判", "蓝队", "基线",
)
_BOTH_INTENT_MARKERS = (
    "both", "dual", "purple", "compare", "pair", "paired",
    "双轨", "攻防", "对照", "红蓝", "紫队",
)


def _capabilities_for(track: str) -> dict[str, bool]:
    return {
        "blue_kb": track in ("blue", "both"),
        "red_kb": track in ("red", "both"),
        "red_tools_allowed": track in ("red", "both"),
        "paired_view": track == "both",
    }


def get_track() -> str:
    """Return the active track ('blue', 'red', or 'both')."""
    if _runtime_track is not None:
        return _runtime_track
    env_val = os.environ.get(TRACK_ENV_VAR, "").strip().lower()
    if env_val in VALID_TRACKS:
        return env_val
    return DEFAULT_TRACK


def reset_track() -> None:
    """Clear any runtime track override (falls back to env or default)."""
    global _runtime_track
    _runtime_track = None


def resolve_track(track: str = "") -> str:
    """Resolve an explicit track or 'auto'/'' to an active track name."""
    norm = (track or "").strip().lower()
    if not norm or norm == "auto":
        return get_track()
    if norm not in VALID_TRACKS:
        raise ValueError(
            f"Invalid track '{track}'. Must be one of: {', '.join(VALID_TRACKS)} or 'auto'."
        )
    return norm


def get_track_status() -> dict[str, Any]:
    """Return current track mode, source, env value, and gating status."""
    env_raw = os.environ.get(TRACK_ENV_VAR, "")
    env_norm = env_raw.strip().lower()

    if _runtime_track is not None:
        current = _runtime_track
        source = "runtime"
    elif env_norm in VALID_TRACKS:
        current = env_norm
        source = "env"
    else:
        current = DEFAULT_TRACK
        source = "default"

    status: dict[str, Any] = {
        "track": current,
        "source": source,
        "env_var": TRACK_ENV_VAR,
        "env_value": env_raw,
        "valid_tracks": list(VALID_TRACKS),
        "capabilities": _capabilities_for(current),
        "red_gated_tools": sorted(RED_GATED_TOOLS),
    }
    if env_raw.strip() and env_norm not in VALID_TRACKS:
        status["env_warning"] = (
            f"{TRACK_ENV_VAR}={env_raw!r} is invalid; falling back to '{current}'."
        )
    return status


def set_track(track: str) -> dict[str, Any]:
    """Switch the runtime track ('blue', 'red', or 'both')."""
    global _runtime_track
    normalized = (track or "").strip().lower()
    if normalized not in VALID_TRACKS:
        return {
            "error": f"Invalid track '{track}'. Must be one of: {', '.join(VALID_TRACKS)}.",
            "valid_tracks": list(VALID_TRACKS),
            "track": get_track(),
        }

    previous = get_track()
    _runtime_track = normalized
    return {
        "track": normalized,
        "previous_track": previous,
        "source": "runtime",
        "capabilities": _capabilities_for(normalized),
        "red_gated_tools": sorted(RED_GATED_TOOLS),
    }


def check_red_tool_allowed(tool_name: str, track: str | None = None) -> dict[str, Any] | None:
    """Return a structured block error dict if tool_name is gated in current track."""
    active = (track or get_track()).strip().lower()
    if tool_name in RED_GATED_TOOLS and active == "blue":
        return {
            "error": f"Tool '{tool_name}' is blocked in 'blue' track mode.",
            "tool": tool_name,
            "blocked_by_track": "blue",
            "required_track": "red",
            "hint": "Call set_track('red') or set_track('both')",
        }
    return None


def _detect_board(text_lower: str) -> str:
    scores = {
        "apk-reverse": sum(1 for m in _APK_MARKERS if m in text_lower),
        "pe-reverse": sum(1 for m in _PE_MARKERS if m in text_lower),
        "ctf-website": sum(1 for m in _WEB_MARKERS if m in text_lower),
        "general": sum(1 for m in _GENERAL_MARKERS if m in text_lower),
    }
    best_board, best_score = max(scores.items(), key=lambda kv: kv[1])
    return best_board if best_score > 0 else ""


def _detect_intent(text_lower: str, active_track: str) -> tuple[str, str]:
    if any(m in text_lower for m in _BOTH_INTENT_MARKERS):
        return "dual", "both"
    red_hits = sum(1 for m in _RED_INTENT_MARKERS if m in text_lower)
    blue_hits = sum(1 for m in _BLUE_INTENT_MARKERS if m in text_lower)
    if red_hits > 0 and blue_hits > 0:
        return "dual", "both"
    if red_hits > blue_hits:
        return "offense", "red"
    if blue_hits > red_hits:
        return "defense", "blue"
    return "triage", active_track


def _recommended_tools(board: str, track: str) -> list[str]:
    blue_common = ["kb_router", "kb_read_file", "kb_catalog"]
    if board == "pe-reverse":
        blue_tools = [
            *blue_common,
            "triage_pe",
            "hash_file",
            "die_scan",
            "rizin_bin_info",
            "rizin_imports",
            "rizin_strings",
            "ghidra_headless_analyze",
            "extract_iocs_from_summary",
            "make_yara_stub",
            "make_sigma_stub",
        ]
        red_tools = [
            "patch_bytes",
            "patch_pe_bytes",
            "patch_pattern",
            "rizin_write_bytes",
            "rizin_assemble_patch",
        ]
    elif board == "apk-reverse":
        blue_tools = [
            *blue_common,
            "android_device_info",
            "android_package_info",
            "android_app_baseline",
            "android_pull_artifact_recipe",
            "android_package_fs_recipe",
        ]
        red_tools = ["android_frida_run_script"]
    elif board == "ctf-website":
        blue_tools = [*blue_common, "ctf_tool_status", "burp_status"]
        red_tools = [
            "http_probe",
            "ctf_new_challenge",
            "ctf_autopilot_round",
            "run_ctf_tool",
            "run_sqlmap_request",
            "burp_launch",
        ]
    else:
        blue_tools = [*blue_common, "triage_pe", "hash_file", "die_scan"]
        red_tools = ["http_probe", "run_ctf_tool", "android_frida_run_script", "patch_bytes"]

    if track == "blue":
        return blue_tools
    if track == "red":
        return [*red_tools, *blue_common]
    return [*blue_tools, *[t for t in red_tools if t not in blue_tools]]


def _workflow_steps(board: str, track: str) -> list[str]:
    target_label = board or "all boards"
    if track == "blue":
        return [
            f"1. Query defensive KB entries with kb_router(query, board='{board}', track='blue').",
            f"2. Run read-only triage / static inspection tools for {target_label}.",
            "3. Produce detection rules (YARA/Sigma/IOC) and hardening recommendations.",
        ]
    if track == "red":
        return [
            f"1. Query offensive KB entries with kb_router(query, board='{board}', track='red').",
            "2. Validate target surface with active probes / dynamic hooks / binary patch tools.",
            "3. Record reproducible proof-of-concept steps and verify impact.",
        ]
    return [
        f"1. Query paired offense+defense KB entries with kb_router(query, board='{board}', track='both').",
        "2. Perform static/dynamic validation and map each attack vector to its paired defense doc.",
        "3. Deliver dual-track findings covering both exploit path and remediation.",
    ]


def route_track(target_or_intent: str, track: str = "auto") -> dict[str, Any]:
    """Route a target or intent to track, board, recommended tools, and KB hits."""
    from .tools import kb

    status = get_track_status()
    active_track = status["track"]

    try:
        effective_track = resolve_track(track)
    except ValueError as exc:
        return {
            "error": str(exc),
            "valid_tracks": [*VALID_TRACKS, "auto"],
            "track": active_track,
        }

    text = (target_or_intent or "").strip()
    text_lower = text.lower()
    board_guess = _detect_board(text_lower)
    intent_kind, suggested_track = _detect_intent(text_lower, active_track)

    kb_res: dict[str, Any] = {"top": [], "total": 0}
    if text:
        kb_res = kb.kb_router(text, board=board_guess, track=effective_track)
        if kb_res.get("total", 0) == 0:
            tokens = [tok for tok in re.split(r"[^a-zA-Z0-9_\u4e00-\u9fff.-]+", text) if len(tok) >= 2]
            merged: dict[tuple[str, str], dict[str, Any]] = {}
            for tok in tokens[:8]:
                sub = kb.kb_router(tok, board=board_guess, track=effective_track)
                for item in sub.get("top", []):
                    key = (item["board"], item["id"])
                    if key not in merged or item["score"] > merged[key]["score"]:
                        merged[key] = item
            if merged:
                ranked = sorted(
                    merged.values(),
                    key=lambda r: (r["score"], r.get("priority", 0)),
                    reverse=True,
                )
                kb_res = {"top": ranked[:10], "total": len(ranked)}

    payload: dict[str, Any] = {
        "target_or_intent": target_or_intent,
        "track": effective_track,
        "active_track": active_track,
        "suggested_track": suggested_track,
        "track_source": status["source"],
        "board": board_guess,
        "intent": intent_kind,
        "red_tools_allowed": effective_track in ("red", "both"),
        "blocked_red_tools": sorted(RED_GATED_TOOLS) if effective_track == "blue" else [],
        "recommended_tools": _recommended_tools(board_guess, effective_track),
        "workflow_steps": _workflow_steps(board_guess, effective_track),
        "kb_matches": kb_res.get("top", [])[:5],
    }
    if active_track == "blue" and suggested_track == "red" and (track or "").strip().lower() in ("", "auto"):
        payload["hint"] = (
            "Offensive intent detected while active track is 'blue'. "
            "Call set_track('red') or set_track('both') to unlock RED tools."
        )
    return payload
