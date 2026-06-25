from __future__ import annotations

import importlib
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

from ..audit import append_audit, audit_log_path
from ..config import HOST_PYTHON_EXE
from ..errors import ToolError
from ..runner import run


PACKAGE_MAP = {
    "lief": ("lief",),
    "frida": ("frida",),
    "angr": ("angr",),
    "capstone": ("capstone",),
    "keystone": ("keystone-engine",),
    "unicorn": ("unicorn",),
}


def _normalize_tool_id(tool_id: str) -> str:
    normalized = tool_id.strip().lower()
    if normalized not in PACKAGE_MAP:
        known = ", ".join(sorted(PACKAGE_MAP))
        raise ToolError(f"unknown tool_id: {tool_id}; known tool ids: {known}")
    return normalized


def _run_host_python_json(source: str) -> dict[str, Any]:
    if not HOST_PYTHON_EXE.exists():
        raise ToolError(f"host python not found: {HOST_PYTHON_EXE}")
    code, stdout, stderr = run([str(HOST_PYTHON_EXE), "-c", source], timeout=180)
    if code != 0:
        raise ToolError(f"host python failed: returncode={code}; stderr={stderr or stdout}")
    try:
        value = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise ToolError(f"host python returned non-JSON output: {stdout}") from exc
    if not isinstance(value, dict):
        raise ToolError(f"host python returned unexpected payload: {type(value).__name__}")
    return value


def python_re_tool_status() -> dict[str, Any]:
    payload = {
        "package_map": {tool_id: list(packages) for tool_id, packages in PACKAGE_MAP.items()},
    }
    script = f"""
import importlib.util, json, sys
payload = {json.dumps(payload, ensure_ascii=False)}
tools = []
for tool_id, packages in sorted(payload["package_map"].items()):
    tools.append({{"tool_id": tool_id, "packages": packages, "installed": bool(importlib.util.find_spec(tool_id))}})
print(json.dumps({{"python_executable": sys.executable, "tools": tools, "installed_count": sum(1 for item in tools if item["installed"])}}, ensure_ascii=False))
"""
    return _run_host_python_json(script)


def python_re_tool_install(tool_id: str, version: str = "", user_scope: bool = True, timeout: int = 600) -> dict[str, Any]:
    normalized = _normalize_tool_id(tool_id)
    packages = [f"{pkg}=={version}" if version.strip() else pkg for pkg in PACKAGE_MAP[normalized]]
    args = [str(HOST_PYTHON_EXE), "-m", "pip", "install"]
    if user_scope:
        args.append("--user")
    args.extend(packages)
    code, stdout, stderr = run(args, timeout=max(30, timeout))
    if code != 0:
        raise ToolError(f"pip install failed: returncode={code}; stderr={stderr or stdout}")
    audit_record = append_audit(
        {
            "action": "python_re_tool_install",
            "status": "ok",
            "tool_id": normalized,
            "packages": packages,
            "user_scope": user_scope,
        }
    )
    return {
        "operation_id": audit_record["operation_id"],
        "tool_id": normalized,
        "packages": packages,
        "user_scope": user_scope,
        "python_executable": str(HOST_PYTHON_EXE),
        "stdout": stdout,
        "stderr": stderr,
        "audit_log": str(audit_log_path()),
    }


def python_re_tool_version(tool_id: str) -> dict[str, Any]:
    normalized = _normalize_tool_id(tool_id)
    script = f"""
import importlib, importlib.util, json, pathlib, sys
tool_id = {json.dumps(normalized, ensure_ascii=False)}
if not importlib.util.find_spec(tool_id):
    print(json.dumps({{"error": f"module is not installed: {{tool_id}}"}}))
    raise SystemExit(0)
module = importlib.import_module(tool_id)
version = getattr(module, "__version__", "") or getattr(module, "version", "")
module_path = getattr(module, "__file__", "")
print(json.dumps({{"tool_id": tool_id, "version": str(version), "module_path": str(pathlib.Path(module_path).resolve()) if module_path else "", "python_executable": sys.executable}}, ensure_ascii=False))
"""
    result = _run_host_python_json(script)
    if "error" in result:
        raise ToolError(str(result["error"]))
    return result
