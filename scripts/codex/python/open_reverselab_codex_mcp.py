from __future__ import annotations

import argparse
import importlib
import inspect
import json
import os
import sys
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import Context, FastMCP

import open_reverselab_codex_support as support

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")


def _ensure_upstream_import_path() -> None:
    module_dir = str(support.upstream_module_dir())
    if module_dir not in sys.path:
        sys.path.insert(0, module_dir)


def _load_upstream_module():
    _ensure_upstream_import_path()
    return importlib.import_module("reverse_lab_tools_mcp")


def _load_upstream_tools() -> dict[str, Any]:
    upstream = _load_upstream_module()
    return upstream.mcp._tool_manager._tools


async def _context_roots(ctx: Context | None) -> list[str]:
    if ctx is None:
        return []
    try:
        result = await ctx.session.list_roots()
    except Exception:
        return []
    return [root.uri for root in getattr(result, "roots", [])]


def _selected_project_root(explicit_project_root: str, roots: list[str]) -> Path:
    return support.select_project_root(explicit_project_root, roots)


def _wrapper_description(description: str) -> str:
    description = description.strip()
    extra = "Codex adapter: optional project_root routes generated artifacts to the current project."
    if description:
        return f"{description}\n\n{extra}"
    return extra


def _make_upstream_wrapper(tool_name: str, tool_obj: Any):
    async def wrapper(*args, ctx: Context, project_root: str = "", **kwargs):
        roots = await _context_roots(ctx)
        target_project = _selected_project_root(project_root, roots)
        result = support.invoke_upstream_tool(tool_name, kwargs, target_project)
        if isinstance(result, dict):
            result.setdefault("project_root_used", str(target_project))
        return result

    wrapper.__name__ = tool_name
    wrapper.__doc__ = _wrapper_description(tool_obj.description or "")
    original_signature = inspect.signature(tool_obj.fn)
    parameters = list(original_signature.parameters.values())
    parameters.append(
        inspect.Parameter(
            "project_root",
            inspect.Parameter.KEYWORD_ONLY,
            default="",
            annotation=str,
        )
    )
    parameters.append(
        inspect.Parameter(
            "ctx",
            inspect.Parameter.KEYWORD_ONLY,
            annotation=Context,
        )
    )
    wrapper.__signature__ = original_signature.replace(parameters=parameters)
    return wrapper


def _run_upstream_invocation(tool_name: str, arguments_json: str, project_root: str = "") -> int:
    args = json.loads(arguments_json or "{}")
    if not isinstance(args, dict):
        raise ValueError("arguments_json must decode to an object")

    target_root = support.select_project_root(project_root or support.repo_root(), [])
    env = support.wrapper_environment(target_root)
    os.environ.update(env)
    upstream = _load_upstream_module()
    fn = getattr(upstream, tool_name, None)
    if fn is None:
        raise AttributeError(f"unknown upstream tool: {tool_name}")
    result = fn(**args)
    print(json.dumps(result, ensure_ascii=False))
    return 0


def _list_upstream_tools() -> int:
    tools = sorted(_load_upstream_tools().keys())
    print(json.dumps({"tools": tools}, ensure_ascii=False))
    return 0


def _doctor() -> int:
    payload = support.doctor()
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


def build_server() -> FastMCP:
    server = FastMCP(support.SERVER_NAME)

    @server.tool(
        name="codex_enable_project_mode",
        description="Enable open-reverselab Codex mode for the current or specified project. First activation previews changes and requires an exact confirmation text before writing files.",
    )
    async def codex_enable_project_mode(project_root: str = "", confirm_text: str = "", ctx: Context | None = None) -> dict[str, Any]:
        roots = await _context_roots(ctx)
        target_root = _selected_project_root(project_root, roots)
        return support.enable_project_mode(target_root, confirm=confirm_text)

    @server.tool(
        name="codex_disable_project_mode",
        description="Disable open-reverselab Codex mode for the current or specified project. This removes only the integration state and leaves analysis artifacts in place.",
    )
    async def codex_disable_project_mode(project_root: str = "", confirm_text: str = "", ctx: Context | None = None) -> dict[str, Any]:
        roots = await _context_roots(ctx)
        target_root = _selected_project_root(project_root, roots)
        return support.disable_project_mode(target_root, confirm=confirm_text)

    @server.tool(
        name="codex_project_mode_status",
        description="Show whether the current or specified project is bound to open-reverselab Codex mode and whether the binding is healthy.",
    )
    async def codex_project_mode_status(project_root: str = "", ctx: Context | None = None) -> dict[str, Any]:
        roots = await _context_roots(ctx)
        target_root = _selected_project_root(project_root, roots)
        return support.project_mode_status(target_root)

    @server.tool(
        name="codex_repair_project_mode",
        description="Repair a bound project by recreating the managed marker files, AGENTS block, and namespaced directories. Requires the same confirmation text as enable.",
    )
    async def codex_repair_project_mode(project_root: str = "", confirm_text: str = "", ctx: Context | None = None) -> dict[str, Any]:
        roots = await _context_roots(ctx)
        target_root = _selected_project_root(project_root, roots)
        return support.repair_project_mode(target_root, confirm=confirm_text)

    for tool_name, tool_obj in sorted(_load_upstream_tools().items()):
        server.add_tool(
            _make_upstream_wrapper(tool_name, tool_obj),
            name=tool_name,
            description=_wrapper_description(tool_obj.description or ""),
        )

    return server


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="open-reverselab Codex MCP wrapper")
    parser.add_argument("--invoke-upstream", default="", help="Invoke one upstream tool and exit")
    parser.add_argument("--arguments-json", default="{}", help="JSON object with upstream tool arguments")
    parser.add_argument("--project-root", default="", help="Project root for routed output")
    parser.add_argument("--list-upstream-tools", action="store_true", help="List upstream tool names and exit")
    parser.add_argument("--doctor", action="store_true", help="Run local wrapper diagnostics and exit")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.list_upstream_tools:
        return _list_upstream_tools()
    if args.doctor:
        return _doctor()
    if args.invoke_upstream:
        return _run_upstream_invocation(args.invoke_upstream, args.arguments_json, args.project_root)
    build_server().run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
