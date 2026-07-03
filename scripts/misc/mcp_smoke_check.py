#!/usr/bin/env python3
"""Start the configured ReverseLab MCP server and run a small tool-call smoke test."""

from __future__ import annotations

import argparse
import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
MCP_CONFIG = ROOT / ".mcp.json"
SERVER_NAME = "reverse_lab_tools"
DEFAULT_REPORT = ROOT / "reports" / "misc" / "mcp-smoke-report.json"
REQUIRED_TOOLS = {
    "kb_router",
    "kb_read_file",
    "project_skills_status",
    "ctf_tool_status",
    "http_probe",
}


def _load_server_config() -> tuple[Any | None, str]:
    try:
        from mcp import StdioServerParameters

        config = json.loads(MCP_CONFIG.read_text(encoding="utf-8"))
    except Exception as exc:
        return None, f"cannot parse .mcp.json: {exc}"

    server = config.get("mcpServers", {}).get(SERVER_NAME)
    if not isinstance(server, dict):
        return None, f"{SERVER_NAME} is missing from .mcp.json"

    command = server.get("command")
    args = server.get("args", [])
    env = server.get("env") or None
    if not command or not isinstance(args, list):
        return None, f"{SERVER_NAME} must define command and args"
    return StdioServerParameters(command=command, args=[str(arg) for arg in args], env=env), ""


def _json_from_tool_result(result: Any) -> dict[str, Any]:
    if result.isError:
        return {"error": "tool returned isError=True"}
    if not result.content:
        return {}
    text = getattr(result.content[0], "text", "")
    if not text:
        return {}
    return json.loads(text)


async def run_smoke() -> dict[str, Any]:
    try:
        from mcp import ClientSession
        from mcp.client.stdio import stdio_client
    except ModuleNotFoundError as exc:
        return {
            "schema": 1,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "root": str(ROOT),
            "overall": "FAIL",
            "error": (
                f"missing Python package: {exc.name}. Run this smoke check via "
                "`uv run --project tools/skills/mcp/ReverseLabToolsMCP python scripts/misc/mcp_smoke_check.py --write-report`."
            ),
            "checks": [],
        }

    params, error = _load_server_config()
    started_at = datetime.now(timezone.utc).isoformat()
    if error or params is None:
        return {
            "schema": 1,
            "generated_at": started_at,
            "root": str(ROOT),
            "overall": "FAIL",
            "error": error,
            "checks": [],
        }

    checks: list[dict[str, Any]] = []
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            tool_names = sorted(tool.name for tool in tools.tools)
            missing = sorted(REQUIRED_TOOLS - set(tool_names))
            checks.append(
                {
                    "name": "list_tools",
                    "level": "FAIL" if missing else "PASS",
                    "detail": f"{len(tool_names)} tools available",
                    "missing_required": missing,
                }
            )

            if missing:
                return {
                    "schema": 1,
                    "generated_at": started_at,
                    "root": str(ROOT),
                    "overall": "FAIL",
                    "tool_count": len(tool_names),
                    "required_tools": sorted(REQUIRED_TOOLS),
                    "checks": checks,
                }

            router_result = await session.call_tool("kb_router", {"query": "JWT", "board": "ctf-website"})
            router_payload = _json_from_tool_result(router_result)
            router_ok = router_payload.get("total", 0) > 0 and bool(router_payload.get("top"))
            checks.append(
                {
                    "name": "kb_router",
                    "level": "PASS" if router_ok else "FAIL",
                    "detail": f"matches={router_payload.get('total', 0)}",
                }
            )

            read_ok = False
            read_path = ""
            if router_ok:
                first_file = router_payload["top"][0]["files"][0]
                read_result = await session.call_tool(
                    "kb_read_file",
                    {"technique_path": first_file, "board": "ctf-website"},
                )
                read_payload = _json_from_tool_result(read_result)
                read_ok = not read_payload.get("error") and read_payload.get("size", 0) > 0
                read_path = read_payload.get("path", first_file)
            checks.append(
                {
                    "name": "kb_read_file",
                    "level": "PASS" if read_ok else "FAIL",
                    "detail": read_path or "not executed",
                }
            )

            skills_result = await session.call_tool("project_skills_status", {})
            skills_payload = _json_from_tool_result(skills_result)
            skills_ok = "skills" in skills_payload
            checks.append(
                {
                    "name": "project_skills_status",
                    "level": "PASS" if skills_ok else "FAIL",
                    "detail": f"skills={len(skills_payload.get('skills', {}))}",
                }
            )

            ctf_result = await session.call_tool("ctf_tool_status", {})
            ctf_payload = _json_from_tool_result(ctf_result)
            ctf_ok = "tools" in ctf_payload
            checks.append(
                {
                    "name": "ctf_tool_status",
                    "level": "PASS" if ctf_ok else "FAIL",
                    "detail": f"tools={len(ctf_payload.get('tools', {}))}",
                }
            )

            overall = "FAIL" if any(check["level"] == "FAIL" for check in checks) else "PASS"
            return {
                "schema": 1,
                "generated_at": started_at,
                "root": str(ROOT),
                "overall": overall,
                "tool_count": len(tool_names),
                "required_tools": sorted(REQUIRED_TOOLS),
                "checks": checks,
            }


def write_report(payload: dict[str, Any], report_path: Path = DEFAULT_REPORT) -> Path:
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return report_path


def print_human(payload: dict[str, Any]) -> None:
    print("ReverseLab MCP smoke check")
    print(f"Repository root: {ROOT}")
    print(f"Overall: {payload.get('overall', 'FAIL')}")
    if payload.get("error"):
        print(f"Error: {payload['error']}")
    if "tool_count" in payload:
        print(f"Tools: {payload['tool_count']}")
    print("")
    for check in payload.get("checks", []):
        print(f"[{check.get('level', 'FAIL')}] {check.get('name')}: {check.get('detail')}")
        missing = check.get("missing_required") or []
        if missing:
            print(f"      Missing: {', '.join(missing)}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="print machine-readable output")
    parser.add_argument(
        "--write-report",
        nargs="?",
        const=str(DEFAULT_REPORT),
        help=f"write smoke report JSON; default path is {DEFAULT_REPORT.relative_to(ROOT)}",
    )
    args = parser.parse_args()

    payload = asyncio.run(run_smoke())
    if args.write_report:
        report_path = Path(args.write_report)
        if not report_path.is_absolute():
            report_path = ROOT / report_path
        write_report(payload, report_path)
        payload["report_path"] = str(report_path)

    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print_human(payload)
        if args.write_report:
            print("")
            print(f"Report written: {payload['report_path']}")

    return 0 if payload.get("overall") == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
