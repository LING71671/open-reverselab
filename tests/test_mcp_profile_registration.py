from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
MCP_ROOT = ROOT / "tools" / "skills" / "mcp" / "ReverseLabToolsMCP"
sys.path.insert(0, str(MCP_ROOT))

from reverselab_mcp import paths, registry  # noqa: E402


class FakeMCP:
    def __init__(self, names: set[str]) -> None:
        self._tool_manager = SimpleNamespace(_tools={name: object() for name in names})

    def remove_tool(self, name: str) -> None:
        del self._tool_manager._tools[name]


@pytest.fixture(scope="module")
def server():
    spec = importlib.util.spec_from_file_location(
        "reverselab_server_registration_test", MCP_ROOT / "reverse_lab_tools_mcp.py"
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _registered_names(server) -> set[str]:
    manager = getattr(server.mcp, "_tool_manager", None)
    if manager is None:
        pytest.skip("FastMCP registry is unavailable; the MCP CLI smoke step covers real registration")
    return set(manager._tools)


def test_real_fastmcp_registrations_match_registry(server):
    registered = _registered_names(server)
    reported = {spec.name for spec in registry.native_specs()}

    assert registered == reported


@pytest.mark.parametrize("profile", ["common", "ctf", "pe", "apk", "general"])
def test_profile_pruning_matches_report(server, profile):
    fake = FakeMCP(_registered_names(server))

    result = registry.apply_profile(fake, profile)

    assert result["ok"] is True
    assert set(fake._tool_manager._tools) == registry.allowed_tools(profile)
    assert result["kept"] == len(registry.allowed_tools(profile))


@pytest.mark.parametrize("tool", ["static_headless_analyze", "ghidra_headless_analyze", "ida_headless_analyze"])
def test_mcp_schema_preserves_projects_by_default(server, tool):
    assert tool in _registered_names(server)
    schema = server.mcp._tool_manager._tools[tool].parameters
    assert schema["properties"]["overwrite"]["default"] is False


@pytest.mark.parametrize(
    "tool, options, simulate_deadline",
    [
        ("ghidra_headless_analyze", {}, False),
        ("static_headless_analyze", {"backend": "ghidra"}, True),
        ("static_headless_analyze", {"backend": "ghidra", "overwrite": True}, False),
    ],
)
def test_mcp_ghidra_publishes_consistent_partial_summary(server, tmp_path, monkeypatch, tool, options, simulate_deadline):
    sample = tmp_path / "fixture.bin"
    sample.write_bytes(b"static fixture")
    executable = tmp_path / "analyzeHeadless"
    executable.touch()
    (tmp_path / "ReverseLabExportSummary.java").touch()
    exports = tmp_path / "exports"
    ghidra = server.ghidra_headless
    monkeypatch.setattr(paths, "ALLOWED_ROOTS", [tmp_path])
    monkeypatch.setattr(ghidra, "GHIDRA_HEADLESS_BAT", executable)
    monkeypatch.setattr(ghidra, "GHIDRA_SCRIPT_DIR", tmp_path)
    monkeypatch.setattr(ghidra, "GHIDRA_PROJECTS_DIR", tmp_path / "projects")
    monkeypatch.setattr(ghidra, "GHIDRA_EXPORTS_DIR", exports)

    def export(args, timeout):
        assert ("-overwrite" in args) is options.get("overwrite", False)
        output = Path(args[args.index("-postScript") + 2])
        output.write_text(json.dumps({
            "run_id": args[-2], "target_sha256": args[-1], "analysis_complete": True,
            "program": {}, "functions": [], "imports": [], "strings": [],
        }), encoding="utf-8")
        assert not list(exports.glob("*-ghidra-summary.json"))
        if simulate_deadline:
            raise subprocess.TimeoutExpired(args, timeout)
        return 0, "REPORT: Analysis timed out at 1 seconds.", ""

    monkeypatch.setattr(ghidra, "run", export)
    result = getattr(server, tool)(str(sample), project_name="existing-project", **options)
    assert result["status"] == "partial", result
    assert result["analysis_timed_out"] is True
    assert result["summary"]["analysis_complete"] is False
    assert json.loads(Path(result["summary_path"]).read_text(encoding="utf-8")) == result["summary"]
    if tool == "static_headless_analyze":
        assert result["fallback_used"] is False
        assert result["attempts"][0]["error"]


def test_mcp_pcap_keeps_hierarchy_when_capinfos_exits_with_error(server, tmp_path, monkeypatch):
    capture = tmp_path / "fixture.pcap"
    capture.touch()
    monkeypatch.setattr(paths, "ALLOWED_ROOTS", [tmp_path])
    monkeypatch.setattr(server.pcap, "_tshark", lambda: "tshark")
    monkeypatch.setattr(server.pcap, "_capinfos", lambda: "capinfos")

    def run(args, timeout):
        if args[0] == "tshark":
            return 0, "DNS hierarchy", ""
        return 2, "", "metadata unavailable"

    monkeypatch.setattr(server.pcap, "run", run)
    result = server.pcap_summary(str(capture))
    assert result["ok"] is False
    assert result["error"]["kind"] == "partial"
    assert result["coverage"]["complete"] is False
    assert result["findings"]["protocol_hierarchy"] == "DNS hierarchy"
    assert result["findings"]["capture_error"] == "capinfos exited 2: metadata unavailable"
