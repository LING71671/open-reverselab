from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
MCP_ROOT = ROOT / "tools" / "skills" / "mcp" / "ReverseLabToolsMCP"
sys.path.insert(0, str(MCP_ROOT))

from reverselab_mcp import registry  # noqa: E402


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
