from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
MCP_ROOT = ROOT / "tools" / "skills" / "mcp" / "ReverseLabToolsMCP"
sys.path.insert(0, str(MCP_ROOT))

from reverselab_mcp import registry  # noqa: E402
from reverselab_mcp.contracts import Coverage, fail, ok  # noqa: E402


class FakeMCP:
    def __init__(self, names: list[str]) -> None:
        self._tool_manager = SimpleNamespace(_tools={name: object() for name in names})

    def remove_tool(self, name: str) -> None:
        del self._tool_manager._tools[name]

    def add_tool(self, fn, name=None, description=None) -> None:
        self._tool_manager._tools[name] = fn


def test_legacy_covers_every_registered_tool():
    discovered = {name for name, _ in registry.discover_native_tools()}
    specs = {spec.name for spec in registry.native_specs()}
    assert discovered == specs
    assert len(specs) >= 120


def test_profiles_are_disjoint_by_format():
    pe = registry.allowed_tools("pe")
    apk = registry.allowed_tools("apk")
    ctf = registry.allowed_tools("ctf")

    assert "ghidra_headless_analyze" in pe
    assert "http_probe" not in pe
    assert "android_adb_devices" not in pe

    assert "android_adb_devices" in apk
    assert "ghidra_headless_analyze" not in apk

    assert "http_probe" in ctf
    assert "ghidra_headless_analyze" not in ctf


def test_common_profile_always_has_intake_and_workspace_tools():
    common = registry.allowed_tools("common")
    assert {"hash_file", "triage_pe", "static_backend_status"} <= common


def test_general_profile_owns_new_format_tools():
    general = registry.allowed_tools("general")
    assert {"pcap_summary", "dotnet_metadata", "wasm_info"} <= general
    assert "ghidra_headless_analyze" not in general


def test_unknown_profile_is_rejected():
    with pytest.raises(ValueError):
        registry.allowed_tools("does-not-exist")


def test_apply_profile_prunes_unrelated_tools():
    mcp = FakeMCP(["hash_file", "ghidra_headless_analyze", "http_probe", "android_adb_devices"])
    report = registry.apply_profile(mcp, "pe")
    assert report["ok"] is True
    assert "ghidra_headless_analyze" in mcp._tool_manager._tools
    assert "http_probe" not in mcp._tool_manager._tools
    assert "android_adb_devices" not in mcp._tool_manager._tools


def test_apply_profile_legacy_is_a_noop():
    mcp = FakeMCP(["hash_file", "http_probe"])
    report = registry.apply_profile(mcp, "legacy")
    assert report["kept"] == 2
    assert set(mcp._tool_manager._tools) == {"hash_file", "http_probe"}


def test_apply_profile_rejects_unknown_without_pruning():
    mcp = FakeMCP(["hash_file"])
    report = registry.apply_profile(mcp, "nope")
    assert report["ok"] is False
    assert "hash_file" in mcp._tool_manager._tools


def test_envelope_ok_and_fail_share_one_shape():
    success = ok("pcap_summary", target={"path": "a.pcap"}, findings={"count": 1})
    failure = fail("pcap_summary", kind="missing_engine", message="no tshark", remedy="install it")
    assert success["schema"] == failure["schema"] == "reverselab.envelope.v1"
    assert success["ok"] is True and success["error"] is None
    assert failure["ok"] is False
    assert failure["error"]["kind"] == "missing_engine"
    assert failure["error"]["remedy"] == "install it"
    assert failure["coverage"]["complete"] is False


def test_coverage_dataclass_is_serialized():
    result = ok("x", coverage=Coverage(scope="capture", complete=False, reason="filtered"))
    assert result["coverage"] == {"scope": "capture", "complete": False, "reason": "filtered"}


@pytest.mark.parametrize("profile", ["common", "apk", "pe", "general"])
def test_reference_tools_in_sample_profiles(profile):
    assert {"kb_router", "kb_read_file"} <= registry.allowed_tools(profile)


def test_shared_knowledge_lookup(monkeypatch):
    from reverselab_mcp.tools import kb

    monkeypatch.setattr(kb, "kb_router", lambda query, board, track: {"track": track, "board": board})
    assert kb.blue_kb_router("checksum", "general") == {"track": "blue", "board": "general"}
    assert "error" in kb.blue_kb_router("checksum", track="red")
    for track in ["blue", "both", "red"]:
        monkeypatch.setattr(kb, "kb_read_file", lambda *a: {"track": track, "content": "fixture"})
        result = kb.blue_kb_read_file("fixture")
        assert ("content" in result) == (track in {"blue", "both"})
