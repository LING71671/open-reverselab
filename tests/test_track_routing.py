from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
MCP_ROOT = ROOT / "tools" / "skills" / "mcp" / "ReverseLabToolsMCP"
if str(MCP_ROOT) not in sys.path:
    sys.path.insert(0, str(MCP_ROOT))

import reverse_lab_tools_mcp as mcp_server  # noqa: E402
from reverselab_mcp import track as track_mod  # noqa: E402
from reverselab_mcp.tools import kb  # noqa: E402


@pytest.fixture(autouse=True)
def _clean_track_state(monkeypatch):
    monkeypatch.delenv("REVERSELAB_MODE", raising=False)
    track_mod.reset_track()
    yield
    track_mod.reset_track()


def test_track_defaults_to_blue_and_honors_env(monkeypatch):
    status = mcp_server.get_track_status()
    assert status["track"] == "blue"
    assert status["source"] == "default"
    assert status["capabilities"]["red_tools_allowed"] is False

    monkeypatch.setenv("REVERSELAB_MODE", "red")
    status_red = mcp_server.get_track_status()
    assert status_red["track"] == "red"
    assert status_red["source"] == "env"
    assert status_red["capabilities"]["red_tools_allowed"] is True

    monkeypatch.setenv("REVERSELAB_MODE", "both")
    status_both = mcp_server.get_track_status()
    assert status_both["track"] == "both"
    assert status_both["capabilities"]["paired_view"] is True

    monkeypatch.setenv("REVERSELAB_MODE", "invalid_mode")
    status_invalid = mcp_server.get_track_status()
    assert status_invalid["track"] == "blue"
    assert "env_warning" in status_invalid


def test_set_track_switches_and_validates():
    res = mcp_server.set_track("red")
    assert res["track"] == "red"
    assert res["previous_track"] == "blue"
    assert res["source"] == "runtime"

    res_both = mcp_server.set_track("BOTH")
    assert res_both["track"] == "both"
    assert res_both["previous_track"] == "red"

    err = mcp_server.set_track("purple")
    assert "error" in err
    assert mcp_server.get_track_status()["track"] == "both"


def test_route_track_infers_board_and_respects_active_track():
    web_blue = mcp_server.route_track("http://example.test/login?id=1 sqli exploit", track="auto")
    assert web_blue["board"] == "ctf-website"
    assert web_blue["track"] == "blue"
    assert web_blue["suggested_track"] == "red"
    assert web_blue["red_tools_allowed"] is False
    assert "hint" in web_blue

    apk_red = mcp_server.route_track("app-debug.apk frida hook JNI_OnLoad", track="red")
    assert apk_red["board"] == "apk-reverse"
    assert apk_red["track"] == "red"
    assert apk_red["red_tools_allowed"] is True
    assert "android_frida_run_script" in apk_red["recommended_tools"]

    pe_both = mcp_server.route_track("sample.exe upx x64dbg", track="both")
    assert pe_both["board"] == "pe-reverse"
    assert pe_both["track"] == "both"
    assert pe_both["red_tools_allowed"] is True

    bad = mcp_server.route_track("sample.exe", track="invalid")
    assert "error" in bad


def test_kb_router_supports_general_board_and_track_filtering(tmp_path, monkeypatch):
    gen_dir = tmp_path / "general" / "techniques"
    gen_dir.mkdir(parents=True)
    index_data = {
        "version": "1.1",
        "entries": [
            {
                "id": "rsa-attack",
                "track": "red",
                "signals": ["rsa", "wiener"],
                "files": ["crypto/04-rsa-attack-family.md"],
                "priority": 10,
            },
            {
                "id": "rsa-attack-defense",
                "track": "blue",
                "defends": "rsa-attack",
                "signals": ["rsa", "oaep"],
                "files": ["crypto/04-rsa-attack-family-defense.md"],
                "priority": 10,
            },
            {
                "id": "crypto-id",
                "track": "both",
                "signals": ["rsa", "aes", "cipher"],
                "files": ["crypto/01-algorithm-identification.md"],
                "priority": 9,
            },
        ],
    }
    (gen_dir / "kb-index.json").write_text(json.dumps(index_data), encoding="utf-8")
    monkeypatch.setitem(kb.KB_ROOTS, "general", gen_dir)

    blue = kb.kb_router("rsa", board="general", track="blue")
    assert blue["track"] == "blue"
    assert blue["boards_searched"] == ["general"]
    assert [item["id"] for item in blue["top"]] == ["rsa-attack-defense", "crypto-id"]
    assert blue["top"][0]["score"] >= kb.SCORE_SIGNAL_EXACT

    red = kb.kb_router("rsa", board="general", track="red")
    assert red["track"] == "red"
    assert [item["id"] for item in red["top"]] == ["rsa-attack", "crypto-id"]

    both = kb.kb_router("rsa", board="general", track="both")
    assert both["track"] == "both"
    assert {item["id"] for item in both["top"]} == {"rsa-attack", "rsa-attack-defense", "crypto-id"}
    assert both["paired_links"]
    rsa_item = next(item for item in both["top"] if item["id"] == "rsa-attack")
    assert rsa_item["paired_entries"][0]["id"] == "rsa-attack-defense"
    assert any(p.endswith("crypto/04-rsa-attack-family-defense.md") for p in rsa_item["paired_files"])


def test_kb_catalog_and_read_file_support_general_board():
    catalog = mcp_server.kb_catalog(board="general")
    assert "general" in catalog["boards"]
    assert catalog["boards"]["general"]["total_entries"] >= 1
    assert "track_counts" in catalog["boards"]["general"]

    read_res = mcp_server.kb_read_file("crypto/01-algorithm-identification.md", board="general")
    assert "error" not in read_res
    assert read_res["board"] == "general"
    assert read_res["size"] > 0


def test_red_mcp_tools_blocked_in_blue_and_allowed_in_red_and_both(monkeypatch):
    called: list[str] = []

    def _stub(name: str):
        def _inner(*args, **kwargs):
            called.append(name)
            return {"ok": True, "tool": name}
        return _inner

    monkeypatch.setattr(mcp_server.web_ctf, "http_probe", _stub("http_probe"))
    monkeypatch.setattr(mcp_server.web_ctf, "ctf_new_challenge", _stub("ctf_new_challenge"))
    monkeypatch.setattr(mcp_server.web_ctf, "ctf_autopilot_round", _stub("ctf_autopilot_round"))
    monkeypatch.setattr(mcp_server.web_ctf, "run_ctf_tool", _stub("run_ctf_tool"))
    monkeypatch.setattr(mcp_server.web_ctf, "run_sqlmap_request", _stub("run_sqlmap_request"))
    monkeypatch.setattr(mcp_server.web_ctf, "burp_launch", _stub("burp_launch"))
    monkeypatch.setattr(mcp_server.android_mumu, "android_frida_run_script", _stub("android_frida_run_script"))
    monkeypatch.setattr(mcp_server.mutations, "patch_bytes", _stub("patch_bytes"))
    monkeypatch.setattr(mcp_server.mutations, "patch_pe_bytes", _stub("patch_pe_bytes"))
    monkeypatch.setattr(mcp_server.mutations, "patch_pattern", _stub("patch_pattern"))
    monkeypatch.setattr(mcp_server.rizin_write, "rizin_write_bytes", _stub("rizin_write_bytes"))
    monkeypatch.setattr(mcp_server.rizin_write, "rizin_assemble_patch", _stub("rizin_assemble_patch"))

    invocations = [
        ("http_probe", lambda: mcp_server.http_probe("http://example.test")),
        ("ctf_new_challenge", lambda: mcp_server.ctf_new_challenge("demo")),
        ("ctf_autopilot_round", lambda: mcp_server.ctf_autopilot_round("cases/demo/ai_manifest.json")),
        ("run_ctf_tool", lambda: mcp_server.run_ctf_tool("sqlmap", "--version")),
        ("run_sqlmap_request", lambda: mcp_server.run_sqlmap_request("req.txt")),
        ("burp_launch", lambda: mcp_server.burp_launch()),
        ("android_frida_run_script", lambda: mcp_server.android_frida_run_script("pkg", "send(1)")),
        ("patch_bytes", lambda: mcp_server.patch_bytes("sample.exe", 0, "90")),
        ("patch_pe_bytes", lambda: mcp_server.patch_pe_bytes("sample.exe", "0x0", "90")),
        ("patch_pattern", lambda: mcp_server.patch_pattern("sample.exe", "4D 5A", "90 90")),
        ("rizin_write_bytes", lambda: mcp_server.rizin_write_bytes("sample.exe", 0, "90")),
        ("rizin_assemble_patch", lambda: mcp_server.rizin_assemble_patch("sample.exe", 0, "nop")),
    ]

    # Default 'blue' mode blocks every RED tool without executing
    for name, fn in invocations:
        res = fn()
        assert res["blocked_by_track"] == "blue", name
        assert res["required_track"] == "red", name
        assert res["hint"] == "Call set_track('red') or set_track('both')", name
        assert "error" in res, name
    assert called == []

    # 'red' mode allows every RED tool
    mcp_server.set_track("red")
    for name, fn in invocations:
        res = fn()
        assert res == {"ok": True, "tool": name}, name
    assert len(called) == 12

    # 'both' mode also allows every RED tool
    called.clear()
    mcp_server.set_track("both")
    for name, fn in invocations:
        res = fn()
        assert res == {"ok": True, "tool": name}, name
    assert len(called) == 12
