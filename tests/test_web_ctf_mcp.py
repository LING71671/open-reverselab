from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MCP_ROOT = ROOT / "tools" / "skills" / "mcp" / "ReverseLabToolsMCP"
sys.path.insert(0, str(MCP_ROOT))

from reverselab_mcp.tools import web_ctf  # noqa: E402


def test_split_args_preserves_quoted_url():
    args = web_ctf._split_args('--batch -u "http://example.test/a.php?id=1&x=two words"')

    assert args == ["--batch", "-u", "http://example.test/a.php?id=1&x=two words"]


def test_ctf_save_request_writes_under_exports(tmp_path, monkeypatch):
    monkeypatch.setattr(web_ctf, "CTF_EXPORTS_DIR", tmp_path / "exports" / "ctf-website")

    result = web_ctf.ctf_save_request(
        "GET /vuln?id=1 HTTP/1.1\nHost: example.test\n\n",
        case_name="../bad case",
        filename="../request.raw",
    )

    assert "error" not in result
    written = Path(result["path"])
    if not written.is_absolute():
        written = ROOT / written
    assert written.name == "request.raw.txt"
    assert ".." not in result["path"]


def test_burp_status_is_file_probe_only(tmp_path, monkeypatch):
    burp_dir = tmp_path / "burp"
    burp_dir.mkdir()
    jar = burp_dir / "burpsuite_community_test.jar"
    jar.write_bytes(b"jar")
    monkeypatch.setattr(web_ctf, "BURP_DIR", burp_dir)
    monkeypatch.setattr(web_ctf, "BIN_DIR", tmp_path)

    status = web_ctf.burp_status()

    assert status["installed"] is True
    assert status["jars"][0]["path"].endswith("burpsuite_community_test.jar")
    assert status["proxy"] == "http://127.0.0.1:8080"


def test_tool_command_uses_posix_wrapper_without_cmd_on_unix(tmp_path, monkeypatch):
    script = tmp_path / "missing" / "sqlmap.py"
    wrapper = tmp_path / "bin" / "sqlmap.bat"
    posix_wrapper = tmp_path / "bin" / "sqlmap"
    posix_wrapper.parent.mkdir(parents=True)
    if sys.platform.startswith("win"):
        wrapper.write_text("@echo off\necho sqlmap\n", encoding="utf-8")
    posix_wrapper.write_text("#!/usr/bin/env sh\necho sqlmap\n", encoding="utf-8")
    monkeypatch.setitem(web_ctf._CTF_TOOL_MAP, "test_sqlmap", {"script": script, "wrapper": wrapper})

    cmd, meta = web_ctf._tool_command("test_sqlmap")

    assert cmd is not None
    if sys.platform.startswith("win"):
        assert "cmd.exe" in cmd[0].lower() or cmd[:2] == [web_ctf.os.environ.get("COMSPEC", "cmd.exe"), "/c"]
    else:
        assert "cmd.exe" not in " ".join(cmd).lower()
        assert str(posix_wrapper) in cmd
        assert "POSIX wrapper" in meta["warning"]


def test_run_sqlmap_request_builds_request_args(tmp_path, monkeypatch):
    req = tmp_path / "request.txt"
    req.write_text("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n", encoding="utf-8")
    called = {}

    def fake_run(tool: str, args: str, timeout: int):
        called.update({"tool": tool, "args": args, "timeout": timeout})
        return {"ok": True}

    monkeypatch.setattr(web_ctf, "run_ctf_tool", fake_run)
    monkeypatch.setattr(web_ctf, "ensure_under", lambda path, roots, label: path)

    result = web_ctf.run_sqlmap_request(str(req), "--batch --dbs", timeout=12)

    assert result == {"ok": True}
    assert called["tool"] == "sqlmap"
    assert called["args"].endswith('" --batch --dbs')
    assert called["timeout"] == 12


def test_ctf_autopilot_round_invokes_controller(tmp_path, monkeypatch):
    manifest = tmp_path / "ai_manifest.json"
    manifest.write_text("{}", encoding="utf-8")
    controller = tmp_path / "ctf_autopilot.py"
    controller.write_text("# test controller\n", encoding="utf-8")
    called = {}

    class FakeCompleted:
        returncode = 0
        stdout = '{"ok": true}'
        stderr = ""

    def fake_run(cmd, cwd, capture_output, text, timeout):
        called.update({"cmd": cmd, "cwd": cwd, "timeout": timeout})
        return FakeCompleted()

    monkeypatch.setattr(web_ctf, "CTF_AUTOPILOT", controller)
    monkeypatch.setattr(web_ctf, "ensure_under", lambda path, roots, label: path)
    monkeypatch.setattr(web_ctf.subprocess, "run", fake_run)

    result = web_ctf.ctf_autopilot_round(
        str(manifest),
        max_actions=2,
        execute=True,
        allow_network_cve=True,
        timeout=12,
    )

    assert result["ok"] is True
    assert result["exit_code"] == 0
    assert "--execute" in called["cmd"]
    assert "--allow-network-cve" in called["cmd"]
    assert called["cmd"][called["cmd"].index("--max-actions") + 1] == "2"
    assert called["timeout"] == 60
