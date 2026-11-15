from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from conftest import ROOT, load_script_module


desktop_mcp = load_script_module("scripts/misc/desktop_mcp.py", "desktop_mcp_test")


SERVER = r'''
import json, os, sys, time
mode, log = sys.argv[1:3]
def send(value):
    print(json.dumps({"jsonrpc":"2.0", **value}), flush=True)
initialized = False
for line in sys.stdin:
    request = json.loads(line)
    with open(log, "a", encoding="utf-8") as output:
        output.write(json.dumps(request) + "\n")
    method = request.get("method")
    if method == "notifications/initialized":
        initialized = True
        continue
    if "id" not in request or not method:
        continue
    rid = request["id"]
    if method == "initialize":
        send({"id":rid, "result":{"protocolVersion":"1900-01-01" if mode == "version" else "2025-11-25", "serverInfo":{"name":"synthetic", "version":"1"}, "capabilities":{"tools":{"listChanged":True}, "resources":{}}}})
        continue
    if not initialized:
        send({"id":rid, "error":{"code":-32000,"message":"initialize first"}})
        continue
    if method == "tools/list":
        if not request.get("params", {}).get("cursor"):
            send({"id":"server-ping", "method":"ping"})
            send({"id":rid,"result":{"tools":[{"name":"echo", "inputSchema":{"type":"object","properties":{"text":{"type":"string"}}}, "outputSchema":{"type":"object"}}], "nextCursor":"page-2"}})
        else:
            result = {"tools":[{"name":"observe","inputSchema":{"type":"object"}}]}
            if mode == "cursor": result["nextCursor"] = "page-2"
            send({"id":rid,"result":result})
    elif method == "resources/list":
        page = request.get("params",{}).get("cursor")
        send({"id":rid,"result":{"resources":[{"uri":"synthetic://two" if page else "synthetic://one","name":"Fixture"}], **({} if page else {"nextCursor":"resources-2"})}})
    elif method == "tools/call":
        if mode == "exit": sys.exit(4)
        if mode == "timeout": time.sleep(5)
        if mode == "rpc-error":
            send({"id":rid,"error":{"code":-32000,"message":os.getenv("SYNTHETIC_TOKEN", "fixture error")}})
        else:
            send({"id":rid,"result":{"content":[{"type":"text","text":os.getenv("SYNTHETIC_TOKEN", request["params"]["arguments"].get("text","ok"))}], "structuredContent":{"seen":request["params"]["arguments"]}, "isError":mode == "tool-error"}})
    elif method == "resources/read":
        send({"id":rid,"result":{"contents":[{"uri":request["params"]["uri"],"text":"synthetic document"}]}})
'''


@pytest.fixture
def store(tmp_path, monkeypatch):
    # Isolate the connection tests from the independently tested package manager.
    store = desktop_mcp.ConnectionStore(tmp_path / "settings")
    monkeypatch.setattr(store, "installations", lambda: [])
    return store


def configure(store, tmp_path, mode="normal", **extra):
    server = tmp_path / "synthetic_mcp.py"
    server.write_text(SERVER, encoding="utf-8")
    log = tmp_path / "requests.jsonl"
    response = desktop_mcp.safe_request({"operation":"configure", "connection":{
        "id":"fixture", "name":"Synthetic MCP", "transport":"stdio", "command":sys.executable,
        "args":[str(server), mode, str(log)], **extra}}, store)
    assert response["ok"], response
    return log


def invoke(store, operation, **fields):
    return desktop_mcp.safe_request({"operation":operation, "connectionId":"fixture", **fields}, store)


def test_configuration_and_list_never_start_a_process(store, tmp_path):
    log = configure(store, tmp_path)
    result = desktop_mcp.safe_request({"operation":"list"}, store)
    assert result["connections"][0]["connected"] is False
    assert result["connections"][0]["sessionMode"] == "per-request"
    assert not log.exists()
    assert invoke(store, "call", tool="fixture/echo")["error"]["code"] == "connection-disabled"
    assert not log.exists()


def test_stdio_negotiation_pagination_call_and_resource_read(store, tmp_path):
    log = configure(store, tmp_path)
    connected = invoke(store, "connect")
    assert connected["ok"], connected
    connection = connected["connection"]
    assert connection["status"] == "ready" and connection["enabled"] and not connection["connected"]
    assert [tool["id"] for tool in connection["tools"]] == ["fixture/echo", "fixture/observe"]
    assert len(connection["resources"]) == 2
    assert connection["tools"][0]["outputSchema"] == {"type":"object"}
    called = invoke(store, "call", tool="fixture/echo", arguments={"text":"hello"}, expectedSchemaHash=connection["schemaHash"])
    assert called["result"]["structuredContent"] == {"seen":{"text":"hello"}}
    assert called["outcome"] == "completed"
    assert called["invocationId"]
    read = invoke(store, "read", uri="synthetic://one")
    assert read["result"]["contents"][0]["text"] == "synthetic document"
    requests = [json.loads(line) for line in log.read_text().splitlines()]
    assert [item.get("method") for item in requests[:3]] == ["initialize", "notifications/initialized", "tools/list"]
    assert any(item.get("id") == "server-ping" and item.get("result") == {} for item in requests)
    assert sum(item.get("method") == "initialize" for item in requests) == 3


@pytest.mark.parametrize("mode,code", [("version","unsupported-protocol"),("cursor","invalid-pagination")])
def test_rejects_unsupported_protocol_and_repeating_cursor(store, tmp_path, mode, code):
    configure(store, tmp_path, mode)
    assert invoke(store, "connect")["error"]["code"] == code


def test_changed_schema_and_unknown_tool_do_not_execute(store, tmp_path):
    log = configure(store, tmp_path)
    invoke(store, "connect")
    result = invoke(store, "call", tool="fixture/echo", expectedSchemaHash="outdated")
    assert result["error"]["code"] == "schema-changed"
    assert invoke(store, "call", tool="fixture/missing")["error"]["code"] == "tool-not-found"
    assert invoke(store, "call", tool="echo")["error"]["code"] == "invalid-tool"
    assert '"tools/call"' not in log.read_text()


@pytest.mark.parametrize("mode", ["exit", "timeout"])
def test_unknown_action_outcome_never_replays(store, tmp_path, mode):
    log = configure(store, tmp_path, mode)
    assert invoke(store, "connect")["ok"]
    result = invoke(store, "call", tool="fixture/echo", timeoutSeconds=0.3)
    assert not result["ok"] and result["error"]["outcome"] == "unknown"
    requests = [json.loads(line) for line in log.read_text().splitlines()]
    assert sum(item.get("method") == "tools/call" for item in requests) == 1


@pytest.mark.parametrize("mode", ["normal", "rpc-error"])
def test_local_credentials_do_not_escape_results_or_settings_view(store, tmp_path, mode):
    sentinel = "synthetic-secret-for-test"
    configure(store, tmp_path, mode, env={"SYNTHETIC_TOKEN":sentinel})
    assert sentinel in store.path.read_text()
    assert invoke(store, "connect")["ok"]
    result = invoke(store, "call", tool="fixture/echo")
    assert sentinel not in json.dumps(result)
    assert sentinel not in json.dumps(desktop_mcp.safe_request({"operation":"list"}, store))
    assert "[redacted]" in json.dumps(result)
    if mode == "rpc-error":
        assert result["error"]["outcome"] == "failed"


def test_tool_error_is_a_completed_mcp_exchange_with_failed_tool_result(store, tmp_path):
    configure(store, tmp_path, "tool-error")
    invoke(store, "connect")
    result = invoke(store, "call", tool="fixture/echo")
    assert result["ok"] and result["result"]["isError"] and result["outcome"] == "failed"


def test_disconnect_and_remove_are_explicit(store, tmp_path):
    configure(store, tmp_path)
    invoke(store, "connect")
    assert not invoke(store, "disconnect")["connection"]["enabled"]
    assert invoke(store, "read", uri="synthetic://one")["error"]["code"] == "connection-disabled"
    assert invoke(store, "remove")["ok"]
    assert desktop_mcp.safe_request({"operation":"list"}, store)["connections"] == []


def test_descriptor_inputs_and_installed_presets_are_independent(store, tmp_path, monkeypatch):
    server = tmp_path / "synthetic_mcp.py"
    server.write_text(SERVER, encoding="utf-8")
    entry = {"installationId":"fixture-installation", "id":"fixture.server", "title":"Fixture preset", "kind":"mcp", "digest":"digest1", "root":str(tmp_path), "enabled":True,
        "descriptor":{"transport":"stdio", "command":"${inputs.python}", "args":[str(server), "normal", str(tmp_path / "requests.jsonl")],
            "env":{"SYNTHETIC_TOKEN":"${inputs.token}"}, "inputs":[{"name":"python", "type":"path", "required":True},{"name":"token", "type":"secret", "required":True}]}}
    monkeypatch.setattr(store, "installations", lambda:[entry])
    listed = desktop_mcp.safe_request({"operation":"list"}, store)["connections"]
    assert listed[0]["status"] == "unconfigured"
    assert not (tmp_path / "requests.jsonl").exists()
    configured = desktop_mcp.safe_request({"operation":"configure", "installationId":entry["installationId"], "inputs":{"python":sys.executable, "token":"fixture-secret"}}, store)
    assert configured["ok"]
    cid = configured["connection"]["id"]
    result = desktop_mcp.safe_request({"operation":"connect", "connectionId":cid}, store)
    assert result["ok"], result
    assert result["connection"]["installationId"] == entry["installationId"]
    assert "fixture-secret" not in json.dumps(result)
    entry["digest"] = "digest2"
    assert desktop_mcp.safe_request({"operation":"call", "connectionId":cid, "tool":cid+"/echo"}, store)["error"]["code"] == "connection-disabled"
    entry["enabled"] = False
    assert desktop_mcp.safe_request({"operation":"connect", "connectionId":cid}, store)["error"]["code"] == "extension-unavailable"


@pytest.mark.parametrize("connection", [
    {"transport":"stdio", "command":"fixture", "args":"--shell argument"},
    {"transport":"streamable-http", "url":"http://127.0.0.1/mcp", "headers":{"X-Token":"value\r\ninjected: header"}},
])
def test_configuration_rejects_shell_strings_and_header_injection(store, connection):
    assert not desktop_mcp.safe_request({"operation":"configure", "connection":connection}, store)["ok"]


@pytest.fixture
def http_server():
    state = {"requests":[], "calls":0, "sse":False, "drop":False, "deleted":0}
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            state["requests"].append((body, dict(self.headers)))
            method = body.get("method")
            if method != "initialize":
                assert self.headers.get("MCP-Session-Id") == "synthetic-session"
                assert self.headers.get("MCP-Protocol-Version") == "2025-06-18"
            assert "application/json" in self.headers["Accept"] and "text/event-stream" in self.headers["Accept"]
            if "id" not in body:
                self.send_response(202)
                self.end_headers()
                return
            if method == "initialize":
                result = {"protocolVersion":"2025-06-18", "serverInfo":{"name":"synthetic-http", "version":"1"}, "capabilities":{"tools":{}, "resources":{}}}
            elif method == "tools/list":
                result = {"tools":[{"name":"echo", "inputSchema":{"type":"object"}}]}
            elif method == "resources/list":
                result = {"resources":[]}
            elif method == "tools/call":
                state["calls"] += 1
                if state["drop"]:
                    self.close_connection = True
                    return
                result = {"content":[{"type":"text", "text":"fixture HTTP result"}]}
            else:
                result = {"contents":[{"uri":body["params"]["uri"], "text":"resource"}]}
            payload = json.dumps({"jsonrpc":"2.0", "id":body["id"], "result":result}).encode()
            if state["sse"]:
                payload = b"id: primed\ndata:\n\n: keepalive\n\ndata: " + payload + b"\n\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream" if state["sse"] else "application/json")
            self.send_header("Content-Length", str(len(payload)))
            if method == "initialize": self.send_header("MCP-Session-Id", "synthetic-session")
            self.end_headers()
            self.wfile.write(payload)
        def do_DELETE(self):
            state["deleted"] += 1
            assert self.headers["MCP-Session-Id"] == "synthetic-session"
            self.send_response(204)
            self.end_headers()
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/mcp", state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.parametrize("sse", [False, True])
def test_streamable_http_negotiation_headers_json_and_sse(store, http_server, sse):
    url, state = http_server
    state["sse"] = sse
    assert desktop_mcp.safe_request({"operation":"configure", "connection":{"id":"fixture", "transport":"streamable-http", "url":url}}, store)["ok"]
    assert invoke(store, "connect")["ok"]
    result = invoke(store, "call", tool="fixture/echo")
    assert result["result"]["content"][0]["text"] == "fixture HTTP result"
    assert state["calls"] == 1 and state["deleted"] == 2
    assert invoke(store, "read", uri="synthetic://one")["result"]["contents"][0]["text"] == "resource"


def test_streamable_http_lost_response_does_not_replay(store, http_server):
    url, state = http_server
    desktop_mcp.safe_request({"operation":"configure", "connection":{"id":"fixture", "transport":"streamable-http", "url":url}}, store)
    invoke(store, "connect")
    state["drop"] = True
    result = invoke(store, "call", tool="fixture/echo")
    assert not result["ok"] and result["error"]["outcome"] == "unknown"
    assert state["calls"] == 1


def test_json_stdin_cli_is_a_single_json_response(tmp_path):
    result = subprocess.run([sys.executable, str(ROOT / "scripts/misc/desktop_mcp.py")], input=json.dumps({"operation":"list"}),
        text=True, capture_output=True, env={**os.environ, "REVERSELAB_EXTENSIONS_DIR":str(tmp_path)}, timeout=15)
    assert result.returncode == 0
    assert json.loads(result.stdout) == {"ok":True, "connections":[]}
    assert not result.stderr
