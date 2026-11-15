#!/usr/bin/env python3
"""Small MCP client using standard stdio and Streamable HTTP transports.

Sessions are scoped to one desktop request. No sampling, elicitation, persistent
subscriptions, legacy HTTP+SSE, or automatic replay of tool calls is advertised.
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import queue
import signal
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable


PROTOCOL_VERSIONS = ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")
MAX_MESSAGE_BYTES = 32 * 1024 * 1024


class McpError(Exception):
    def __init__(self, code: str, message: str, *, outcome: str = "not-started"):
        super().__init__(message)
        self.code = code
        self.outcome = outcome

    def as_dict(self) -> dict[str, Any]:
        return {"code": self.code, "message": str(self), "outcome": self.outcome}


def _decode(data: bytes | str) -> dict[str, Any]:
    try:
        value = json.loads(data)
    except (ValueError, UnicodeError) as exc:
        raise McpError("invalid-message", "MCP server returned invalid UTF-8 JSON") from exc
    if not isinstance(value, dict) or value.get("jsonrpc") != "2.0":
        raise McpError("invalid-message", "Expected one JSON-RPC 2.0 object")
    return value


def _encode(message: dict[str, Any]) -> bytes:
    return json.dumps(message, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


class _WindowsJob:
    """Kill the server tree even if the parent desktop helper is terminated."""

    def __init__(self, process: subprocess.Popen[bytes]):
        self.handle = None
        if os.name != "nt":
            return
        from ctypes import wintypes

        class BasicLimits(ctypes.Structure):
            _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
                        ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                        ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                        ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD),
                        ("SchedulingClass", wintypes.DWORD)]

        class IoCounters(ctypes.Structure):
            _fields_ = [(name, ctypes.c_uint64) for name in ("ReadOperationCount", "WriteOperationCount",
                        "OtherOperationCount", "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

        class ExtendedLimits(ctypes.Structure):
            _fields_ = [("BasicLimitInformation", BasicLimits), ("IoInfo", IoCounters),
                        ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                        ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]

        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        self.kernel.CreateJobObjectW.restype = wintypes.HANDLE
        self.kernel.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        self.kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        self.kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        handle = self.kernel.CreateJobObjectW(None, None)
        limits = ExtendedLimits()
        limits.BasicLimitInformation.LimitFlags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if (not handle or not self.kernel.SetInformationJobObject(handle, 9, ctypes.byref(limits), ctypes.sizeof(limits))
                or not self.kernel.AssignProcessToJobObject(handle, int(process._handle))):
            if handle:
                self.kernel.CloseHandle(handle)
            process.kill()
            process.wait()
            raise McpError("process-containment-failed", "Could not attach MCP server to a cleanup job")
        self.handle = handle

    def close(self) -> None:
        if self.handle:
            self.kernel.CloseHandle(self.handle)
            self.handle = None


class StdioTransport:
    def __init__(self, config: dict[str, Any]):
        command = config["command"]
        args = config.get("args", [])
        # Windows invokes .cmd/.bat through a shell even with shell=False. Do not
        # interpret package-manager shims; configure node + the JS entry instead.
        if os.name == "nt":
            import shutil
            resolved = shutil.which(command) or command
            if os.path.splitext(resolved)[1].lower() in (".bat", ".cmd"):
                raise McpError("shell-command", "Use an executable and an argument array; Windows .cmd/.bat shims are not supported")
        options: dict[str, Any] = {"creationflags": subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt" else {"start_new_session": True}
        try:
            self.process = subprocess.Popen([command, *args], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                            stderr=subprocess.DEVNULL, env={**os.environ, **config.get("env", {})},
                                            cwd=config.get("cwd") or None, shell=False, **options)
        except OSError as exc:
            raise McpError("start-failed", "Could not start the configured MCP executable") from exc
        self.job = _WindowsJob(self.process)
        self.messages: queue.Queue[dict[str, Any] | McpError] = queue.Queue()
        self.closed = False
        self.protocol_version: str | None = None
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()

    def _read(self) -> None:
        assert self.process.stdout is not None
        try:
            while not self.closed:
                line = self.process.stdout.readline(MAX_MESSAGE_BYTES + 1)
                if not line:
                    self.messages.put(McpError("connection-lost", "MCP server closed stdout"))
                    return
                if len(line) > MAX_MESSAGE_BYTES:
                    raise McpError("message-too-large", "MCP message exceeds the 32 MiB limit")
                self.messages.put(_decode(line))
        except (OSError, ValueError) as exc:
            if not self.closed:
                self.messages.put(McpError("connection-lost", "MCP stdout is unavailable"))
        except McpError as exc:
            self.messages.put(exc)

    def send(self, message: dict[str, Any], timeout: float | None = None) -> None:
        try:
            assert self.process.stdin is not None
            self.process.stdin.write(_encode(message) + b"\n")
            self.process.stdin.flush()
        except (OSError, ValueError) as exc:
            raise McpError("connection-lost", "MCP stdin is unavailable") from exc

    def receive(self, timeout: float | None) -> dict[str, Any]:
        try:
            item = self.messages.get(timeout=timeout)
        except queue.Empty as exc:
            raise McpError("timeout", "MCP request exceeded its time budget") from exc
        if isinstance(item, McpError):
            raise item
        return item

    def exchange(self, message: dict[str, Any], handler: Callable[[dict[str, Any]], Any], remaining: Callable[[], float | None]) -> Any:
        self.send(message)
        while True:
            response = self.receive(remaining())
            result = handler(response)
            if result is not None:
                return result

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        if self.process.stdin:
            try:
                self.process.stdin.close()
            except OSError:
                pass
        # A server can exit while its grandchildren still run: always clean the
        # process group/job, even when process.poll() reports a completed parent.
        if os.name == "nt":
            self.job.close()
        else:
            try:
                os.killpg(self.process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        try:
            self.process.wait(timeout=0.5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=2)
        if os.name != "nt":
            try:
                os.killpg(self.process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        self.reader.join(timeout=0.5)
        if self.process.stdout:
            self.process.stdout.close()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Redirecting credentials or replaying a POST is not an MCP reconnect.
        return None


class HttpTransport:
    def __init__(self, config: dict[str, Any]):
        self.url = config["url"]
        self.headers = dict(config.get("headers", {}))
        self.opener = urllib.request.build_opener(_NoRedirect())
        self.session_id: str | None = None
        self.protocol_version: str | None = None

    def _open(self, message: dict[str, Any] | None, timeout: float | None, *, method: str = "POST"):
        headers = {**self.headers, "Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
        if self.session_id:
            headers["MCP-Session-Id"] = self.session_id
        if self.protocol_version:
            headers["MCP-Protocol-Version"] = self.protocol_version
        request = urllib.request.Request(self.url, data=_encode(message) if message is not None else None,
                                         headers=headers, method=method)
        try:
            response = self.opener.open(request, timeout=timeout)
        except urllib.error.HTTPError as exc:
            exc.close()
            if exc.code == 404 and self.session_id:
                raise McpError("session-expired", "MCP session expired; reconnect before a new invocation") from exc
            raise McpError("http-error", f"MCP endpoint returned HTTP {exc.code}") from exc
        except (OSError, urllib.error.URLError, ValueError) as exc:
            code = "timeout" if isinstance(exc, (TimeoutError, socket.timeout)) or isinstance(getattr(exc, "reason", None), TimeoutError) else "connection-lost"
            raise McpError(code, "MCP HTTP request did not complete") from exc
        if message and message.get("method") == "initialize":
            session_id = response.headers.get("MCP-Session-Id")
            if session_id and (len(session_id) > 4096 or any(not 0x21 <= ord(c) <= 0x7E for c in session_id)):
                response.close()
                raise McpError("invalid-session", "Invalid MCP session ID")
            self.session_id = session_id
        return response

    def send(self, message: dict[str, Any], timeout: float | None = None) -> None:
        with self._open(message, timeout) as response:
            if response.status != 202:
                raise McpError("invalid-message", "MCP notifications and responses require HTTP 202")

    def exchange(self, message: dict[str, Any], handler: Callable[[dict[str, Any]], Any], remaining: Callable[[], float | None]) -> Any:
        try:
            with self._open(message, remaining()) as response:
                content_type = response.headers.get_content_type()
                if content_type == "application/json":
                    data = response.read(MAX_MESSAGE_BYTES + 1)
                    if len(data) > MAX_MESSAGE_BYTES:
                        raise McpError("message-too-large", "MCP response exceeds the 32 MiB limit")
                    remaining()
                    result = handler(_decode(data))
                    if result is not None:
                        return result
                elif content_type == "text/event-stream":
                    event: list[bytes] = []
                    size = 0
                    while True:
                        remaining()
                        line = response.readline(MAX_MESSAGE_BYTES + 1)
                        if not line:
                            break
                        size += len(line)
                        if size > MAX_MESSAGE_BYTES:
                            raise McpError("message-too-large", "MCP SSE event exceeds the 32 MiB limit")
                        line = line.rstrip(b"\r\n")
                        if line.startswith(b"data:"):
                            data = line[5:]
                            event.append(data[1:] if data.startswith(b" ") else data)
                        elif not line:
                            payload = b"\n".join(event)
                            event, size = [], 0
                            # Empty priming events are legal in 2025-11-25.
                            if payload:
                                result = handler(_decode(payload))
                                if result is not None:
                                    return result
                else:
                    raise McpError("invalid-content-type", "MCP endpoint must return JSON or an SSE stream")
        except (OSError, urllib.error.URLError) as exc:
            raise McpError("timeout" if isinstance(exc, TimeoutError) else "connection-lost", "MCP response stream did not complete") from exc
        raise McpError("connection-lost", "MCP stream ended without a matching response; no action was replayed")

    def close(self) -> None:
        if self.session_id:
            try:
                with self._open(None, 2, method="DELETE"):
                    pass
            except McpError:
                pass
            self.session_id = None


class McpClient:
    def __init__(self, config: dict[str, Any], timeout: float | None = None):
        if timeout is not None and (isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0):
            raise McpError("invalid-config", "timeoutSeconds must be a positive number or omitted")
        self.deadline = time.monotonic() + timeout if timeout is not None else None
        self.transport = StdioTransport(config) if config["transport"] == "stdio" else HttpTransport(config)
        self.next_id = 0
        self.capabilities: dict[str, Any] = {}
        self.server_info: dict[str, Any] = {}
        self.protocol_version: str | None = None
        self.changes = {"tools": 0, "resources": 0}

    def _remaining(self) -> float | None:
        if self.deadline is None:
            return None
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise McpError("timeout", "MCP request exceeded its time budget")
        return remaining

    def _handle_message(self, message: dict[str, Any], request_id: int) -> Any:
        if "method" in message:
            method = message["method"]
            if "id" in message:
                reply = {"jsonrpc": "2.0", "id": message["id"]}
                if method == "ping":
                    reply["result"] = {}
                else:
                    reply["error"] = {"code": -32601, "message": "Client capability not supported"}
                self.transport.send(reply, self._remaining())
            elif method == "notifications/tools/list_changed":
                self.changes["tools"] += 1
            elif method == "notifications/resources/list_changed":
                self.changes["resources"] += 1
            return None
        if message.get("id") != request_id:
            raise McpError("invalid-message", "MCP response ID does not match the active request")
        if "error" in message:
            error = message["error"]
            if not isinstance(error, dict):
                raise McpError("invalid-message", "Invalid JSON-RPC error")
            raise McpError("rpc-error", f"MCP error {error.get('code')}: {error.get('message', 'Request failed')}", outcome="failed")
        if not isinstance(message.get("result"), dict):
            raise McpError("invalid-message", "MCP response is missing an object result")
        # Wrapper distinguishes a valid empty object result from a notification.
        return (message["result"],)

    def request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        self._remaining()
        self.next_id += 1
        request_id = self.next_id
        message = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not None:
            message["params"] = params
        try:
            response = self.transport.exchange(message, lambda item: self._handle_message(item, request_id), self._remaining)
            return response[0]
        except (McpError, KeyboardInterrupt) as exc:
            if isinstance(exc, KeyboardInterrupt) or getattr(exc, "code", "") == "timeout":
                try:
                    self.transport.send({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {
                        "requestId": request_id, "reason": "Client request cancelled"}}, 0.2)
                except (McpError, OSError):
                    pass
            if isinstance(exc, KeyboardInterrupt):
                raise McpError("cancelled", "MCP request cancelled", outcome="unknown" if method == "tools/call" else "not-started") from exc
            if method == "tools/call" and exc.code != "rpc-error":
                exc.outcome = "unknown"
            raise

    def initialize(self) -> dict[str, Any]:
        result = self.request("initialize", {"protocolVersion": PROTOCOL_VERSIONS[0], "capabilities": {},
                                            "clientInfo": {"name": "open-reverselab-desktop", "version": "0.1.0"}})
        version = result.get("protocolVersion")
        if version not in PROTOCOL_VERSIONS or (isinstance(self.transport, HttpTransport) and version == "2024-11-05"):
            raise McpError("unsupported-protocol", "MCP server selected an unsupported protocol version")
        if not isinstance(result.get("capabilities"), dict) or not isinstance(result.get("serverInfo"), dict):
            raise McpError("invalid-initialize", "MCP initialize result is missing capabilities or serverInfo")
        self.protocol_version = version
        self.transport.protocol_version = version
        self.capabilities = result["capabilities"]
        self.server_info = result["serverInfo"]
        self.transport.send({"jsonrpc": "2.0", "method": "notifications/initialized"}, self._remaining())
        return result

    def _list(self, method: str, field: str) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        seen: set[str] = set()
        cursor: str | None = None
        while True:
            result = self.request(method, {"cursor": cursor} if cursor is not None else {})
            page = result.get(field)
            if not isinstance(page, list) or any(not isinstance(item, dict) for item in page):
                raise McpError("invalid-catalog", f"MCP {method} returned an invalid catalog page")
            items.extend(page)
            cursor = result.get("nextCursor")
            if cursor is None:
                return items
            if not isinstance(cursor, str) or not cursor or cursor in seen:
                raise McpError("invalid-pagination", f"MCP {method} returned an invalid or repeated cursor")
            seen.add(cursor)

    def discover(self, connection_id: str) -> dict[str, Any]:
        # A list_changed notification during pagination invalidates that snapshot.
        # Fail explicitly if the server cannot supply a stable catalog.
        for _ in range(3):
            changes = dict(self.changes)
            tools = self._list("tools/list", "tools") if "tools" in self.capabilities else []
            resources = self._list("resources/list", "resources") if "resources" in self.capabilities else []
            if changes == self.changes:
                break
        else:
            raise McpError("catalog-changing", "MCP catalog kept changing during discovery; reconnect to refresh")
        names: set[str] = set()
        for item in tools:
            name = item.get("name")
            if not isinstance(name, str) or not name or name in names or not isinstance(item.get("inputSchema"), dict):
                raise McpError("invalid-catalog", "Tool names must be unique and every tool needs inputSchema")
            names.add(name)
            item["id"] = f"{connection_id}/{name}"
            item["connectionId"] = connection_id
        uris: set[str] = set()
        for item in resources:
            uri = item.get("uri")
            if not isinstance(uri, str) or not uri or uri in uris:
                raise McpError("invalid-catalog", "Resource URIs must be nonempty and unique")
            uris.add(uri)
            item["connectionId"] = connection_id
        fingerprint = hashlib.sha256(json.dumps({"tools": tools, "resources": resources, "serverInfo": self.server_info, "protocolVersion": self.protocol_version}, sort_keys=True,
                                               separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()
        return {"tools": tools, "resources": resources, "schemaHash": fingerprint,
                "protocolVersion": self.protocol_version, "capabilities": self.capabilities, "serverInfo": self.server_info}

    def close(self) -> None:
        self.transport.close()

    def __enter__(self) -> "McpClient":
        return self

    def __exit__(self, *_args) -> None:
        self.close()
