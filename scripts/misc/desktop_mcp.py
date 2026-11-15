#!/usr/bin/env python3
"""Independent desktop MCP connections; one JSON request on stdin, one on stdout.

Configuration is local application data, never an extension payload. Installing
or listing a descriptor does not execute it. Explicit connect verifies/discovers
the server, and each later call/read opens its own short-lived MCP session.
"""

from __future__ import annotations

import contextlib
import datetime
import hashlib
import importlib.util
import json
import math
import os
import re
import signal
import sys
import tempfile
import time
import urllib.parse
import uuid
from pathlib import Path
from typing import Any


def _module(name: str):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(f"{name}.py"))
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_client = _module("mcp_client")
McpClient = _client.McpClient
McpError = _client.McpError
ID_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,95}$")
INPUT_RE = re.compile(r"\$\{inputs\.([a-zA-Z0-9_.-]+)\}")
SECRET_RE = re.compile(r"key|token|secret|password|auth|credential", re.I)


def extensions_root() -> Path:
    if os.environ.get("REVERSELAB_EXTENSIONS_DIR"):
        return Path(os.environ["REVERSELAB_EXTENSIONS_DIR"]).expanduser().resolve()
    if os.environ.get("REVERSELAB_DATA_DIR"):
        return (Path(os.environ["REVERSELAB_DATA_DIR"]) / "extensions").expanduser().resolve()
    return Path.home() / ".open-reverselab" / "extensions"


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _id(value: Any) -> str:
    if not isinstance(value, str) or not ID_RE.fullmatch(value):
        raise McpError("invalid-config", "Connection ID must contain 1–96 letters, digits, dots, underscores or hyphens")
    return value


def _strings(value: Any, label: str) -> dict[str, str]:
    if not isinstance(value, dict) or any(not isinstance(k, str) or not isinstance(v, str) or "\x00" in k + v for k, v in value.items()):
        raise McpError("invalid-config", f"{label} must be an object of string values")
    return dict(value)


def _url(value: str) -> None:
    try:
        parsed = urllib.parse.urlsplit(value)
        valid = parsed.scheme in ("http", "https") and parsed.hostname and not parsed.username and not parsed.password and not parsed.fragment
        parsed.port
    except ValueError:
        valid = False
    if not valid or any(char.isspace() for char in value):
        raise McpError("invalid-config", "MCP URL must be HTTP(S) without embedded credentials or a fragment")


def _descriptor(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("transport") not in ("stdio", "streamable-http"):
        raise McpError("invalid-config", "Transport must be stdio or streamable-http")
    descriptor = {key: value[key] for key in ("transport", "command", "args", "url", "env", "headers", "cwd", "inputs") if key in value}
    inputs = descriptor.setdefault("inputs", [])
    if not isinstance(inputs, list):
        raise McpError("invalid-config", "Descriptor inputs must be an array")
    names: set[str] = set()
    for item in inputs:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str) or not ID_RE.fullmatch(item["name"]) or item["name"] in names or item.get("type") not in ("string", "url", "path", "secret") or not isinstance(item.get("required", False), bool):
            raise McpError("invalid-config", "Invalid or duplicate MCP input definition")
        names.add(item["name"])
    for field in ("env", "headers"):
        descriptor[field] = _strings(descriptor.get(field, {}), field)
    for key, value in descriptor["env"].items():
        if not key or "=" in key:
            raise McpError("invalid-config", "Invalid MCP environment variable name")
    reserved = {"host", "content-length", "content-type", "accept", "mcp-session-id", "mcp-protocol-version"}
    for key, value in descriptor["headers"].items():
        if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", key) or "\r" in value or "\n" in value or key.lower() in reserved:
            raise McpError("invalid-config", "Invalid or reserved MCP HTTP header")
    if descriptor["transport"] == "stdio":
        command = descriptor.get("command")
        if not isinstance(command, str) or not command.strip() or "\x00" in command:
            raise McpError("invalid-config", "stdio requires an executable command")
        args = descriptor.setdefault("args", [])
        if not isinstance(args, list) or any(not isinstance(arg, str) or "\x00" in arg for arg in args):
            raise McpError("invalid-config", "stdio args must be an argument array, not shell text")
        if "cwd" in descriptor and (not isinstance(descriptor["cwd"], str) or "\x00" in descriptor["cwd"]):
            raise McpError("invalid-config", "cwd must be a path string")
    elif not isinstance(descriptor.get("url"), str) or not descriptor["url"]:
        raise McpError("invalid-config", "streamable-http requires a URL")
    return descriptor


def resolve_descriptor(descriptor: dict[str, Any], values: dict[str, str], root: str | None = None) -> dict[str, Any]:
    definitions = {item["name"]: item for item in descriptor.get("inputs", [])}
    unknown = set(values) - definitions.keys()
    if unknown:
        raise McpError("invalid-input", "Configuration contains inputs absent from the descriptor")
    for name, definition in definitions.items():
        value = values.get(name, "")
        if definition.get("required") and not value:
            raise McpError("missing-input", f"Required input is not configured: {name}")
        if value and definition["type"] == "url":
            _url(value)

    def interpolate(value: Any) -> Any:
        if isinstance(value, str):
            def replace(match):
                name = match.group(1)
                if name not in definitions:
                    raise McpError("invalid-input", f"Descriptor references an undeclared input: {name}")
                return values.get(name, "")
            result = INPUT_RE.sub(replace, value)
            if "${" in result:
                raise McpError("invalid-input", "Unsupported descriptor substitution")
            return result
        if isinstance(value, list):
            return [interpolate(item) for item in value]
        if isinstance(value, dict):
            return {key: interpolate(item) for key, item in value.items()}
        return value

    resolved = interpolate({key: value for key, value in descriptor.items() if key != "inputs"})
    resolved = _descriptor(resolved)
    if resolved["transport"] == "streamable-http":
        _url(resolved["url"])
    elif root and not resolved.get("cwd"):
        resolved["cwd"] = root
    return resolved


def _secret_values(record: dict[str, Any]) -> list[str]:
    descriptor = record.get("descriptor", {})
    values = record.get("values", {})
    secrets = [values.get(item["name"], "") for item in descriptor.get("inputs", []) if item.get("type") == "secret"]
    secrets += [value for key, value in descriptor.get("env", {}).items() if SECRET_RE.search(key)]
    secrets += list(descriptor.get("headers", {}).values())
    args = descriptor.get("args", [])
    for index, value in enumerate(args):
        if SECRET_RE.search(value.split("=", 1)[0]) and value.startswith("-"):
            if "=" in value:
                secrets.append(value.split("=", 1)[1])
            elif index + 1 < len(args):
                secrets.append(args[index + 1])
    # Header/env references may resolve non-secret inputs into credentials.
    for key, value in {**descriptor.get("headers", {}), **descriptor.get("env", {})}.items():
        if key in descriptor.get("headers", {}) or SECRET_RE.search(key):
            secrets.extend(values.get(match, "") for match in INPUT_RE.findall(value))
    return sorted({value for value in secrets if value and "${inputs." not in value}, key=len, reverse=True)


def _redact(value: Any, secrets: list[str]) -> Any:
    if isinstance(value, str):
        for secret in secrets:
            value = value.replace(secret, "[redacted]")
        return value
    if isinstance(value, list):
        return [_redact(item, secrets) for item in value]
    if isinstance(value, dict):
        return {_redact(key, secrets): _redact(item, secrets) for key, item in value.items()}
    return value


class ConnectionStore:
    def __init__(self, root: Path | None = None):
        self.root = Path(root) if root else extensions_root()
        self.path = self.root / "mcp-connections.json"

    @contextlib.contextmanager
    def _lock(self):
        self.root.mkdir(parents=True, exist_ok=True)
        with (self.root / ".mcp-connections.lock").open("a+b") as stream:
            stream.seek(0, 2)
            if not stream.tell():
                stream.write(b"\0")
                stream.flush()
            stream.seek(0)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(stream.fileno(), msvcrt.LK_LOCK, 1)
            else:
                import fcntl
                fcntl.flock(stream, fcntl.LOCK_EX)
            try:
                yield
            finally:
                stream.seek(0)
                if os.name == "nt":
                    msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(stream, fcntl.LOCK_UN)

    def load(self) -> dict[str, dict[str, Any]]:
        if not self.path.exists():
            return {}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if data.get("version") != 1 or not isinstance(data.get("connections"), dict):
                raise ValueError("Invalid settings format")
            return data["connections"]
        except (OSError, ValueError, AttributeError) as exc:
            raise McpError("settings-unreadable", "MCP connection settings could not be read") from exc

    def _save(self, connections: dict[str, dict[str, Any]]) -> None:
        fd, name = tempfile.mkstemp(prefix=".mcp-", suffix=".json", dir=self.root)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump({"version": 1, "connections": connections}, stream, ensure_ascii=False, indent=2, allow_nan=False)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(name, 0o600)
            os.replace(name, self.path)
        finally:
            if os.path.exists(name):
                os.unlink(name)

    def put(self, record: dict[str, Any], *, revision: str | None = None) -> bool:
        with self._lock():
            records = self.load()
            if revision is not None and records.get(record["id"], {}).get("revision") != revision:
                return False
            records[record["id"]] = record
            self._save(records)
            return True

    def remove(self, connection_id: str) -> None:
        with self._lock():
            records = self.load()
            if connection_id not in records:
                raise McpError("connection-not-found", "MCP connection was not found")
            del records[connection_id]
            self._save(records)

    def installations(self) -> list[dict[str, Any]]:
        if not Path(__file__).with_name("extension_store.py").is_file():
            return []
        module = sys.modules.get("extension_store") or _module("extension_store")
        return [entry for entry in module.ExtensionStore(root=self.root).list() if entry["kind"] == "mcp"]

    @staticmethod
    def preset_id(installation_id: str) -> str:
        return "mcp-" + hashlib.sha256(installation_id.encode("utf-8")).hexdigest()[:16]

    def records(self) -> dict[str, dict[str, Any]]:
        records = self.load()
        installed = {item["installationId"]: item for item in self.installations()}
        for record in records.values():
            installation_id = record.get("installationId")
            if not installation_id:
                continue
            entry = installed.get(installation_id)
            if not entry:
                record["available"] = False
                record["status"] = "unavailable"
            else:
                record["available"] = entry.get("enabled", True)
                record["root"] = entry["root"]
                if record.get("installationDigest") != entry["digest"]:
                    record["descriptor"] = _descriptor(entry["descriptor"])
                    record["installationDigest"] = entry["digest"]
                    record["catalog"] = {}
                    record["status"] = "unconfigured"
                    record["enabled"] = False
        configured = {record.get("installationId") for record in records.values()}
        for installation_id, entry in installed.items():
            if installation_id in configured:
                continue
            connection_id = self.preset_id(installation_id)
            if connection_id in records:
                continue
            records[connection_id] = {"id": connection_id, "name": entry["title"], "installationId": installation_id,
                "installationDigest": entry["digest"], "descriptor": _descriptor(entry["descriptor"]), "values": {},
                "root": entry["root"], "available": entry.get("enabled", True), "enabled": False, "status": "unconfigured"}
        return records


def _public(record: dict[str, Any]) -> dict[str, Any]:
    descriptor = record["descriptor"]
    catalog = record.get("catalog", {})
    value = {"id": record["id"], "name": record["name"], "transport": descriptor["transport"],
        "installationId": record.get("installationId"), "enabled": record.get("enabled", False),
        "available": record.get("available", True), "status": record.get("status", "unconfigured"),
        "connected": False, "sessionMode": "per-request", "inputs": descriptor.get("inputs", []),
        "configuredInputs": [name for name, item in record.get("values", {}).items() if item],
        "tools": catalog.get("tools", []), "resources": catalog.get("resources", []),
        "schemaHash": catalog.get("schemaHash"), "protocolVersion": catalog.get("protocolVersion"),
        "serverInfo": catalog.get("serverInfo"), "lastChecked": record.get("lastChecked"), "error": record.get("error")}
    if descriptor["transport"] == "stdio":
        value["command"] = descriptor["command"]
    elif "${" not in descriptor["url"]:
        parsed = urllib.parse.urlsplit(descriptor["url"])
        value["url"] = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc.rsplit("@", 1)[-1], parsed.path, "", ""))
    return _redact(value, _secret_values(record))


def _configure(request: dict[str, Any], store: ConnectionStore) -> dict[str, Any]:
    connection = request.get("connection", {})
    if not isinstance(connection, dict):
        raise McpError("invalid-config", "connection must be an object")
    installation_id = request.get("installationId") or connection.get("installationId")
    records = store.records()
    connection_id = request.get("connectionId") or connection.get("id")
    if installation_id and not connection_id:
        connection_id = next((item["id"] for item in records.values() if item.get("installationId") == installation_id), store.preset_id(installation_id))
    connection_id = _id(connection_id or "mcp-" + uuid.uuid4().hex[:16])
    previous = records.get(connection_id, {})
    if installation_id:
        entry = next((item for item in store.installations() if item["installationId"] == installation_id), None)
        if not entry:
            raise McpError("extension-not-found", "Installed MCP descriptor was not found")
        if previous and previous.get("installationId") != installation_id:
            raise McpError("connection-conflict", "Connection ID belongs to a different source")
        descriptor = _descriptor(entry["descriptor"])
        name = connection.get("name") or previous.get("name") or entry["title"]
    else:
        if previous.get("installationId"):
            raise McpError("connection-conflict", "Use installationId to configure an installed MCP descriptor")
        descriptor = _descriptor({**previous.get("descriptor", {}), **connection})
        name = connection.get("name") or previous.get("name") or connection_id
    if not isinstance(name, str) or not name.strip():
        raise McpError("invalid-config", "Connection name must be nonempty")
    values = {**previous.get("values", {})}
    supplied = request.get("inputs", connection.get("inputValues", {}))
    supplied = _strings(supplied, "inputs")
    values.update({key: value for key, value in supplied.items() if value})
    clear = request.get("clearInputs", [])
    if not isinstance(clear, list) or any(not isinstance(name, str) for name in clear):
        raise McpError("invalid-input", "clearInputs must be an array of input names")
    for key in clear:
        values.pop(key, None)
    definitions = {item["name"] for item in descriptor.get("inputs", [])}
    if set(values) - definitions:
        raise McpError("invalid-input", "Configuration contains inputs absent from the descriptor")
    record = {"id": connection_id, "name": name.strip(), "descriptor": descriptor, "values": values,
              "enabled": False, "status": "disconnected", "revision": uuid.uuid4().hex, "catalog": {}}
    if installation_id:
        record.update(installationId=installation_id, installationDigest=entry["digest"], root=entry["root"], available=entry.get("enabled", True))
    store.put(record)
    return {"ok": True, "connection": _public(record)}


def handle_request(request: dict[str, Any], store: ConnectionStore | None = None) -> dict[str, Any]:
    if not isinstance(request, dict):
        raise McpError("invalid-request", "Expected a JSON request object")
    store = store or ConnectionStore()
    operation = request.get("operation", "list")
    if operation == "list":
        return {"ok": True, "connections": [_public(item) for item in store.records().values()]}
    if operation == "configure":
        return _configure(request, store)
    if operation not in ("remove", "connect", "disconnect", "call", "read"):
        raise McpError("invalid-operation", "Unknown MCP operation")
    connection_id = _id(request.get("connectionId"))
    if operation == "remove":
        store.remove(connection_id)
        return {"ok": True, "connectionId": connection_id}
    record = store.records().get(connection_id)
    if not record:
        raise McpError("connection-not-found", "MCP connection was not found")
    if operation == "disconnect":
        record.update(enabled=False, status="disconnected", revision=uuid.uuid4().hex)
        store.put(record)
        return {"ok": True, "connection": _public(record)}
    if not record.get("available", True):
        raise McpError("extension-unavailable", "The installed MCP descriptor is disabled or removed")
    if operation in ("call", "read") and not record.get("enabled"):
        raise McpError("connection-disabled", "Connect and discover this MCP server before invoking it")
    secrets = _secret_values(record)
    revision = record.get("revision")
    try:
        config = resolve_descriptor(record["descriptor"], record.get("values", {}), record.get("root"))
        timeout = request.get("timeoutSeconds")
        if timeout is not None and (isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0):
            raise McpError("invalid-config", "timeoutSeconds must be finite and positive, or omitted")
        with McpClient(config, timeout=timeout) as client:
            client.initialize()
            catalog = client.discover(connection_id)
            # Tool schemas can change between independent sessions. Never invoke
            # a plan against a different snapshot without a recorded replan.
            expected_hash = request.get("expectedSchemaHash")
            if expected_hash and expected_hash != catalog["schemaHash"]:
                record.update(catalog=_redact(catalog, secrets), status="ready", lastChecked=_now())
                store.put(record, revision=revision)
                raise McpError("schema-changed", "MCP catalog changed; refresh the plan before invoking the tool")
            result = None
            invocation_id = uuid.uuid4().hex
            if operation == "call":
                tool = request.get("tool")
                if not isinstance(tool, str) or not tool.startswith(connection_id + "/"):
                    raise McpError("invalid-tool", "Use a connection-qualified tool ID")
                definition = next((item for item in catalog["tools"] if item["id"] == tool), None)
                if not definition:
                    raise McpError("tool-not-found", "Tool is absent from the freshly discovered catalog")
                if definition.get("execution", {}).get("taskSupport") == "required":
                    raise McpError("unsupported-capability", "This tool requires MCP task support, which this client does not advertise")
                arguments = request.get("arguments", {})
                if not isinstance(arguments, dict):
                    raise McpError("invalid-arguments", "Tool arguments must be an object matching inputSchema")
                result = client.request("tools/call", {"name": definition["name"], "arguments": arguments})
            elif operation == "read":
                uri = request.get("uri")
                if "resources" not in client.capabilities or not isinstance(uri, str) or not uri:
                    raise McpError("invalid-resource", "A resource URI and server resources capability are required")
                result = client.request("resources/read", {"uri": uri})
            record.update(catalog=_redact(catalog, secrets), status="ready", enabled=True, lastChecked=_now())
            record.pop("error", None)
            if not record.get("revision"):
                record["revision"] = uuid.uuid4().hex
            store.put(record, revision=revision)
            response = {"ok": True, "connection": _public(record), "catalog": catalog}
            if operation in ("call", "read"):
                response.update(result=result, invocationId=invocation_id, outcome="failed" if result.get("isError") else "completed")
            return _redact(response, secrets)
    except McpError as exc:
        error = _redact(exc.as_dict(), secrets)
        record.update(status="error", error=error, lastChecked=_now())
        if not record.get("revision"):
            record["revision"] = uuid.uuid4().hex
        store.put(record, revision=revision)
        return {"ok": False, "error": error, "connection": _public(record)}


def safe_request(request: dict[str, Any], store: ConnectionStore | None = None) -> dict[str, Any]:
    try:
        return handle_request(request, store)
    except McpError as exc:
        return {"ok": False, "error": exc.as_dict()}
    except (OSError, ValueError, TypeError, KeyError) as exc:
        # Exception text can contain environment, headers, URL tokens or paths.
        return {"ok": False, "error": {"code": "local-error", "message": "Could not process local MCP configuration", "outcome": "not-started"}}


def main() -> int:
    if hasattr(sys.stdin, "reconfigure"):
        sys.stdin.reconfigure(encoding="utf-8")
        sys.stdout.reconfigure(encoding="utf-8")
    if os.name != "nt":
        def cancel(_signum, _frame):
            raise KeyboardInterrupt
        signal.signal(signal.SIGTERM, cancel)
    try:
        request = json.load(sys.stdin)
    except (ValueError, UnicodeError):
        response = {"ok": False, "error": {"code": "invalid-json", "message": "Expected one JSON request on stdin", "outcome": "not-started"}}
    else:
        response = safe_request(request)
    print(json.dumps(response, ensure_ascii=False, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
