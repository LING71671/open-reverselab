"""Native packet-capture tools.

These tools shell out to `tshark` / `capinfos` when present and return a structured
`missing_engine` envelope otherwise. Wireshark is optional; the core lab works without it.
"""

from __future__ import annotations

import os
import shutil
from typing import Any

from ..contracts.envelope import Coverage, component_failure, fail, ok
from ..errors import ToolError
from ..paths import resolve_file
from ..runner import run, run_component


def _find_tool(env_name: str, names: list[str]) -> str | None:
    explicit = os.environ.get(env_name)
    if explicit:
        return explicit
    for name in names:
        found = shutil.which(name)
        if found:
            return found
    return None


def _tshark() -> str | None:
    return _find_tool("TSHARK_COMMAND", ["tshark"])


def _capinfos() -> str | None:
    return _find_tool("CAPINFOS_COMMAND", ["capinfos"])


def _missing() -> dict[str, Any]:
    return fail(
        "pcap_summary",
        kind="missing_engine",
        message="tshark was not found.",
        remedy="Install Wireshark 4.x, or set TSHARK_COMMAND to an absolute tshark path.",
    )


def pcap_summary(path: str, display_filter: str = "", max_packets: int = 0) -> dict[str, Any]:
    """Summarize a capture: packet count, capture metadata, and protocol hierarchy."""

    try:
        target = resolve_file(path)
    except (ToolError, OSError) as exc:
        return fail("pcap_summary", kind="invalid_argument", message=str(exc))
    tshark = _tshark()
    if not tshark:
        return _missing()

    command = [tshark, "-r", str(target), "-q", "-z", "io,phs"]
    if display_filter:
        command += ["-Y", display_filter]
    if max_packets:
        command += ["-c", str(max_packets)]

    try:
        code, out, err = run(command, timeout=180)
    except (OSError, RuntimeError, ValueError) as exc:
        return fail(
            "pcap_summary",
            kind="internal",
            message=f"tshark failed to start: {exc}",
            remedy="Check the tshark path and permissions.",
            retryable=True,
        )
    if code != 0:
        return fail(
            "pcap_summary",
            kind="unsupported",
            message=f"tshark exited {code}: {(err or out).strip()[:500]}",
            remedy="Verify the capture is valid and tshark supports it.",
        )

    findings: dict[str, Any] = {
        "path": str(target),
        "display_filter": display_filter,
        "protocol_hierarchy": out,
    }
    capinfos = _capinfos()
    if capinfos:
        try:
            info_code, info_out, info_err = run([capinfos, "-c", "-M", str(target)], timeout=120)
            if info_code == 0:
                findings["capture"] = info_out
            else:
                findings["capture_error"] = (info_err or info_out).strip()[:300]
        except (OSError, RuntimeError, ValueError) as exc:
            findings["capture_error"] = str(exc)
    else:
        findings["capture_error"] = "capinfos not found; packet count omitted"

    return ok(
        "pcap_summary",
        target={"path": str(target), "format": "pcap"},
        findings=findings,
        coverage=Coverage(scope="capture", complete=not display_filter, reason="display filter applied" if display_filter else ""),
    )


def pcap_extract_http(
    path: str,
    kind: str = "request",
    max_rows: int = 500,
) -> dict[str, Any]:
    """Extract HTTP request/response rows from a capture as structured fields."""

    try:
        target = resolve_file(path)
    except (ToolError, OSError) as exc:
        return fail("pcap_extract_http", kind="invalid_argument", message=str(exc))
    tshark = _tshark()
    if not tshark:
        return fail(
            "pcap_extract_http",
            kind="missing_engine",
            message="tshark was not found.",
            remedy="Install Wireshark 4.x, or set TSHARK_COMMAND to an absolute tshark path.",
        )

    normalized = (kind or "request").strip().lower()
    if normalized not in {"request", "response", "both"}:
        return fail(
            "pcap_extract_http",
            kind="invalid_argument",
            message="kind must be request, response, or both",
        )

    findings: dict[str, Any] = {"path": str(target), "kind": normalized}
    filters = {
        "request": (
            "http.request",
            [
                "frame.number",
                "ip.src",
                "ip.dst",
                "tcp.stream",
                "http.host",
                "http.request.method",
                "http.request.uri",
                "http.user_agent",
            ],
        ),
        "response": (
            "http.response",
            [
                "frame.number",
                "ip.src",
                "ip.dst",
                "tcp.stream",
                "http.response.code",
                "http.content_type",
                "http.content_length",
            ],
        ),
    }
    selected = list(filters) if normalized == "both" else [normalized]
    limit = max(1, max_rows)
    truncated = False
    for item in selected:
        display_filter, fields = filters[item]
        command = [tshark, "-r", str(target), "-Y", display_filter, "-T", "fields"]
        for field in fields:
            command += ["-e", field]
        # TShark's -a packets counts displayed matches; -c counts every input frame.
        command += ["-E", "separator=/t", "-E", "occurrence=f", "-a", f"packets:{limit + 1}"]
        out, failure = run_component(command, timeout=180)
        if failure:
            findings[item] = failure
            continue
        rows = []
        for line in out.splitlines():
            if len(rows) == limit:
                truncated = True
                break
            values = line.split("\t")
            values += [""] * (len(fields) - len(values))
            rows.append(dict(zip(fields, values)))
        findings[item] = {"count": len(rows), "rows": rows}

    descriptor = {"path": str(target), "format": "pcap"}
    failure = component_failure("pcap_extract_http", descriptor, findings, selected)
    if failure:
        return failure
    return ok(
        "pcap_extract_http",
        target=descriptor,
        findings=findings,
        coverage=Coverage(scope="http rows", complete=not truncated,
                          reason=f"capped at {limit} rows per kind" if truncated else ""),
    )
