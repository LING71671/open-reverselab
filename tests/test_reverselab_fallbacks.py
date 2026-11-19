from __future__ import annotations

import struct
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MCP_ROOT = ROOT / "tools" / "skills" / "mcp" / "ReverseLabToolsMCP"
sys.path.insert(0, str(MCP_ROOT))

from reverselab_mcp import runner
from reverselab_mcp.tools import dotnet, pcap, wasm  # noqa: E402


def _build_pe(managed: bool = True) -> bytes:
    data = bytearray(0x400)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x40)
    data[0x40:0x44] = b"PE\x00\x00"
    struct.pack_into("<H", data, 0x44, 0x8664)
    struct.pack_into("<H", data, 0x46, 1)
    struct.pack_into("<H", data, 0x54, 0xF0)
    struct.pack_into("<H", data, 0x58, 0x20B)
    directories = 0x58 + 112
    struct.pack_into("<I", data, directories + 14 * 8, 0x1000 if managed else 0)
    struct.pack_into("<I", data, directories + 14 * 8 + 4, 0x48 if managed else 0)
    data[0x148:0x150] = b".text\x00\x00\x00"
    struct.pack_into("<I", data, 0x148 + 8, 0x200)
    struct.pack_into("<I", data, 0x148 + 12, 0x1000)
    struct.pack_into("<I", data, 0x148 + 16, 0x200)
    struct.pack_into("<I", data, 0x148 + 20, 0x200)
    if managed:
        struct.pack_into("<I", data, 0x200, 0x48)
        struct.pack_into("<H", data, 0x204, 2)
        struct.pack_into("<H", data, 0x206, 5)
        struct.pack_into("<I", data, 0x208, 0x1040)
        struct.pack_into("<I", data, 0x20C, 0x40)
        struct.pack_into("<I", data, 0x210, 1)
        struct.pack_into("<I", data, 0x214, 0x06000001)
        data[0x240:0x244] = b"BSJB"
        struct.pack_into("<H", data, 0x244, 1)
        struct.pack_into("<H", data, 0x246, 1)
        struct.pack_into("<I", data, 0x248, 0)
        struct.pack_into("<I", data, 0x24C, 12)
        data[0x250:0x25C] = b"v4.0.30319\x00\x00"
    return bytes(data)


def test_dotnet_metadata_reads_managed_header(tmp_path, monkeypatch):
    sample = tmp_path / "managed.exe"
    sample.write_bytes(_build_pe(managed=True))
    monkeypatch.setattr(dotnet, "resolve_file", lambda path: sample)

    result = dotnet.dotnet_metadata(str(sample))

    assert result["ok"] is True
    assert result["findings"]["is_managed"] is True
    assert result["findings"]["metadata_root"]["signature"] == "BSJB"
    assert result["findings"]["metadata_root"]["runtime_version"].startswith("v4.0")


def test_dotnet_metadata_rejects_native_pe(tmp_path, monkeypatch):
    sample = tmp_path / "native.exe"
    sample.write_bytes(_build_pe(managed=False))
    monkeypatch.setattr(dotnet, "resolve_file", lambda path: sample)

    result = dotnet.dotnet_metadata(str(sample))

    assert result["ok"] is True
    assert result["findings"]["is_managed"] is False


def test_dotnet_metadata_rejects_non_pe(tmp_path, monkeypatch):
    sample = tmp_path / "readme.txt"
    sample.write_text("not a pe", encoding="utf-8")
    monkeypatch.setattr(dotnet, "resolve_file", lambda path: sample)

    result = dotnet.dotnet_metadata(str(sample))

    assert result["ok"] is False
    assert result["error"]["kind"] == "invalid_argument"


def test_dotnet_list_types_without_ilspycmd(monkeypatch, tmp_path):
    sample = tmp_path / "managed.exe"
    sample.write_bytes(_build_pe())
    monkeypatch.setattr(dotnet, "resolve_file", lambda path: sample)
    monkeypatch.setattr(dotnet, "_ilspycmd", lambda: None)

    result = dotnet.dotnet_list_types(str(sample))

    assert result["ok"] is False
    assert result["error"]["kind"] == "missing_engine"


def test_pcap_summary_without_tshark(monkeypatch):
    monkeypatch.delenv("TSHARK_COMMAND", raising=False)
    monkeypatch.setattr(pcap.shutil, "which", lambda name: None)
    monkeypatch.setattr(pcap, "resolve_file", lambda path: Path(__file__))

    result = pcap.pcap_summary("anything.pcap")

    assert result["ok"] is False
    assert result["error"]["kind"] == "missing_engine"


def test_wasm_info_without_wabt(monkeypatch):
    monkeypatch.delenv("WASM_OBJDUMP", raising=False)
    monkeypatch.delenv("WASM2WAT", raising=False)
    monkeypatch.setattr(wasm.shutil, "which", lambda name: None)
    monkeypatch.setattr(wasm, "resolve_file", lambda path: Path(__file__))

    result = wasm.wasm_info("anything.wasm")

    assert result["ok"] is False
    assert result["error"]["kind"] == "missing_engine"

@pytest.mark.parametrize("exits, expected", [((1, 1), "unsupported"), ((1, 0), "partial"), ((0, 1), "partial")])
def test_wabt_failures_keep_successful_outputs(monkeypatch, exits, expected):
    monkeypatch.setattr(wasm, "resolve_file", lambda _: Path(__file__))
    monkeypatch.setattr(wasm, "_find", lambda name, _: name)
    results = iter((code, "result" if code == 0 else "", "invalid module") for code in exits)
    monkeypatch.setattr(runner, "run", lambda *a, **kw: next(results))
    result = wasm.wasm_info("fixture")
    assert not result["ok"] and not result["coverage"]["complete"]
    assert result["error"]["kind"] == expected
    if 0 in exits:
        component, key = ("objdump", "output") if exits[0] == 0 else ("wat", "preview")
        assert result["findings"][component][key] == "result"


@pytest.mark.parametrize("kind, expected", [("request", "unsupported"), ("both", "partial")])
def test_http_extraction_reports_failure(monkeypatch, kind, expected):
    monkeypatch.setattr(pcap, "resolve_file", lambda _: Path(__file__))
    monkeypatch.setattr(pcap, "_tshark", lambda: "tshark")

    def run(args, timeout):
        if "http.request" in args:
            return 1, "", "bad capture"
        return 0, "", ""

    monkeypatch.setattr(runner, "run", run)
    result = pcap.pcap_extract_http("fixture", kind)
    assert not result["ok"] and result["error"]["kind"] == expected
    assert result["findings"]["request"]["exit"] == 1
    if kind == "both":
        assert result["findings"]["response"]["rows"] == []


def test_http_extraction_handles_timeout(monkeypatch):
    monkeypatch.setattr(pcap, "resolve_file", lambda _: Path(__file__))
    monkeypatch.setattr(pcap, "_tshark", lambda: "tshark")

    def timeout(args, timeout):
        raise subprocess.TimeoutExpired(args, timeout)

    monkeypatch.setattr(runner, "run", timeout)
    result = pcap.pcap_extract_http("fixture")
    assert result["error"]["kind"] == "timeout" and result["error"]["retryable"]


def test_http_row_limit_uses_displayed_packets(monkeypatch):
    monkeypatch.setattr(pcap, "resolve_file", lambda _: Path(__file__))
    monkeypatch.setattr(pcap, "_tshark", lambda: "tshark")

    def run(args, timeout):
        assert "-c" not in args and args[args.index("-a") + 1] == "packets:2"
        return 0, "501\n502", ""

    monkeypatch.setattr(runner, "run", run)
    result = pcap.pcap_extract_http("fixture", max_rows=1)
    assert result["ok"] and not result["coverage"]["complete"]
    assert [row["frame.number"] for row in result["findings"]["request"]["rows"]] == ["501"]


def test_real_tshark_finds_late_http_request(monkeypatch, tmp_path):
    if not pcap._tshark():
        pytest.skip("tshark is optional")
    # 500 unrelated Ethernet frames followed by one local HTTP request.
    ethernet = bytes.fromhex("020000000002020000000001")
    unrelated = ethernet + bytes.fromhex("88b5") + bytes(46)
    payload = b"GET /fixture HTTP/1.1\r\nHost: example.test\r\n\r\n"
    tcp = struct.pack("!HHIIBBHHH", 45678, 80, 1, 0, 0x50, 0x18, 4096, 0, 0)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp) + len(payload), 0,
                     0, 64, 6, 0, bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2]))
    request = ethernet + bytes.fromhex("0800") + ip + tcp + payload
    capture = tmp_path / "late.pcap"
    with capture.open("wb") as stream:
        stream.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, packet in enumerate([unrelated] * 500 + [request]):
            stream.write(struct.pack("<IIII", i, 0, len(packet), len(packet)))
            stream.write(packet)
    monkeypatch.setattr(pcap, "resolve_file", lambda _: capture)
    result = pcap.pcap_extract_http(str(capture), max_rows=1)
    assert result["ok"], result
    rows = result["findings"]["request"]["rows"]
    assert [(row["frame.number"], row["http.request.uri"]) for row in rows] == [("501", "/fixture")]
    assert result["coverage"]["complete"]
