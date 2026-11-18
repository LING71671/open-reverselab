from __future__ import annotations

import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MCP_ROOT = ROOT / "tools" / "skills" / "mcp" / "ReverseLabToolsMCP"
sys.path.insert(0, str(MCP_ROOT))

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
