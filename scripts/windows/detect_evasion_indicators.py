#!/usr/bin/env python3
"""[Track: BLUE] Static detector for PE evasion, anti-sandbox, syscall stub, and obfuscation indicators."""

from __future__ import annotations

import argparse
import json
import math
import re
from collections import Counter
from pathlib import Path

ANTI_SANDBOX_MARKERS = (
    b"GetTickCount64",
    b"GetSystemInfo",
    b"GlobalMemoryStatusEx",
    b"IsDebuggerPresent",
    b"CheckRemoteDebuggerPresent",
    b"NtQueryInformationProcess",
    b"AddVectoredExceptionHandler",
    b"VirtualAlloc",
    b"VirtualProtect",
    b"NtAllocateVirtualMemory",
    b"NtProtectVirtualMemory",
)

UUID_RE = re.compile(rb"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
IPV4_RE = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")
MAC_RE = re.compile(rb"(?:[0-9A-F]{2}-){5}[0-9A-F]{2}", re.I)
# x64 direct syscall pattern: mov r10, rcx (4C 8B D1) + mov eax, imm32 (B8 ?? ?? 00 00) + syscall (0F 05)
SYSCALL_STUB_RE = re.compile(rb"\x4c\x8b\xd1\xb8.{2}\x00\x00.{0,12}\x0f\x05", re.S)


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def scan_bytes(data: bytes) -> dict:
    entropy = round(shannon_entropy(data), 3)
    api_hits = [m.decode("ascii") for m in ANTI_SANDBOX_MARKERS if m in data]
    uuid_count = len(UUID_RE.findall(data))
    ipv4_count = len(IPV4_RE.findall(data))
    mac_count = len(MAC_RE.findall(data))
    syscall_stubs = [m.start() for m in SYSCALL_STUB_RE.finditer(data)]

    indicators = []
    if entropy >= 7.2:
        indicators.append(f"high_entropy:{entropy}")
    if len(api_hits) >= 3:
        indicators.append(f"anti_analysis_or_alloc_apis:{len(api_hits)}")
    if uuid_count >= 8 or ipv4_count >= 12 or mac_count >= 8:
        indicators.append(f"encoded_table_camouflage(uuid={uuid_count},ip={ipv4_count},mac={mac_count})")
    if syscall_stubs:
        indicators.append(f"x64_direct_syscall_stubs:{len(syscall_stubs)}")

    return {
        "size": len(data),
        "entropy": entropy,
        "api_hits": api_hits,
        "camouflage_counts": {"uuid": uuid_count, "ipv4": ipv4_count, "mac": mac_count},
        "syscall_stub_offsets": [hex(off) for off in syscall_stubs[:20]],
        "indicators": indicators,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sample", type=Path, help="Path to binary sample to inspect")
    args = parser.parse_args(argv)
    data = args.sample.read_bytes()
    result = scan_bytes(data)
    result["sample"] = str(args.sample)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
