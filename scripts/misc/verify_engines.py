#!/usr/bin/env python3
"""Verify tool profiles and native format fallbacks.

This check covers the parts of the integration that need no optional engine: the operation
registry, the profile surface, and the dependency-free .NET metadata fallback. Optional
external tools (tshark, ilspycmd, WABT) are reported by `lab_healthcheck.py`; their absence is
an environment state, not a product failure.

Usage:
    python scripts/misc/verify_engines.py
    uv run --project tools/skills/mcp/ReverseLabToolsMCP python scripts/misc/verify_engines.py \
        --json reports/misc/engine-verification.json
"""

from __future__ import annotations

import argparse
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools" / "skills" / "mcp" / "ReverseLabToolsMCP"))

from reverselab_mcp import registry  # noqa: E402
from reverselab_mcp.tools import dotnet  # noqa: E402

REQUIRED_FILES = [
    "docs/capability-matrix.md",
    "docs/static-analysis-backends.md",
    "tools/skills/mcp/ReverseLabToolsMCP/reverselab_mcp/registry.py",
    "tools/skills/mcp/ReverseLabToolsMCP/reverselab_mcp/contracts/envelope.py",
    "tools/skills/mcp/ReverseLabToolsMCP/reverselab_mcp/tools/pcap.py",
    "tools/skills/mcp/ReverseLabToolsMCP/reverselab_mcp/tools/dotnet.py",
    "tools/skills/mcp/ReverseLabToolsMCP/reverselab_mcp/tools/wasm.py",
]


def _build_managed_pe() -> bytes:
    data = bytearray(0x400)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x40)
    data[0x40:0x44] = b"PE\x00\x00"
    struct.pack_into("<H", data, 0x44, 0x8664)
    struct.pack_into("<H", data, 0x46, 1)
    struct.pack_into("<H", data, 0x54, 0xF0)
    struct.pack_into("<H", data, 0x58, 0x20B)
    directories = 0x58 + 112
    struct.pack_into("<I", data, directories + 14 * 8, 0x1000)
    struct.pack_into("<I", data, directories + 14 * 8 + 4, 0x48)
    data[0x148:0x150] = b".text\x00\x00\x00"
    struct.pack_into("<I", data, 0x148 + 8, 0x200)
    struct.pack_into("<I", data, 0x148 + 12, 0x1000)
    struct.pack_into("<I", data, 0x148 + 16, 0x200)
    struct.pack_into("<I", data, 0x148 + 20, 0x200)
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


def _fixture(base: Path) -> Path:
    base.mkdir(parents=True, exist_ok=True)
    managed = base / "managed.exe"
    managed.write_bytes(_build_managed_pe())
    return managed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", dest="json_path", default="", help="write the full report to this path")
    args = parser.parse_args()

    checks: list[dict[str, object]] = []

    def record(name: str, ok: bool, detail: object = "") -> None:
        checks.append({"name": name, "ok": bool(ok), "detail": detail})

    missing = [rel for rel in REQUIRED_FILES if not (ROOT / rel).is_file()]
    record("deliverable files", not missing, missing or "all present")

    legacy = registry.profile_report("legacy")
    record(
        "profiles",
        legacy["total"] >= 120,
        {name: registry.profile_report(name)["total"] for name in registry.PROFILES},
    )

    fixture = _fixture(ROOT / "tmp" / "engine-verify")
    metadata = dotnet.dotnet_metadata(str(fixture))
    record(
        "dotnet_metadata fallback (no external tool)",
        bool(metadata.get("ok")) and bool(metadata.get("findings", {}).get("is_managed")),
        "CLI header parsed without ilspycmd" if metadata.get("ok") else metadata.get("error"),
    )

    failed = [check for check in checks if not check["ok"]]
    report = {
        "schema": "reverselab.engine_verification.v1",
        "overall": "PASS" if not failed else "FAIL",
        "checks": checks,
        "failed": [check["name"] for check in failed],
        "skipped": [],
        "note": "Optional external tools are reported by lab_healthcheck.py; their absence is not a product failure.",
    }
    text = json.dumps(report, ensure_ascii=False, indent=2)
    print(text)
    if args.json_path:
        target = ROOT / args.json_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
