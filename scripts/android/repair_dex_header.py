from __future__ import annotations

import argparse
import hashlib
import zlib
from pathlib import Path


def repair_dex_header(path: Path) -> dict[str, str]:
    data = bytearray(path.read_bytes())
    if len(data) < 32 or not data.startswith(b"dex\n"):
        raise ValueError(f"Not a dex file: {path}")

    signature = hashlib.sha1(data[32:]).digest()
    data[12:32] = signature

    checksum = zlib.adler32(data[12:]) & 0xFFFFFFFF
    data[8:12] = checksum.to_bytes(4, "little")

    path.write_bytes(data)
    return {
        "path": str(path),
        "sha1": signature.hex(),
        "adler32_le": f"{checksum:08x}",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Repair dex SHA-1 signature and Adler32 checksum in-place.")
    parser.add_argument("paths", nargs="+", help="DEX file paths to repair")
    args = parser.parse_args()

    for raw_path in args.paths:
        result = repair_dex_header(Path(raw_path).resolve())
        print(result)


if __name__ == "__main__":
    main()
