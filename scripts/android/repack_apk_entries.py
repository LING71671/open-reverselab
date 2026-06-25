from __future__ import annotations

import argparse
import shutil
from pathlib import Path
import zipfile


def copy_with_replacements(
    src_apk: Path,
    dst_apk: Path,
    replacements: dict[str, Path],
) -> None:
    dst_apk.parent.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(src_apk, "r") as src, zipfile.ZipFile(
        dst_apk, "w"
    ) as dst:
        written: set[str] = set()

        for info in src.infolist():
            name = info.filename
            payload = replacements.get(name)
            if payload is None:
                data = src.read(name)
            else:
                data = payload.read_bytes()
                written.add(name)

            new_info = zipfile.ZipInfo(name)
            new_info.date_time = info.date_time
            new_info.compress_type = info.compress_type
            new_info.comment = info.comment
            new_info.create_system = info.create_system
            new_info.external_attr = info.external_attr
            dst.writestr(new_info, data)

        for name, payload in replacements.items():
            if name in written or name in src.namelist():
                continue
            new_info = zipfile.ZipInfo(name)
            new_info.compress_type = zipfile.ZIP_DEFLATED
            dst.writestr(new_info, payload.read_bytes())


def parse_mapping(values: list[str]) -> dict[str, Path]:
    mapping: dict[str, Path] = {}
    for value in values:
        if "=" not in value:
            raise ValueError(f"Invalid mapping: {value!r}, expected zip_name=path")
        zip_name, raw_path = value.split("=", 1)
        path = Path(raw_path).resolve()
        if not path.is_file():
            raise FileNotFoundError(path)
        mapping[zip_name] = path
    return mapping


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Repack an APK while replacing or adding selected entries."
    )
    parser.add_argument("src_apk", help="Source APK path")
    parser.add_argument("dst_apk", help="Destination APK path")
    parser.add_argument(
        "--entry",
        action="append",
        default=[],
        help="Replacement/addition mapping in the form zip_name=local_path",
    )
    parser.add_argument(
        "--backup",
        action="store_true",
        help="Copy the source APK next to the destination as *.bak before writing",
    )
    args = parser.parse_args()

    src_apk = Path(args.src_apk).resolve()
    dst_apk = Path(args.dst_apk).resolve()
    replacements = parse_mapping(args.entry)

    if args.backup and dst_apk.exists():
        shutil.copy2(dst_apk, dst_apk.with_suffix(dst_apk.suffix + ".bak"))

    copy_with_replacements(src_apk, dst_apk, replacements)
    print(
        {
            "src_apk": str(src_apk),
            "dst_apk": str(dst_apk),
            "entries": sorted(replacements),
        }
    )


if __name__ == "__main__":
    main()
