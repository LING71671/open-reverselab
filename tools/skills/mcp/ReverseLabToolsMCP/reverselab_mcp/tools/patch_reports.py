from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from ..audit import audit_log_path, read_audit_records
from ..config import REPORTS_DIR
from ..paths import is_relative_to
from ..utils import slug


PATCH_ACTIONS = {"patch_bytes", "patch_pe_bytes", "patch_pattern"}


def _matches_filter(record: dict[str, Any], source_contains: str, destination_contains: str) -> bool:
    if source_contains and source_contains.lower() not in str(record.get("source_path", "")).lower():
        return False
    if destination_contains and destination_contains.lower() not in str(record.get("destination_path", "")).lower():
        return False
    return True


def _record_line(record: dict[str, Any]) -> str:
    action = record.get("action", "")
    op = record.get("operation_id", "")
    source = record.get("source_path", "")
    destination = record.get("destination_path", "")
    offset = record.get("file_offset", record.get("offset", ""))
    old_bytes = record.get("old_bytes_hex", "")
    new_bytes = record.get("new_bytes_hex", "")
    address = record.get("address")
    address_type = record.get("address_type", "")
    section = record.get("section", "")
    details = []
    if address is not None:
        details.append(f"address `{address_type}:0x{int(address):X}`")
    if offset != "":
        details.append(f"file offset `0x{int(offset):X}`")
    if section:
        details.append(f"section `{section}`")
    detail_text = "; ".join(details) if details else "-"
    return (
        f"| `{action}` | `{op}` | `{source}` | `{destination}` | "
        f"{detail_text} | `{old_bytes}` | `{new_bytes}` |"
    )


def generate_patch_report(
    output_path: str = "",
    source_contains: str = "",
    destination_contains: str = "",
    limit: int = 200,
) -> dict[str, Any]:
    records = [
        record
        for record in read_audit_records()
        if record.get("action") in PATCH_ACTIONS and _matches_filter(record, source_contains, destination_contains)
    ]
    selected = records[-max(0, limit):]

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    if output_path:
        out = Path(output_path).expanduser().resolve()
        if not is_relative_to(out, REPORTS_DIR.resolve()):
            raise ValueError(f"patch report output path must be under reports: {out}")
    else:
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        name_part = slug(source_contains or destination_contains or "patches")
        out = REPORTS_DIR / f"patch-report-{name_part}-{stamp}.md"

    lines = [
        "# Patch Report",
        "",
        f"- Audit log: `{audit_log_path()}`",
        f"- Records matched: `{len(records)}`",
        f"- Records included: `{len(selected)}`",
        f"- Source filter: `{source_contains}`",
        f"- Destination filter: `{destination_contains}`",
        "",
        "| Action | Operation ID | Source | Destination | Location | Old Bytes | New Bytes |",
        "|---|---|---|---|---|---|---|",
    ]
    for record in selected:
        lines.append(_record_line(record))

    if not selected:
        lines.append("| - | - | - | - | - | - | - |")

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return {
        "report_path": str(out),
        "audit_log": str(audit_log_path()),
        "records_matched": len(records),
        "records_included": len(selected),
        "source_contains": source_contains,
        "destination_contains": destination_contains,
    }
