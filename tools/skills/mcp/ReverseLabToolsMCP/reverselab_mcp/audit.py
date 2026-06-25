from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import AUDIT_LOG


def new_operation_id() -> str:
    return str(uuid.uuid4())


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def append_audit(record: dict[str, Any]) -> dict[str, Any]:
    AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
    normalized = {
        "operation_id": record.get("operation_id") or new_operation_id(),
        "timestamp": record.get("timestamp") or utc_now(),
        **record,
    }
    with AUDIT_LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(normalized, ensure_ascii=False, sort_keys=True) + "\n")
    return normalized


def audit_log_path() -> Path:
    return AUDIT_LOG


def read_audit_tail(limit: int = 50) -> dict[str, Any]:
    if not AUDIT_LOG.exists():
        return {"audit_log": str(AUDIT_LOG), "records": [], "records_total_returned": 0}
    lines = AUDIT_LOG.read_text(encoding="utf-8", errors="replace").splitlines()
    selected = lines[-max(0, limit):]
    records = []
    for line in selected:
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            records.append({"raw": line})
    return {
        "audit_log": str(AUDIT_LOG),
        "records": records,
        "records_total_returned": len(records),
    }


def read_audit_records() -> list[dict[str, Any]]:
    if not AUDIT_LOG.exists():
        return []
    records = []
    for line in AUDIT_LOG.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            records.append(value)
    return records
