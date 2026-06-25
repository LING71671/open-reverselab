from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def json_or_text(text: str) -> Any:
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


def limited_list(value: Any, key: str, limit: int) -> Any:
    if isinstance(value, dict) and isinstance(value.get(key), list):
        copied = dict(value)
        copied[key] = copied[key][: max(0, limit)]
        copied[f"{key}_total"] = len(value[key])
        return copied
    if isinstance(value, list):
        return {key: value[: max(0, limit)], f"{key}_total": len(value)}
    return value


def sanitize_line(text: str) -> str:
    return "".join(ch if ch == "\t" or ch == "\n" or ord(ch) >= 32 else "\\x%02x" % ord(ch) for ch in text)


def slug(text: str) -> str:
    cleaned = []
    for ch in text:
        if ch.isalnum() or ch in ("-", "_", "."):
            cleaned.append(ch)
        else:
            cleaned.append("_")
    value = "".join(cleaned).strip("._")
    return value[:80] or "sample"


def read_text(path: Path, max_chars: int = 12000) -> str:
    if not path.exists():
        return ""
    text = path.read_text(encoding="utf-8", errors="replace")
    if len(text) <= max_chars:
        return text
    return "... truncated ...\n" + text[-max_chars:]


def contains(value: Any, query: str) -> bool:
    if not query:
        return True
    return query.lower() in str(value or "").lower()


def match_any(item: dict[str, Any], query: str, fields: list[str]) -> bool:
    if not query:
        return True
    return any(contains(item.get(field), query) for field in fields)
