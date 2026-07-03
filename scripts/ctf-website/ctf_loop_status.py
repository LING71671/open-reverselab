#!/usr/bin/env python3
"""Compute deterministic loop status for a Web CTF ai_manifest.json."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


TERMINAL_HYPOTHESIS_STATES = {"dead", "failed", "false_positive", "confirmed-negative", "done"}


def parse_time(value: str) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def has_flag_evidence(manifest: dict[str, Any]) -> bool:
    for item in manifest.get("evidence", []) or []:
        item_type = str(item.get("type", "")).lower()
        text = json.dumps(item, ensure_ascii=False).lower()
        if item_type in {"flag", "ctf_flag", "solve", "solved"}:
            return True
        if "flag{" in text or "ctf{" in text:
            return True
    return False


def round_count(manifest: dict[str, Any]) -> int:
    return len(((manifest.get("autopilot") or {}).get("rounds")) or [])


def budget_exhausted(manifest: dict[str, Any], now: datetime | None = None) -> tuple[bool, str]:
    if manifest.get("next_actions") or manifest.get("next_round_focus") or manifest.get("attack_paths"):
        return False, ""

    state = manifest.get("autopilot") or {}
    budget = state.get("budget") or {}
    max_rounds = int(budget.get("max_rounds") or 0)
    if max_rounds and round_count(manifest) >= max_rounds:
        return True, f"max_rounds reached: {round_count(manifest)}/{max_rounds}"

    budget_seconds = int(budget.get("budget_seconds") or 0)
    started_at = parse_time(str(state.get("started_at") or ""))
    if budget_seconds and started_at:
        current = now or datetime.now(timezone.utc)
        elapsed = (current - started_at).total_seconds()
        if elapsed >= budget_seconds:
            return True, f"budget_seconds exhausted: {int(elapsed)}/{budget_seconds}"
    return False, ""


def paths_exhausted(manifest: dict[str, Any]) -> bool:
    hypotheses = manifest.get("hypotheses") or []
    next_actions = [x for x in (manifest.get("next_actions") or []) if str(x).strip()]
    next_round_focus = [x for x in (manifest.get("next_round_focus") or []) if x]
    attack_paths = [x for x in (manifest.get("attack_paths") or []) if x]
    if next_actions or next_round_focus or attack_paths:
        return False
    if not hypotheses:
        return False
    return all(str(item.get("status", "")).lower() in TERMINAL_HYPOTHESIS_STATES for item in hypotheses)


def evaluate_manifest(manifest: dict[str, Any], now: datetime | None = None) -> dict[str, Any]:
    if has_flag_evidence(manifest):
        return {"status": "DONE", "reason": "flag or solved evidence recorded"}

    exhausted, reason = budget_exhausted(manifest, now=now)
    if exhausted:
        return {"status": "EXHAUSTED", "reason": reason}

    if paths_exhausted(manifest):
        return {"status": "EXHAUSTED", "reason": "all hypotheses and attack paths are exhausted"}

    focus_count = len(manifest.get("next_round_focus") or [])
    action_count = len(manifest.get("next_actions") or [])
    return {
        "status": "CONTINUE",
        "reason": f"pending focus/actions remain: focus={focus_count}, actions={action_count}",
    }


def load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compute CTF loop status from ai_manifest.json.")
    parser.add_argument("manifest", help="Path to ai_manifest.json")
    parser.add_argument("--write", action="store_true", help="Write loop_status back to the manifest.")
    args = parser.parse_args(argv)

    manifest_path = Path(args.manifest).expanduser().resolve()
    manifest = load(manifest_path)
    status = evaluate_manifest(manifest)
    if args.write:
        manifest["loop_status"] = status
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"manifest": str(manifest_path), "loop_status": status}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
