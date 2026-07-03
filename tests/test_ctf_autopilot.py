from __future__ import annotations

import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = ROOT / "scripts" / "ctf-website"
sys.path.insert(0, str(SCRIPT_DIR))

import ctf_autopilot  # noqa: E402


def write_manifest(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def test_run_round_dry_run_writes_checkpoint(tmp_path):
    manifest_path = tmp_path / "ai_manifest.json"
    write_manifest(
        manifest_path,
        {
            "schema": "reverselab.ctf_website.ai_manifest.v1",
            "case": "autopilot-dry-run",
            "board": "ctf-website",
            "target": {"url": "http://example.test/"},
            "paths": {"case": str(tmp_path), "exports": str(tmp_path / "exports"), "reports": str(tmp_path / "reports")},
            "baseline": {},
            "parsed": {"links": [], "scripts": [], "forms": []},
            "evidence": [],
            "dead_ends": [],
        },
    )

    result = ctf_autopilot.run_round(
        manifest_path,
        max_actions=2,
        execute=False,
        max_rounds=1,
    )

    updated = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert result["selected_action_count"] == 2
    assert updated["autopilot"]["schema"] == "reverselab.ctf_website.autopilot.v1"
    assert updated["autopilot"]["status"] == "dry_run"
    assert updated["autopilot"]["rounds"][0]["actions"][0]["execution"]["status"] == "planned"
    assert updated["next_actions"]
    assert updated["next_round_focus"]
    assert updated["loop_status"]["status"] == "CONTINUE"


def test_run_round_execute_creates_fingerprint_template(tmp_path):
    manifest_path = tmp_path / "ai_manifest.json"
    write_manifest(
        manifest_path,
        {
            "schema": "reverselab.ctf_website.ai_manifest.v1",
            "case": "autopilot-fingerprint",
            "board": "ctf-website",
            "target": {"url": "http://example.test/"},
            "paths": {"case": str(tmp_path), "exports": str(tmp_path / "exports"), "reports": str(tmp_path / "reports")},
            "baseline": {"headers": {}, "status": 200},
            "parsed": {"links": ["http://example.test/"], "scripts": [], "forms": []},
            "evidence": [],
            "dead_ends": [],
        },
    )

    result = ctf_autopilot.run_round(
        manifest_path,
        max_actions=1,
        execute=True,
        max_rounds=1,
    )

    updated = json.loads(manifest_path.read_text(encoding="utf-8"))
    fingerprint_path = tmp_path / "fingerprints.json"
    assert fingerprint_path.exists()
    assert updated["fingerprints"] == str(fingerprint_path)
    assert updated["evidence"][0]["type"] == "fingerprint_template"
    assert result["round"]["actions"][0]["execution"]["handler"] == "create_fingerprint_template"
