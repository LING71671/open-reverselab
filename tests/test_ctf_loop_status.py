from __future__ import annotations

import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = ROOT / "scripts" / "ctf-website"
sys.path.insert(0, str(SCRIPT_DIR))

import ctf_intake  # noqa: E402
import ctf_loop_status  # noqa: E402


def test_loop_status_done_on_flag_evidence():
    status = ctf_loop_status.evaluate_manifest(
        {
            "evidence": [{"type": "flag", "artifact": "reports/ctf-website/case/final.md"}],
            "next_actions": ["anything"],
        }
    )

    assert status["status"] == "DONE"


def test_loop_status_exhausted_when_paths_are_exhausted():
    status = ctf_loop_status.evaluate_manifest(
        {
            "hypotheses": [{"status": "dead"}, {"status": "confirmed-negative"}],
            "next_actions": [],
            "next_round_focus": [],
            "attack_paths": [],
        }
    )

    assert status["status"] == "EXHAUSTED"
    assert "attack paths" in status["reason"]


def test_loop_status_continue_with_focus():
    status = ctf_loop_status.evaluate_manifest(
        {
            "next_round_focus": [{"action": "Probe SQLi"}],
            "hypotheses": [{"status": "pending"}],
        }
    )

    assert status["status"] == "CONTINUE"


def test_intake_explicit_case_dir_uses_stable_manifest_path(tmp_path):
    case_dir = tmp_path / "cases" / "fleet-example"
    rc = ctf_intake.main(
        [
            "Fleet Example",
            "--root",
            str(tmp_path),
            "--case-dir",
            str(case_dir),
            "--case-name",
            "fleet-example",
        ]
    )

    manifest_path = case_dir / "ai_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert rc == 0
    assert manifest["case"] == "fleet-example"
    assert manifest["paths"]["case"] == str(case_dir)
    assert manifest["loop_status"]["status"] == "CONTINUE"
