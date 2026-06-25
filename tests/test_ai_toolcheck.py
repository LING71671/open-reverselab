from __future__ import annotations

import sys
from pathlib import Path

from conftest import load_script_module


ai_toolcheck = load_script_module("scripts/misc/ai_toolcheck.py", "ai_toolcheck_test")


def test_sanitize_payload_removes_machine_paths(monkeypatch, tmp_path):
    private_root = r"E:\ReverseLab"
    monkeypatch.setenv("REVERSELAB_PRIVATE_ROOTS", private_root)
    report = tmp_path / "reports" / "misc" / "toolcheck.json"
    report.parent.mkdir(parents=True)
    report.write_text("{}", encoding="utf-8")

    payload = {
        "registry": str(report),
        "results": [
            {
                "path": "C:" + r"\Users\alice\.cursor\secret.txt",
                "detail": rf"created under {private_root}\reports\misc",
            }
        ],
    }

    sanitized = ai_toolcheck.sanitize_payload(payload, tmp_path)

    assert sanitized["registry"] == "reports/misc/toolcheck.json"
    assert "<user>" in sanitized["results"][0]["path"]
    assert "<private-root>" in sanitized["results"][0]["detail"]


def test_allow_nonzero_command_is_warning_not_failure():
    result = ai_toolcheck.check_command(
        {"command": sys.executable, "args": ["-c", "import sys; print('allowed'); sys.exit(2)"]},
        {"type": "command", "timeout_ms": 5000, "allow_nonzero": True},
    )

    assert result["status"] == "FOUND_WITH_WARN"
    assert "nonzero allowed" in result["detail"]


def test_render_md_includes_board_summary():
    payload = {
        "time": "2026-01-01T00:00:00+00:00",
        "registry": "tools/ai-tool-registry.json",
        "overall": "PASS",
        "found": 2,
        "warn": 1,
        "bad": 0,
        "boards": {"misc": {"FOUND": 1, "FOUND_WITH_WARN": 1}},
        "results": [
            {
                "status": "FOUND_WITH_WARN",
                "board": "misc",
                "id": "misc.proxy_test",
                "launch_mode": "cli",
                "ai_callable": True,
                "detail": "exit=1 (nonzero allowed)",
                "path": "python",
            }
        ],
    }

    markdown = ai_toolcheck.render_md(payload)

    assert "## Board Summary" in markdown
    assert "FOUND_WITH_WARN" in markdown
    assert "| misc | 1 | 1 |" in markdown
