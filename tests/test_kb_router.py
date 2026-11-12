from __future__ import annotations

from pathlib import Path

from conftest import load_script_module


kb_router = load_script_module("scripts/ctf-website/kb_router.py", "kb_router_test")
misc_kb_router = load_script_module("scripts/misc/kb_router.py", "misc_kb_router_test")


def test_kb_router_prioritizes_jwt_signal():
    entries = kb_router.load_index()
    results = kb_router.search("jwt bearer token in authorization header", entries, track="red")

    assert results
    assert results[0]["id"] == "jwt"
    assert "02-auth/jwt/00-overview.md" in results[0]["files"]


def test_kb_router_results_reference_existing_files():
    entries = kb_router.load_index()
    results = kb_router.search("sql injection", entries, track="both")

    assert results
    techniques_dir = Path(kb_router.TECHNIQUES_DIR)
    for rel_path in results[0]["files"]:
        assert (techniques_dir / rel_path).is_file()


def test_misc_kb_router_supports_all_four_boards():
    assert set(misc_kb_router.BOARDS) == {"general", "pe-reverse", "apk-reverse", "ctf-website"}
    general_entries = misc_kb_router.load_index("general")
    assert general_entries
    results = misc_kb_router.search("rsa", general_entries, track="both")
    assert results
    assert results[0]["_board"] == "general"


def test_misc_kb_router_exact_signal_score_and_track_pairing():
    assert misc_kb_router.SCORE_SIGNAL_EXACT == 30
    entries = [
        {
            "_board": "general",
            "id": "rsa-attack",
            "track": "red",
            "signals": ["rsa", "rsa key"],
            "files": ["crypto/04-rsa-attack-family.md"],
            "priority": 10,
        },
        {
            "_board": "general",
            "id": "rsa-attack-defense",
            "track": "blue",
            "defends": "rsa-attack",
            "signals": ["rsa", "rsa hardening"],
            "files": ["crypto/04-rsa-attack-family-defense.md"],
            "priority": 10,
        },
        {
            "_board": "general",
            "id": "path-traversal-note",
            "track": "both",
            "signals": ["path traversal"],
            "files": ["misc/traversal.md"],
            "priority": 5,
        },
    ]

    blue_results = misc_kb_router.search("rsa", entries, track="blue")
    blue_ids = [r["id"] for r in blue_results]
    assert "rsa-attack" not in blue_ids
    assert blue_ids[0] == "rsa-attack-defense"
    assert blue_results[0]["_score"] > blue_results[1]["_score"]

    red_results = misc_kb_router.search("rsa", entries, track="red")
    red_ids = [r["id"] for r in red_results]
    assert "rsa-attack-defense" not in red_ids
    assert red_ids[0] == "rsa-attack"

    both_results = misc_kb_router.search("rsa", entries, track="both")
    assert [r["id"] for r in both_results[:2]] == ["rsa-attack", "rsa-attack-defense"]
    assert both_results[0]["_paired"]
    assert both_results[1]["_paired"]
