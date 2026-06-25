from __future__ import annotations

from pathlib import Path

from conftest import load_script_module


kb_router = load_script_module("scripts/ctf-website/kb_router.py", "kb_router_test")


def test_kb_router_prioritizes_jwt_signal():
    entries = kb_router.load_index()
    results = kb_router.search("jwt bearer token in authorization header", entries)

    assert results
    assert results[0]["id"] == "jwt"
    assert "02-auth/jwt/00-overview.md" in results[0]["files"]


def test_kb_router_results_reference_existing_files():
    entries = kb_router.load_index()
    results = kb_router.search("sql injection", entries)

    assert results
    techniques_dir = Path(kb_router.TECHNIQUES_DIR)
    for rel_path in results[0]["files"]:
        assert (techniques_dir / rel_path).is_file()
