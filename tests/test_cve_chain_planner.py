from __future__ import annotations

from conftest import ROOT, load_script_module


cve_chain_planner = load_script_module("scripts/ctf-website/cve_chain_planner.py", "cve_chain_planner_test")


def test_cve_fixture_builds_chain_candidates():
    fixture_dir = ROOT / "tests" / "fixtures" / "cve-chain"
    nodes = cve_chain_planner.load_reports(sorted(fixture_dir.glob("CVE-*.json")))
    candidates = cve_chain_planner.build_chain_candidates(nodes)

    assert len(nodes) == 3
    assert candidates
    assert any("info_leak" in candidate["primitives"] for candidate in candidates)
    assert any("rce" in candidate["primitives"] for candidate in candidates)
    assert any(len(candidate["cves"]) >= 2 for candidate in candidates)


def test_cve_fixture_render_contains_mermaid():
    fixture_dir = ROOT / "tests" / "fixtures" / "cve-chain"
    nodes = cve_chain_planner.load_reports(sorted(fixture_dir.glob("CVE-*.json")))
    candidates = cve_chain_planner.build_chain_candidates(nodes)
    markdown = cve_chain_planner.render_md(nodes, candidates, "2026-01-01T00:00:00+00:00")

    assert "# Multi-CVE Chain Plan" in markdown
    assert "```mermaid" in markdown
