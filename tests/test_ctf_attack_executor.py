from __future__ import annotations

import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = ROOT / "scripts" / "ctf-website"
sys.path.insert(0, str(SCRIPT_DIR))

import ctf_attack_executor  # noqa: E402


def write_manifest(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def test_probe_routes_writes_evidence_without_network(tmp_path, monkeypatch):
    manifest_path = tmp_path / "ai_manifest.json"
    write_manifest(
        manifest_path,
        {
            "case": "executor-routes",
            "target": {"url": "http://target.invalid/"},
            "paths": {"exports": str(tmp_path / "exports")},
            "parsed": {"links": [], "scripts": [], "forms": []},
            "evidence": [],
            "next_round_focus": [],
        },
    )

    def fake_request(url, **kwargs):
        status = 200 if url.endswith("/robots.txt") else 404
        return {"url": url, "final_url": url, "status": status, "elapsed_ms": 1, "headers": {}, "body_text": "", "body_size": 0, "error": ""}

    monkeypatch.setattr(ctf_attack_executor, "request_url", fake_request)
    result = ctf_attack_executor.execute(manifest_path, ["routes"], limit=1, origin="https://origin.invalid", ssrf_targets=[], redirect_host="redirect.invalid", lfi_payloads=[], write=True)

    updated = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert result["results"][0]["handler"] == "probe_routes"
    assert updated["evidence"][0]["type"] == "route_discovery"
    assert updated["next_round_focus"]


def test_probe_open_redirect_detects_location(tmp_path, monkeypatch):
    manifest_path = tmp_path / "ai_manifest.json"
    write_manifest(
        manifest_path,
        {
            "case": "executor-redirect",
            "target": {"url": "http://target.invalid/"},
            "paths": {"exports": str(tmp_path / "exports")},
            "parsed": {"links": ["http://target.invalid/login?next=/home"], "scripts": [], "forms": []},
            "evidence": [],
            "next_round_focus": [],
        },
    )

    def fake_request(url, **kwargs):
        return {"url": url, "final_url": url, "status": 302, "elapsed_ms": 1, "headers": {"Location": "https://redirect.invalid"}, "body_text": "", "body_size": 0, "error": ""}

    monkeypatch.setattr(ctf_attack_executor, "request_url", fake_request)
    result = ctf_attack_executor.execute(manifest_path, ["open_redirect"], limit=2, origin="https://origin.invalid", ssrf_targets=[], redirect_host="redirect.invalid", lfi_payloads=[], write=True)

    updated = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert result["results"][0]["finding_count"] >= 1
    assert updated["evidence"][0]["type"] == "open_redirect"
