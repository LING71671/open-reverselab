#!/usr/bin/env python3
"""
Generate an AI-friendly next-action plan from a Web CTF ai_manifest.json.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def existing_fingerprint_path(manifest: dict, manifest_path: Path | None = None) -> str:
    """Return the best known fingerprint file path if the manifest/case already has one."""
    candidates: list[Path] = []
    paths = manifest.get("paths", {}) or {}
    for raw in [
        manifest.get("fingerprints"),
        paths.get("fingerprints"),
    ]:
        if raw:
            candidates.append(Path(str(raw)))

    case_path = paths.get("case")
    if case_path:
        candidates.append(Path(str(case_path)) / "fingerprints.json")
    if manifest_path:
        candidates.append(manifest_path.parent / "fingerprints.json")

    for candidate in candidates:
        try:
            if candidate.exists():
                return str(candidate.resolve())
        except OSError:
            continue
    return ""


def plan(manifest: dict, manifest_path: Path | None = None) -> dict:
    parsed = manifest.get("parsed", {})
    baseline = manifest.get("baseline", {})
    target = manifest.get("target", {})
    paths = manifest.get("paths", {})
    actions: list[dict] = []

    if not baseline:
        actions.append({
            "priority": "P0",
            "action": "Collect HTTP baseline",
            "command": f"python scripts/ctf-website/http_probe.py {target.get('url') or '<url>'}",
            "why": "No baseline response is recorded.",
            "kb_files": ["01-recon/recon-routing.md", "attack-network.md"],
        })

    scripts = parsed.get("scripts") or []
    if scripts:
        actions.append({
            "priority": "P0",
            "action": "Inspect JavaScript runtime and API routes",
            "command": "Use JSHook/browser hooks for fetch/XHR/WebSocket/crypto; grep saved bundles for endpoints and signatures.",
            "why": f"{len(scripts)} script asset(s) discovered.",
            "kb_files": ["07-client/js-runtime.md", "07-client/web-crypto-abuse.md"],
        })

    forms = parsed.get("forms") or []
    if forms:
        actions.append({
            "priority": "P1",
            "action": "Probe forms for auth/injection/state bugs",
            "command": "Test content-types, method override, SQLi/NoSQLi/SSTI probes, CSRF/session behavior.",
            "why": f"{len(forms)} form(s) discovered.",
            "kb_files": ["03-injection/sqli-nosqli.md", "03-injection/ssti.md", "03-injection/hpp-crlf.md"],
        })

    links = parsed.get("links") or []
    if len(links) < 5:
        actions.append({
            "priority": "P1",
            "action": "Run targeted route discovery",
            "command": "Use tools/ctf-website/wordlists/small-routes.txt with curl/ffuf/gobuster if available.",
            "why": "Route map is sparse.",
        })

    headers = baseline.get("headers") or {}
    header_text = json.dumps(headers).lower()
    if any(x in header_text for x in ["express", "next", "spring", "struts", "django", "flask", "laravel", "php"]):
        actions.append({
            "priority": "P1",
            "action": "Fingerprint framework version and build CVE chain candidates",
            "command": "Record product/version evidence into cases/<case>/fingerprints.json, then run scripts/ctf-website/fingerprint_cve_pipeline.py --fingerprints cases/<case>/fingerprints.json --per-fingerprint-limit 5 --max-cves 10.",
            "why": "Framework/product signal appears in headers.",
        })

    fingerprints = existing_fingerprint_path(manifest, manifest_path)
    if fingerprints:
        actions.append({
            "priority": "P0",
            "action": "Run fingerprint-to-CVE graph and chain pipeline",
            "command": f"python scripts/ctf-website/fingerprint_cve_pipeline.py --fingerprints {fingerprints} --per-fingerprint-limit 5 --max-cves 10",
            "why": f"Fingerprint evidence file exists: {fingerprints}",
        })
    elif baseline or parsed:
        actions.append({
            "priority": "P1",
            "action": "Create version fingerprint evidence file",
            "command": f"Copy templates/cases/fingerprints.json to {paths.get('case', '<case>')}/fingerprints.json and fill product/version/source/url/evidence.",
            "why": "Multi-CVE chaining needs explicit product/version evidence before CVE correlation.",
        })

    cve_reports = manifest.get("cve_reports") or paths.get("cve_reports")
    if cve_reports:
        actions.append({
            "priority": "P0",
            "action": "Rebuild CVE correlation graph and multi-CVE chain plan",
            "command": f"python scripts/ctf-website/cve_graph.py --input-dir {cve_reports}; python scripts/ctf-website/cve_chain_planner.py --input-dir {cve_reports}",
            "why": "CVE enrichment artifacts are already present; prioritize exploit-chain validation over more broad recon.",
        })

    actions.append({
        "priority": "P2",
        "action": "Update evidence and dead-end log",
        "command": f"Edit {paths.get('case', '<case>')}/ai_manifest.json and case notes after each decisive test.",
        "why": "Keeps the AI state machine aligned with runtime evidence.",
    })

    priority_order = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
    actions = sorted(
        actions,
        key=lambda item: (priority_order.get(str(item.get("priority")), 99), str(item.get("action", ""))),
    )

    return {
        "case": manifest.get("case"),
        "target": target,
        "action_count": len(actions),
        "actions": actions,
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", help="Path to ai_manifest.json")
    parser.add_argument("--out", default="", help="Optional markdown output path")
    args = parser.parse_args(argv)
    manifest_path = Path(args.manifest)
    result = plan(load(manifest_path), manifest_path)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if args.out:
        lines = [f"# AI Next Plan: {result.get('case')}", ""]
        for item in result["actions"]:
            lines += [
                f"## {item['priority']} - {item['action']}",
                "",
                f"- Why: {item['why']}",
                f"- Command/Method: `{item['command']}`",
                "",
            ]
        Path(args.out).write_text("\n".join(lines), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
