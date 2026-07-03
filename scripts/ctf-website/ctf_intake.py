#!/usr/bin/env python3
"""
AI-oriented Web CTF intake.

Creates a challenge directory set and an ai_manifest.json that captures target,
routes, scripts, forms, headers, hypotheses, next actions, and evidence slots.
"""

from __future__ import annotations

import argparse
import html.parser
import json
import re
import ssl
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path


class LinkParser(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.forms: list[dict] = []
        self._current_form: dict | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        data = {k.lower(): v for k, v in attrs}
        if tag == "a" and data.get("href"):
            self.links.append(data["href"] or "")
        elif tag == "script" and data.get("src"):
            self.scripts.append(data["src"] or "")
        elif tag == "form":
            self._current_form = {"action": data.get("action", ""), "method": data.get("method", "GET"), "inputs": []}
            self.forms.append(self._current_form)
        elif tag in {"input", "textarea", "select"} and self._current_form is not None:
            self._current_form["inputs"].append({"name": data.get("name", ""), "type": data.get("type", tag)})

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._current_form = None


def slugify(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    if not slug:
        raise ValueError("invalid name")
    return slug


def fetch(url: str, timeout: float = 10.0) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "ReverseLab-CTF-Intake/1.0"})
    start = time.time()
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        body = resp.read(1024 * 1024)
        return {
            "url": url,
            "final_url": resp.geturl(),
            "status": resp.status,
            "elapsed_ms": round((time.time() - start) * 1000, 2),
            "headers": dict(resp.headers.items()),
            "body_text": body.decode("utf-8", errors="replace"),
            "body_size": len(body),
        }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("name")
    parser.add_argument("--url", default="")
    parser.add_argument("--root", default=".")
    parser.add_argument("--board", default="ctf-website")
    parser.add_argument("--case-dir", default="", help="Optional case directory, relative to --root or absolute.")
    parser.add_argument("--case-name", default="", help="Optional exact case name stored in ai_manifest.json.")
    parser.add_argument("--no-date-prefix", action="store_true", help="Use the slug as the case name without YYYY-MM- prefix.")
    args = parser.parse_args(argv)

    root = Path(args.root).resolve()
    slug = slugify(args.case_name or args.name)
    if args.case_dir:
        raw_case_dir = Path(args.case_dir).expanduser()
        case_dir = raw_case_dir if raw_case_dir.is_absolute() else root / raw_case_dir
        case_name = slugify(args.case_name or case_dir.name)
        artifact_slug = case_name
    else:
        case_name = slug if args.no_date_prefix else time.strftime("%Y-%m-") + slug
        case_dir = root / "cases" / case_name
        artifact_slug = slug
    paths = {
        "case": case_dir,
        "samples": root / "samples" / args.board / artifact_slug,
        "projects": root / "projects" / args.board / artifact_slug,
        "exports": root / "exports" / args.board / artifact_slug,
        "patches": root / "patches" / args.board / artifact_slug,
        "notes": root / "notes" / args.board / artifact_slug,
        "reports": root / "reports" / args.board / artifact_slug,
        "scripts": root / "scripts" / args.board / artifact_slug,
    }
    for p in paths.values():
        p.mkdir(parents=True, exist_ok=True)

    baseline = {}
    parsed = {"links": [], "scripts": [], "forms": []}
    error = ""
    if args.url:
        try:
            baseline = fetch(args.url)
            parser_obj = LinkParser()
            parser_obj.feed(baseline.get("body_text", ""))
            base = baseline.get("final_url") or args.url
            parsed = {
                "links": sorted({urllib.parse.urljoin(base, x) for x in parser_obj.links}),
                "scripts": sorted({urllib.parse.urljoin(base, x) for x in parser_obj.scripts}),
                "forms": parser_obj.forms,
            }
        except Exception as exc:
            error = repr(exc)

    manifest = {
        "schema": "reverselab.ctf_website.ai_manifest.v1",
        "case": case_name,
        "board": args.board,
        "target": {"url": args.url},
        "paths": {k: str(v) for k, v in paths.items()},
        "baseline": {k: v for k, v in baseline.items() if k != "body_text"},
        "parsed": parsed,
        "error": error,
        "hypotheses": [
            {"id": "H-001", "class": "recon", "claim": "Map hidden routes and APIs", "status": "pending"},
            {"id": "H-002", "class": "auth", "claim": "Inspect session/token trust boundaries", "status": "pending"},
            {"id": "H-003", "class": "injection", "claim": "Probe server-side parsers and template/query contexts", "status": "pending"},
        ],
        "next_actions": [
            "Run ctf_toolcheck and note missing tools.",
            "Follow kb/ctf-website/checklists/web-ctf-first-30-min.md.",
            "If JS-heavy, use JSHook to capture fetch/XHR/WebSocket/crypto.",
            "If product/version is fingerprinted, write cases/<case>/fingerprints.json and run fingerprint_cve_pipeline.py for CVE graph/chain candidates.",
        ],
        "next_round_focus": [],
        "attack_paths": [],
        "loop_status": {"status": "CONTINUE", "reason": "initial intake"},
        "evidence": [],
        "dead_ends": [],
    }

    manifest_path = paths["case"] / "ai_manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    (paths["case"] / "README.md").write_text(
        f"# Case: {case_name}\n\n- Board: {args.board}\n- Target: {args.url}\n- AI Manifest: `ai_manifest.json`\n\n## Next\n\n"
        + "\n".join(f"- {x}" for x in manifest["next_actions"])
        + "\n",
        encoding="utf-8",
    )
    if baseline.get("body_text"):
        (paths["exports"] / "baseline_body.html").write_text(baseline["body_text"], encoding="utf-8")
    print(json.dumps({"case": case_name, "manifest": str(manifest_path), "paths": manifest["paths"]}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
