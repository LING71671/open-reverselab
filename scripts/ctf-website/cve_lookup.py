#!/usr/bin/env python3
"""
CTF-friendly CVE enrichment helper.

Queries:
- NVD CVE API 2.0
- FIRST EPSS API
- CISA KEV data mirror on GitHub

Usage:
  python scripts/ctf-website/cve_lookup.py CVE-2024-36401 --out reports/ctf-website/cve
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path


NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_GITHUB_RAW = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"


def fetch_json(url: str, timeout: float = 20.0) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "ReverseLab-CTF-CVE/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", errors="replace"))


def nvd_lookup(cve_id: str) -> dict:
    url = f"{NVD_URL}?{urllib.parse.urlencode({'cveIds': cve_id})}"
    return fetch_json(url)


def epss_lookup(cve_id: str) -> dict:
    url = f"{EPSS_URL}?{urllib.parse.urlencode({'cve': cve_id})}"
    return fetch_json(url)


def kev_lookup(cve_id: str) -> dict:
    data = fetch_json(KEV_GITHUB_RAW)
    vulns = data.get("vulnerabilities", [])
    matches = [v for v in vulns if v.get("cveID", "").upper() == cve_id.upper()]
    return {
        "catalogVersion": data.get("catalogVersion"),
        "dateReleased": data.get("dateReleased"),
        "count": len(matches),
        "matches": matches,
    }


def summarize(cve_id: str, nvd: dict, epss: dict, kev: dict) -> dict:
    vuln = None
    vulns = nvd.get("vulnerabilities") or []
    if vulns:
        vuln = vulns[0].get("cve", {})

    descriptions = []
    metrics = {}
    weaknesses = []
    refs = []
    published = last_modified = status = None
    if vuln:
        published = vuln.get("published")
        last_modified = vuln.get("lastModified")
        status = vuln.get("vulnStatus")
        descriptions = [d for d in vuln.get("descriptions", []) if d.get("lang") == "en"]
        metrics = vuln.get("metrics", {})
        weaknesses = vuln.get("weaknesses", [])
        raw_refs = vuln.get("references", [])
        if isinstance(raw_refs, dict):
            refs = raw_refs.get("referenceData", [])
        elif isinstance(raw_refs, list):
            refs = raw_refs
        else:
            refs = []

    epss_rows = epss.get("data", [])
    epss_top = epss_rows[0] if epss_rows else {}

    return {
        "cve": cve_id,
        "published": published,
        "lastModified": last_modified,
        "status": status,
        "description": descriptions[0].get("value") if descriptions else "",
        "cvss": metrics,
        "weaknesses": weaknesses,
        "references": refs[:20],
        "epss": epss_top,
        "kev": kev,
        "triage": {
            "isKev": bool(kev.get("count")),
            "epss": epss_top.get("epss"),
            "percentile": epss_top.get("percentile"),
            "referenceCount": len(refs),
        },
    }


def write_report(out_dir: Path, cve_id: str, summary: dict, raw: dict) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    slug = cve_id.upper()
    json_path = out_dir / f"{slug}.json"
    md_path = out_dir / f"{slug}.md"
    json_path.write_text(json.dumps({"summary": summary, "raw": raw}, ensure_ascii=False, indent=2), encoding="utf-8")

    lines = [
        f"# CVE Enrichment: {slug}",
        "",
        f"- Published: {summary.get('published')}",
        f"- Last Modified: {summary.get('lastModified')}",
        f"- NVD Status: {summary.get('status')}",
        f"- EPSS: {summary.get('triage', {}).get('epss')}",
        f"- EPSS Percentile: {summary.get('triage', {}).get('percentile')}",
        f"- In CISA KEV: {summary.get('triage', {}).get('isKev')}",
        "",
        "## Description",
        "",
        summary.get("description") or "",
        "",
        "## Exploit-Oriented Triage",
        "",
        "- Is there public PoC/reference code?",
        "- Is the product/version fingerprintable from challenge artifacts?",
        "- Is exploitation unauthenticated or auth-gated?",
        "- Is a file read/RCE/SSRF/deserialization primitive implied?",
        "- Can the CVE be adapted safely to the sandbox target?",
        "",
        "## References",
        "",
    ]
    for ref in summary.get("references", [])[:15]:
        if isinstance(ref, dict):
            lines.append(f"- {ref.get('url')}")
        else:
            lines.append(f"- {ref}")
    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return {"json": str(json_path), "markdown": str(md_path)}


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("cve")
    parser.add_argument("--out", default="reports/ctf-website/cve")
    parser.add_argument("--no-network", action="store_true", help="Create an empty scaffold without querying APIs")
    args = parser.parse_args(argv)

    cve_id = args.cve.upper()
    if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id):
        raise SystemExit(f"invalid CVE id: {args.cve}")

    if args.no_network:
        raw = {"nvd": {}, "epss": {}, "kev": {}}
        summary = summarize(cve_id, {}, {}, {})
    else:
        nvd = nvd_lookup(cve_id)
        time.sleep(0.7)  # be polite to public APIs
        epss = epss_lookup(cve_id)
        kev = kev_lookup(cve_id)
        raw = {"nvd": nvd, "epss": epss, "kev": kev}
        summary = summarize(cve_id, nvd, epss, kev)

    written = write_report(Path(args.out), cve_id, summary, raw)
    print(json.dumps({"summary": summary, "written": written}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
