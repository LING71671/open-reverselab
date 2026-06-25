#!/usr/bin/env python3
"""
Fingerprint -> CVE -> graph -> multi-CVE chain pipeline.

Input examples:

1) JSON fingerprints
{
  "case": "2026-06-target",
  "fingerprints": [
    {"product": "geoserver", "version": "2.25.1"},
    {"product": "geotools", "version": "31.1"}
  ]
}

2) Plain text
geoserver 2.25.1
geotools 31.1

Outputs:
  reports/ctf-website/cve/<CVE>.json
  reports/ctf-website/cve-graph/...
  reports/ctf-website/cve-chain/...
  reports/ctf-website/fingerprint-cve/<timestamp>.md/json
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


@dataclass
class Fingerprint:
    product: str
    version: str = ""
    vendor: str = ""
    evidence: str = ""
    source: str = ""

    @property
    def query(self) -> str:
        parts = [self.vendor, self.product, self.version]
        return " ".join(p for p in parts if p).strip()


def fetch_json(url: str, timeout: float = 30.0) -> dict[str, Any]:
    req = urllib.request.Request(url, headers={"User-Agent": "ReverseLab-Fingerprint-CVE/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", errors="replace"))


def load_fingerprints(path: Path) -> list[Fingerprint]:
    text = path.read_text(encoding="utf-8", errors="replace")
    if path.suffix.lower() == ".json":
        data = json.loads(text)
        rows = data.get("fingerprints") if isinstance(data, dict) else data
        fps: list[Fingerprint] = []
        for row in rows or []:
            if isinstance(row, str):
                fps.append(parse_line(row))
            elif isinstance(row, dict):
                product = str(row.get("product") or row.get("name") or "").strip()
                if not product:
                    continue
                fps.append(Fingerprint(
                    product=product,
                    version=str(row.get("version") or "").strip(),
                    vendor=str(row.get("vendor") or "").strip(),
                    evidence=str(row.get("evidence") or "").strip(),
                    source=str(row.get("source") or "").strip(),
                ))
        return fps
    return [parse_line(line) for line in text.splitlines() if line.strip() and not line.strip().startswith("#")]


def parse_line(line: str) -> Fingerprint:
    line = line.strip()
    # product version [vendor=...] is enough for CTF use.
    parts = re.split(r"\s+", line)
    product = parts[0]
    version = parts[1] if len(parts) > 1 else ""
    return Fingerprint(product=product, version=version, evidence=line, source="text")


def nvd_keyword_search(fp: Fingerprint, limit: int = 20) -> list[dict[str, Any]]:
    query = fp.query
    params = {
        "keywordSearch": query,
        "resultsPerPage": str(limit),
    }
    url = f"{NVD_URL}?{urllib.parse.urlencode(params)}"
    data = fetch_json(url)
    return data.get("vulnerabilities") or []


def best_description(cve_obj: dict[str, Any]) -> str:
    for d in cve_obj.get("descriptions") or []:
        if d.get("lang") == "en":
            return d.get("value") or ""
    return ""


def version_relevance(fp: Fingerprint, cve_obj: dict[str, Any]) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []
    text = json.dumps(cve_obj, ensure_ascii=False).lower()
    product = fp.product.lower()
    version = fp.version.lower()
    vendor = fp.vendor.lower()
    if product and product in text:
        score += 25
        reasons.append(f"product:{fp.product}")
    if vendor and vendor in text:
        score += 10
        reasons.append(f"vendor:{fp.vendor}")
    if version and version in text:
        score += 30
        reasons.append(f"version:{fp.version}")
    desc = best_description(cve_obj).lower()
    for word, add in [("remote code execution", 20), ("rce", 15), ("authentication bypass", 14), ("ssrf", 12), ("sql injection", 10), ("path traversal", 10)]:
        if word in desc:
            score += add
            reasons.append(word)
    return score, reasons


def collect_candidate_cves(fps: list[Fingerprint], per_fp_limit: int, min_score: int) -> dict[str, dict[str, Any]]:
    candidates: dict[str, dict[str, Any]] = {}
    for fp in fps:
        print(f"[NVD] keywordSearch={fp.query!r}")
        try:
            vulns = nvd_keyword_search(fp, limit=per_fp_limit)
        except Exception as exc:
            print(f"[WARN] NVD search failed for {fp.query}: {exc}", file=sys.stderr)
            continue
        time.sleep(0.7)
        for item in vulns:
            cve_obj = item.get("cve") or {}
            cve_id = cve_obj.get("id")
            if not cve_id:
                continue
            score, reasons = version_relevance(fp, cve_obj)
            if score < min_score:
                continue
            entry = candidates.setdefault(cve_id, {"cve": cve_id, "score": 0, "fingerprints": [], "reasons": []})
            entry["score"] = max(entry["score"], score)
            entry["fingerprints"].append(fp.__dict__)
            entry["reasons"].extend(reasons)
    for entry in candidates.values():
        entry["reasons"] = sorted(set(entry["reasons"]))
    return dict(sorted(candidates.items(), key=lambda kv: kv[1]["score"], reverse=True))


def run(cmd: list[str], cwd: Path = ROOT) -> None:
    print("[RUN]", " ".join(cmd))
    subprocess.run(cmd, cwd=str(cwd), check=True)


def enrich_cves(candidates: dict[str, dict[str, Any]], out_dir: Path, max_cves: int, no_network: bool = False) -> list[str]:
    cves = list(candidates.keys())[:max_cves]
    for cve in cves:
        target = out_dir / f"{cve}.json"
        if target.exists():
            print(f"[PRESENT] {target}")
            continue
        cmd = [sys.executable, "scripts/ctf-website/cve_lookup.py", cve, "--out", str(out_dir)]
        if no_network:
            cmd.append("--no-network")
        run(cmd)
    return cves


def render_pipeline_md(fps: list[Fingerprint], candidates: dict[str, dict[str, Any]], outputs: dict[str, str]) -> str:
    lines: list[str] = []
    lines.append("# Fingerprint to Multi-CVE Chain Pipeline")
    lines.append("")
    lines.append(f"- Generated: `{datetime.now(timezone.utc).isoformat()}`")
    lines.append("")
    lines.append("## Fingerprints")
    lines.append("")
    lines.append("| Product | Version | Vendor | Evidence |")
    lines.append("|---|---|---|---|")
    for fp in fps:
        lines.append(f"| {fp.product} | {fp.version} | {fp.vendor} | {fp.evidence} |")
    lines.append("")
    lines.append("## Candidate CVEs")
    lines.append("")
    lines.append("| CVE | Score | Reasons |")
    lines.append("|---|---:|---|")
    for cve, entry in candidates.items():
        lines.append(f"| {cve} | {entry['score']} | {', '.join(entry['reasons'])} |")
    lines.append("")
    lines.append("## Outputs")
    lines.append("")
    for k, v in outputs.items():
        lines.append(f"- {k}: `{v}`")
    lines.append("")
    lines.append("## Next")
    lines.append("")
    lines.append("- Review CVE affected ranges against target fingerprint evidence.")
    lines.append("- Open the generated CVE graph and chain plan.")
    lines.append("- Validate primitives in chain order, not by CVSS order.")
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description="Run fingerprint -> CVE -> graph -> multi-CVE chain pipeline.")
    ap.add_argument("--fingerprints", required=True, help="JSON or text file containing product/version fingerprints.")
    ap.add_argument("--cve-out", default="reports/ctf-website/cve")
    ap.add_argument("--graph-out", default="reports/ctf-website/cve-graph")
    ap.add_argument("--chain-out", default="reports/ctf-website/cve-chain")
    ap.add_argument("--pipeline-out", default="reports/ctf-website/fingerprint-cve")
    ap.add_argument("--per-fingerprint-limit", type=int, default=20)
    ap.add_argument("--max-cves", type=int, default=12)
    ap.add_argument("--min-score", type=int, default=20)
    ap.add_argument("--no-network", action="store_true")
    args = ap.parse_args()

    fps = load_fingerprints(Path(args.fingerprints))
    if not fps:
        raise SystemExit("no fingerprints found")

    candidates = collect_candidate_cves(fps, args.per_fingerprint_limit, args.min_score)
    if not candidates:
        raise SystemExit("no candidate CVEs found; lower --min-score or improve fingerprints")

    cve_out = Path(args.cve_out)
    cves = enrich_cves(candidates, cve_out, max_cves=args.max_cves, no_network=args.no_network)

    graph_out = Path(args.graph_out)
    chain_out = Path(args.chain_out)
    run([sys.executable, "scripts/ctf-website/cve_graph.py", "--from-dir", str(cve_out), "--out", str(graph_out)])
    run([sys.executable, "scripts/ctf-website/cve_chain_planner.py", "--from-dir", str(cve_out), "--out", str(chain_out)])

    pipeline_out = Path(args.pipeline_out)
    pipeline_out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = pipeline_out / f"fingerprint_cve_{stamp}.json"
    md_path = pipeline_out / f"fingerprint_cve_{stamp}.md"
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "fingerprints": [fp.__dict__ for fp in fps],
        "candidate_cves": list(candidates.values()),
        "enriched_cves": cves,
        "outputs": {"cve_out": str(cve_out), "graph_out": str(graph_out), "chain_out": str(chain_out)},
    }
    json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    md_path.write_text(render_pipeline_md(fps, candidates, {"json": str(json_path), "cve_out": str(cve_out), "graph_out": str(graph_out), "chain_out": str(chain_out)}), encoding="utf-8")

    print(f"[OK] pipeline JSON: {json_path}")
    print(f"[OK] pipeline MD:   {md_path}")
    print(f"[OK] enriched CVEs: {len(cves)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
