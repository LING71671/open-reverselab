#!/usr/bin/env python3
"""
ReverseLab CVE correlation graph builder.

Reads JSON reports produced by cve_lookup.py and builds a lightweight
dependency-free graph for CTF triage:

- CVE -> CWE
- CVE -> affected vendor/product from CPE or CISA KEV
- CVE -> reference domains
- CVE -> EPSS risk bucket
- CVE -> KEV marker
- CVE <-> CVE when sharing CWE/product/reference domain
"""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)


@dataclass
class CveFact:
    cve: str
    description: str = ""
    published: str = ""
    cvss: float | None = None
    severity: str = ""
    epss: float | None = None
    epss_percentile: float | None = None
    is_kev: bool = False
    cwes: set[str] = field(default_factory=set)
    products: set[str] = field(default_factory=set)
    vendors: set[str] = field(default_factory=set)
    reference_domains: set[str] = field(default_factory=set)
    references: list[str] = field(default_factory=list)


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def normalize_cve(value: str) -> str:
    value = value.upper()
    if not CVE_RE.match(value):
        raise ValueError(f"invalid CVE id: {value}")
    return value


def first_cvss(summary: dict[str, Any]) -> tuple[float | None, str]:
    cvss = summary.get("cvss") or {}
    for metric_name in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metrics = cvss.get(metric_name) or []
        if not metrics:
            continue
        data = metrics[0].get("cvssData") or {}
        score = data.get("baseScore")
        severity = data.get("baseSeverity") or metrics[0].get("baseSeverity") or ""
        try:
            score_f = float(score) if score is not None else None
        except (TypeError, ValueError):
            score_f = None
        return score_f, str(severity)
    return None, ""


def epss_bucket(score: float | None) -> str:
    if score is None:
        return "EPSS:unknown"
    if score >= 0.9:
        return "EPSS:>=0.90"
    if score >= 0.5:
        return "EPSS:0.50-0.90"
    if score >= 0.1:
        return "EPSS:0.10-0.50"
    return "EPSS:<0.10"


def parse_cpe(criteria: str) -> tuple[str | None, str | None]:
    # cpe:2.3:a:vendor:product:version:...
    parts = criteria.split(":")
    if len(parts) >= 5 and parts[0] == "cpe" and parts[1] == "2.3":
        vendor = parts[3].replace("\\", "").replace("_", " ")
        product = parts[4].replace("\\", "").replace("_", " ")
        return vendor, product
    return None, None


def canonical_name(value: Any) -> str:
    return str(value).strip().replace("_", " ")


def walk_cpe_nodes(node: Any) -> list[str]:
    found: list[str] = []
    if isinstance(node, dict):
        for match in node.get("cpeMatch") or []:
            criteria = match.get("criteria")
            if criteria and match.get("vulnerable", True):
                found.append(criteria)
        for child in node.get("nodes") or []:
            found.extend(walk_cpe_nodes(child))
    elif isinstance(node, list):
        for item in node:
            found.extend(walk_cpe_nodes(item))
    return found


def extract_fact(report: dict[str, Any]) -> CveFact:
    summary = report.get("summary") or {}
    raw = report.get("raw") or {}
    cve = normalize_cve(summary.get("cve") or "")
    fact = CveFact(
        cve=cve,
        description=(summary.get("description") or "").strip(),
        published=summary.get("published") or "",
        is_kev=bool((summary.get("kev") or {}).get("matches")) or bool((summary.get("triage") or {}).get("isKev")),
    )
    fact.cvss, fact.severity = first_cvss(summary)

    epss = summary.get("epss") or {}
    try:
        fact.epss = float(epss.get("epss")) if epss.get("epss") is not None else None
    except (TypeError, ValueError):
        pass
    try:
        fact.epss_percentile = float(epss.get("percentile")) if epss.get("percentile") is not None else None
    except (TypeError, ValueError):
        pass

    for weakness in summary.get("weaknesses") or []:
        for desc in weakness.get("description") or []:
            value = desc.get("value")
            if value and value.startswith("CWE-"):
                fact.cwes.add(value)

    for ref in summary.get("references") or []:
        url = ref.get("url")
        if not url:
            continue
        fact.references.append(url)
        domain = urlparse(url).netloc.lower()
        if domain:
            fact.reference_domains.add(domain)

    # CISA KEV often contains a cleaner vendor/product pair than NVD CPEs.
    kev = summary.get("kev") or {}
    for match in kev.get("matches") or []:
        if match.get("vendorProject"):
            fact.vendors.add(canonical_name(match["vendorProject"]).lower())
        if match.get("product"):
            fact.products.add(canonical_name(match["product"]).lower())
        for cwe in match.get("cwes") or []:
            if str(cwe).startswith("CWE-"):
                fact.cwes.add(str(cwe))

    nvd_vulns = (((raw.get("nvd") or {}).get("vulnerabilities")) or [])
    for vuln in nvd_vulns:
        cve_obj = vuln.get("cve") or {}
        for conf in cve_obj.get("configurations") or []:
            for criteria in walk_cpe_nodes(conf):
                vendor, product = parse_cpe(criteria)
                if vendor:
                    fact.vendors.add(canonical_name(vendor).lower())
                if product:
                    fact.products.add(canonical_name(product).lower())

    return fact


def add_node(nodes: dict[str, dict[str, Any]], node_id: str, label: str, kind: str, **attrs: Any) -> None:
    if node_id not in nodes:
        nodes[node_id] = {"id": node_id, "label": label, "kind": kind}
    nodes[node_id].update({k: v for k, v in attrs.items() if v not in (None, "", [], {})})


def add_edge(edges: list[dict[str, str]], src: str, dst: str, rel: str) -> None:
    edge = {"source": src, "target": dst, "relation": rel}
    if edge not in edges:
        edges.append(edge)


def build_graph(facts: list[CveFact]) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, str]] = []
    by_cwe: dict[str, list[str]] = defaultdict(list)
    by_product: dict[str, list[str]] = defaultdict(list)
    by_domain: dict[str, list[str]] = defaultdict(list)

    for fact in facts:
        cve_id = f"cve:{fact.cve}"
        add_node(
            nodes,
            cve_id,
            fact.cve,
            "cve",
            published=fact.published,
            cvss=fact.cvss,
            severity=fact.severity,
            epss=fact.epss,
            epss_percentile=fact.epss_percentile,
            is_kev=fact.is_kev,
            description=fact.description[:500],
        )

        bucket = epss_bucket(fact.epss)
        add_node(nodes, f"epss:{bucket}", bucket, "epss_bucket")
        add_edge(edges, cve_id, f"epss:{bucket}", "epss_bucket")

        if fact.is_kev:
            add_node(nodes, "kev:CISA", "CISA KEV", "kev")
            add_edge(edges, cve_id, "kev:CISA", "in_kev")

        for cwe in sorted(fact.cwes):
            node_id = f"cwe:{cwe}"
            add_node(nodes, node_id, cwe, "cwe")
            add_edge(edges, cve_id, node_id, "has_cwe")
            by_cwe[cwe].append(cve_id)

        for vendor in sorted(fact.vendors):
            node_id = f"vendor:{vendor.lower()}"
            add_node(nodes, node_id, vendor, "vendor")
            add_edge(edges, cve_id, node_id, "vendor")

        for product in sorted(fact.products):
            node_id = f"product:{product.lower()}"
            add_node(nodes, node_id, product, "product")
            add_edge(edges, cve_id, node_id, "affects")
            by_product[product.lower()].append(cve_id)

        for domain in sorted(fact.reference_domains):
            node_id = f"domain:{domain}"
            add_node(nodes, node_id, domain, "reference_domain")
            add_edge(edges, cve_id, node_id, "referenced_by")
            by_domain[domain].append(cve_id)

    for mapping, rel in ((by_cwe, "same_cwe"), (by_product, "same_product"), (by_domain, "same_reference_domain")):
        for members in mapping.values():
            unique = sorted(set(members))
            for i, src in enumerate(unique):
                for dst in unique[i + 1:]:
                    add_edge(edges, src, dst, rel)

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "nodes": list(nodes.values()),
        "edges": edges,
        "stats": {
            "cve_count": len(facts),
            "node_count": len(nodes),
            "edge_count": len(edges),
        },
    }


def mermaid_id(node_id: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]", "_", node_id)


def render_markdown(graph: dict[str, Any], facts: list[CveFact]) -> str:
    lines: list[str] = []
    lines.append("# CVE Correlation Graph")
    lines.append("")
    lines.append(f"- Generated: `{graph['generated_at']}`")
    lines.append(f"- CVEs: `{graph['stats']['cve_count']}`")
    lines.append(f"- Nodes: `{graph['stats']['node_count']}`")
    lines.append(f"- Edges: `{graph['stats']['edge_count']}`")
    lines.append("")
    lines.append("## High-priority CVEs")
    lines.append("")
    lines.append("| CVE | CVSS | EPSS | KEV | CWE | Product |")
    lines.append("|---|---:|---:|---|---|---|")
    for fact in sorted(facts, key=lambda f: (f.is_kev, f.epss or 0, f.cvss or 0), reverse=True):
        lines.append(
            f"| {fact.cve} | {fact.cvss if fact.cvss is not None else ''} | "
            f"{fact.epss if fact.epss is not None else ''} | {'yes' if fact.is_kev else 'no'} | "
            f"{', '.join(sorted(fact.cwes))} | {', '.join(sorted(fact.products))} |"
        )
    lines.append("")
    lines.append("## Mermaid view")
    lines.append("")
    lines.append("```mermaid")
    lines.append("graph LR")

    # Keep diagram readable: include CVE/CWE/product/KEV/EPSS, omit noisy domains when many.
    wanted_kinds = {"cve", "cwe", "product", "kev", "epss_bucket"}
    node_by_id = {n["id"]: n for n in graph["nodes"]}
    for edge in graph["edges"]:
        src = node_by_id.get(edge["source"])
        dst = node_by_id.get(edge["target"])
        if not src or not dst:
            continue
        if src["kind"] not in wanted_kinds or dst["kind"] not in wanted_kinds:
            continue
        lines.append(
            f'  {mermaid_id(src["id"])}["{src["label"]}"] -- "{edge["relation"]}" --> '
            f'{mermaid_id(dst["id"])}["{dst["label"]}"]'
        )
    lines.append("```")
    lines.append("")
    lines.append("## Replay")
    lines.append("")
    lines.append("```powershell")
    lines.append("python scripts\\ctf-website\\cve_graph.py --from-dir reports\\ctf-website\\cve --out reports\\ctf-website\\cve-graph")
    lines.append("```")
    return "\n".join(lines) + "\n"


def collect_reports(args: argparse.Namespace) -> list[Path]:
    paths: list[Path] = []
    for cve in args.cve or []:
        cve_id = normalize_cve(cve)
        candidate = Path(args.from_dir) / f"{cve_id}.json"
        if not candidate.exists():
            raise FileNotFoundError(f"missing CVE report: {candidate}; run cve_lookup.py first")
        paths.append(candidate)
    if not args.cve:
        paths.extend(sorted(Path(args.from_dir).glob("CVE-*.json")))
    return paths


def main() -> int:
    ap = argparse.ArgumentParser(description="Build a CVE relationship graph from cve_lookup.py reports.")
    ap.add_argument("--cve", action="append", help="CVE id to include; can be repeated. Defaults to all reports in --from-dir.")
    ap.add_argument("--from-dir", default="reports/ctf-website/cve", help="Directory containing CVE-*.json reports.")
    ap.add_argument("--out", default="reports/ctf-website/cve-graph", help="Output directory.")
    args = ap.parse_args()

    report_paths = collect_reports(args)
    if not report_paths:
        raise SystemExit(f"no CVE reports found in {args.from_dir}; run cve_lookup.py first")

    facts = [extract_fact(load_json(path)) for path in report_paths]
    graph = build_graph(facts)

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = out_dir / f"cve_graph_{timestamp}.json"
    md_path = out_dir / f"cve_graph_{timestamp}.md"

    json_path.write_text(json.dumps(graph, ensure_ascii=False, indent=2), encoding="utf-8")
    md_path.write_text(render_markdown(graph, facts), encoding="utf-8")

    print(f"[OK] graph JSON: {json_path}")
    print(f"[OK] graph MD:   {md_path}")
    print(f"[OK] stats: CVEs={graph['stats']['cve_count']} nodes={graph['stats']['node_count']} edges={graph['stats']['edge_count']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
