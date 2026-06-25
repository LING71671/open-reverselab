#!/usr/bin/env python3
"""
ReverseLab multi-CVE chain planner.

Input:
  - JSON reports produced by cve_lookup.py under reports/ctf-website/cve/

Output:
  - chain candidates that combine CVEs by exploit primitive, product overlap,
    CWE similarity, EPSS/KEV priority, and CTF-style exploitation stages.

This is not a magic exploit generator. It is an AI-readable chain model that
turns many CVEs into a prioritized validation plan:

  fingerprint -> candidate CVEs -> primitive graph -> chain hypothesis -> tests
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)


PRIMITIVE_RULES: list[tuple[str, int, list[str], list[str]]] = [
    ("rce", 100, ["remote code execution", "execute arbitrary code", "command injection", "code injection", "os command", "template injection", "deserialization"], ["CWE-78", "CWE-94", "CWE-95", "CWE-502"]),
    ("auth_bypass", 80, ["authentication bypass", "auth bypass", "improper authentication", "authorization bypass", "access control", "privilege escalation"], ["CWE-287", "CWE-288", "CWE-306", "CWE-862", "CWE-863", "CWE-269"]),
    ("ssrf", 75, ["server-side request forgery", "ssrf"], ["CWE-918"]),
    ("file_read", 70, ["path traversal", "directory traversal", "arbitrary file read", "local file inclusion", "lfi", "xxe", "external entity"], ["CWE-22", "CWE-23", "CWE-35", "CWE-611", "CWE-827"]),
    ("file_write_upload", 70, ["arbitrary file write", "file upload", "unrestricted upload", "write arbitrary file", "zip slip"], ["CWE-434", "CWE-73", "CWE-59"]),
    ("sqli", 65, ["sql injection", "sqli"], ["CWE-89"]),
    ("nosqli", 60, ["nosql injection", "mongodb injection"], ["CWE-943"]),
    ("xss", 55, ["cross-site scripting", "xss", "stored script", "reflected script"], ["CWE-79", "CWE-80"]),
    ("csrf", 40, ["cross-site request forgery", "csrf"], ["CWE-352"]),
    ("info_leak", 45, ["information disclosure", "sensitive information", "exposure of", "leak", "disclose", "read sensitive"], ["CWE-200", "CWE-209", "CWE-532"]),
    ("cache_poison", 50, ["cache poisoning", "request smuggling", "http request smuggling", "web cache deception"], ["CWE-444"]),
    ("prototype_pollution", 60, ["prototype pollution"], ["CWE-1321"]),
    ("crypto_weakness", 35, ["weak cryptography", "hard-coded key", "jwt", "signature bypass", "algorithm confusion"], ["CWE-321", "CWE-347", "CWE-327"]),
]


CHAIN_PATTERNS: list[tuple[str, list[str], str]] = [
    ("Auth bypass -> RCE", ["auth_bypass", "rce"], "先绕过鉴权/权限边界，再触发需要登录或高权限的 RCE。"),
    ("Info leak -> Auth bypass/RCE", ["info_leak", "auth_bypass", "rce"], "先泄露 secret/session/config，再进入高危漏洞路径。"),
    ("File read -> Secret -> RCE", ["file_read", "rce"], "任意文件读拿配置、密钥、凭据，再打 RCE 或管理面。"),
    ("SSRF -> Internal service -> RCE", ["ssrf", "rce"], "SSRF 打内网管理面/metadata/本地服务，再触发二阶段。"),
    ("XSS -> Admin action -> RCE", ["xss", "rce"], "利用 admin bot / 管理员上下文，触发后台 RCE 或配置写入。"),
    ("Upload/write -> Webshell/RCE", ["file_write_upload", "rce"], "上传/写文件落脚本或覆盖配置，再执行。"),
    ("SQLi -> Credential/session -> RCE", ["sqli", "auth_bypass", "rce"], "SQLi 枚举凭据/session，再进入后台或 RCE。"),
    ("Prototype pollution -> Template/child_process RCE", ["prototype_pollution", "rce"], "污染对象影响模板/child_process/配置，升级到 RCE。"),
    ("Request smuggling/cache -> Auth confusion -> RCE", ["cache_poison", "auth_bypass", "rce"], "协议层混淆导致身份/路由错配，再进入高危能力。"),
]


@dataclass
class CveNode:
    cve: str
    description: str
    cvss: float | None = None
    severity: str = ""
    epss: float | None = None
    kev: bool = False
    cwes: set[str] = field(default_factory=set)
    products: set[str] = field(default_factory=set)
    vendors: set[str] = field(default_factory=set)
    references: list[str] = field(default_factory=list)
    primitives: set[str] = field(default_factory=set)


def normalize_cve(value: str) -> str:
    value = value.upper()
    if not CVE_RE.match(value):
        raise ValueError(f"invalid CVE id: {value}")
    return value


def parse_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def first_cvss(summary: dict[str, Any]) -> tuple[float | None, str]:
    cvss = summary.get("cvss") or {}
    for metric_name in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metrics = cvss.get(metric_name) or []
        if not metrics:
            continue
        data = metrics[0].get("cvssData") or {}
        return parse_float(data.get("baseScore")), str(data.get("baseSeverity") or metrics[0].get("baseSeverity") or "")
    return None, ""


def parse_cpe(criteria: str) -> tuple[str | None, str | None]:
    parts = criteria.split(":")
    if len(parts) >= 5 and parts[0] == "cpe" and parts[1] == "2.3":
        return parts[3].replace("_", " ").lower(), parts[4].replace("_", " ").lower()
    return None, None


def walk_cpe(node: Any) -> list[str]:
    out: list[str] = []
    if isinstance(node, dict):
        for m in node.get("cpeMatch") or []:
            if m.get("criteria") and m.get("vulnerable", True):
                out.append(m["criteria"])
        for child in node.get("nodes") or []:
            out.extend(walk_cpe(child))
    elif isinstance(node, list):
        for item in node:
            out.extend(walk_cpe(item))
    return out


def classify_primitives(description: str, cwes: set[str]) -> set[str]:
    text = description.lower()
    found: set[str] = set()
    for name, _weight, phrases, cwe_rules in PRIMITIVE_RULES:
        if any(p in text for p in phrases) or any(cwe in cwes for cwe in cwe_rules):
            found.add(name)
    if not found:
        found.add("unknown")
    return found


def extract_node(report: dict[str, Any]) -> CveNode:
    summary = report.get("summary") or {}
    raw = report.get("raw") or {}
    cve = normalize_cve(summary.get("cve") or "")
    node = CveNode(cve=cve, description=(summary.get("description") or "").strip())
    node.cvss, node.severity = first_cvss(summary)
    epss = summary.get("epss") or {}
    node.epss = parse_float(epss.get("epss"))
    node.kev = bool((summary.get("kev") or {}).get("matches")) or bool((summary.get("triage") or {}).get("isKev"))

    for weakness in summary.get("weaknesses") or []:
        for desc in weakness.get("description") or []:
            val = desc.get("value")
            if isinstance(val, str) and val.startswith("CWE-"):
                node.cwes.add(val)

    for ref in summary.get("references") or []:
        url = ref.get("url")
        if url:
            node.references.append(url)

    kev = summary.get("kev") or {}
    for match in kev.get("matches") or []:
        if match.get("vendorProject"):
            node.vendors.add(str(match["vendorProject"]).lower())
        if match.get("product"):
            node.products.add(str(match["product"]).lower())
        for cwe in match.get("cwes") or []:
            if str(cwe).startswith("CWE-"):
                node.cwes.add(str(cwe))

    for vuln in (((raw.get("nvd") or {}).get("vulnerabilities")) or []):
        cve_obj = vuln.get("cve") or {}
        for conf in cve_obj.get("configurations") or []:
            for criteria in walk_cpe(conf):
                vendor, product = parse_cpe(criteria)
                if vendor:
                    node.vendors.add(vendor)
                if product:
                    node.products.add(product)

    node.primitives = classify_primitives(node.description, node.cwes)
    return node


def primitive_weight(name: str) -> int:
    for primitive, weight, _phrases, _cwes in PRIMITIVE_RULES:
        if primitive == name:
            return weight
    return 10


def node_priority(node: CveNode) -> float:
    score = 0.0
    if node.cvss is not None:
        score += node.cvss * 7
    if node.epss is not None:
        score += node.epss * 25
    if node.kev:
        score += 25
    score += max((primitive_weight(p) for p in node.primitives), default=0) / 5
    return score


def relation_bonus(a: CveNode, b: CveNode) -> tuple[float, list[str]]:
    bonus = 0.0
    reasons: list[str] = []
    if a.products & b.products:
        bonus += 25
        reasons.append("same_product:" + ",".join(sorted(a.products & b.products)))
    if a.vendors & b.vendors:
        bonus += 10
        reasons.append("same_vendor:" + ",".join(sorted(a.vendors & b.vendors)))
    if a.cwes & b.cwes:
        bonus += 8
        reasons.append("same_cwe:" + ",".join(sorted(a.cwes & b.cwes)))
    domains_a = {urlparse(u).netloc.lower() for u in a.references if u}
    domains_b = {urlparse(u).netloc.lower() for u in b.references if u}
    shared_domains = domains_a & domains_b
    if shared_domains:
        bonus += 5
        reasons.append("same_reference_domain:" + ",".join(sorted(shared_domains)))
    return bonus, reasons


def covers_pattern(nodes: list[CveNode], primitives: list[str]) -> bool:
    available = set().union(*(n.primitives for n in nodes))
    return all(p in available for p in primitives)


def build_chain_candidates(nodes: list[CveNode], max_len: int = 3) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    sorted_nodes = sorted(nodes, key=node_priority, reverse=True)

    # Single-node candidates are still useful for RCE/KEV CVEs.
    for n in sorted_nodes:
        candidates.append({
            "name": f"Single high-impact primitive: {n.cve}",
            "cves": [n.cve],
            "primitives": sorted(n.primitives),
            "score": round(node_priority(n), 2),
            "reasons": ["single_node", f"cvss={n.cvss}", f"epss={n.epss}", f"kev={n.kev}"],
            "validation_steps": validation_steps([n]),
        })

    # Pair and triple candidates.
    for i, a in enumerate(sorted_nodes):
        for b in sorted_nodes[i + 1:]:
            group = [a, b]
            add_candidate_if_pattern(candidates, group)
            if max_len >= 3:
                for c in sorted_nodes:
                    if c.cve in {a.cve, b.cve}:
                        continue
                    add_candidate_if_pattern(candidates, [a, b, c])

    # Deduplicate by ordered CVE set + pattern name.
    seen: set[tuple[str, tuple[str, ...]]] = set()
    unique: list[dict[str, Any]] = []
    for cand in sorted(candidates, key=lambda x: x["score"], reverse=True):
        key = (cand["name"], tuple(sorted(cand["cves"])))
        if key in seen:
            continue
        seen.add(key)
        unique.append(cand)
    return unique


def add_candidate_if_pattern(candidates: list[dict[str, Any]], group: list[CveNode]) -> None:
    for pattern_name, primitives, description in CHAIN_PATTERNS:
        if not covers_pattern(group, primitives):
            continue
        ordered_group = order_group_for_pattern(group, primitives)
        score = sum(node_priority(n) for n in ordered_group)
        reasons = [description, "pattern:" + " -> ".join(primitives)]
        for i, a in enumerate(ordered_group):
            for b in ordered_group[i + 1:]:
                bonus, rel_reasons = relation_bonus(a, b)
                score += bonus
                reasons.extend(rel_reasons)
        candidates.append({
            "name": pattern_name,
            "cves": [n.cve for n in ordered_group],
            "primitives": sorted(set().union(*(n.primitives for n in ordered_group))),
            "score": round(score, 2),
            "reasons": sorted(set(reasons)),
            "validation_steps": validation_steps(ordered_group, required_primitives=primitives),
        })


def order_group_for_pattern(group: list[CveNode], primitives: list[str]) -> list[CveNode]:
    """Order CVEs by the intended validation primitive sequence.

    A single CVE may cover multiple primitives. Keep each CVE once and append
    any extra CVEs by priority at the end.
    """
    remaining = list(group)
    ordered: list[CveNode] = []
    for primitive in primitives:
        candidates = [n for n in remaining if primitive in n.primitives]
        if not candidates:
            continue
        picked = max(candidates, key=node_priority)
        ordered.append(picked)
        remaining.remove(picked)
    return ordered


def validation_steps(nodes: list[CveNode], required_primitives: list[str] | None = None) -> list[str]:
    primitive_set = set(required_primitives or []).union(*(n.primitives for n in nodes))
    steps = [
        "确认目标真实产品/版本/插件/模块与 CVE affected range 匹配。",
        "确认暴露路由、认证状态、默认配置与 CVE 前置条件匹配。",
    ]
    if "info_leak" in primitive_set:
        steps.append("验证信息泄露：配置、secret、token、路径、版本、内部地址。")
    if "file_read" in primitive_set:
        steps.append("验证任意文件读/LFI/XXE：优先读取配置、环境变量、密钥、源码。")
    if "ssrf" in primitive_set:
        steps.append("验证 SSRF：DNS、HTTP、内网 IP、metadata、redirect、scheme 支持。")
    if "auth_bypass" in primitive_set:
        steps.append("验证鉴权/越权：低权限到高权限、session/role/tenant 边界。")
    if "xss" in primitive_set:
        steps.append("验证 XSS/admin bot：cookie、localStorage、CSRF token、后台动作。")
    if "sqli" in primitive_set or "nosqli" in primitive_set:
        steps.append("验证数据库注入：布尔/时间/错误/回显信号，先证伪再自动化。")
    if "file_write_upload" in primitive_set:
        steps.append("验证文件写/上传：扩展名、MIME、路径穿越、解析链、覆盖配置。")
    if "rce" in primitive_set:
        steps.append("验证 RCE：先无害命令/时间延迟/回显，再读取 flag 或落地最小 proof。")
    steps.append("每一步记录 request/response、命令、输出路径，失败后回退到前置假设。")
    return steps


def load_reports(paths: list[Path]) -> list[CveNode]:
    nodes: list[CveNode] = []
    for path in paths:
        data = json.loads(path.read_text(encoding="utf-8"))
        nodes.append(extract_node(data))
    return nodes


def collect_paths(args: argparse.Namespace) -> list[Path]:
    base = Path(args.from_dir)
    if args.cve:
        paths = []
        for cve in args.cve:
            cve_id = normalize_cve(cve)
            p = base / f"{cve_id}.json"
            if not p.exists():
                raise FileNotFoundError(f"missing report for {cve_id}: {p}; run cve_lookup.py first")
            paths.append(p)
        return paths
    return sorted(base.glob("CVE-*.json"))


def render_md(nodes: list[CveNode], candidates: list[dict[str, Any]], generated_at: str) -> str:
    lines: list[str] = []
    lines.append("# Multi-CVE Chain Plan")
    lines.append("")
    lines.append(f"- Generated: `{generated_at}`")
    lines.append(f"- CVEs: `{len(nodes)}`")
    lines.append(f"- Candidates: `{len(candidates)}`")
    lines.append("")
    lines.append("## CVE Primitive Matrix")
    lines.append("")
    lines.append("| CVE | Product | CWE | CVSS | EPSS | KEV | Primitives |")
    lines.append("|---|---|---|---:|---:|---|---|")
    for n in sorted(nodes, key=node_priority, reverse=True):
        lines.append(
            f"| {n.cve} | {', '.join(sorted(n.products))} | {', '.join(sorted(n.cwes))} | "
            f"{n.cvss if n.cvss is not None else ''} | {n.epss if n.epss is not None else ''} | "
            f"{'yes' if n.kev else 'no'} | {', '.join(sorted(n.primitives))} |"
        )
    lines.append("")
    lines.append("## Top Chain Candidates")
    lines.append("")
    for idx, cand in enumerate(candidates[:20], 1):
        lines.append(f"### {idx}. {cand['name']} — score `{cand['score']}`")
        lines.append("")
        lines.append(f"- CVEs: `{', '.join(cand['cves'])}`")
        lines.append(f"- Primitives: `{', '.join(cand['primitives'])}`")
        lines.append("- Reasons:")
        for reason in cand["reasons"][:12]:
            lines.append(f"  - {reason}")
        lines.append("- Validation:")
        for step in cand["validation_steps"]:
            lines.append(f"  - [ ] {step}")
        lines.append("")
    lines.append("## Mermaid")
    lines.append("")
    lines.append("```mermaid")
    lines.append("graph LR")
    for cand in candidates[:8]:
        prev = None
        cid = re.sub(r"[^A-Za-z0-9_]", "_", cand["name"])[:48]
        lines.append(f'  subgraph {cid}["{cand["name"]}"]')
        for cve in cand["cves"]:
            node_id = re.sub(r"[^A-Za-z0-9_]", "_", cve)
            lines.append(f'    {node_id}["{cve}"]')
            if prev:
                lines.append(f"    {prev} --> {node_id}")
            prev = node_id
        lines.append("  end")
    lines.append("```")
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description="Build multi-CVE CTF chain candidates from cve_lookup reports.")
    ap.add_argument("--from-dir", default="reports/ctf-website/cve", help="Directory containing CVE-*.json reports.")
    ap.add_argument("--cve", action="append", help="Limit to a CVE id; can repeat.")
    ap.add_argument("--out", default="reports/ctf-website/cve-chain", help="Output directory.")
    ap.add_argument("--max-len", type=int, default=3, choices=(1, 2, 3), help="Maximum CVE chain length.")
    args = ap.parse_args()

    paths = collect_paths(args)
    if not paths:
        raise SystemExit(f"no CVE reports found in {args.from_dir}; run cve_lookup.py first")
    nodes = load_reports(paths)
    candidates = build_chain_candidates(nodes, max_len=args.max_len)

    generated_at = datetime.now(timezone.utc).isoformat()
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = out_dir / f"cve_chain_{stamp}.json"
    md_path = out_dir / f"cve_chain_{stamp}.md"

    payload = {
        "generated_at": generated_at,
        "source_reports": [str(p) for p in paths],
        "nodes": [
            {
                "cve": n.cve,
                "cvss": n.cvss,
                "severity": n.severity,
                "epss": n.epss,
                "kev": n.kev,
                "cwes": sorted(n.cwes),
                "products": sorted(n.products),
                "vendors": sorted(n.vendors),
                "primitives": sorted(n.primitives),
                "priority": round(node_priority(n), 2),
            }
            for n in nodes
        ],
        "candidates": candidates,
    }
    json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    md_path.write_text(render_md(nodes, candidates, generated_at), encoding="utf-8")

    print(f"[OK] chain JSON: {json_path}")
    print(f"[OK] chain MD:   {md_path}")
    print(f"[OK] candidates: {len(candidates)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
