#!/usr/bin/env python3
"""
Quick single-proxy connectivity and anonymity test.

Usage:
  python tools/proxy_pool/test_proxy.py socks5://127.0.0.1:1080
  python tools/proxy_pool/test_proxy.py http://127.0.0.1:8080 --test-url https://api.ipify.org?format=json
"""

from __future__ import annotations

import argparse
import json
import ssl
import sys
import time
import urllib.request


def _ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def test_proxy(proxy_url: str, test_url: str, timeout: float = 8.0) -> dict:
    """Test a proxy's connectivity, latency, and anonymity."""
    result = {
        "proxy": proxy_url,
        "ok": False,
        "latency_ms": 0,
        "exit_ip": None,
        "anon_level": "unknown",
        "headers": {},
        "error": None,
    }

    # Parse protocol
    parsed = proxy_url.split("://", 1)
    protocol = parsed[0] if len(parsed) == 2 else "http"

    start = time.time()
    try:
        proxy_handler = urllib.request.ProxyHandler({protocol: proxy_url})
        https_handler = urllib.request.HTTPSHandler(context=_ssl_context())
        opener = urllib.request.build_opener(proxy_handler, https_handler)
        req = urllib.request.Request(
            test_url,
            headers={"User-Agent": "ReverseLab-ProxyTest/1.0", "Accept": "*/*"},
        )
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read(4096).decode("utf-8", errors="replace")
            elapsed = time.time() - start
            result["ok"] = True
            result["latency_ms"] = round(elapsed * 1000, 1)
            result["headers"] = dict(resp.headers.items())
            result["body_preview"] = body[:512]

            # Try to extract exit IP from common test endpoints
            try:
                data = json.loads(body)
                result["exit_ip"] = data.get("ip") or data.get("origin", "")
            except json.JSONDecodeError:
                result["exit_ip"] = body.strip()

    except Exception as exc:
        result["error"] = str(exc)

    # Determine anonymity level
    if result["ok"]:
        forwarded_for = result["headers"].get("X-Forwarded-For", "")
        via = result["headers"].get("Via", "")
        if not forwarded_for and not via:
            result["anon_level"] = "elite"
        elif forwarded_for:
            result["anon_level"] = "transparent"
        else:
            result["anon_level"] = "anonymous"

    return result


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Quick proxy connectivity test")
    ap.add_argument("proxy", help="Proxy URL, e.g. socks5://127.0.0.1:1080")
    ap.add_argument("--test-url", default="https://httpbin.org/ip")
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--json-only", action="store_true", help="Suppress human-readable summary")
    args = ap.parse_args(argv)

    result = test_proxy(args.proxy, args.test_url, args.timeout)

    if not args.json_only:
        status = "✓ ALIVE" if result["ok"] else "✗ DEAD"
        print(f"{status}  {result['proxy']}")
        if result["ok"]:
            print(f"  Latency:   {result['latency_ms']} ms")
            print(f"  Exit IP:   {result['exit_ip']}")
            print(f"  Anonymity: {result['anon_level']}")
        else:
            print(f"  Error:     {result['error']}")
    else:
        print(json.dumps(result, ensure_ascii=False, indent=2))

    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
