#!/usr/bin/env python3
"""
Minimal dependency-free HTTP baseline probe for Web CTF targets.

Usage:
  python scripts/ctf-website/http_probe.py http://127.0.0.1:3000/
"""

from __future__ import annotations

import argparse
import json
import ssl
import sys
import time
import urllib.error
import urllib.request


def probe(url: str, timeout: float = 8.0, method: str = "GET") -> dict:
    req = urllib.request.Request(
        url,
        method=method,
        headers={
            "User-Agent": "ReverseLab-CTF-Probe/1.0",
            "Accept": "*/*",
        },
    )
    ctx = ssl.create_default_context()
    start = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(4096)
            elapsed = time.time() - start
            return {
                "ok": True,
                "url": url,
                "final_url": resp.geturl(),
                "status": resp.status,
                "reason": resp.reason,
                "elapsed_ms": round(elapsed * 1000, 2),
                "headers": dict(resp.headers.items()),
                "body_preview_hex": body[:256].hex(),
                "body_preview_text": body[:512].decode("utf-8", errors="replace"),
            }
    except urllib.error.HTTPError as exc:
        body = exc.read(4096)
        return {
            "ok": False,
            "url": url,
            "status": exc.code,
            "reason": exc.reason,
            "headers": dict(exc.headers.items()) if exc.headers else {},
            "body_preview_text": body[:512].decode("utf-8", errors="replace"),
        }
    except Exception as exc:
        return {"ok": False, "url": url, "error": repr(exc)}


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("url")
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--method", default="GET")
    args = parser.parse_args(argv)
    print(json.dumps(probe(args.url, args.timeout, args.method), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
