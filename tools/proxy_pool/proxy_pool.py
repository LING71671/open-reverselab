#!/usr/bin/env python3
"""
Proxy Pool — fetch, validate, and rotate HTTP/SOCKS proxies.

Usage:
  python tools/proxy_pool/proxy_pool.py fetch --sources proxy_sources.json
  python tools/proxy_pool/proxy_pool.py validate --proxy socks5://127.0.0.1:1080
  python tools/proxy_pool/proxy_pool.py list --pool pool_state.json
  python tools/proxy_pool/proxy_pool.py rotate --pool pool_state.json
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any

import ssl

ROOT = Path(__file__).resolve().parents[2]

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class Proxy:
    url: str          # protocol://host:port
    protocol: str = ""  # http, https, socks4, socks5
    host: str = ""
    port: int = 0
    source_id: str = ""
    latency_ms: float = 0.0
    anon_level: str = "unknown"
    country: str = ""
    last_checked: float = 0.0
    failures: int = 0
    last_failure: float = 0.0

    def __post_init__(self):
        if not self.protocol:
            parsed = self.url.split("://", 1)
            if len(parsed) == 2:
                self.protocol = parsed[0]
                hostport = parsed[1]
            else:
                self.protocol = "http"
                hostport = self.url
            if ":" in hostport:
                h, p = hostport.rsplit(":", 1)
                self.host = h
                self.port = int(p)
            else:
                self.host = hostport
                self.port = 8080

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Proxy":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})

    @property
    def is_socks(self) -> bool:
        return self.protocol in ("socks4", "socks5")

    @property
    def alive(self) -> bool:
        return self.latency_ms > 0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _urllib_proxy_handler(proxy: Proxy) -> urllib.request.ProxyHandler:
    """Build a ProxyHandler for urllib that routes through the given proxy."""
    scheme = "socks5" if proxy.protocol == "socks5" else proxy.protocol
    proxy_url = f"{scheme}://{proxy.host}:{proxy.port}"
    return urllib.request.ProxyHandler({proxy.protocol: proxy_url})


# ---------------------------------------------------------------------------
# Source loaders
# ---------------------------------------------------------------------------

def load_sources(config_path: Path) -> list[dict[str, Any]]:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    if config.get("schema") != "reverselab.proxy_sources.v1":
        print(f"[warn] unknown schema: {config.get('schema')}", file=sys.stderr)
    sources = config.get("sources", [])
    enabled = [s for s in sources if s.get("enabled", True)]
    if not enabled:
        print("[warn] no enabled sources found", file=sys.stderr)
    return enabled


def fetch_api_source(source: dict[str, Any]) -> list[Proxy]:
    """Fetch proxies from an API source."""
    proxies: list[Proxy] = []
    url = source["url"]
    fmt = source.get("format", "raw")
    timeout = source.get("timeout_sec", 15.0)

    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "ReverseLab-ProxyPool/1.0", "Accept": "application/json"},
        )
        https_handler = urllib.request.HTTPSHandler(context=_ssl_context())
        opener = urllib.request.build_opener(https_handler)
        with opener.open(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        if fmt == "geonode":
            for item in data.get("data", []):
                proto = (item.get("protocols", ["http"]) or ["http"])[0].lower()
                proxies.append(Proxy(
                    url=f"{proto}://{item['ip']}:{item['port']}",
                    source_id=source["id"],
                    anon_level=item.get("anonymityLevel", "unknown"),
                    country=item.get("country", ""),
                ))
        elif fmt == "proxyscrape":
            for item in data.get("proxies", []):
                proxies.append(Proxy(
                    url=f"{item['protocol']}://{item['ip']}:{item['port']}",
                    source_id=source["id"],
                    anon_level=item.get("anonymityLevel", "unknown"),
                ))
        elif fmt == "json_list":
            for item in data if isinstance(data, list) else data.get("proxies", data.get("data", [])):
                if isinstance(item, str):
                    proxies.append(Proxy(url=item, source_id=source["id"]))
                elif isinstance(item, dict):
                    proxies.append(Proxy(
                        url=item.get("url", item.get("proxy", f"{item.get('host','')}:{item.get('port','')}")),
                        source_id=source["id"],
                    ))
        else:
            # raw: parse as text
            raw = data if isinstance(data, str) else json.dumps(data)
            for line in raw.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    proxies.append(Proxy(url=line, source_id=source["id"]))
    except Exception as exc:
        print(f"[warn] source {source['id']}: {exc}", file=sys.stderr)

    return proxies


def fetch_file_source(source: dict[str, Any]) -> list[Proxy]:
    """Load proxies from a local file."""
    proxies: list[Proxy] = []
    path = ROOT / source["path"]
    if not path.exists():
        print(f"[warn] file not found: {path}", file=sys.stderr)
        return proxies

    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            proxies.append(Proxy(url=line, source_id=source["id"]))
    return proxies


def fetch_inline_source(source: dict[str, Any]) -> list[Proxy]:
    """Load proxies from inline config."""
    return [Proxy(url=p, source_id=source["id"]) for p in source.get("proxies", [])]


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_proxy(proxy: Proxy, test_url: str, timeout: float = 8.0) -> Proxy:
    """Test a single proxy against test_url. Updates latency_ms on success."""
    start = time.time()
    try:
        proxy_handler = _urllib_proxy_handler(proxy)
        https_handler = urllib.request.HTTPSHandler(context=_ssl_context())
        opener = urllib.request.build_opener(proxy_handler, https_handler)
        req = urllib.request.Request(
            test_url,
            headers={"User-Agent": "ReverseLab-ProxyPool/1.0", "Accept": "*/*"},
        )
        with opener.open(req, timeout=timeout) as resp:
            resp.read(1024)
            proxy.latency_ms = round((time.time() - start) * 1000, 1)
            proxy.last_checked = time.time()
            proxy.failures = 0
    except Exception:
        proxy.latency_ms = 0
        proxy.failures += 1
        proxy.last_failure = time.time()
    return proxy


def validate_batch(
    proxies: list[Proxy], test_url: str, timeout: float = 8.0, concurrency: int = 10
) -> list[Proxy]:
    """Validate a batch of proxies concurrently."""
    results: list[Proxy] = []
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = {pool.submit(validate_proxy, p, test_url, timeout): p for p in proxies}
        for fut in as_completed(futures):
            results.append(fut.result())
    results.sort(key=lambda p: p.latency_ms if p.latency_ms > 0 else float("inf"))
    return results


# ---------------------------------------------------------------------------
# Pool state
# ---------------------------------------------------------------------------

def load_pool(pool_path: Path) -> dict[str, Any]:
    if pool_path.exists():
        return json.loads(pool_path.read_text(encoding="utf-8"))
    return {"schema": "reverselab.proxy_pool_state.v1", "proxies": [], "cursor": 0, "updated": 0.0}


def save_pool(pool_path: Path, pool: dict[str, Any]) -> None:
    pool["updated"] = time.time()
    pool_path.parent.mkdir(parents=True, exist_ok=True)
    pool_path.write_text(json.dumps(pool, ensure_ascii=False, indent=2), encoding="utf-8")


def _proxies_from_pool(pool: dict[str, Any]) -> list[Proxy]:
    """Deserialize all stored proxy dicts back to Proxy objects, sorted by latency."""
    proxies = [Proxy.from_dict(d) for d in pool.get("proxies", [])]
    # Evict dead entries (3+ failures and last failure > 5 min ago)
    now = time.time()
    cleaned: list[Proxy] = []
    for p in proxies:
        if p.failures >= 3 and (now - p.last_failure) > 300:
            continue  # evict
        cleaned.append(p)
    pool["proxies"] = [asdict(p) for p in cleaned]
    return cleaned


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------

def cmd_fetch(args: argparse.Namespace) -> int:
    config_path = Path(args.sources)
    if not config_path.exists():
        print(f"[error] sources config not found: {config_path}", file=sys.stderr)
        return 1

    sources = load_sources(config_path)
    all_proxies: list[Proxy] = []

    for src in sources:
        stype = src.get("type", "api")
        if stype == "api":
            all_proxies.extend(fetch_api_source(src))
        elif stype == "file":
            all_proxies.extend(fetch_file_source(src))
        elif stype == "inline":
            all_proxies.extend(fetch_inline_source(src))

    print(f"[info] fetched {len(all_proxies)} proxies from {len(sources)} source(s)", file=sys.stderr)

    if args.validate:
        test_url = json.loads(config_path.read_text(encoding="utf-8")).get("test_url", "https://httpbin.org/ip")
        all_proxies = validate_batch(all_proxies, test_url, args.timeout, args.concurrency)
        alive = [p for p in all_proxies if p.alive]
        print(f"[info] {len(alive)}/{len(all_proxies)} alive", file=sys.stderr)
        all_proxies = alive

    if args.limit > 0:
        all_proxies = all_proxies[: args.limit]

    # Save to pool state
    pool = load_pool(Path(args.pool))
    existing_urls = {p["url"] for p in pool.get("proxies", [])}
    new_count = 0
    for p in all_proxies:
        if p.url not in existing_urls:
            pool["proxies"].append(asdict(p))
            existing_urls.add(p.url)
            new_count += 1
    save_pool(Path(args.pool), pool)
    print(f"[info] added {new_count} new proxies to pool", file=sys.stderr)

    # Print JSON output
    print(json.dumps([asdict(p) for p in all_proxies], ensure_ascii=False, indent=2))
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    pool = load_pool(Path(args.pool))
    proxies = _proxies_from_pool(pool)
    if args.alive:
        proxies = [p for p in proxies if p.alive]
    if args.protocol:
        proxies = [p for p in proxies if p.protocol == args.protocol]
    if args.limit > 0:
        proxies = proxies[: args.limit]
    print(json.dumps([asdict(p) for p in proxies], ensure_ascii=False, indent=2))
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    if args.proxy:
        proxies = [Proxy(url=p) for p in args.proxy]
    elif args.pool:
        pool = load_pool(Path(args.pool))
        proxies = _proxies_from_pool(pool)
        if args.limit > 0:
            proxies = proxies[: args.limit]
    else:
        print("[error] need --proxy or --pool", file=sys.stderr)
        return 1

    test_url = args.test_url or "https://httpbin.org/ip"
    results = validate_batch(proxies, test_url, args.timeout, args.concurrency)
    alive = [p for p in results if p.alive]
    dead = [p for p in results if not p.alive]
    print(f"[info] {len(alive)} alive, {len(dead)} dead", file=sys.stderr)

    # Update pool if one was loaded
    if args.pool:
        pool = load_pool(Path(args.pool))
        url_map = {p.url: p for p in results}
        for entry in pool["proxies"]:
            if entry["url"] in url_map:
                updated = url_map[entry["url"]]
                entry["latency_ms"] = updated.latency_ms
                entry["last_checked"] = updated.last_checked
                entry["failures"] = updated.failures
                entry["last_failure"] = updated.last_failure
        save_pool(Path(args.pool), pool)

    print(json.dumps([asdict(p) for p in results], ensure_ascii=False, indent=2))
    return 0


def cmd_rotate(args: argparse.Namespace) -> int:
    pool = load_pool(Path(args.pool))
    proxies = _proxies_from_pool(pool)
    alive = [p for p in proxies if p.alive]
    if args.protocol:
        alive = [p for p in alive if p.protocol == args.protocol]

    if not alive:
        print("[error] no alive proxies in pool", file=sys.stderr)
        return 1

    strategy = args.strategy or json.loads(
        (ROOT / "tools/proxy_pool/proxy_sources.example.json").read_text(encoding="utf-8")
    ).get("pool", {}).get("strategy", "round_robin")

    if strategy == "random":
        chosen = random.choice(alive)
    elif strategy == "lowest_latency":
        alive.sort(key=lambda p: p.latency_ms)
        chosen = alive[0]
    else:
        # round_robin
        cursor = pool.get("cursor", 0) % len(alive)
        chosen = alive[cursor]
        pool["cursor"] = (cursor + 1) % len(alive)
        save_pool(Path(args.pool), pool)

    print(json.dumps(asdict(chosen), ensure_ascii=False, indent=2))
    return 0


def cmd_stats(args: argparse.Namespace) -> int:
    pool = load_pool(Path(args.pool))
    proxies = _proxies_from_pool(pool)
    alive = [p for p in proxies if p.alive]
    dead = [p for p in proxies if not p.alive]
    stats = {
        "total": len(proxies),
        "alive": len(alive),
        "dead": len(dead),
        "avg_latency_ms": round(sum(p.latency_ms for p in alive) / len(alive), 1) if alive else 0,
        "protocols": {},
        "by_source": {},
        "pool_cursor": pool.get("cursor", 0),
        "last_updated": pool.get("updated", 0),
    }
    for p in proxies:
        stats["protocols"][p.protocol] = stats["protocols"].get(p.protocol, 0) + 1
        stats["by_source"][p.source_id] = stats["by_source"].get(p.source_id, 0) + 1
    print(json.dumps(stats, ensure_ascii=False, indent=2))
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="ReverseLab Proxy Pool")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("fetch", help="Fetch proxies from configured sources")
    p.add_argument("--sources", default="tools/proxy_pool/proxy_sources.json")
    p.add_argument("--pool", default="tools/proxy_pool/pool_state.json")
    p.add_argument("--validate", action="store_true")
    p.add_argument("--timeout", type=float, default=8.0)
    p.add_argument("--concurrency", type=int, default=10)
    p.add_argument("--limit", type=int, default=50)
    p.set_defaults(func=cmd_fetch)

    p = sub.add_parser("list", help="List proxies in pool")
    p.add_argument("--pool", default="tools/proxy_pool/pool_state.json")
    p.add_argument("--alive", action="store_true")
    p.add_argument("--protocol")
    p.add_argument("--limit", type=int, default=0)
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("validate", help="Validate proxies")
    p.add_argument("--proxy", nargs="*")
    p.add_argument("--pool")
    p.add_argument("--test-url", default="https://httpbin.org/ip")
    p.add_argument("--timeout", type=float, default=8.0)
    p.add_argument("--concurrency", type=int, default=10)
    p.add_argument("--limit", type=int, default=0)
    p.set_defaults(func=cmd_validate)

    p = sub.add_parser("rotate", help="Get next proxy from pool")
    p.add_argument("--pool", default="tools/proxy_pool/pool_state.json")
    p.add_argument("--strategy", choices=["round_robin", "random", "lowest_latency"])
    p.add_argument("--protocol")
    p.set_defaults(func=cmd_rotate)

    p = sub.add_parser("stats", help="Show pool statistics")
    p.add_argument("--pool", default="tools/proxy_pool/pool_state.json")
    p.set_defaults(func=cmd_stats)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
