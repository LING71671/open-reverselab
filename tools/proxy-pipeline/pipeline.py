#!/usr/bin/env python3
"""
Proxy Pipeline — multi-hop proxy chaining and routing.

Usage:
  python tools/proxy-pipeline/pipeline.py forward --listen 9090 --via socks5://127.0.0.1:1080
  python tools/proxy-pipeline/pipeline.py chain --config pipeline_config.json
  python tools/proxy-pipeline/pipeline.py route --config pipeline_config.json --rule rule_burp
"""

from __future__ import annotations

import argparse
import json
import select
import socket
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# ---------------------------------------------------------------------------
# CONNECT tunnel through a chain of proxies
# ---------------------------------------------------------------------------

def _connect_via_proxy(target_host: str, target_port: int, proxy_url: str, timeout: float = 10.0) -> socket.socket:
    """Establish a TCP connection to target through a single HTTP/SOCKS proxy."""
    parsed = proxy_url.split("://", 1)
    protocol = parsed[0] if len(parsed) == 2 else "http"
    hostport = parsed[1] if len(parsed) == 2 else proxy_url
    host, port_str = hostport.rsplit(":", 1) if ":" in hostport else (hostport, "8080")
    port = int(port_str)

    sock = socket.create_connection((host, port), timeout=timeout)

    if protocol in ("http", "https"):
        # HTTP CONNECT tunnel
        connect_req = f"CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}:{target_port}\r\n\r\n"
        sock.sendall(connect_req.encode())
        response = b""
        while b"\r\n\r\n" not in response:
            chunk = sock.recv(4096)
            if not chunk:
                raise ConnectionError("Proxy closed connection during CONNECT")
            response += chunk
        status_line = response.split(b"\r\n")[0].decode(errors="replace")
        status_parts = status_line.split()
        if len(status_parts) < 2 or status_parts[1] != "200":
            raise ConnectionError(f"Proxy CONNECT failed: {status_line}")

    elif protocol in ("socks5", "socks4"):
        # SOCKS5 handshake
        # Greeting
        sock.sendall(b"\x05\x01\x00")  # SOCKS5, 1 method, no auth
        greeting = sock.recv(2)
        if greeting != b"\x05\x00":
            raise ConnectionError(f"SOCKS5 greeting failed: {greeting.hex()}")

        # CONNECT request
        host_bytes = target_host.encode()
        req = b"\x05\x01\x00\x03" + bytes([len(host_bytes)]) + host_bytes + target_port.to_bytes(2, "big")
        sock.sendall(req)
        resp = sock.recv(10)
        if len(resp) < 2 or resp[1] != 0x00:
            raise ConnectionError(f"SOCKS5 connect failed: {resp.hex()}")

    else:
        raise ValueError(f"Unsupported proxy protocol: {protocol}")

    return sock


def connect_chain(target_host: str, target_port: int, hops: list[str], timeout: float = 10.0) -> socket.socket:
    """Connect through a chain of proxies. Only single-hop is currently supported."""
    if not hops:
        return socket.create_connection((target_host, target_port), timeout=timeout)

    if len(hops) >= 2:
        raise NotImplementedError(
            "Multi-hop proxy chaining requires a proper proxy library (e.g., aiohttp, httpx). "
            "Use a single proxy or tools like proxychains for multi-hop."
        )

    return _connect_via_proxy(target_host, target_port, hops[0], timeout)


# ---------------------------------------------------------------------------
# Forward proxy server (single hop)
# ---------------------------------------------------------------------------

def forward_server(listen_host: str, listen_port: int, upstream_proxy: str, timeout: float = 10.0) -> None:
    """Run a simple HTTP forward proxy that routes through an upstream proxy."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((listen_host, listen_port))
    server.listen(5)
    print(f"[proxy-pipeline] listening on {listen_host}:{listen_port} → {upstream_proxy}", file=sys.stderr)

    def handle_client(client_sock: socket.socket) -> None:
        try:
            # Read the first request line to determine the target
            data = client_sock.recv(4096)
            lines = data.split(b"\r\n")
            first_line = lines[0].decode(errors="replace")
            parts = first_line.split()
            if len(parts) < 3:
                client_sock.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                client_sock.close()
                return

            method, target, _ = parts
            if method.upper() == "CONNECT":
                # HTTPS: parse host:port and tunnel
                hostport = target.rsplit(":", 1) if ":" in target else (target, "443")
                target_host, target_port_str = hostport
                target_port = int(target_port_str)

                try:
                    upstream = _connect_via_proxy(target_host, target_port, upstream_proxy, timeout)
                    client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                except Exception as exc:
                    client_sock.sendall(f"HTTP/1.1 502 Bad Gateway\r\n\r\n{exc}".encode())
                    client_sock.close()
                    return

                # Bidirectional relay
                _relay(client_sock, upstream)
            else:
                # HTTP: extract host from headers, forward request
                host = None
                for line in lines[1:]:
                    if line.lower().startswith(b"host:"):
                        host = line.split(b":", 1)[1].strip().decode()
                        break
                if not host:
                    # Try to parse from URL
                    if target.startswith("http://") or target.startswith("https://"):
                        from urllib.parse import urlparse
                        parsed = urlparse(target)
                        host = parsed.netloc
                    else:
                        client_sock.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                        client_sock.close()
                        return

                hostport = host.rsplit(":", 1) if ":" in host else (host, "80")
                target_host, target_port_str = hostport
                target_port = int(target_port_str)

                try:
                    upstream = _connect_via_proxy(target_host, target_port, upstream_proxy, timeout)
                    # Send the original request
                    upstream.sendall(data)
                except Exception as exc:
                    client_sock.sendall(f"HTTP/1.1 502 Bad Gateway\r\n\r\n{exc}".encode())
                    client_sock.close()
                    return

                _relay(client_sock, upstream)

        except Exception as exc:
            print(f"[proxy-pipeline] client error: {exc}", file=sys.stderr)
        finally:
            try:
                client_sock.close()
            except Exception:
                pass

    while True:
        try:
            client, _addr = server.accept()
            t = threading.Thread(target=handle_client, args=(client,), daemon=True)
            t.start()
        except KeyboardInterrupt:
            print("\n[proxy-pipeline] shutting down", file=sys.stderr)
            break

    server.close()


def _relay(a: socket.socket, b: socket.socket) -> None:
    """Bidirectional relay between two sockets."""
    a.setblocking(False)
    b.setblocking(False)
    try:
        while True:
            rlist, _, xlist = select.select([a, b], [], [a, b], 30)
            if not rlist and not xlist:
                break  # timeout
            if xlist:
                break
            for sock in rlist:
                other = b if sock is a else a
                try:
                    data = sock.recv(8192)
                    if not data:
                        return
                    other.sendall(data)
                except (BlockingIOError, ConnectionError, OSError):
                    return
    except Exception:
        pass
    finally:
        try:
            a.close()
        except Exception:
            pass
        try:
            b.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def cmd_forward(args: argparse.Namespace) -> int:
    if not args.via:
        print("[error] need at least one --via proxy URL", file=sys.stderr)
        return 1
    # Use first proxy as the upstream (multi-hop not yet implemented)
    upstream = args.via[0]
    print(f"[proxy-pipeline] forward {args.listen}:{args.port} → {upstream}", file=sys.stderr)
    forward_server(args.listen, args.port, upstream, args.timeout)
    return 0


def cmd_chain(args: argparse.Namespace) -> int:
    config_path = Path(args.config)
    if not config_path.exists():
        print(f"[error] config not found: {config_path}", file=sys.stderr)
        return 1

    cfg = json.loads(config_path.read_text(encoding="utf-8"))
    hops = cfg.get("hops", [])
    enabled_hops = [h for h in hops if h.get("enabled", True)]
    hop_urls = [h["proxy"] for h in enabled_hops]

    print(f"[proxy-pipeline] chain: {' → '.join(hop_urls)}", file=sys.stderr)
    print("[info] multi-hop chaining requires a dedicated proxy library (see README)", file=sys.stderr)

    # Print the configured chain as JSON for external tools to consume
    print(json.dumps({"hops": [{"id": h["id"], "proxy": h["proxy"]} for h in enabled_hops]}, ensure_ascii=False, indent=2))
    return 0


def cmd_route(args: argparse.Namespace) -> int:
    config_path = Path(args.config)
    if not config_path.exists():
        print(f"[error] config not found: {config_path}", file=sys.stderr)
        return 1

    cfg = json.loads(config_path.read_text(encoding="utf-8"))
    rules = cfg.get("rules", [])
    rule = next((r for r in rules if r["id"] == args.rule), None)
    if not rule:
        print(f"[error] rule not found: {args.rule}", file=sys.stderr)
        return 1

    print(f"[proxy-pipeline] route {rule['id']}: {rule.get('comment', '')}", file=sys.stderr)
    listen = rule.get("listen", {})
    host = listen.get("host", "127.0.0.1")
    port = listen.get("port", 9090)

    if rule.get("target") == "pool":
        pool_state = Path(rule.get("pool_state", "tools/proxy_pool/pool_state.json"))
        if not pool_state.exists():
            print("[error] pool state not found; run proxy_pool fetch first", file=sys.stderr)
            return 1
        pool = json.loads(pool_state.read_text(encoding="utf-8"))
        proxies = [p for p in pool.get("proxies", []) if p.get("latency_ms", 0) > 0]
        if not proxies:
            print("[error] no alive proxies in pool", file=sys.stderr)
            return 1
        proxies.sort(key=lambda p: p.get("latency_ms", 99999))
        upstream = proxies[0]["url"]
        print(f"[proxy-pipeline] pool → {upstream}", file=sys.stderr)
    else:
        # Direct hop reference
        hops = cfg.get("hops", [])
        hop = next((h for h in hops if h["id"] == rule["target"]), None)
        if not hop:
            print(f"[error] target hop not found: {rule['target']}", file=sys.stderr)
            return 1
        upstream = hop["proxy"]
        print(f"[proxy-pipeline] hop → {upstream}", file=sys.stderr)

    forward_server(host, port, upstream, args.timeout)
    return 0


def cmd_test(args: argparse.Namespace) -> int:
    """Test connectivity through a chain of proxies to a target."""
    target_host = args.target
    target_port = args.port or 443
    hops = args.via or []

    print(f"[proxy-pipeline] test: {' → '.join(hops)} → {target_host}:{target_port}", file=sys.stderr)

    start = time.time()
    try:
        if not hops:
            sock = socket.create_connection((target_host, target_port), timeout=args.timeout)
        elif len(hops) == 1:
            sock = _connect_via_proxy(target_host, target_port, hops[0], args.timeout)
        else:
            print("[error] multi-hop test not yet supported", file=sys.stderr)
            return 1

        elapsed = round((time.time() - start) * 1000, 1)
        result = {
            "ok": True,
            "target": f"{target_host}:{target_port}",
            "hops": hops,
            "latency_ms": elapsed,
        }
        print(json.dumps(result, ensure_ascii=False, indent=2))
        sock.close()
        return 0
    except Exception as exc:
        elapsed = round((time.time() - start) * 1000, 1)
        result = {
            "ok": False,
            "target": f"{target_host}:{target_port}",
            "hops": hops,
            "latency_ms": elapsed,
            "error": str(exc),
        }
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 1


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="ReverseLab Proxy Pipeline")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("forward", help="Start a local forward proxy → upstream proxy")
    p.add_argument("--listen", default="127.0.0.1")
    p.add_argument("--port", type=int, default=9090)
    p.add_argument("--via", nargs="*", help="Upstream proxy URL(s)")
    p.add_argument("--timeout", type=float, default=10.0)
    p.set_defaults(func=cmd_forward)

    p = sub.add_parser("chain", help="Show the proxy chain from config")
    p.add_argument("--config", default="tools/proxy-pipeline/pipeline_config.json")
    p.set_defaults(func=cmd_chain)

    p = sub.add_parser("route", help="Start a forward proxy using a named routing rule")
    p.add_argument("--config", default="tools/proxy-pipeline/pipeline_config.json")
    p.add_argument("--rule", required=True, help="Rule ID from pipeline config")
    p.add_argument("--timeout", type=float, default=10.0)
    p.set_defaults(func=cmd_route)

    p = sub.add_parser("test", help="Test connectivity through proxy chain to target")
    p.add_argument("target", help="Target hostname or IP")
    p.add_argument("--port", type=int, help="Target port (default: 443)")
    p.add_argument("--via", nargs="*", help="Proxy hops")
    p.add_argument("--timeout", type=float, default=10.0)
    p.set_defaults(func=cmd_test)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
