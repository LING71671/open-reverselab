#!/usr/bin/env python3
"""
MITM Proxy Capture — 自动化抓包/改包/发包工具。

基于 mitmproxy 12.x，提供:
  - capture:    启动透明代理，自动保存全量 HTTP/HTTPS flow
  - modify:     启动代理 + 自定义 Python addon 脚本实时改包
  - replay:     从保存的 flow 文件中重放请求
  - craft:      从 JSON 模板构造并发送自定义 HTTP 请求

Usage:
  python tools/mitmproxy_capture/mitmproxy_capture.py capture -p 8080 -o flows.json
  python tools/mitmproxy_capture/mitmproxy_capture.py modify -r rules.py -p 8080
  python tools/mitmproxy_capture/mitmproxy_capture.py replay -f flows.json -t https://target.com
  python tools/mitmproxy_capture/mitmproxy_capture.py craft -d @request.json
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

ADDON_TEMPLATE = r'''
"""Auto-generated capture addon — do not hand-edit."""
from mitmproxy import http, ctx
import json, time, os

SAVE_PATH = {save_path!r}
FILTER_HOST = {filter_host!r}
COLLECT_BODY = {collect_body!r}
MAX_BODY = {max_body}

flows: list[dict] = []

def _trim(body: bytes) -> str:
    try:
        s = body.decode("utf-8", errors="replace")
    except Exception:
        s = repr(body)
    return s[:MAX_BODY] if len(s) > MAX_BODY else s

def response(flow: http.HTTPFlow) -> None:
    if FILTER_HOST and FILTER_HOST not in flow.request.pretty_host:
        return
    entry = dict(
        id=flow.id,
        timestamp=flow.request.timestamp_start,
        method=flow.request.method,
        url=flow.request.pretty_url,
        host=flow.request.pretty_host,
        port=flow.request.port,
        path=flow.request.path,
        request_headers=dict(flow.request.headers),
        response_headers=dict(flow.response.headers) if flow.response else None,
        status_code=flow.response.status_code if flow.response else None,
        request_body=_trim(flow.request.content or b""),
        response_body=_trim(flow.response.content or b"") if flow.response else "",
        duration_ms=(flow.response.timestamp_end - flow.request.timestamp_start) * 1000 if flow.response and flow.response.timestamp_end else None,
    )
    flows.append(entry)

def done() -> None:
    os.makedirs(os.path.dirname(SAVE_PATH) or ".", exist_ok=True)
    with open(SAVE_PATH, "w", encoding="utf-8") as f:
        json.dump(flows, f, ensure_ascii=False, indent=2)
    ctx.log.info(f"[capture] saved {len(flows)} flow(s) -> {SAVE_PATH}")
'''

REPLAY_ADDON = r'''
"""Auto-generated replay addon — do not hand-edit."""
from mitmproxy import http, ctx
import json

FLOWS = {flows_json}
TARGET = {target!r}
idx = [-1]

def request(flow: http.HTTPFlow) -> None:
    idx[0] += 1
    if idx[0] >= len(FLOWS):
        ctx.log.info("[replay] all flows done, stopping")
        import asyncio
        asyncio.get_event_loop().call_soon(lambda: None)
        return

    src = FLOWS[idx[0]]
    target = TARGET or src.get("host", "")
    flow.request.method = src.get("method", "GET")
    flow.request.scheme = "https"
    flow.request.host = target
    flow.request.port = 443
    flow.request.path = src.get("path", "/")
    for k, v in (src.get("request_headers") or {{}}).items():
        if k.lower() not in ("host", "content-length"):
            flow.request.headers[k] = v
    if src.get("request_body"):
        flow.request.content = src["request_body"].encode("utf-8", errors="replace")
    ctx.log.info(f"[replay] {{idx[0]+1}}/{{len(FLOWS)}}: {{flow.request.method}} {{flow.request.pretty_url}}")

def response(flow: http.HTTPFlow) -> None:
    ctx.log.info(f"[replay] <- {{flow.response.status_code if flow.response else 'ERR'}} {{flow.request.pretty_url}}")
'''

MODIFY_BASE_ADDON = r'''
"""基础改包 addon — 用户可通过 --rule 覆盖或扩展。"""

def request(flow):
    """在请求发出前调用。修改 flow.request 实现改包。"""
    # 示例: 修改 User-Agent
    # flow.request.headers["User-Agent"] = "CustomAgent/1.0"
    pass

def response(flow):
    """在收到响应后、返回客户端前调用。修改 flow.response 实现改包。"""
    # 示例: 替换响应体中的敏感词
    # if flow.response and flow.response.content:
    #     flow.response.content = flow.response.content.replace(b"original", b"modified")
    pass
'''


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run_mitmdump(script_path: str, port: int, timeout: float | None = None) -> int:
    """Run mitmdump with a Python addon script. Returns exit code."""
    cmd = [
        "mitmdump",
        "--listen-port", str(port),
        "--set", "block_global=false",
        "--scripts", script_path,
        "--quiet",
    ]
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"

    proc = subprocess.Popen(
        cmd,
        cwd=str(ROOT),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    try:
        if timeout:
            stdout, stderr = proc.communicate(timeout=timeout)
        else:
            stdout, stderr = proc.communicate()
    except subprocess.TimeoutExpired:
        proc.send_signal(signal.SIGINT)
        try:
            stdout, stderr = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
    except KeyboardInterrupt:
        proc.send_signal(signal.SIGINT)
        try:
            stdout, stderr = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()

    if stdout:
        for line in stdout.splitlines():
            line = line.strip()
            if line:
                print(f"[mitmdump] {line}", file=sys.stderr)
    if stderr:
        for line in stderr.splitlines():
            line = line.strip()
            if line and not line.startswith("["):
                print(f"[mitmdump] {line}", file=sys.stderr)

    return proc.returncode if proc.returncode is not None else 0


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------

def cmd_capture(args: argparse.Namespace) -> int:
    """抓包: 启动代理并自动保存所有 flow 到 JSON 文件。"""
    out_path = Path(args.output)
    if out_path.parent != Path("."):
        out_path.parent.mkdir(parents=True, exist_ok=True)

    filter_host = args.host or ""
    addon_code = ADDON_TEMPLATE.format(
        save_path=str(out_path.resolve()),
        filter_host=filter_host,
        collect_body=not args.no_body,
        max_body=args.max_body,
    )

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".py", delete=False, encoding="utf-8", prefix="rcap_"
    ) as f:
        f.write(addon_code)
        addon_path = f.name

    print(f"[capture] proxy on 0.0.0.0:{args.port}", file=sys.stderr)
    print(f"[capture] filter host: {filter_host or '(all)'}", file=sys.stderr)
    print(f"[capture] output: {out_path.resolve()}", file=sys.stderr)
    print(f"[capture] duration: {args.timeout}s (Ctrl+C to stop earlier)", file=sys.stderr)
    print(f"[capture] CA cert: %USERPROFILE%/.mitmproxy/", file=sys.stderr)
    print("", file=sys.stderr)
    print("[capture] 客户端代理设置: http://127.0.0.1:{args.port}".format(args=args), file=sys.stderr)

    ret = _run_mitmdump(addon_path, args.port, timeout=args.timeout if args.timeout > 0 else None)

    # Print summary
    if out_path.exists():
        try:
            flows = json.loads(out_path.read_text(encoding="utf-8"))
            print(json.dumps({
                "ok": True,
                "total_flows": len(flows),
                "output": str(out_path.resolve()),
                "methods": list(set(f.get("method", "") for f in flows)),
                "hosts": list(set(f.get("host", "") for f in flows)),
            }, ensure_ascii=False, indent=2))
        except Exception as exc:
            print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False, indent=2))
            return 1
    else:
        print(json.dumps({"ok": True, "total_flows": 0, "output": str(out_path.resolve())}, ensure_ascii=False, indent=2))

    try:
        os.unlink(addon_path)
    except OSError:
        pass

    return 0 if ret == 0 else ret


def cmd_modify(args: argparse.Namespace) -> int:
    """改包: 启动代理 + 用户提供的 Python addon 脚本实时修改请求/响应。"""
    rule_path = Path(args.rule)
    if not rule_path.exists():
        print(f"[error] rule file not found: {rule_path}", file=sys.stderr)
        return 1

    if args.gen_rule:
        # Generate a base modify rule template
        out = Path(args.gen_rule)
        out.write_text(MODIFY_BASE_ADDON, encoding="utf-8")
        print(f"[modify] generated rule template: {out.resolve()}", file=sys.stderr)
        return 0

    # If no rule provided, generate a temporary base addon
    if args.rule == "base":
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, encoding="utf-8", prefix="rmod_"
        ) as f:
            f.write(MODIFY_BASE_ADDON)
            rule_path = Path(f.name)
        print("[modify] using base addon (no-op, pass --rule for custom logic)", file=sys.stderr)

    print(f"[modify] proxy on 0.0.0.0:{args.port}", file=sys.stderr)
    print(f"[modify] rule: {rule_path}", file=sys.stderr)
    print(f"[modify] 客户端代理设置: http://127.0.0.1:{args.port}", file=sys.stderr)
    print("", file=sys.stderr)

    ret = _run_mitmdump(str(rule_path.resolve()), args.port, timeout=args.timeout if args.timeout > 0 else None)

    if args.rule == "base":
        try:
            os.unlink(str(rule_path))
        except OSError:
            pass

    return 0 if ret == 0 else ret


def cmd_replay(args: argparse.Namespace) -> int:
    """重放发包: 从保存的 flow 文件中读取请求并重新发送。"""
    flows_path = Path(args.flows)
    if not flows_path.exists():
        print(f"[error] flows file not found: {flows_path}", file=sys.stderr)
        return 1

    try:
        flows = json.loads(flows_path.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"[error] failed to load flows: {exc}", file=sys.stderr)
        return 1

    if not isinstance(flows, list):
        print("[error] flows file must contain a JSON array", file=sys.stderr)
        return 1

    if not flows:
        print("[warn] no flows to replay", file=sys.stderr)
        return 0

    # Filter flows
    if args.filter_host:
        flows = [f for f in flows if args.filter_host in f.get("host", "")]
        print(f"[replay] filtered to {len(flows)} flow(s) for host '{args.filter_host}'", file=sys.stderr)
    if args.filter_method:
        flows = [f for f in flows if f.get("method", "").upper() == args.filter_method.upper()]
        print(f"[replay] filtered to {len(flows)} flow(s) with method '{args.filter_method}'", file=sys.stderr)
    if args.limit > 0:
        flows = flows[: args.limit]
        print(f"[replay] limited to first {args.limit} flow(s)", file=sys.stderr)

    if not flows:
        print("[error] no flows after filtering", file=sys.stderr)
        return 1

    # For direct HTTP replay (no proxy needed), use requests/httpx
    if args.direct:
        return _replay_direct(flows, args)

    # mitmdump-based replay with proxy
    addon_code = REPLAY_ADDON.format(
        flows_json=json.dumps(flows, ensure_ascii=False),
        target=args.target or "",
    )

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".py", delete=False, encoding="utf-8", prefix="rply_"
    ) as f:
        f.write(addon_code)
        addon_path = f.name

    print(f"[replay] {len(flows)} flow(s) via proxy on 0.0.0.0:{args.port}", file=sys.stderr)
    print(f"[replay] target: {args.target or '(original hosts)'}", file=sys.stderr)

    ret = _run_mitmdump(addon_path, args.port)

    try:
        os.unlink(addon_path)
    except OSError:
        pass

    return 0 if ret == 0 else ret


def _replay_direct(flows: list[dict], args: argparse.Namespace) -> int:
    """Direct HTTP replay using requests library (no mitmproxy needed)."""
    import urllib.request
    import ssl

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    results = []
    for i, flow in enumerate(flows):
        method = flow.get("method", "GET").upper()
        target = args.target or flow.get("host", "")
        scheme = "https" if flow.get("port") == 443 else "http"
        path = flow.get("path", "/")
        url = f"{scheme}://{target}{path}"

        headers = dict(flow.get("request_headers") or {})
        headers.pop("Host", None)
        headers.pop("Content-Length", None)
        headers["User-Agent"] = headers.get("User-Agent", "ReverseLab-Replay/1.0")

        body = flow.get("request_body", "")
        data = body.encode("utf-8", errors="replace") if body else None

        start = time.time()
        try:
            req = urllib.request.Request(url, data=data, headers=headers, method=method)
            resp = urllib.request.urlopen(req, context=ctx, timeout=args.timeout or 15)
            status = resp.status
            resp_body = resp.read(args.max_body if hasattr(args, "max_body") else 102400).decode("utf-8", errors="replace")
            elapsed = round((time.time() - start) * 1000, 1)
            results.append({"i": i, "url": url, "method": method, "status": status, "elapsed_ms": elapsed, "body_preview": resp_body[:500]})
            print(f"[replay] {i+1}/{len(flows)} {method} {url} -> {status} ({elapsed}ms)", file=sys.stderr)
        except Exception as exc:
            elapsed = round((time.time() - start) * 1000, 1)
            results.append({"i": i, "url": url, "method": method, "error": str(exc), "elapsed_ms": elapsed})
            print(f"[replay] {i+1}/{len(flows)} {method} {url} -> ERR: {exc}", file=sys.stderr)

    ok = sum(1 for r in results if "error" not in r)
    print(json.dumps({"ok": True, "total": len(flows), "success": ok, "failed": len(flows) - ok, "results": results}, ensure_ascii=False, indent=2))
    return 0


def cmd_craft(args: argparse.Namespace) -> int:
    """构造发包: 从 JSON 模板构造 HTTP 请求并发送。"""
    import urllib.request
    import ssl

    if args.data:
        try:
            req_def = json.loads(args.data)
        except json.JSONDecodeError as exc:
            print(f"[error] invalid JSON: {exc}", file=sys.stderr)
            return 1
    elif args.file:
        file_path = Path(args.file)
        if not file_path.exists():
            print(f"[error] file not found: {file_path}", file=sys.stderr)
            return 1
        try:
            req_def = json.loads(file_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            print(f"[error] invalid JSON in {file_path}: {exc}", file=sys.stderr)
            return 1
    else:
        print("[error] need --data or --file", file=sys.stderr)
        return 1

    # Support both single request and batch
    requests_list = req_def if isinstance(req_def, list) else [req_def]

    ctx_ssl = ssl.create_default_context()
    ctx_ssl.check_hostname = not args.no_verify
    ctx_ssl.verify_mode = ssl.CERT_NONE if args.no_verify else ssl.CERT_REQUIRED

    results = []
    for i, req in enumerate(requests_list):
        method = req.get("method", "GET").upper()
        url = req.get("url", "")
        if not url:
            results.append({"i": i, "error": "missing url"})
            continue

        headers = dict(req.get("headers") or {})
        headers["User-Agent"] = headers.get("User-Agent", "ReverseLab-Craft/1.0")

        body = req.get("body", "")
        if isinstance(body, dict):
            body = json.dumps(body, ensure_ascii=False)
            if "Content-Type" not in headers:
                headers["Content-Type"] = "application/json"
        data = body.encode("utf-8", errors="replace") if body else None

        start = time.time()
        try:
            r = urllib.request.Request(url, data=data, headers=headers, method=method)
            resp = urllib.request.urlopen(r, context=ctx_ssl, timeout=args.timeout or 15)
            status = resp.status
            resp_headers = dict(resp.headers)
            resp_body = resp.read(args.max_body).decode("utf-8", errors="replace")
            elapsed = round((time.time() - start) * 1000, 1)
            result = {"i": i, "url": url, "method": method, "status": status, "elapsed_ms": elapsed, "headers": resp_headers, "body_preview": resp_body[:args.max_body]}
            results.append(result)
            print(f"[craft] {i+1}/{len(requests_list)} {method} {url} -> {status} ({elapsed}ms)", file=sys.stderr)
        except Exception as exc:
            elapsed = round((time.time() - start) * 1000, 1)
            results.append({"i": i, "url": url, "method": method, "error": str(exc), "elapsed_ms": elapsed})
            print(f"[craft] {i+1}/{len(requests_list)} {method} {url} -> ERR: {exc}", file=sys.stderr)

    ok = sum(1 for r in results if "error" not in r)
    print(json.dumps({"ok": True, "total": len(requests_list), "success": ok, "failed": len(requests_list) - ok, "results": results}, ensure_ascii=False, indent=2))
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    """检查 mitmproxy 状态。"""
    try:
        result = subprocess.run(
            ["mitmdump", "--version"],
            capture_output=True, text=True, timeout=10
        )
        print(json.dumps({
            "ok": True,
            "mitmproxy_installed": True,
            "version": result.stdout.strip().split("\n")[0] if result.stdout else "unknown",
        }, ensure_ascii=False, indent=2))
        return 0
    except FileNotFoundError:
        print(json.dumps({"ok": False, "mitmproxy_installed": False, "error": "mitmdump not found. Run: pip install mitmproxy"}, ensure_ascii=False, indent=2))
        return 1


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        description="ReverseLab MITM Proxy Capture — 抓包/改包/发包",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # 抓包 30 秒, 保存到 exports/mitmproxy/capture.json
  python tools/mitmproxy_capture/mitmproxy_capture.py capture -p 8080 -o exports/mitmproxy/capture.json -t 30

  # 改包: 用自定义规则启动代理
  python tools/mitmproxy_capture/mitmproxy_capture.py modify -r my_rules.py -p 8080

  # 重放已抓的包到另一个目标
  python tools/mitmproxy_capture/mitmproxy_capture.py replay -f capture.json --direct -t https://staging.example.com

  # 构造发包
  python tools/mitmproxy_capture/mitmproxy_capture.py craft -d '{"url":"https://httpbin.org/post","method":"POST","body":"test"}'
        """,
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    # ---- capture ----
    p = sub.add_parser("capture", help="启动代理抓包，自动保存 flow 到 JSON")
    p.add_argument("-p", "--port", type=int, default=8080, help="代理监听端口 (默认: 8080)")
    p.add_argument("-o", "--output", default="exports/mitmproxy/capture.json", help="输出 JSON 文件路径")
    p.add_argument("-t", "--timeout", type=float, default=0, help="抓包时长(秒), 0=手动 Ctrl+C 停止")
    p.add_argument("--host", default="", help="只抓指定主机的流量 (可选)")
    p.add_argument("--no-body", action="store_true", help="不保存请求/响应体")
    p.add_argument("--max-body", type=int, default=102400, help="单个 body 最大保存长度 (默认: 100KB)")
    p.set_defaults(func=cmd_capture)

    # ---- modify ----
    p = sub.add_parser("modify", help="启动代理 + Python addon 脚本实时改包")
    p.add_argument("-r", "--rule", default="base", help="Python addon 脚本路径 ('base'=使用空模板)")
    p.add_argument("-p", "--port", type=int, default=8080, help="代理监听端口 (默认: 8080)")
    p.add_argument("-t", "--timeout", type=float, default=0, help="运行时长(秒), 0=手动 Ctrl+C 停止")
    p.add_argument("--gen-rule", default="", metavar="PATH", help="生成改包规则模板文件并退出")
    p.set_defaults(func=cmd_modify)

    # ---- replay ----
    p = sub.add_parser("replay", help="重放已保存的 flow → 目标服务器")
    p.add_argument("-f", "--flows", required=True, help="capture 保存的 JSON flow 文件")
    p.add_argument("--target", default="", help="重放到指定目标主机 (不指定则用原始 host)")
    p.add_argument("--direct", action="store_true", help="直接 HTTP 重放 (不需要 mitmproxy 代理)")
    p.add_argument("--filter-host", default="", help="只重放匹配主机的 flow")
    p.add_argument("--filter-method", default="", help="只重放指定方法的 flow (GET/POST/...)")
    p.add_argument("--limit", type=int, default=0, help="最多重放 N 个 flow (0=全部)")
    p.add_argument("-p", "--port", type=int, default=8080, help="代理端口 (非 --direct 模式)")
    p.add_argument("-t", "--timeout", type=float, default=15, help="请求超时(秒)")
    p.add_argument("--max-body", type=int, default=102400, help="响应体最大读取长度 (默认: 100KB)")
    p.set_defaults(func=cmd_replay)

    # ---- craft ----
    p = sub.add_parser("craft", help="从 JSON 模板构造并发送 HTTP 请求")
    p.add_argument("-d", "--data", default="", help='JSON 请求定义, 如 \'{"url":"...","method":"POST"}\'')
    p.add_argument("-f", "--file", default="", help="从 JSON 文件读取请求定义")
    p.add_argument("-t", "--timeout", type=float, default=15, help="请求超时(秒)")
    p.add_argument("--no-verify", action="store_true", help="跳过 SSL 证书验证")
    p.add_argument("--max-body", type=int, default=102400, help="响应体最大读取长度 (默认: 100KB)")
    p.set_defaults(func=cmd_craft)

    # ---- status ----
    p = sub.add_parser("status", help="检查 mitmproxy 安装状态")
    p.set_defaults(func=cmd_status)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
