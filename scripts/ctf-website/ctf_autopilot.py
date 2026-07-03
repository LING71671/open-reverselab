#!/usr/bin/env python3
"""
Stateful Web CTF autopilot controller.

The controller turns ctf_ai_next.py's advisory plan into repeatable rounds with
checkpoint and manifest write-back.  It deliberately executes only a
small allowlist of deterministic actions; everything else is recorded as a
next-round AI task.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import time
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import ctf_ai_next
import ctf_intake
import ctf_loop_status


ROOT = Path(__file__).resolve().parents[2]
SCHEMA = "reverselab.ctf_website.ai_manifest.v1"
AUTOPILOT_SCHEMA = "reverselab.ctf_website.autopilot.v1"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_manifest(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def save_manifest(path: Path, manifest: dict[str, Any]) -> None:
    path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")


def resolve_manifest_path(raw_path: str) -> Path:
    path = Path(raw_path).expanduser()
    if not path.is_absolute():
        path = ROOT / path
    path = path.resolve()
    if not path.exists():
        raise FileNotFoundError(f"manifest not found: {path}")
    if path.name != "ai_manifest.json":
        raise ValueError(f"expected ai_manifest.json, got: {path}")
    try:
        path.relative_to(ROOT)
    except ValueError as exc:
        raise ValueError(f"manifest is outside workspace root: {path}") from exc
    return path


def resolve_workspace_path(raw_path: str, fallback: Path) -> Path:
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


def ensure_manifest_shape(manifest: dict[str, Any], manifest_path: Path) -> None:
    manifest.setdefault("schema", SCHEMA)
    manifest.setdefault("case", manifest_path.parent.name)
    manifest.setdefault("board", "ctf-website")
    manifest.setdefault("target", {})
    manifest.setdefault("paths", {})
    manifest.setdefault("baseline", {})
    manifest.setdefault("parsed", {"links": [], "scripts": [], "forms": []})
    manifest.setdefault("hypotheses", [])
    manifest.setdefault("next_actions", [])
    manifest.setdefault("next_round_focus", [])
    manifest.setdefault("attack_paths", [])
    manifest.setdefault("loop_status", {"status": "CONTINUE", "reason": "manifest shape initialized"})
    manifest.setdefault("evidence", [])
    manifest.setdefault("dead_ends", [])

    paths = manifest["paths"]
    paths.setdefault("case", str(manifest_path.parent))
    case_slug = str(manifest.get("case") or manifest_path.parent.name)
    paths.setdefault("exports", str(ROOT / "exports" / "ctf-website" / case_slug))
    paths.setdefault("reports", str(ROOT / "reports" / "ctf-website" / case_slug))


def append_evidence(manifest: dict[str, Any], evidence: dict[str, Any]) -> None:
    manifest.setdefault("evidence", []).append(
        {
            "time": utc_now(),
            "source": "ctf_autopilot",
            **evidence,
        }
    )


def case_path(manifest: dict[str, Any], manifest_path: Path) -> Path:
    return resolve_workspace_path(str(manifest.get("paths", {}).get("case", "")), manifest_path.parent)


def reports_path(manifest: dict[str, Any], manifest_path: Path) -> Path:
    fallback = ROOT / "reports" / "ctf-website" / str(manifest.get("case") or manifest_path.parent.name)
    path = resolve_workspace_path(str(manifest.get("paths", {}).get("reports", "")), fallback)
    path.mkdir(parents=True, exist_ok=True)
    return path


def collect_http_baseline(manifest: dict[str, Any], manifest_path: Path) -> dict[str, Any]:
    target_url = str(manifest.get("target", {}).get("url") or "").strip()
    if not target_url:
        return {"status": "skipped", "reason": "target.url is empty"}

    baseline = ctf_intake.fetch(target_url)
    parser = ctf_intake.LinkParser()
    parser.feed(baseline.get("body_text", ""))
    base = baseline.get("final_url") or target_url
    manifest["baseline"] = {k: v for k, v in baseline.items() if k != "body_text"}
    manifest["parsed"] = {
        "links": sorted({urllib.parse.urljoin(base, value) for value in parser.links}),
        "scripts": sorted({urllib.parse.urljoin(base, value) for value in parser.scripts}),
        "forms": parser.forms,
    }
    manifest["error"] = ""

    exports_dir = resolve_workspace_path(
        str(manifest.get("paths", {}).get("exports", "")),
        ROOT / "exports" / "ctf-website" / str(manifest.get("case") or manifest_path.parent.name),
    )
    exports_dir.mkdir(parents=True, exist_ok=True)
    body_path = exports_dir / "baseline_body.html"
    if baseline.get("body_text"):
        body_path.write_text(baseline["body_text"], encoding="utf-8")

    append_evidence(
        manifest,
        {
            "type": "http_baseline",
            "url": target_url,
            "status_code": baseline.get("status"),
            "elapsed_ms": baseline.get("elapsed_ms"),
            "body_size": baseline.get("body_size"),
            "artifact": display_path(body_path) if body_path.exists() else "",
        },
    )
    return {
        "status": "executed",
        "handler": "collect_http_baseline",
        "status_code": baseline.get("status"),
        "links": len(manifest["parsed"]["links"]),
        "scripts": len(manifest["parsed"]["scripts"]),
        "forms": len(manifest["parsed"]["forms"]),
    }


def create_fingerprint_template(manifest: dict[str, Any], manifest_path: Path) -> dict[str, Any]:
    out_path = case_path(manifest, manifest_path) / "fingerprints.json"
    if out_path.exists():
        return {"status": "skipped", "handler": "create_fingerprint_template", "reason": "already exists", "path": str(out_path)}

    template_path = ROOT / "templates" / "cases" / "fingerprints.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if template_path.exists():
        shutil.copyfile(template_path, out_path)
        data = json.loads(out_path.read_text(encoding="utf-8"))
    else:
        data = {"target": "", "url": "", "timestamp": "", "fingerprints": []}

    target_url = str(manifest.get("target", {}).get("url") or "")
    data["target"] = manifest.get("case", "")
    data["url"] = target_url
    data["timestamp"] = utc_now()
    out_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    manifest["fingerprints"] = str(out_path)
    append_evidence(
        manifest,
        {
            "type": "fingerprint_template",
            "artifact": display_path(out_path),
            "note": "Fill product/version evidence before running CVE correlation.",
        },
    )
    return {"status": "executed", "handler": "create_fingerprint_template", "path": str(out_path)}


def run_command(cmd: list[str], timeout: int) -> dict[str, Any]:
    result = subprocess.run(
        cmd,
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return {
        "command": cmd,
        "exit_code": result.returncode,
        "stdout": result.stdout[-8192:],
        "stderr": result.stderr[-4096:],
    }


def run_attack_executor(
    manifest: dict[str, Any],
    manifest_path: Path,
    *,
    probes: list[str],
    timeout: int,
) -> dict[str, Any]:
    cmd = [
        sys.executable,
        str(ROOT / "scripts" / "ctf-website" / "ctf_attack_executor.py"),
        str(manifest_path),
    ]
    for probe in probes:
        cmd.extend(["--probe", probe])
    result = run_command(cmd, timeout)
    try:
        refreshed = load_manifest(manifest_path)
        manifest.clear()
        manifest.update(refreshed)
    except Exception:
        pass
    return {"status": "executed", "handler": "run_attack_executor", "probes": probes, **result}


def run_fingerprint_cve_pipeline(
    manifest: dict[str, Any],
    manifest_path: Path,
    *,
    no_network_cve: bool,
    timeout: int,
) -> dict[str, Any]:
    fingerprint_path = ctf_ai_next.existing_fingerprint_path(manifest, manifest_path)
    if not fingerprint_path:
        return {"status": "skipped", "handler": "run_fingerprint_cve_pipeline", "reason": "fingerprints.json is missing"}

    report_dir = reports_path(manifest, manifest_path)
    cve_out = report_dir / "cve"
    graph_out = report_dir / "cve-graph"
    chain_out = report_dir / "cve-chain"
    pipeline_out = report_dir / "fingerprint-cve"
    cmd = [
        sys.executable,
        str(ROOT / "scripts" / "ctf-website" / "fingerprint_cve_pipeline.py"),
        "--fingerprints",
        fingerprint_path,
        "--cve-out",
        str(cve_out),
        "--graph-out",
        str(graph_out),
        "--chain-out",
        str(chain_out),
        "--pipeline-out",
        str(pipeline_out),
        "--per-fingerprint-limit",
        "5",
        "--max-cves",
        "10",
    ]
    if no_network_cve:
        cmd.append("--no-network")

    result = run_command(cmd, timeout)
    manifest["cve_reports"] = str(cve_out)
    append_evidence(
        manifest,
        {
            "type": "cve_pipeline",
            "fingerprints": str(Path(fingerprint_path).resolve()),
            "exit_code": result["exit_code"],
            "reports": display_path(report_dir),
        },
    )
    return {"status": "executed", "handler": "run_fingerprint_cve_pipeline", **result}


def rebuild_cve_graph_chain(manifest: dict[str, Any], manifest_path: Path, *, timeout: int) -> dict[str, Any]:
    cve_reports = str(manifest.get("cve_reports") or manifest.get("paths", {}).get("cve_reports") or "")
    if not cve_reports:
        return {"status": "skipped", "handler": "rebuild_cve_graph_chain", "reason": "cve_reports path is missing"}

    report_dir = reports_path(manifest, manifest_path)
    graph_out = report_dir / "cve-graph"
    chain_out = report_dir / "cve-chain"
    graph = run_command(
        [
            sys.executable,
            str(ROOT / "scripts" / "ctf-website" / "cve_graph.py"),
            "--from-dir",
            cve_reports,
            "--out",
            str(graph_out),
        ],
        timeout,
    )
    chain = run_command(
        [
            sys.executable,
            str(ROOT / "scripts" / "ctf-website" / "cve_chain_planner.py"),
            "--from-dir",
            cve_reports,
            "--out",
            str(chain_out),
        ],
        timeout,
    )
    append_evidence(
        manifest,
        {
            "type": "cve_graph_chain",
            "cve_reports": cve_reports,
            "graph_exit_code": graph["exit_code"],
            "chain_exit_code": chain["exit_code"],
        },
    )
    return {"status": "executed", "handler": "rebuild_cve_graph_chain", "graph": graph, "chain": chain}


def execute_action(
    action: dict[str, Any],
    manifest: dict[str, Any],
    manifest_path: Path,
    *,
    no_network_cve: bool,
    command_timeout: int,
) -> dict[str, Any]:
    action_name = str(action.get("action") or "")
    try:
        if action_name == "Collect HTTP baseline":
            return collect_http_baseline(manifest, manifest_path)
        if action_name == "Run targeted route discovery":
            return run_attack_executor(manifest, manifest_path, probes=["routes"], timeout=command_timeout)
        if action_name == "Inspect JavaScript runtime and API routes":
            return run_attack_executor(manifest, manifest_path, probes=["javascript"], timeout=command_timeout)
        if action_name == "Probe forms for auth/injection/state bugs":
            return run_attack_executor(manifest, manifest_path, probes=["sqli", "xss"], timeout=command_timeout)
        if action_name == "Run deterministic client and redirect probes":
            return run_attack_executor(manifest, manifest_path, probes=["cors", "open_redirect", "xss"], timeout=command_timeout)
        if action_name == "Run deterministic SSRF and file-read probes":
            return run_attack_executor(manifest, manifest_path, probes=["ssrf", "lfi"], timeout=command_timeout)
        if action_name == "Create version fingerprint evidence file":
            return create_fingerprint_template(manifest, manifest_path)
        if action_name == "Run fingerprint-to-CVE graph and chain pipeline":
            return run_fingerprint_cve_pipeline(
                manifest,
                manifest_path,
                no_network_cve=no_network_cve,
                timeout=command_timeout,
            )
        if action_name == "Rebuild CVE correlation graph and multi-CVE chain plan":
            return rebuild_cve_graph_chain(manifest, manifest_path, timeout=command_timeout)
        return {
            "status": "agent_required",
            "reason": "no deterministic allowlist handler; queue for the next AI-driven attack round",
        }
    except subprocess.TimeoutExpired as exc:
        return {"status": "error", "error": f"timeout after {exc.timeout}s", "handler": action_name}
    except Exception as exc:
        return {"status": "error", "error": repr(exc), "handler": action_name}


def select_actions(plan_result: dict[str, Any], max_actions: int) -> list[dict[str, Any]]:
    actions = list(plan_result.get("actions") or [])
    if max_actions <= 0:
        return actions
    return actions[:max_actions]


def update_autopilot_state(
    manifest: dict[str, Any],
    *,
    round_record: dict[str, Any],
    max_rounds: int,
    execute: bool,
) -> None:
    state = manifest.setdefault("autopilot", {})
    state.setdefault("schema", AUTOPILOT_SCHEMA)
    state.setdefault("started_at", round_record["started_at"])
    state["updated_at"] = utc_now()
    state["status"] = "running" if execute else "dry_run"
    state["loop"] = {
        "max_rounds": max_rounds,
        "execute": execute,
    }
    state.setdefault("rounds", []).append(round_record)
    state["last_round_id"] = round_record["round_id"]
    manifest["next_actions"] = [
        item.get("action", "")
        for item in round_record.get("actions", [])
        if item.get("action")
    ]
    manifest["next_round_focus"] = [
        {
            "action": item.get("action", ""),
            "priority": item.get("priority", ""),
            "reason": item.get("why", ""),
        }
        for item in round_record.get("actions", [])
        if (item.get("execution") or {}).get("status") in {"agent_required", "planned", "error"}
    ]
    manifest["loop_status"] = ctf_loop_status.evaluate_manifest(manifest)


def run_round(
    manifest_path: Path,
    *,
    max_actions: int = 0,
    execute: bool = False,
    no_network_cve: bool = True,
    command_timeout: int = 600,
    max_rounds: int = 0,
) -> dict[str, Any]:
    manifest = load_manifest(manifest_path)
    ensure_manifest_shape(manifest, manifest_path)

    plan_result = ctf_ai_next.plan(manifest, manifest_path)
    selected = select_actions(plan_result, max_actions)
    started_at = utc_now()
    round_id = "R-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    action_records: list[dict[str, Any]] = []

    for action in selected:
        execution = (
            execute_action(
                action,
                manifest,
                manifest_path,
                no_network_cve=no_network_cve,
                command_timeout=command_timeout,
            )
            if execute
            else {
                "status": "planned",
                "handler_available": str(action.get("action") or "")
                in {
                    "Collect HTTP baseline",
                    "Run targeted route discovery",
                    "Inspect JavaScript runtime and API routes",
                    "Probe forms for auth/injection/state bugs",
                    "Run deterministic client and redirect probes",
                    "Run deterministic SSRF and file-read probes",
                    "Create version fingerprint evidence file",
                    "Run fingerprint-to-CVE graph and chain pipeline",
                    "Rebuild CVE correlation graph and multi-CVE chain plan",
                },
            }
        )
        action_records.append({**action, "execution": execution})

    round_record = {
        "round_id": round_id,
        "started_at": started_at,
        "finished_at": utc_now(),
        "execute": execute,
        "action_count": len(action_records),
        "actions": action_records,
    }
    update_autopilot_state(
        manifest,
        round_record=round_record,
        max_rounds=max_rounds,
        execute=execute,
    )
    save_manifest(manifest_path, manifest)

    return {
        "manifest": str(manifest_path),
        "case": manifest.get("case"),
        "round": round_record,
        "plan_action_count": plan_result.get("action_count", 0),
        "selected_action_count": len(action_records),
        "execute": execute,
    }


def run_loop(
    manifest_path: Path,
    *,
    max_rounds: int,
    max_actions: int,
    interval_seconds: int,
    execute: bool,
    no_network_cve: bool,
    command_timeout: int,
) -> dict[str, Any]:
    rounds: list[dict[str, Any]] = []
    stop_reason = "max_rounds"

    index = 0
    while max_rounds <= 0 or index < max_rounds:
        result = run_round(
            manifest_path,
            max_actions=max_actions,
            execute=execute,
            no_network_cve=no_network_cve,
            command_timeout=command_timeout,
            max_rounds=max_rounds,
        )
        rounds.append(result)
        index += 1
        if max_rounds > 0 and index >= max_rounds:
            break
        time.sleep(max(0, interval_seconds))

    return {
        "manifest": str(manifest_path),
        "round_count": len(rounds),
        "stop_reason": stop_reason,
        "execute": execute,
        "rounds": rounds,
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Run a stateful Web CTF autopilot round or fallback loop.")
    parser.add_argument("manifest", help="Path to cases/<case>/ai_manifest.json")
    parser.add_argument("--loop", action="store_true", help="Run repeated fallback rounds until --max-rounds is reached.")
    parser.add_argument("--max-rounds", type=int, default=0, help="Optional local fallback round limit. 0 means unlimited.")
    parser.add_argument("--max-actions", type=int, default=0, help="Optional action limit per round. 0 means all planned actions.")
    parser.add_argument("--interval-seconds", type=int, default=900, help="Sleep between loop rounds.")
    parser.add_argument("--execute", action="store_true", help="Execute allowlisted actions; default records a dry-run plan.")
    parser.add_argument("--allow-network-cve", action="store_true", help="Allow live CVE enrichment network calls.")
    parser.add_argument("--command-timeout", type=int, default=600, help="Timeout for each subprocess action.")
    args = parser.parse_args(argv)

    manifest_path = resolve_manifest_path(args.manifest)
    if args.loop:
        result = run_loop(
            manifest_path,
            max_rounds=args.max_rounds,
            max_actions=args.max_actions,
            interval_seconds=args.interval_seconds,
            execute=args.execute,
            no_network_cve=not args.allow_network_cve,
            command_timeout=args.command_timeout,
        )
    else:
        result = run_round(
            manifest_path,
            max_actions=args.max_actions,
            execute=args.execute,
            no_network_cve=not args.allow_network_cve,
            command_timeout=args.command_timeout,
            max_rounds=1,
        )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
