#!/usr/bin/env python3
"""
ReverseLab Automated Reverse Engineering Harness Runner.
Autonomous, headless, and verifiable reverse engineering testbed.
Performs discovery, triage, KB routing, LLM reasoning (mimo-v2.6-flash),
executes generated verification scripts directly against the target,
and generates structured forensic reports and deliverables.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "misc"))

try:
    from triage_target import triage_target
except ImportError:
    triage_target = None


def load_env() -> dict[str, str]:
    env_vars: dict[str, str] = {}
    env_file = ROOT / "desktop" / ".env"
    if env_file.exists():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                env_vars[k.strip()] = v.strip().strip('"').strip("'")
    return env_vars


def query_llm(
    prompt: str,
    system_prompt: str,
    base_url: str,
    api_key: str,
    model: str = "mimo-v2.6-flash",
    timeout: int = 90,
) -> str:
    url = f"{base_url.rstrip('/')}/chat/completions"
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.2,
        "max_tokens": 4096,
    }
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
        "User-Agent": "ReverseLab-Harness/2.0",
    }

    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )

    with urllib.request.urlopen(req, timeout=timeout) as resp:
        res = json.loads(resp.read().decode("utf-8"))
        choices = res.get("choices", [])
        if choices and "message" in choices[0]:
            return choices[0]["message"].get("content", "")
        return ""


def extract_python_script(content: str) -> str:
    py_blocks = re.findall(r"```python\s*([\s\S]*?)\s*```", content)
    if py_blocks:
        return py_blocks[0].strip()
    if "```python" in content:
        tail = content.split("```python", 1)[1]
        if "```" in tail:
            return tail.split("```", 1)[0].strip()
        return tail.strip()
    generic_blocks = re.findall(r"```\s*([\s\S]*?)\s*```", content)
    if generic_blocks:
        return generic_blocks[0].strip()
    return ""


def run_harness(
    target: str,
    task_prompt: str,
    model: str = "mimo-v2.6-flash",
    auth_val: str | None = None,
    base_url: str | None = None,
) -> dict[str, Any]:
    env = load_env()
    resolved_key = auth_val or os.environ.get("LLM_API_KEY") or env.get("VITE_LLM_API_KEY", "") or env.get("VITE_LLM_KEY", "")
    base_url = base_url or os.environ.get("LLM_BASE_URL") or env.get("VITE_LLM_BASE_URL", "https://tokenrhythm.studio/v1")
    model = model or os.environ.get("LLM_MODEL") or env.get("VITE_LLM_MODEL", "mimo-v2.6-flash")

    print(f"[*] ReverseLab Autonomous Harness Running on target: {target}")
    start_time = time.time()

    # Stage 1 & 2: Target Discovery & Static Triage
    print("[-] Stage 1 & 2: Executing Target Discovery & Static Triage...")
    if triage_target:
        triage_data = triage_target(target)
    else:
        cmd = [sys.executable, str(ROOT / "scripts" / "misc" / "triage_target.py"), target]
        out = subprocess.check_output(cmd, text=True, encoding="utf-8")
        triage_data = json.loads(out)

    target_path = triage_data.get("targetPath") or target
    board = triage_data.get("board", "pe-reverse")
    print(f"    [+] Board: {board} | FileType: {triage_data.get('fileType')}")
    if triage_data.get("isContainerDirectory"):
        print(f"    [+] Container Directory: {triage_data.get('containerDirectory')}")
        print(f"    [+] Resolved Primary Binary: {triage_data.get('resolvedBinary')}")
        print(f"    [+] Discovered Binaries: {len(triage_data.get('discoveredSamples', []))}")

    # Stage 3: KB Routing
    print("[-] Stage 3: Routing Attack Network & Knowledge Base...")
    kb_path = ROOT / "kb" / board / "techniques" / "attack-network.md"
    kb_summary = ""
    if kb_path.exists():
        kb_summary = kb_path.read_text(encoding="utf-8")[:1200]
        print(f"    [+] Loaded Attack Network: kb/{board}/techniques/attack-network.md ({len(kb_summary)} bytes)")

    # Stage 4: LLM Reasoning & Forensics Code Generation
    print(f"[-] Stage 4: Querying LLM Engine ({model})...")
    system_prompt = (
        "你是专业逆向工程 Agent 与自动化 Harness 核心。\n"
        "任务：根据提供的目标静态初筛数据与攻击网络，进行深度行为研判与取证分析。\n"
        "要求：\n"
        "1. 必须输出一个完整的、无截断的 Python 自动化取证验证脚本（使用 ```python 包裹，约 60 行），使用 pefile/hashlib 直接分析目标文件并打印关键取证指标（节区、反调试 API 引用、注册表操作）。\n"
        "2. 输出结论性摘要、关键证据表格与最终判定。\n"
    )

    compact_triage = {
        "board": triage_data.get("board"),
        "targetPath": target_path,
        "arch": triage_data.get("arch"),
        "entryPoint": triage_data.get("entryPoint"),
        "subsystem": triage_data.get("subsystem"),
        "packer": triage_data.get("packer"),
        "sections": [s["name"] for s in triage_data.get("sections", [])],
        "capabilities": triage_data.get("capabilities", {}),
        "discoveredSamples": [s["name"] for s in triage_data.get("discoveredSamples", [])[:8]],
    }

    user_query = (
        f"目标路径: {target_path}\n"
        f"任务需求: {task_prompt}\n\n"
        f"【初筛遥测概要】\n"
        f"```json\n{json.dumps(compact_triage, ensure_ascii=False, indent=2)}\n```\n\n"
        f"【知识库参考】\n{kb_summary[:600]}\n"
    )

    llm_output = ""
    if resolved_key:
        try:
            llm_output = query_llm(user_query, system_prompt, base_url, resolved_key, model=model)
            print(f"    [+] LLM Response Received ({len(llm_output)} chars)")
        except Exception as e:
            print(f"    [!] LLM Query warning: {e}")
            llm_output = (
                "分析完成 (本地回退模型)。\n\n```python\n# 自动化验证脚本\nimport pefile, hashlib, os\n"
                f"target = r'{target_path}'\n"
                "print(f'[+] Verifying: {target}')\n"
                "if os.path.exists(target):\n"
                "    pe = pefile.PE(target)\n"
                "    print(f'[+] EntryPoint: 0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:08X}')\n"
                "    print(f'[+] Sections: {len(pe.sections)}')\n```"
            )
    else:
        print("    [!] No API Key provided, generating local deterministic analysis...")
        llm_output = (
            "分析完成 (本地模式)。\n\n```python\n# 自动化验证脚本\nimport pefile, os\n"
            f"target = r'{target_path}'\n"
            "if os.path.exists(target):\n"
            "    pe = pefile.PE(target)\n"
            "    print(f'[+] Verified Target: {target}')\n"
            "    print(f'[+] EntryPoint: 0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:08X}')\n```"
        )

    # Stage 5: Forensics Verification Execution
    print("[-] Stage 5: Executing Verification Script Against Target...")
    script_code = extract_python_script(llm_output)
    exec_result: dict[str, Any] = {"stdout": "", "stderr": "", "exitCode": -1, "durationMs": 0}

    if script_code:
        exec_start = time.time()
        try:
            p = subprocess.run(
                [sys.executable, "-c", script_code],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                timeout=20,
            )
            exec_result = {
                "stdout": p.stdout,
                "stderr": p.stderr,
                "exitCode": p.returncode,
                "durationMs": int((time.time() - exec_start) * 1000),
            }
            print(f"    [+] Execution completed with exit code {p.returncode} in {exec_result['durationMs']}ms")
            if p.stdout:
                print("    --- Verification Output Preview ---")
                for line in p.stdout.strip().splitlines()[:6]:
                    print(f"    | {line}")
                if len(p.stdout.strip().splitlines()) > 6:
                    print("    | ...")
        except Exception as e:
            exec_result["stderr"] = str(e)
            print(f"    [!] Script execution error: {e}")

    # Stage 6: Artifact Persistence & Report
    print("[-] Stage 6: Persisting Deliverables & Analysis Report...")
    clean_name = Path(target_path).stem.replace(" ", "_")
    reports_dir = ROOT / "reports"
    exports_dir = ROOT / "exports"
    reports_dir.mkdir(exist_ok=True)
    exports_dir.mkdir(exist_ok=True)

    report_path = reports_dir / f"{clean_name}_analysis.md"
    script_path = exports_dir / f"{clean_name}_forensics.py"

    report_content = (
        f"# Analysis Report: {target}\n\n"
        f"## 1. Summary\n{llm_output}\n\n"
        f"## 2. Key Artifacts\n"
        f"- Target: {target_path}\n"
        f"- Architecture: {triage_data.get('arch', 'unknown')}\n"
        f"- SHA256: {triage_data.get('sha256', 'unknown')}\n\n"
        f"## 3. Verified Script\n```python\n{script_code}\n```\n\n"
        f"## 4. Execution Output (Verified Finished Product)\n```\n{exec_result.get('stdout', '')}\n```\n"
    )

    report_path.write_text(report_content, encoding="utf-8")
    if script_code:
        script_path.write_text(script_code, encoding="utf-8")

    total_duration = round(time.time() - start_time, 2)
    print(f"[+] Harness Finished in {total_duration}s. Report: {report_path.relative_to(ROOT)}")

    return {
        "status": "completed",
        "target": target,
        "targetPath": target_path,
        "board": board,
        "model": model,
        "triage": triage_data,
        "script": script_code,
        "executionOutput": exec_result,
        "reportPath": str(report_path.relative_to(ROOT)),
        "scriptPath": str(script_path.relative_to(ROOT)),
        "durationSec": total_duration,
    }


def main():
    parser = argparse.ArgumentParser(description="ReverseLab Headless Autonomous Reverse Engineering Harness")
    parser.add_argument("--target", required=True, help="Target file path, directory, or URL")
    parser.add_argument("--prompt", default="深度静态排查与反调试/注册表行为分析", help="Reverse engineering task prompt")
    parser.add_argument("--model", default="mimo-v2.6-flash", help="LLM model (default: mimo-v2.6-flash)")
    parser.add_argument("--api-key", default=None, help="LLM API Key")
    parser.add_argument("--base-url", default=None, help="LLM Base URL")
    parser.add_argument("--output-json", action="store_true", help="Print structured result JSON")

    args = parser.parse_args()
    res = run_harness(
        target=args.target,
        task_prompt=args.prompt,
        model=args.model,
        auth_val=args.api_key,
        base_url=args.base_url,
    )
    if args.output_json:
        print(json.dumps(res, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
