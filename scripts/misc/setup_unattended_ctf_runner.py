#!/usr/bin/env python3
"""
Generate local Claude Code / Codex profiles for unattended Web CTF loops.

The generated files are machine-local runner configuration.  They are meant to
live in this workspace folder and are ignored by git when possible.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


CODEX_PROMPT = """# CTF Optimized Agent Prompt

你正在 open-reverselab 文件夹内运行。默认目标是授权 CTF/lab 自动化。

## Unattended loop protocol

- 不等待人工审批；运行器层面的 approval/sandbox 配置已允许自动执行。
- 24h Web CTF 使用 `/loop + ctf-24h-round + ai_manifest.json` 模式。
- 单轮任务必须有界执行，输出 `STATUS: CONTINUE|DONE|EXHAUSTED`。
- `cases/<case>/ai_manifest.json` 是恢复点；中断后读取它继续，不从头开始。
- 每发现信号先读 `kb/red/ctf-website/techniques/attack-network.md`，再用
  `scripts/ctf-website/kb_router.py "<signal>"` 路由技术文档。
- 非 Python allowlist 动作标记为 `agent_required`，由下一轮 Agent 自动处理，不交给人。

## Evidence

- 原始请求/响应、截图、flag 和日志只写入本地 `cases/`、`exports/`、`reports/`。
- 不把真实目标、凭据、Cookie、token、flag 或个人路径提交到公开仓库。
"""


CODEX_CONFIG = """model_instructions_file = "ctf_optimized.md"
approval_policy = "never"
sandbox_mode = "danger-full-access"

[mcp_servers.reverse_lab_tools]
command = "uv"
args = [
  "run",
  "--project",
  "tools/skills/mcp/ReverseLabToolsMCP",
  "python",
  "tools/skills/mcp/ReverseLabToolsMCP/reverse_lab_tools_mcp.py",
]
"""


CLAUDE_SETTINGS = {
    "permissions": {
        "allow": [
            "Bash(*)",
            "Read(*)",
            "Write(*)",
            "Edit(*)",
            "MultiEdit(*)",
            "Glob(*)",
            "Grep(*)",
            "LS(*)",
            "WebFetch(*)",
            "WebSearch(*)",
        ],
        "deny": [],
    }
}


def write_text(path: Path, content: str, overwrite: bool) -> str:
    if path.exists() and not overwrite:
        return "exists"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return "written"


def write_json(path: Path, payload: dict, overwrite: bool) -> str:
    return write_text(path, json.dumps(payload, ensure_ascii=False, indent=2) + "\n", overwrite)


def ensure_gitignore_entries(overwrite: bool) -> str:
    gitignore = ROOT / ".gitignore"
    entries = [".codex/", ".claude/settings.local.json"]
    if not gitignore.exists():
        gitignore.write_text("\n".join(entries) + "\n", encoding="utf-8")
        return "written"

    text = gitignore.read_text(encoding="utf-8")
    changed = False
    for entry in entries:
        if entry not in text:
            text = text.rstrip() + "\n" + entry + "\n"
            changed = True
    if changed and overwrite:
        gitignore.write_text(text, encoding="utf-8")
        return "updated"
    return "ok" if not changed else "needs-update"


def main() -> int:
    parser = argparse.ArgumentParser(description="Create unattended CTF runner profiles for Claude Code and Codex.")
    parser.add_argument("--overwrite", action="store_true", help="Overwrite existing local runner files.")
    parser.add_argument("--skip-gitignore", action="store_true", help="Do not update .gitignore for local runner files.")
    args = parser.parse_args()

    outputs = {
        "codex_config": write_text(ROOT / ".codex" / "config.toml", CODEX_CONFIG, args.overwrite),
        "codex_ctf_config": write_text(ROOT / ".codex" / "ctf.config.toml", CODEX_CONFIG, args.overwrite),
        "codex_prompt": write_text(ROOT / ".codex" / "ctf_optimized.md", CODEX_PROMPT, args.overwrite),
        "claude_settings": write_json(ROOT / ".claude" / "settings.local.json", CLAUDE_SETTINGS, args.overwrite),
    }
    if not args.skip_gitignore:
        outputs["gitignore"] = ensure_gitignore_entries(overwrite=True)

    print(json.dumps({"root": str(ROOT), "outputs": outputs}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
