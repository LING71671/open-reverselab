# START

第一次使用时，先按你的目标选入口。

## 我只想确认能不能跑

1. Windows 双击 `START_HERE.bat`。
2. 确认最后显示 `现在可以用 Codex APP 打开这个文件夹，或在 Claude Code 中 cd 到这里。`
3. 需要机器可读结果时看 `reports/misc/first-run-report.json` 和 `reports/misc/mcp-smoke-report.json`。

## 我要让 AI 帮我安装

1. 打开 `templates/prompts/ai-install.zh.md`。
2. 把整段提示词复制给 Codex 或 Claude Code。
3. 让 AI 汇报 `first-run-report.json` 的 `overall/warn/fail`。

## 我要做 Web CTF

1. 读 `boards/ctf-website/AI-USAGE.md`。
2. 创建本地任务：`python scripts/misc/new_task.py --board ctf-website --name <name>`。
3. 对每个信号先走 `kb_router`，再按技术文件的 MCP 工具映射执行。

## 我要分析 APK

1. 读 `boards/android/AI-USAGE.md`。
2. 创建本地任务：`python scripts/misc/new_task.py --board android --name <name>`。
3. 先跑 APK baseline，再按加密、壳、native、网络等信号查 KB。

## 我要分析 Windows PE / EXE

1. 读 `boards/windows/AI-USAGE.md`。
2. 创建本地任务：`python scripts/misc/new_task.py --board windows --name <name>`。
3. 先做 triage，再推进 Ghidra、动态验证、IOC/YARA/Sigma。

## 我要检查 MCP

1. 跑 `uv run --project tools/skills/mcp/ReverseLabToolsMCP python scripts/misc/mcp_smoke_check.py --write-report`。
2. 确认工具数、`kb_router`、`kb_read_file`、`project_skills_status` 都是 PASS。
3. 如果失败，先修 `.mcp.json`、Python、uv，再重新打开 Codex APP 或 Claude Code。
