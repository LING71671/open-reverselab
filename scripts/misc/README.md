# Misc Scripts

通用/环境维护脚本。

## 主要脚本

- `lab_healthcheck.py` — 实验室环境健康检查
- `first_run_check.py` — 首次打开仓库时检查 Python / uv / Git / 工作区与 `reverse_lab_tools` MCP 配置
- `mcp_smoke_check.py` — 真实启动 `reverse_lab_tools` MCP 并调用核心工具
- `new_task.py` — 为指定 board 创建本地 case / note / exports / reports 骨架
- `start_here.ps1` — Windows 双击入口 `START_HERE.bat` / `START_HERE.cmd` 调用的首次设置助手，会写 `reports/misc/first-run-report.json`
- `bootstrap.sh` — macOS/Linux core wrapper 生成器，会写 `tools/bin/ai_*` shell wrapper
- `ai_toolcheck.py` — AI 工具可用性检查
- `ai_tool.py` — AI 工具路由器
- `ai_context.py` — 任务上下文生成
- `ai_finding.py` — 发现记录管理
- `configure_codex_model_instructions.py` — 将项目 `.codex/*.toml` 的 `model_instructions_file` 指向仓库根 `CODEX.md`
- `setup_unattended_ctf_runner.py` — 无人值守 runner（调用上一脚本 + approval/sandbox/MCP + Claude local settings）
- `verify_codex_ctf_profile.ps1` — 校验 Codex 已指向 `../CODEX.md` 且 `CODEX.md` 含关键契约条款
- `remove_disclaimer.py` — 确认后删除中英 `DISCLAIMER*`，并剥离 README 免责声明节（减少 AI 过度解读）

## macOS/Linux quick start

```sh
./START_HERE.sh
./scripts/misc/bootstrap.sh
export PATH="$PWD/tools/bin:$PWD/tools/ctf-website/bin:$PATH"
python scripts/misc/ai_toolcheck.py --board misc
```

Windows 专用 GUI/PE 工具（例如 Procmon、x64dbg、PE-bear）在 macOS/Linux 上会被标记为
unsupported/skipped；这些工具随 Windows release 分发。macOS/Linux release 聚焦 Python/MCP
core、Web/Android CLI 工具和 PATH 中已安装的 native 工具。
