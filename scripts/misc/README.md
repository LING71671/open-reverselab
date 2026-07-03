# Misc Scripts

通用/环境维护脚本。

## 主要脚本

- `lab_healthcheck.py` — 实验室环境健康检查
- `first_run_check.py` — 首次打开仓库时检查 Python / uv / Git / 工作区与 `reverse_lab_tools` MCP 配置
- `mcp_smoke_check.py` — 真实启动 `reverse_lab_tools` MCP 并调用核心工具
- `new_task.py` — 为指定 board 创建本地 case / note / exports / reports 骨架
- `start_here.ps1` — Windows 双击入口 `START_HERE.bat` / `START_HERE.cmd` 调用的首次设置助手，会写 `reports/misc/first-run-report.json`
- `ai_toolcheck.py` — AI 工具可用性检查
- `ai_tool.py` — AI 工具路由器
- `ai_context.py` — 任务上下文生成
- `ai_finding.py` — 发现记录管理
