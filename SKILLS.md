# Skills 与外部 Agent

仓库通过 [AGENTS.md](AGENTS.md)、[AI-USAGE.md](AI-USAGE.md)、board 文档和知识库向外部 Agent 提供工作约定。`tools/skills/` 主要存放 MCP 实现，不是客户端自动发现 skill 的目录。

## 内置入口

- [reverse_lab_tools MCP](tools/skills/mcp/ReverseLabToolsMCP/README.md)：工具实现、依赖与启动说明。
- [板块路由](boards/README.md)：按目标进入 Web、Android、Windows、General 或 Misc。
- [知识库路由](kb/AI-USAGE.md)：按信号和 `red / blue / both` 选择技术文档。
- [外部工作流来源](docs/upstreams/reverse-skills.md)：已记录的上游版本、参考范围与再分发边界。

## 接入可选 skill

使用客户端实际支持的安装方式，并核对来源仓库、许可证和 `SKILL.md`。项目不假设存在同名插件市场包，也不提供未经核实的 `claude plugins install` 命令。外部 skill 不能替代本机工具安装或实际执行验收。

通过 MCP 调用 `project_skills_status` 可检查项目提供的入口。首次接入还应执行 `python scripts/misc/mcp_smoke_check.py --write-report`，使用已安装 MCP 依赖的 Python 环境。

桌面端的运行引擎由项目自身提供，并不会自动加载外部客户端的 skills。扩展桌面工具见 [desktop/DEV_GUIDE.md](desktop/DEV_GUIDE.md)。
