# Skills / MCP AI Usage

本目录保存 MCP 实现；项目级行为由 `AGENTS.md`、board 的 `AI-USAGE.md` 和知识库技术文件定义。

## MCP 服务器

MCP 配置在项目根目录的 `.mcp.json` 中。默认服务器：

- **reverse_lab_tools** — 逆向实验室工具集 MCP

可选的第三方桥接示例在 `.mcp.optional.example.json` 中：

- **ghidra** — Ghidra GUI MCP 桥接；Ghidra headless 分析不依赖此桥接
- **jshook** — 浏览器 JS Hook MCP

不要把 optional bridge 当作项目的强制依赖；Ghidra-first 静态分析通过 `reverse_lab_tools` 的 `ghidra_headless_analyze` 和 `ghidra_summary_*` 完成。外部 workflow 参考的来源与再分发规则见 [`docs/upstreams/reverse-skills.md`](../../docs/upstreams/reverse-skills.md)。