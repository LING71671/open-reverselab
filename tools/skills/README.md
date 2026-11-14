# Skills and MCP

本目录保存 MCP（Model Context Protocol）服务器实现和相关文档，不是 Claude Code 自动发现的 skill 根目录。

## 目录

| 目录 | 用途 |
|---|---|
| `mcp/` | MCP 服务器实现；默认启用项由根目录 `.mcp.json` 定义，第三方桥接保留在 `.mcp.optional.example.json` |
| `create-reverselab-extension/` | 创建知识包、MCP 描述与 GitHub 目录的作者 skill；包含草案协议、模板和离线 ZIP 打包工具 |

扩展设计见 [EXTENSIONS.md](../../EXTENSIONS.md) / [中文说明](../../EXTENSIONS.zh-CN.md)。作者 skill 可直接按路径调用，也可将整个 `create-reverselab-extension/` 目录复制到客户端的 skills 目录。当前桌面尚未实现该草案的导入器。

仓库级行为约定由 `AGENTS.md`、各 board 的 `AI-USAGE.md` 和 `kb/` 技术文档提供。外部 workflow 项目的参考与再分发边界见 [`docs/upstreams/reverse-skills.md`](../../docs/upstreams/reverse-skills.md)。
