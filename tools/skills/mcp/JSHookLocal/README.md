# JSHookLocal

浏览器 JS Hook/自动化 MCP server（原项目: JSHook Reverse Tool）。

## 上游状态 (2026-07)

原 GitHub 仓库 `wuji1/jshook-reverse-tool` 已删除（404），但项目**已迁移到 npm 发布并继续维护**：

- npm 包: [`jshook-reverse-tool`](https://www.npmjs.com/package/jshook-reverse-tool)（v0.1.1）
- 活跃维护包: [`@ai-jshook/mcp`](https://www.npmjs.com/package/@ai-jshook/mcp)（v0.1.11+，bin 仍为 `jshook-reverse-tool`）
- MCP Registry: `io.github.wuji1.jshook-reverse-tool`
- License: MIT

## 安装

保持本目录结构（`dist/index.js` 与 `reverse_lab_tools_mcp.py` 的检测路径兼容）：

```powershell
cd tools/skills/mcp/JSHookLocal
$t = npm pack @ai-jshook/mcp 2>$null | Select-Object -Last 1
tar -xzf $t --strip-components=1
Remove-Item $t
```

或全局安装后直接用 `jshook-reverse-tool` 命令：

```bash
npm install -g jshook-reverse-tool   # 或 npx jshook-reverse-tool
```

使用方式详见包内自带 `README.md`（MCP 客户端搜索 `jshook-reverse-tool` 或配置 `io.github.wuji1.jshook-reverse-tool` 亦可安装）。
