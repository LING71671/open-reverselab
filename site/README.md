# 官网开发

VitePress 是官网唯一实现，GitHub Pages 从 main 构建 site/。docs/ 保存旧站路由和知识库的 LLM 索引，不再维护第二套产品页面。

```sh
pnpm install --frozen-lockfile
pnpm dev
pnpm build
```

需要 Node.js 22、pnpm 11 和 Python 3.10+。构建脚本复制 KB 源文件，并生成目录、工具注册表和英文包含页。英文导航已翻译，知识文章保留原文。

设置 VITEPRESS_BASE=/open-reverselab/ 检查 GitHub Pages 子路径部署。构建输出 site/.vitepress/dist/ 不入库。设计约定见 ../DESIGN.md；截图来自 ../assets/desktop/，同步到 public/assets/desktop/。新增产品能力须同时更新中英文页面、README 和发布记录。

首页模式控件只说明产品行为；工具目录来自 tools/ai-tool-registry.json，AI callable 标记不是本机就绪状态。完整 MCP 可用性需运行 scripts/misc/mcp_smoke_check.py。
