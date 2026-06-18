# Knowledge Base AI Usage

`kb/` 是可复用战术知识库，不是单个 case 的证据目录。

## 写入规则

- 可复用技巧、payload 模式、CVE workflow、绕过方法写入 `kb/`。
- 单题/单样本证据不要写进 `kb/`，应写 `notes/` 或 `reports/`。
- 每篇技巧应包含：适用场景、输入信号、验证步骤、常见误判、工具命令、输出位置。

## 当前重点

- Web CTF：`kb/ctf-website/README.md`
- CVE 关联网：`kb/ctf-website/techniques/09-cve/cve-correlation-graph.md`

## AI 联动

- 发现新通用技巧后，从 case 笔记提炼到 `kb/`。
- 用 `kb/` 指导脚本和模板更新，而不是只停留在文字说明。
