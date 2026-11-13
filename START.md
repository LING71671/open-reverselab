# 开始使用 ReverseLab

## 使用桌面端

从 [v2.0.0 Release](https://github.com/LING71671/open-reverselab/releases/tag/v2.0.0) 下载 Windows x64 压缩包并完整解压。准备 Python 3.10+（`python` 在 PATH 中）和 WebView2 Runtime，然后打开 `ReverseLab.exe`。程序需要同目录的 `kb/`、`scripts/`，不要只复制 EXE。

首次启动会创建默认工作区。在左上角选择 `red / blue / both`，在设置中配置模型，填写目标和任务内容后开始。时间、Token 限制可选。导入样本、并发执行、报告和升级说明见 [desktop/README.zh-CN.md](desktop/README.zh-CN.md)。

## 在 Codex / Claude Code 等客户端使用

在客户端打开仓库目录。Windows 双击 `START_HERE.bat` 或 `START_HERE.cmd`；macOS/Linux 运行 `./START_HERE.sh`。它们检查环境和 MCP 配置，结果在 `reports/misc/first-run-report.json` 与 `reports/misc/mcp-smoke-report.json`。

AI 安装提示词见 [中文](templates/prompts/ai-install.zh.md) / [English](templates/prompts/ai-install.en.md)。读取 [AI-USAGE.md](AI-USAGE.md) 后进入对应 board：

| 任务 | 入口 | 创建本地 case |
| --- | --- | --- |
| Web / CTF | [Web](boards/ctf-website/AI-USAGE.md) | `python scripts/misc/new_task.py --board ctf-website --name <name>` |
| APK / DEX | [Android](boards/android/AI-USAGE.md) | `python scripts/misc/new_task.py --board android --name <name>` |
| PE / EXE | [Windows](boards/windows/AI-USAGE.md) | `python scripts/misc/new_task.py --board windows --name <name>` |
| 密码学 / 协议 | [General](boards/general/AI-USAGE.md) | `python scripts/misc/new_task.py --board general --name <name>` |

按信号查知识库：`python scripts/misc/kb_router.py "<信号>" --track blue`。需要其他模式时显式选择 `red` 或 `both`。

## 检查 MCP

```sh
uv sync --project tools/skills/mcp/ReverseLabToolsMCP
uv run --project tools/skills/mcp/ReverseLabToolsMCP python scripts/misc/mcp_smoke_check.py --write-report
```

根据报告检查 `kb_router`、`kb_read_file`、`project_skills_status`。配置失败时先核对 `.mcp.json`、Python 和 uv，再重开客户端。第三方工具按对应安装文档另行准备。

## 开发与发布

桌面开发见 [DEV_GUIDE.md](desktop/DEV_GUIDE.md)，知识库贡献见 [kb/AI-USAGE.md](kb/AI-USAGE.md)，发布流程见 [RELEASING.md](RELEASING.md)。
