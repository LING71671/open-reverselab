# ReverseLab

开源逆向工程实验环境 —— 面向 Android/Windows/Web CTF 的二进制分析与漏洞研究框架。

## AI Entry

- 全局 AI 使用说明：[AI-USAGE.md](AI-USAGE.md)
- Agent 行为约定：[AGENTS.md](AGENTS.md)
- Board 路由：[boards/README.md](boards/README.md)

## Boards

| Board | 用途 | 入口 |
|---|---|---|
| Android | APK、DEX、Frida、repack、签名、移动端行为分析 | [boards/android](boards/android/README.md) |
| Windows | PE、x64dbg、Ghidra、Procmon、YARA/Sigma、patch/crackme | [boards/windows](boards/windows/README.md) |
| CTF Website | Web CTF、JS hook、浏览器行为、HTTP/前端 payload 分析 | [boards/ctf-website](boards/ctf-website/README.md) |
| Misc | MCP、skill、环境、自动化、自测、通用实验 | [boards/misc](boards/misc/README.md) |

## Canonical Layout

| Directory | Role |
|---|---|
| [samples](samples/) | 原始样本、隔离区、unpacked payload；按领域放入 `android/windows/ctf-website/misc` |
| [projects](projects/) | Ghidra、apktool、调试器、CTF 项目文件 |
| [exports](exports/) | 工具导出、triage、IOC、YARA/Sigma、Procmon、unpack 结果 |
| [patches](patches/) | patched binary/APK、补丁实验 |
| [notes](notes/) | 手工分析笔记和过程证据 |
| [reports](reports/) | 自动化报告、整理记录、最终交付 |
| [scripts](scripts/) | Frida、Python replay、Ghidra script、debug/procmon 脚本 |
| [tools](tools/) | 工具链，已按 Android/Windows/CTF/Common/Skills 拆分 |
| [cases](cases/) | 跨板块 case 索引层，连接样本、项目、笔记、报告、补丁和脚本 |
| [templates](templates/) | 分析笔记、case、报告、YARA/Sigma 模板 |
| [kb](kb/) | 可复用知识库；Web CTF 技巧、checklists、payloads |

每个主目录应有本地 `README.md` 或 `AI-USAGE.md`。

## Placement Rules

- 新样本先进 `samples/<board>/`，恶意或不确定样本先进 `samples/_quarantine/`。
- 自动化/工具输出进 `exports/<board>/` 或 `exports/_shared/`。
- 修改后的二进制、APK、patch 结果进 `patches/<board>/`。
- 可复用脚本进 `scripts/<board>/`；跨领域脚本进 `scripts/_shared/`。
- 过程笔记进 `notes/<board>/`，交付型结论进 `reports/<board>/`。
- MCP、skill、agent/workflow 相关内容归 `tools/skills/` 和 `boards/misc/`。
- 新 case 从 `cases/` 开始建索引，不复制大文件，只链接各板块产物。

## 工具安装

`tools/` 下的工具需要单独下载安装，详见各子目录的 `README.md`。常用工具的下载链接和安装说明已在对应目录中提供。

## 前置依赖

本项目设计为与 [codex-session-patcher](https://github.com/LING71671/codex-session-patcher) 配合使用。clone 后请先配置 codex-session-patcher，以确保 AI Agent 能正确路由到各板块的 `AI-USAGE.md` 和工具链。

## 快速开始

```powershell
# 安装 codex-session-patcher（一次性）
# 详见: https://github.com/LING71671/codex-session-patcher

# 查看工具安装状态
python scripts/misc/ai_toolcheck.py

# 查看知识库索引
python scripts/ctf-website/kb_router.py "sql injection"
```
