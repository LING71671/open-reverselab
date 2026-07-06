# ReverseLab

开源逆向工程实验环境 —— 178 篇知识库文章，100+ MCP 自动化工具，覆盖 CTF 渗透测试 / APK 逆向 / PE 二进制分析 / 加密协议破解 / 游戏作弊分析。Agent 原生设计，目录即约定。
<img width="1194" height="430" alt="image" src="https://github.com/user-attachments/assets/65085420-66bd-4c9a-b02d-8b4a55005d03" />

> [English version](README.md)

## 路由

```
信号 → kb_router(board=) → kb_read_file → 攻击链 → MCP 工具映射 → 执行
```

| 信号类型 | Board | KB 分类数/文件数 | MCP 工具族 |
|---------|-------|-----------------|-----------|
| HTTP/Web/API/CVE/Cloud/CAPTCHA | `ctf-website` | 26/118 | `http_probe` `run_ctf_tool` `kb_router` |
| APK/DEX/SO/Frida/Java | `apk-reverse` | 8/20 | `android_app_baseline` `android_crypto_unpack_recipe` `android_frida_*` |
| PE/x64/x86/malware/driver | `pe-reverse` | 9/22 | `triage_pe` `ghidra_headless_analyze` `make_x64dbg_breakpoint_script` `sample_full_workup` |
| Crypto/Protocol/Cheat/IoT/Radio | `general` | 5/17 | `die_scan` `ghidra_*` `rizin_*` `python_re_tool_*` |

## 知识库

```
kb/
├── ctf-website/techniques/   26 类 118 篇 — Web 攻击全表面
├── apk-reverse/techniques/    8 类 20 篇 — APK/DEX 逆向
├── pe-reverse/techniques/     9 类 22 篇 — PE 二进制分析
└── general/techniques/        5 类 17 篇 — 密码学/协议/内核/作弊/方法论
```

每篇技术文件结构：`场景 → 输入信号 → 方法 → 攻击链 → MCP 工具映射`

Agent 工作流：检测到信号 → `kb_router` 查技术 → `kb_read_file` 读 → 按 MCP 工具映射执行。

## 板块

| 板块 | 触发信号 |
|------|---------|
| `boards/ctf-website` | URL, HTTP, JWT, SQLi, SSRF, CVE, API, CSP, OAuth, CAPTCHA, Cloudflare, ReDoS, Slowloris, DoS, Paywall |
| `boards/android` | APK, DEX, adb, Frida, jadx, smali, SO, native |
| `boards/windows` | PE, EXE, DLL, x64dbg, Ghidra, Procmon, packer, malware |
| `boards/general` | AES/DES/RSA, protobuf, game cheat, EAC/BE/Vanguard, firmware, JTAG, SDR |
| `boards/misc` | MCP 配置, skill 安装, 环境自检 |

## 目录约定

```
samples/      → 原始样本 + _quarantine/ + unpacked/
exports/      → 工具输出（triage/IOC/YARA/Sigma/Procmon/Ghidra summary）
patches/      → patch 产物（不修改原始样本）
notes/        → 分析笔记
reports/      → 最终报告
scripts/      → 自动化脚本
projects/     → Ghidra 项目文件
templates/    → 笔记/报告/规则模板
kb/           → 可复用攻击知识库
tools/        → 工具链
cases/        → 轻量索引，不复制大文件
```

## 安装

Windows 新手优先双击根目录的 `START_HERE.bat` 或 `START_HERE.cmd`。它会自动检查
Python / uv / Git / `reverse_lab_tools` MCP、生成核心 wrappers，给出缺失项安装建议，
真实调用 MCP 核心工具，并写入 `reports/misc/first-run-report.json` 与
`reports/misc/mcp-smoke-report.json`。

想让 AI 代装时，复制 [给 AI 的安装提示词](templates/prompts/ai-install.zh.md) 给 Codex 或 Claude Code。
不知道从哪里开始时，先看 [START.md](START.md)。

```powershell
git clone https://github.com/LING71671/open-reverselab.git
cd open-reverselab
python scripts/misc/first_run_check.py       # 确认目录和 reverse_lab_tools MCP
uv run --project tools/skills/mcp/ReverseLabToolsMCP python scripts/misc/mcp_smoke_check.py --write-report
.\scripts\misc\bootstrap.ps1                 # 生成核心脚本 wrappers
.\scripts\misc\install_tools.ps1 -CTF       # Web 工具
.\scripts\misc\install_tools.ps1 -Android   # APK 工具
.\scripts\misc\install_tools.ps1 -Windows   # PE 工具
.\scripts\misc\install_tools.ps1 -Common    # Ghidra + Maven
```

## Agent 快速打开

1. 克隆到一个固定本地目录，例如 `<workspace>/open-reverselab`。
2. Windows：双击 `START_HERE.bat` 或 `START_HERE.cmd` 完成首次检查。
3. Claude Code：先 `cd <workspace>/open-reverselab`，再启动会话。
4. Codex APP：直接打开现有的 `open-reverselab` 文件夹。
5. AI 代装：复制 [templates/prompts/ai-install.zh.md](templates/prompts/ai-install.zh.md) 里的提示词。
6. 创建任务：`python scripts/misc/new_task.py --board ctf-website --name <name>`。
7. 每次换机器或重配 MCP 后，运行 `uv run --project tools/skills/mcp/ReverseLabToolsMCP python scripts/misc/mcp_smoke_check.py --write-report`，确认 MCP 真实可调用。

## 迭代模式

```
打靶 (Playwright/浏览器自动化)    提取增量                写/改 制品             同步 open-reverseLab
─────────────────────────  →  ──────────────  →  ──────────────────────  →  ───────────────────
攻破 Lab / CTF               判断是否新增技巧        kb/   技术文档           git commit (案例不推)
截图验收                     仅增强有差异的点        scripts/ 自动化脚本      技术制品开源
                             无则不硬改             templates/ 模板
                                                   tools/   工具
```

**规则**：
1. 每个 Lab 攻破后判断是否有**新技巧**，有则落成制品，无则不硬写
2. 制品优先追加/插入，保持原文风格不变
3. 案例细节留私库，通用化技术写入制品后同步开源

## 链路

启动时 Agent 沿此链路加载上下文：

```
CLAUDE.md → AGENTS.md → AI-USAGE.md → boards/<board>/AI-USAGE.md
```

搭配 [codex-session-patcher](https://github.com/ryfineZ/codex-session-patcher) 一键配置项目级 `.codex/` 环境与 MCP 服务器。

## 免责声明

**访问或使用本项目即表示同意受完整免责声明的约束。**

声明涵盖：所有版本与分支（追溯及前瞻）、所有使用者（直接与间接）、所有衍生作品（fork、复制、再分发）、全部司法管辖区的法律合规（含出口管制与数据保护法）、仅限授权用途、禁止用途、无担保、责任限制与赔偿、衍生作品强制保留声明、禁止移除条款、教育性沟通保护。

> 📄 阅读完整免责声明：[DISCLAIMER.zh.md](DISCLAIMER.zh.md) | [English](DISCLAIMER.md)

## 许可

GPL-3.0-only. 详见 [LICENSE](LICENSE)。
