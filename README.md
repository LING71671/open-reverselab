# ReverseLab

License: **GPL-3.0-only**. See [LICENSE](LICENSE).

开源逆向工程实验环境 —— 面向 Android / Windows / Web CTF 的二进制分析与漏洞研究框架。目录即约定，AI 友好。

> 公共仓库只包含通用框架、模板和合成测试数据。私人样本、case、日志、目标信息、
> 凭据和个人信息不属于迁移范围，详见 [PUBLICATION.md](PUBLICATION.md)。

## 谁适合用

- **Web CTF 选手** — 50+ 篇可运行的技术文档 + 一键安装全工具链
- **二进制分析师** — PE/APK 分析模板、Ghidra 集成、Frida 脚本
- **AI Agent 用户** — 搭配 [codex-session-patcher](https://github.com/ryfineZ/codex-session-patcher) 实现 Agent 自动路由

## 快速开始

```powershell
git clone https://github.com/LING71671/open-reverselab.git
cd open-reverselab
```

## 使用方法(下面场景一，二都是人工智能瞎写的，嗯，使用方法就是打开codex，cc，直接说话，AI会干这些事情的😂)

### 场景一：Web CTF

```powershell
# 1. 装工具
.\scripts\misc\install_tools.ps1 -CTF

# 2. 建题目 case
.\scripts\ctf-website\ctf_new_challenge.ps1 -Name mychall -Url https://target.com

# 3. 按信号搜攻击技术
python scripts/ctf-website/kb_router.py "jwt"
python scripts/ctf-website/kb_router.py "sql injection"

# 4. 读技术文件，复制伪代码，改 URL，跑
#    技术文件在 kb/ctf-website/techniques/

# 5. 输出放 cases/mychall/ → exports/ → reports/
```

### 场景二：二进制分析 (PE/APK)

```powershell
# 1. 装工具
.\scripts\misc\install_tools.ps1 -Windows    # PE 分析
.\scripts\misc\install_tools.ps1 -Android    # APK 分析

# 2. 样本放 samples/<board>/
# 3. triage → 静态分析 → 动态分析 → 报告
#    模板: templates/notes/sample-analysis.md
#    Ghidra MCP: 启动后 AI 可自动分析
```

### 场景三：AI Agent 模式

```powershell
# 1. 配置 codex-session-patcher（一次性）
#    https://github.com/ryfineZ/codex-session-patcher

# 2. 安装推荐 skills
#    见 SKILLS.md

# 3. 启动 Claude Code 或 Codex
#    AI 自动读取 CLAUDE.md → AGENTS.md → AI-USAGE.md
#    通过 kb_router 查技术，MCP 工具执行分析

# 4. 检查 AI 环境
python scripts/misc/lab_healthcheck.py
```

## AI Entry

| 文件 | 作用 |
|---|---|
| [CLAUDE.md](CLAUDE.md) | Claude Code 入口，启动时自动加载 |
| [AGENTS.md](AGENTS.md) | Agent 行为约定 + 默认分析流程 |
| [AI-USAGE.md](AI-USAGE.md) | 全局任务路由表 + 跨板块联动规则 |
| [SKILLS.md](SKILLS.md) | 推荐安装的 skills |
| [boards/README.md](boards/README.md) | Board 索引（Android / Windows / CTF / Misc） |

**Claude Code** — 启动时自动读取 `CLAUDE.md`，沿链路依次路由至各文件。

**Codex** — 搭配 [codex-session-patcher](https://github.com/ryfineZ/codex-session-patcher) 一键配置项目级 `.codex/` 环境与 MCP 服务器。

## Boards

| Board | 领域 | 入口 |
|---|---|---|
| CTF Website | Web CTF、JS hook、HTTP payload、CVE 链 | [boards/ctf-website](boards/ctf-website/README.md) |
| Android | APK、DEX、Frida、重打包、签名 | [boards/android](boards/android/README.md) |
| Windows | PE、x64dbg、Ghidra、Procmon、YARA/Sigma | [boards/windows](boards/windows/README.md) |
| Misc | MCP、skill、自动化、环境自检 | [boards/misc](boards/misc/README.md) |

## 知识库（kb/）

13 个技术分类，60+ 文件，每篇包含可运行的伪代码：

| 编号 | 分类 | 文件数 | 示例 |
|---|---|---|---|
| 01 | Recon | 2 | 端口扫描、目录爆破、版本指纹 |
| 02 | Auth | 14 | JWT 九大攻击链、OAuth/SSO/SAML/LDAP |
| 03 | Injection | 7 | SQLi、SSTI、GraphQL、Prototype Pollution |
| 04 | SSRF | 2 | SSRF 内网探测、Open Redirect 链 |
| 05 | Deserialization | 1 | PHP/Java/Python 反序列化 |
| 06 | File Attacks | 1 | 文件上传 / XXE / LFI |
| 07 | Client | 6 | XSS、CORS/CSRF、PostMessage、WebSocket |
| 08 | Infra | 3 | HTTP Smuggling、Cache Poisoning、Race Condition |
| 09 | CVE | 3 | CVE 关联图谱、多 CVE 链 playbook |
| 10 | Cloud | 3 | CI/CD、K8s、Serverless |
| 11 | Supply Chain | 1 | 依赖混淆 |
| 12 | Payment | 6 | 支付逻辑绕过、回调异步利用、数字商品 |
| 13 | Signature | 7 | API 签名攻击全链 |

```powershell
# 入口
python scripts/ctf-website/kb_router.py "<信号>"
```

## 目录结构

| 目录 | 职责 |
|---|---|
| [samples/](samples/) | 原始样本 + `_quarantine/` 隔离区 + `unpacked/` 解包产物 |
| [projects/](projects/) | Ghidra、apktool、调试器项目文件 |
| [exports/](exports/) | 工具导出、triage、IOC、YARA/Sigma、Procmon |
| [patches/](patches/) | patched binary / APK、补丁实验 |
| [notes/](notes/) | 手工分析笔记 |
| [reports/](reports/) | 最终报告、自动化报告 |
| [scripts/](scripts/) | Frida、Python、Ghidra Java、PowerShell 脚本 |
| [tools/](tools/) | 工具链（按 Android / Windows / CTF / Common / Skills 拆分） |
| [cases/](cases/) | 跨板块 case 索引，轻量链接 |
| [templates/](templates/) | 笔记、case、报告、YARA/Sigma 模板 |
| [kb/](kb/) | 可复用知识库 |

## 工具安装

按需装，不用全下：

```powershell
.\scripts\misc\install_tools.ps1 -CTF          # sqlmap, dirsearch, jwt_tool, nmap, ffuf, nuclei...
.\scripts\misc\install_tools.ps1 -Android      # apktool, jadx, uber-apk-signer, frida
.\scripts\misc\install_tools.ps1 -Windows      # Cutter, PE-bear, DiE, HxD, Procmon
.\scripts\misc\install_tools.ps1 -GoTools      # ffuf, gobuster, httpx, nuclei, katana
.\scripts\misc\install_tools.ps1 -Common       # Ghidra, Apache Maven
.\scripts\misc\install_tools.ps1 -All          # 全装
```

每个工具目录内也有独立的 `README.md`，包含手动下载链接。

## 常用命令

```powershell
# 环境自检
python scripts/misc/lab_healthcheck.py

# 工具可用性检查
python scripts/misc/ai_toolcheck.py

# CTF 工具巡检
.\scripts\ctf-website\ctf_toolcheck.ps1

# 建新 CTF 题目
.\scripts\ctf-website\ctf_new_challenge.ps1 -Name <name> -Url <url>

# CTF 环境验证（需要 codex-session-patcher）
.\scripts\misc\verify_codex_ctf_profile.ps1

# CVE 流水线冒烟测试
.\scripts\ctf-website\smoke_cve_pipeline.ps1
```

## 分析模板

| 模板 | 用途 |
|---|---|
| [sample-analysis.md](templates/notes/sample-analysis.md) | 通用二进制分析笔记（13 节标准结构） |
| [android-apk-analysis.md](templates/notes/android-apk-analysis.md) | APK 专项 |
| [windows-pe-analysis.md](templates/notes/windows-pe-analysis.md) | PE 专项 |
| [ctf-website-writeup.md](templates/notes/ctf-website-writeup.md) | Web CTF Writeup |
| [final-report.md](templates/reports/final-report.md) | 正式分析报告 |
| [patch-report.md](templates/reports/patch-report.md) | Patch 报告 |
| [yara-rule.yar](templates/rules/yara-rule.yar) | YARA 规则模板 |
| [sigma-rule.yml](templates/rules/sigma-rule.yml) | Sigma 规则模板 |

## Placement Rules

- 样本 → `samples/<board>/`，恶意/未确认 → `samples/_quarantine/`
- 工具输出 → `exports/<board>/`，跨领域 → `exports/_shared/`
- 修改产物 → `patches/<board>/`
- 脚本 → `scripts/<board>/`，跨领域 → `scripts/_shared/`
- 笔记 → `notes/<board>/`，报告 → `reports/<board>/`
- Case 只建索引，不复制大文件

## 依赖

- [codex-session-patcher](https://github.com/ryfineZ/codex-session-patcher) — AI Agent 项目级配置
- Git、Python 3、Java（部分工具需要）

## 贡献

知识库技术文档欢迎各位大佬提 PR 补充、纠错、扩展：

- `kb/ctf-website/techniques/` — 补充攻击技术文档（伪代码优先，能直接跑）
- `scripts/` — 完善工具脚本
- `templates/` — 优化分析模板
- `tools/` — 补充工具安装说明

提交前请运行 `python scripts/misc/public_release_check.py`，并遵守
[CONTRIBUTING.md](CONTRIBUTING.md)。
