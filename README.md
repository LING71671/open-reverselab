<div align="center">

# ReverseLab

**开源逆向工程实验环境 —— 可执行的知识库，100+ MCP 工具，Agent 原生。**

*从入口信号到证据闭环，每一步都能跑。*

<br />

[![文档站](https://img.shields.io/badge/docs-reverselab.int0.cc-3D4F8C?style=flat-square&logo=gitbook&logoColor=white)](https://reverselab.int0.cc)
[![Discord](https://img.shields.io/badge/Discord-join-5865F2?style=flat-square&logo=discord&logoColor=white)](https://discord.gg/But5j58J2f)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/LING71671/open-reverselab)
[![License: GPL-3.0](https://img.shields.io/github/license/LING71671/open-reverselab?style=flat-square&color=blue)](LICENSE)
[![Sponsor: Sentry](https://img.shields.io/badge/sponsored%20by-Sentry-362D59?style=flat-square&logo=sentry&logoColor=white)](#sponsors)

**简体中文** · [English](README.en.md)

</div>

---

## :handshake: Sentry 赞助

<div align="center">

**[Sentry](https://sentry.io)** 为 `openreverselab` 提供赞助账户 —— 错误监控与性能追踪平台，覆盖实验室全工具链。

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/sponsors/sentry-wordmark-dark.svg">
  <img src="assets/sponsors/sentry-wordmark-light.svg" width="220" alt="Sentry">
</picture>

<sub>自 2026 年 8 月起 —— 完整赞助名单与赞助方式见 <a href="SPONSORS.md">SPONSORS.md</a>。</sub>

</div>

---

## 这是什么

ReverseLab 是一份「观点鲜明、可直接跑」的逆向工程攻击知识库，面向逆向工程师、安全研究员、CTF 选手与 AI Agent。每篇文章的结构都是 **`场景 → 输入信号 → 方法 → 攻击链 → MCP 工具映射`**，让人或 Agent 都能从任意入口信号出发，沿着攻击链走到证据闭环。

- **5 大板块**，覆盖 Web、移动端、Windows、跨领域逆向。
- **180+ 篇文章**，按攻击面而非按工具组织。
- **100+ MCP 工具**，通过 `reverse_lab_tools` 暴露 —— curl / frida / ghidra / rizin / yara / triage / kb_router … 都能在 Claude Code、Codex 或任何 MCP 兼容的 Agent 中直接调用。
- **目录即约定**：每个产物都有固定归宿（`samples/` / `exports/` / `patches/` / `kb/` / `reports/`）。样本丢进去，沿链走完，报告交出来。

实验室是用来「跑」的，不是用来「翻」的。如果某一步不能被执行，它就不该进 KB。

## 适合谁

| 你是 … | 从这里开始 |
| --- | --- |
| 在 **CTF 比赛** 中卡在 Web / Android / PE 题 | 浏览 [CTF Website](https://reverselab.int0.cc/kb/ctf-website/README)、[APK Reverse](https://reverselab.int0.cc/kb/apk-reverse/README)、[PE Reverse](https://reverselab.int0.cc/kb/pe-reverse/README) 板块 |
| 拿到一个样本的 **安全研究员** | [快速开始](#快速开始) → `boards/<board>/AI-USAGE.md` → `sample_full_workup` MCP 工具 |
| 只想要一个工作区、不想看教程的 **逆向工程师** | [仓库目录约定](#仓库目录约定) —— clone 下来直接开工 |
| 想给逆向工具接 **AI Agent** 的开发者 | [面向 AI Agent](#面向-ai-agent) —— 上下文链、MCP 烟测、环境快照协议 |

## 快速跳转

<div align="center">

[ :book: 文档站 ](https://reverselab.int0.cc)
&nbsp;&nbsp;[ :rocket: 快速开始 ](#快速开始)
&nbsp;&nbsp;[ :toolbox: MCP 工具 ](https://reverselab.int0.cc/mcp-tools)
&nbsp;&nbsp;[ :question: FAQ ](https://reverselab.int0.cc/faq)
&nbsp;&nbsp;[ :handshake: 参与贡献 ](.github/CONTRIBUTING.md)
&nbsp;&nbsp;[ :speech_balloon: Discord ](https://discord.gg/But5j58J2f)

</div>

---

## 知识库速览

```
kb/                                180+ 篇文章，5 大板块
├── ctf-website/techniques/        26 类 118 篇 —— Web 攻击全表面
├── apk-reverse/techniques/         8 类  23 篇 —— Android 逆向
├── pe-reverse/techniques/          9 类  24 篇 —— Windows PE / 二进制
├── general/techniques/             5 类  17 篇 —— 密码学 · 协议 · 作弊 · IoT · SDR
└── windows/techniques/             Windows 平台专项
```

| 板块 | 触发信号 | MCP 入口 |
| --- | --- | --- |
| `ctf-website` | URL · HTTP · JWT · SQLi · SSRF · CVE · API · CSP · OAuth · CAPTCHA · Cloudflare · ReDoS · Slowloris · DoS · Paywall | `http_probe`、`run_ctf_tool`、`kb_router` |
| `apk-reverse` | APK · DEX · adb · Frida · jadx · smali · SO · native | `android_app_baseline`、`android_crypto_unpack_recipe`、`android_frida_*` |
| `pe-reverse` | PE · EXE · DLL · x64dbg · Ghidra · Procmon · packer · malware | `triage_pe`、`ghidra_headless_analyze`、`make_x64dbg_breakpoint_script`、`sample_full_workup` |
| `general` | AES · DES · RSA · protobuf · 游戏作弊 · EAC / BE / Vanguard · 固件 · JTAG · SDR | `die_scan`、`ghidra_*`、`rizin_*`、`python_re_tool_*` |
| `misc` | MCP 配置 · skill 安装 · 环境自检 | `mcp_smoke_check`、`ai_toolcheck`、`lab_healthcheck` |

完整、自动重建的目录树见 <https://reverselab.int0.cc/kb>。

---

## 快速开始

按你的角色选路径，平台差异在下面分别给出。

### 给真人用户

**Windows（首次运行推荐）** —— 双击仓库根目录的 `START_HERE.bat`（或 `START_HERE.cmd`）。它会自动检查 Python、`uv`、Git、`reverse_lab_tools` MCP，真实调用 MCP 核心工具，并写入 `reports/misc/first-run-report.json` 与 `reports/misc/mcp-smoke-report.json`。

**macOS / Linux** —— 在仓库根目录运行 `./START_HERE.sh`。它做同样的首次检查，并使用 `tools/bin/` 下的 POSIX shell wrapper；Windows 专属的 GUI / PE 工具会被跳过或明确标注。

<details>
<summary><b>按板块安装（首次检查通过后）</b></summary>

```powershell
# 按需选择 —— 实验室是模块化的，不要全装
.\scripts\misc\bootstrap.ps1                # 生成核心脚本 wrappers（无下载）
.\scripts\misc\install_tools.ps1 -CTF       # Web 工具（sqlmap、nuclei、ffuf、jwt_tool …）
.\scripts\misc\install_tools.ps1 -Android   # APK 工具（apktool、jadx、frida、uber-apk-signer …）
.\scripts\misc\install_tools.ps1 -Windows   # PE 工具（cutter、pe-bear、procmon …）
.\scripts\misc\install_tools.ps1 -Common    # Ghidra + Maven
```

macOS / Linux 等价命令：

```sh
./scripts/misc/bootstrap.sh
export PATH="$PWD/tools/bin:$PWD/tools/ctf-website/bin:$PATH"
python scripts/misc/ai_toolcheck.py --board misc    # 校验最小化核心
```

只装你需要的板块。纯做 Web CTF，就别下整个工具链。

</details>

<details>
<summary><b>Windows Defender / 安全软件提示</b></summary>

安装 CTF / ExploitDB 相关工具后，Windows 安全中心可能对漏洞样本、payload 文档报毒 —— 例如 `tools/ctf-website/exploitdb`、`kb/ctf-website/techniques/24-database/03-nosql-injection.md`、`docs/llms-full.txt`。这些文件包含安全测试 payload、webshell、shellcode 或 ExploitDB 样本，**属于正常内容**。

建议**最小范围排除**而不是排除整个仓库：

```powershell
Add-MpPreference -ExclusionPath "D:\open-reverselab\tools\ctf-website\exploitdb"
```

如果个别文档也被拦截，再只针对具体文件处理。

</details>

### 面向 AI Agent

1. 克隆到一个固定的本地目录，例如 `<workspace>/open-reverselab`。
2. **Claude Code**：先 `cd <workspace>/open-reverselab`，再启动会话。
3. **Codex APP**：直接打开现有的 `open-reverselab` 文件夹（无需重新 clone）。
4. 想让 AI 代装：把 [`templates/prompts/ai-install.zh.md`](templates/prompts/ai-install.zh.md) 整段提示词发给 Agent。
5. 创建任务：`python scripts/misc/new_task.py --board ctf-website --name <name>`。
6. 每次换机器或重配 MCP 后，确认 MCP 真实可调用：
   ```sh
   uv run --project tools/skills/mcp/ReverseLabToolsMCP \
     python scripts/misc/mcp_smoke_check.py --write-report
   ```

**上下文链** —— 启动时 Agent 沿此链路加载上下文：

```
CLAUDE.md → AGENTS.md → AI-USAGE.md → boards/<board>/AI-USAGE.md
```

搭配 [codex-session-patcher](https://github.com/ryfineZ/codex-session-patcher) 一键配置项目级 `.codex/` 与 MCP 服务器。

<details>
<summary><b>环境快照协议（本机级、跨项目共享）</b></summary>

首次用 AI 打开本项目时，Agent 会按 [AGENTS.md 的「环境快照协议」](AGENTS.md) 自动探测本机环境（系统、开发环境、逆向工具链、Python 逆向库、设备、环境变量脱敏、网络、工作区），并写入本机 `~/.open-reverselab/env/env.md`（Windows 为 `%USERPROFILE%\.open-reverselab\env\env.md`）。

该文件是**本机级**快照，**跨项目共享**：之后每次新开会话 / 新开文件夹，Agent 直接读取，只有超过 7 天或协议版本升级时才自动重新探测。快照只存本机约定路径，不会进入仓库；环境变量按协议脱敏（密钥类只标"已设置"，代理去除 userinfo）。

</details>

### 安装后校验

```sh
python scripts/misc/lab_healthcheck.py
python scripts/misc/ai_toolcheck.py --board misc
python scripts/misc/public_release_check.py
```

`--board misc` 校验 fresh-clone 下的核心 Agent 脚本与轻量工具。完整 `python scripts/misc/ai_toolcheck.py` 跑全板块工具链校验，只有在你装完 Android / Windows / CTF 板块工具链之后才需要跑。

---

## 仓库目录约定

仓库遵循**目录即约定**。把产物放对位置，剩下的工具链会自动找过来。

```
samples/      原始样本 + _quarantine/ + unpacked/   —— 永不修改
exports/      工具输出（triage / IOC / YARA / Sigma / Procmon / Ghidra 摘要）
patches/      patch 产物（原始样本永不修改）
notes/        分析笔记
reports/      最终报告
scripts/      自动化脚本
projects/     Ghidra 项目文件
templates/    笔记 / 报告 / 规则模板 · AI 安装提示词
kb/           可复用攻击知识库 —— 见「知识库速览」
tools/        工具链（二进制、wrapper、registry、MCP）
cases/        轻量索引 —— 不复制大文件
```

> 不要直接 commit 大样本、完整 PCAP、内存 dump。在 `cases/` 里建索引，链接到私有存储。

---

## 文档站

完整、版本化的文档站在 **[reverselab.int0.cc](https://reverselab.int0.cc)** —— 每次 push 到 `main` 自动从 `site/` 重建，包含：

- 完整 KB 目录树（每个板块、每个分类、每篇文章）
- MCP 工具目录，按板块展示安装状态
- 常见设置问题的 FAQ
- 文件改名后能指回 GitHub 的自定义 404

如果这里的描述和站点有出入，**以站点为准** —— 它每次部署都从源文件重新生成。

---

## 社区与贡献

- **Discord** —— [discord.gg/But5j58J2f](https://discord.gg/But5j58J2f)。问「这个怎么搞」的首选去处。
- **贡献指南** —— 见 [`.github/CONTRIBUTING.md`](.github/CONTRIBUTING.md)。欢迎提 Issue、提交 KB 文章 PR、新增 MCP wrapper、添加新板块。
- **行为准则** —— [`.github/CODE_OF_CONDUCT.md`](.github/CODE_OF_CONDUCT.md)（Contributor Covenant）。
- **安全问题** —— 公开提 Issue 前请先看 [SECURITY 策略](SECURITY.md)。
- **发布守则** —— [PUBLICATION.md](PUBLICATION.md) 涵盖什么可以公开发布、什么保留在私有 cases，以及 AI/ML 训练保护条款。

---

## 赞助方

ReverseLab 的持续运营靠的是为基础设施、工具、审稿时间投入资源的人与组织。

<table width="100%">
  <thead>
    <tr>
      <th width="180" align="left">Logo</th>
      <th align="left">赞助方 / Sponsor</th>
      <th width="110" align="left">时间 / Since</th>
      <th align="left">支持内容 / Support</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td align="left" valign="middle">
        <a href="https://sentry.io"><picture>
          <source media="(prefers-color-scheme: dark)" srcset="assets/sponsors/sentry-wordmark-dark.svg">
          <img src="assets/sponsors/sentry-wordmark-light.svg" width="150" alt="Sentry">
        </picture></a>
      </td>
      <td valign="middle"><strong><a href="https://sentry.io">Sentry</a></strong></td>
      <td valign="middle">2026-08</td>
      <td valign="middle">赞助账户 —— 错误监控与性能追踪平台（error monitoring &amp; performance tracing）</td>
    </tr>
  </tbody>
</table>

**想成为赞助方？** 见 [SPONSORS.md](SPONSORS.md)，或邮件联系 **belloshehubz@gmail.com** —— 无论大小，每一位赞助者都会被列出，并注明所提供支持。

---

## 免责声明

**访问或使用本项目即表示同意受完整免责声明的约束。** 声明涵盖：所有版本与分支（追溯及前瞻）、所有使用者（直接与间接）、所有衍生作品（fork / 复制 / 再分发）、全部司法管辖区的法律合规（含出口管制与数据保护法）、仅限授权用途、禁止用途、无担保、责任限制与赔偿、衍生作品强制保留声明、AI/ML 训练保护等。

> :page_facing_up: 完整法律文本：[DISCLAIMER.zh.md](DISCLAIMER.zh.md) · [English](DISCLAIMER.md)

## 许可协议

**GPL-3.0-only。** 详见 [LICENSE](LICENSE)。贡献即表示你同意你的贡献以相同条款授权。
