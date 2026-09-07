# Changelog

All notable changes to the open-reverseLab project will be documented in this file.

## [1.2.1] - 2026-09-07

单一 release 标签 `v1.2.1`。本版本为纯文档 / 品牌变更，无分平台产物差异，也不需要重新下载工具链。

### Changed — README 重设计

- `docs(readme)`：重写 `README.md` 与 `README.zh.md`，对用户 / 赞助者 / 维护者三类受众都更友好：
  - 顶部居中 hero + 一句话定位 + 5 个浅色徽章（Docs / Discord / DeepWiki / License / Sponsor）
  - **新增「Sponsored by Sentry」赞助位**，紧跟 hero，使用 `<picture>` 暗 / 亮双 wordmark 显著展示
  - 新增「What is ReverseLab / 这是什么」「Who is this for / 适合谁」定位与受众说明
  - 「快速开始」按角色拆分为「For humans / 给真人」与「For AI Agents / 面向 AI Agent」两段，长命令用 `<details>` 折叠
  - 知识库统计改为「180+ 篇文章」口径，避免每次新增文章都要改单元格
  - 链接到 `reverselab.int0.cc` 文档站作为权威信息源（站点是每次部署重新生成的）
  - 「Sponsors」独立区块，二次露出 Sentry 并附赞助入口（`SPONSORS.md` + 邮箱）
- `feat(assets)`：新增 `assets/sponsors/sentry-wordmark-light.svg` 与 `sentry-wordmark-dark.svg`（Sentry 品牌色 `#362D59` + 自适配暗色）
- `docs(readme)`：**中文改为默认语言** —— `README.md` 现为中文版，英文版移至 `README.en.md`，原 `README.zh.md` 移除（与 v1.2.0「后续以中文为主 + EN/ZH 双版并存」的方向一致）；两版顶部均加语言切换行（`简体中文 · English`）
- `docs(sponsors)`：赞助方表格由 markdown 表格改为 `<table width="100%">` HTML 表格并新增 Logo 列（Sentry wordmark 直接入表），解决宽屏下表格不撑满、内容单薄的问题；`README.md` / `README.en.md` / `SPONSORS.md` 三处同步
- `docs(sponsors)`：赞助联系邮箱更新为 **belloshehubz@gmail.com**（原 `lingmoumou53@gmail.com`），`README.md` / `README.en.md` / `SPONSORS.md` 三处同步

### Fixed

- README 中所有引用文件均已对照 git 索引（`START.md` / `START_HERE.bat` / `START_HERE.cmd` / `START_HERE.sh` / `.github/CONTRIBUTING.md` / `.github/CODE_OF_CONDUCT.md` / `SPONSORS.md`），不再有指向不存在文件的链接

## [1.2.0] - 2026-09-06

单一 release 标签 `v1.2.0`（本版本无分平台产物差异）。

### Added — 文档站点与知识库

**VitePress 站点上线（Cloudflare Pages）**
- `feat(site)`：站点部署至 `reverselab.int0.cc`，含工具页、FAQ、自定义 404 与社交预览图
- CI 自动部署（`deploy-site.yml`）；social preview 生成脚本跨平台化，PNG 直接入库
- 板块徽章移除 emoji，改用色点标识

**知识库扩充**
- `feat(kb)`：新增 VMP 虚拟化与反虚拟化技术覆盖
- 新增 license-keygen 技术分类（10 分类 / 31 篇）
- 集成 reverse-skills workflows

**项目文档**
- English README 设为默认、中文版移至 `README.zh.md`（后续以中文为主 + EN/ZH 双版并存）
- 新增 DeepWiki badge、`SPONSORS.md`（Sentry 致谢）、Contributor Covenant Code of Conduct、非商业声明
- AI 环境快照协议（首次运行 `env.md` 探测）
- Discord 风格 22 主题渐变切换器
- 清理：移除 QQ 群、仅保留 Discord 邀请链接；修复死链并恢复 JSHookLocal 上游
- prompts：平台感知的 AI 安装提示，并忽略嵌套项目

### Fixed — Windows CI / 中文输出

- 全局设置 `PYTHONIOENCODING=utf-8`；`ai_context` / `ai_toolcheck` 强制 UTF-8 stdout（修复 CJK 上下文 JSON 异常）
- `kb_router` 返回 POSIX 风格路径（Windows CI 测试修复）
- toolcheck 失败详情截断上限提升至 1500 字符（便于 CI 排障）
- 处理 Windows 首次运行 UX 建议（issue #13）
- 忽略本地 `.reasonix` 目录与生成的社交预览图

### Notes

- 英文站点（`site/en`）工作仍在进行中，未纳入本版本。

## [1.1.0] - 2026-07-08

分平台 release 标签：

- `v1.1.0-macos-linux` — POSIX 核心版（macOS 与 Linux 共用）
- `v1.1.0-windows` — Windows 完整工具链版

### Added — macOS/Linux core release (`v1.1.0-macos-linux`)

**POSIX 入口与 wrapper**
- `START_HERE.sh` — macOS/Linux 首次运行检查入口
- `scripts/misc/bootstrap.sh` — 生成 `tools/bin/ai_*` shell wrapper
- `tools/bin/ai_context` / `ai_tool` / `ai_finding` / `ai_toolcheck` — 无扩展名 POSIX wrapper

**跨平台工具路由**
- `ai_tool.py` / `ai_toolcheck.py` — 注册表反斜杠路径归一化、`.bat/.cmd` POSIX fallback、`python` → 当前解释器 fallback
- `tools/ai-tool-registry.json` — `path_bootstrap_unix`、Windows GUI 工具 `platforms: ["windows"]`
- MCP：`config.py` / `toolbox.py` / `web_ctf.py` / `android_mumu.py` — Ghidra/Rizin/adb/CTF 工具平台感知；Windows-only 工具链明确降级

**文档**
- README / README.zh / tools/bin / scripts/misc — macOS/Linux quick start 与分平台 release 说明

### Release notes

- **macOS/Linux**（`v1.1.0-macos-linux`）：clone 后运行 `./START_HERE.sh`，再执行 `./scripts/misc/bootstrap.sh` 并 `export PATH="$PWD/tools/bin:$PWD/tools/ctf-website/bin:$PATH"`。本 release 聚焦 Python/MCP core、shell wrapper 与 PATH 中已安装的 native CLI 工具。
- **Windows**（`v1.1.0-windows`）：双击 `START_HERE.bat`，运行 `scripts/misc/bootstrap.ps1` 与 `scripts/misc/install_tools.ps1` 安装完整 GUI/PE 工具链。

## [1.0.0] - 2026-06-25

### Added — 首次公开发布

**知识库（Knowledge Base）**
- 197 篇逆向工程技术文章，覆盖 5 个板块
  - CTF Website: 23 分类 97 篇 — Web 攻击全表面（JWT/SQLi/SSRF/XSS/CSRF/CORS/OAuth/CVE/DoS/Payment/签名攻击/Paywall 绕过等）
  - APK Reverse: 8 分类 17 篇 — DEX/Java、Native（IL2CPP/UE4）、加密破解、网络协议、动态 Hook、脱壳、重打包
  - PE Reverse: 8 分类 18 篇 — Triage、PE 结构、静态分析（Ghidra）、动态分析（x64dbg/Frida）、加密脱壳、IOC 提取、YARA/Sigma、Patch、免杀
  - General: 12 篇 — Linux 内核利用、加密算法识别、PRNG 破解、游戏作弊/反作弊、协议逆向、Protobuf、方法论
  - Windows: 1 篇 — notepad++ 配置注入
- 每篇文章包含：场景→输入信号→方法→攻击链→MCP 工具映射
- 4 个 attack-network.md Mermaid 攻击图谱
- CTF Website checklist（攻击矩阵、证据收集、30 分钟速查）

**MCP 工具生态（100+ MCP 工具）**
- CTF/Web 工具族: `http_probe`, `run_ctf_tool`, `kb_router`, `kb_read_file`, `kb_catalog`
- Android 工具族: `android_app_baseline`, `android_crypto_unpack_recipe`, `android_frida_*`, `android_http_observation_recipe`, `android_package_*`, `android_adb_*`
- PE/Windows 工具族: `triage_pe`, `ghidra_headless_analyze`, `ghidra_summary_*`, `make_x64dbg_breakpoint_script`, `make_pe_crypto_unpack_plan`, `sample_full_workup`
- 通用工具族: `die_scan`, `rizin_*`, `solve_crypto_from_evidence`, `make_crypto_replay_scaffold`, `python_re_tool_*`
- 运维工具: `copy_sample`, `patch_bytes`, `quarantine_sample`, `hash_file`, `search_pattern`, `carve_payloads_from_dump`

**自动化工作流**
- CTF 全链路流水线: 资产发现 → DoS 攻击面评估 → 全面漏洞挖掘 → 漏洞逐条验证 → 综合报告
- 样本全流程分析: triage → Ghidra 无头分析 → IOC/YARA/Sigma → patch → 免杀
- CI/CD: `release-check.yml` — 发布前隐私扫描、健康检查、工具状态、KB 文档审计、pytest

**框架与约定**
- 目录即约定的项目结构（samples/exports/patches/notes/reports/scripts/projects/templates/kb/tools/cases）
- 5 板块路由架构: ctf-website / apk-reverse / pe-reverse / general / windows
- Agent 原生上下文链: CLAUDE.md → AGENTS.md → AI-USAGE.md → boards/<board>/AI-USAGE.md
- 公开/私有边界约定: `PUBLICATION.md`
- 代码共献指南: `.github/CONTRIBUTING.md`
- 安全策略: `SECURITY.md`
- GPL-3.0-only 许可证
