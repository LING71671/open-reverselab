# Changelog

All notable changes to the open-reverseLab project will be documented in this file.

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
