<div align="center">

# Open ReverseLab

<img src="assets/social-preview-v2.png" width="960" alt="Open ReverseLab — AI reverse engineering workspace">

**面向目标的 AI 逆向分析工作台**

桌面工作区 · red / blue / both · 并行 Goal · 知识库 · MCP

<p><a href="README.md">English</a> · <strong>简体中文</strong></p>

<p><a href="#从源码运行桌面端"><strong>构建桌面预览版</strong></a> &nbsp; · &nbsp; <a href="desktop/README.zh-CN.md">桌面端说明</a> &nbsp; · &nbsp; <a href="https://ling71671.github.io/open-reverselab/">官网与文档</a> &nbsp; · &nbsp; <a href="kb/README.md">知识库</a></p>

[![Release](https://img.shields.io/github/v/release/LING71671/open-reverselab?include_prereleases&style=flat-square&color=242424)](https://github.com/LING71671/open-reverselab/releases)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-242424?style=flat-square)](LICENSE)
[![Ask DeepWiki](assets/badges/ask-deepwiki.svg)](https://deepwiki.com/LING71671/open-reverselab)

</div>

## 赞助支持

<table width="100%">
  <tr>
    <td width="46%" align="center" valign="middle"><a href="https://infistar.cc/register?aff=OPENREVERSELAB&amp;ref_source=link"><img src="assets/sponsors/infistar-banner-zh.png" width="420" alt="Infistar.cc — 统一多模型 API 接入"></a></td>
    <td valign="middle"><p><strong><a href="https://infistar.cc/register?aff=OPENREVERSELAB&amp;ref_source=link">Infistar.cc</a></strong></p><p>Claude、GPT、Gemini、Grok、DeepSeek，一个 Key，低至官方 0.1 折，省 99%。100% 官方纯血模型，每个模型都能验真，上千线路安全冗余自动切换，200+ 模型覆盖 16 个品牌。用多模型 API 驱动 AI 逆向分析和 MCP 工作流。</p><p><a href="https://infistar.cc/register?aff=OPENREVERSELAB&amp;ref_source=link"><strong>专属链接注册赠 ¥5 体验额度</strong></a></p></td>
  </tr>
  <tr>
    <td align="center" valign="middle"><a href="https://sentry.io"><picture><source media="(prefers-color-scheme: dark)" srcset="assets/sponsors/sentry-wordmark-dark.svg"><img src="assets/sponsors/sentry-wordmark-light.svg" width="150" alt="Sentry"></picture></a></td>
    <td valign="middle"><p><strong><a href="https://sentry.io">Sentry</a></strong></p><p>提供赞助账户，支持项目工具链的错误监控与性能追踪。</p></td>
  </tr>
</table>

<p align="center"><sub>完整赞助名单与合作方式见 <a href="SPONSORS_zh.md">赞助说明</a></sub></p>

## 桌面端

在左上角选择 `red / blue / both`，选好工作区，填写文件、目录或 URL 目标和任务内容。实时流程画板展示执行分支，执行记录、日志、报告和健康监控保留结论所依据的证据。

<img src="assets/desktop/knowledge-light.png" alt="Open ReverseLab 桌面端 both 模式下的知识库阅读界面" width="1280">

- **策略独立。** red 与 blue 分别维护分析策略，both 中两方均可规划多个动作，在执行中交换证据，各自核验后再核验完整目标。
- **多任务并行。** Goal 与就绪动作支持并行，应用不设置数量上限。切换页面、任务或工作区不会改变后台任务的输出归属。
- **工作区管理。** 首次启动创建默认工作区，也可新建或打开其他目录。导入样本时保留原件，另建工作副本。
- **目标控制。** 默认不设时间或 Token 上限，可按需填写，也可停止运行或中途补充要求。执行历史保留核验结果与失败尝试。
- **知识库与操作体验。** 支持 defense 文档、关联阅读、深浅主题；页面切换时保留未提交草稿、阅读位置和筛选条件。

### 下载与启动

`v2.0.0-beta.1` 桌面包已撤下，正在调整为桌面端与知识库独立分发，替代安装包尚未发布。目前可[从源码构建预览版](#从源码运行桌面端)。

1. 安装 Python 3.11 或更新版本，确保终端能执行 `python`。Windows 还需要 Microsoft Edge WebView2 Runtime。
2. 按[源码构建步骤](#从源码运行桌面端)启动，个人工作区放在源码目录之外。
3. 在设置中配置兼容 OpenAI chat-completions 的 API 地址和模型，再填写目标和任务内容。SHA256 核验可直接在本地运行，无需模型。

桌面端以 Windows x64 为打包目标，Python、Ghidra、Frida、x64dbg 等外部工具需另行安装。macOS/Linux 可使用源码形式的 CLI/MCP 工作流，暂未提供桌面安装包。安装版提供“测试版”和“稳定版”更新渠道，beta 构建初始选择测试版渠道，详见[应用更新](desktop/UPDATES.zh-CN.md)。

桌面端执行目标初筛与 Python 动作，默认不设工具时限。知识库中的 MCP 工具名不会自动成为调试器、设备或加固执行适配器。工作区文件保存在本地，模型辅助任务会把任务上下文和所选证据发送到配置的模型端点；Python 动作继承当前用户权限。配置、数据流向和能力范围见[桌面端说明](desktop/README.zh-CN.md)。

## 知识库与 MCP

独立知识包、MCP 扩展及 GitHub/ZIP 导入方案见[扩展设计](EXTENSIONS.zh-CN.md)。[创建 skill](tools/skills/create-reverselab-extension/SKILL.zh-CN.md) 提供草案模板与离线 ZIP 检查工具，应用导入器仍待开发。

知识库覆盖 Web/CTF、Android/APK、Windows/PE，以及密码学、协议等通用主题。文档用 `track: red | blue | both` 标记所属轨道，其中 `both` 表示共享。攻击与防御文档通过索引元数据和 `defends` 关联；实际目录为准，并非每篇文章都存在一对一对应项。

| 领域 | 知识入口 | 工具示例 |
| --- | --- | --- |
| Web / CTF | [Web 知识库](kb/shared/ctf-website/README.md) | `kb_router`、`http_probe`、`run_ctf_tool` |
| Android / APK | [APK 知识库](kb/shared/apk-reverse/README.md) | `android_app_baseline`、`android_crypto_unpack_recipe` |
| Windows / PE | [PE 知识库](kb/shared/pe-reverse/README.md) | `triage_pe`、`ghidra_headless_analyze`、`sample_full_workup` |
| 通用 | [跨领域知识库](kb/shared/general/README.md) | `solve_crypto_from_evidence`、`rizin_*` |

CLI/MCP 默认使用 `blue`，可通过 `REVERSELAB_MODE`、`--track` 或 MCP 轨道工具显式切换。桌面端的模式属于各自 Goal，不会改写其他客户端的环境变量。

```sh
python scripts/misc/kb_router.py "JWT" --track blue
python scripts/misc/desktop_kb.py list --track both
```

## CLI 与 AI Agent 入门

克隆仓库后，Windows 使用 `START_HERE.bat` / `START_HERE.cmd`，macOS/Linux 使用 `./START_HERE.sh`。这些入口负责环境和 MCP 检查，桌面程序单独启动。检查报告写入 `reports/misc/`。

```sh
git clone https://github.com/LING71671/open-reverselab.git
cd open-reverselab
```

在 AI 客户端打开目录并阅读 [AI-USAGE.md](AI-USAGE.md)。上下文链为 `CLAUDE.md → AGENTS.md → AI-USAGE.md → boards/<board>/AI-USAGE.md`。需要 AI 协助安装时使用[中文提示词](templates/prompts/ai-install.zh.md)。MCP 客户端需要 `uv` 和 `tools/skills/mcp/ReverseLabToolsMCP` 中的依赖。

```sh
uv sync --project tools/skills/mcp/ReverseLabToolsMCP
uv run --project tools/skills/mcp/ReverseLabToolsMCP python scripts/misc/mcp_smoke_check.py --write-report
python scripts/misc/lab_healthcheck.py
python scripts/misc/ai_toolcheck.py --board misc
```

按任务安装工具组。Windows 提供 `scripts/misc/install_tools.ps1 -CTF`、`-Android`、`-Windows`、`-Common`；POSIX wrapper 由 `scripts/misc/bootstrap.sh` 生成。详见 [START.md](START.md) 与 [tools/README.md](tools/README.md)。

## 从源码运行桌面端

准备 Node 22+、pnpm、Python、Rust 和当前平台的 Tauri 构建依赖：

```sh
cd desktop
pnpm install --frozen-lockfile
pnpm tauri dev
# 构建生产程序：
pnpm tauri build --no-bundle
```

`pnpm dev` 启动浏览器预览。详见[开发指南](desktop/DEV_GUIDE.zh-CN.md)、[架构图](desktop/ARCHITECTURE.zh-CN.md)、[Agent 契约](desktop/AGENT_SYSTEM.zh-CN.md)、[错误码](desktop/ERROR_CODES.zh-CN.md)和[发布说明](RELEASING.zh-CN.md)。

## 数据与目录

| 位置 | 用途 |
| --- | --- |
| `desktop/` | 桌面 UI、队列、执行引擎与 Tauri 宿主 |
| `kb/` | 通用技术与防御知识 |
| `scripts/`、`tools/`、`templates/` | 自动化脚本、适配器和模板 |
| `boards/` | 外部 AI 客户端的任务路由 |
| `site/` | 文档站源码 |
| 所选工作区的 `.reverselab/` | 桌面样本原件／副本、Goal、输出与报告 |
| 仓库内 `cases/`、`samples/`、`notes/`、`exports/`、`reports/` | CLI 本地分析产物，不进入公开发布 |

桌面默认数据目录为 `~/.open-reverselab/workspaces/Default`。本机环境快照另存于 `~/.open-reverselab/env/env.md`；二者都不能提交到公共仓库。备份与迁移见[工作区文档](desktop/WORKSPACES.zh-CN.md)。

## 参与贡献与发布

请阅读[贡献指南](.github/CONTRIBUTING.md)、[安全策略](SECURITY.md)与[公开边界](PUBLICATION.md)。提交通用实现和合成示例，真实目标、样本、凭据和案例证据留在本地。提交前运行 `python scripts/misc/public_release_check.py` 及所改模块的检查。版本历史见 [CHANGELOG.md](CHANGELOG.zh-CN.md)。

---

## Star History

<div align="center">

<a href="https://star-history.com/#LING71671/open-reverselab&Date">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=LING71671/open-reverselab&type=Date&theme=dark" />
    <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/svg?repos=LING71671/open-reverselab&type=Date" />
    <img alt="Star History Chart" src="https://api.star-history.com/svg?repos=LING71671/open-reverselab&type=Date" />
  </picture>
</a>

</div>

---

## 免责声明

**访问或使用本项目即表示同意受完整免责声明的约束。** 声明涵盖：所有版本与分支（追溯及前瞻）、所有使用者（直接与间接）、所有衍生作品（fork / 复制 / 再分发）、全部司法管辖区的法律合规（含出口管制与数据保护法）、仅限授权用途、禁止用途、无担保、责任限制与赔偿、衍生作品强制保留声明、AI/ML 训练保护等。

> :page_facing_up: 完整法律文本：[DISCLAIMER.zh.md](DISCLAIMER.zh.md) · [English](DISCLAIMER.md)

## 许可协议

**Apache-2.0。** 详见 [LICENSE](LICENSE)。贡献即表示你同意你的贡献以相同条款授权。
