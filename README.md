# Open-ReverseLab

ReverseLab combines a desktop workspace, a red/blue security knowledge base, and MCP tools for target-based analysis. Use the desktop to run and inspect Goals, or connect the repository to Claude Code, Codex, OpenCode, and other MCP clients.

**English** · [简体中文](README.zh.md)

[Download v2.0.0](https://github.com/LING71671/open-reverselab/releases/tag/v2.0.0) · [Desktop guide](desktop/README.md) · [Knowledge base](kb/README.md) · [Documentation](https://ling71671.github.io/open-reverselab/)

[![Ask DeepWiki](assets/badges/ask-deepwiki.svg)](https://deepwiki.com/LING71671/open-reverselab)
[![License: GPL-3.0](https://img.shields.io/github/license/LING71671/open-reverselab?style=flat-square&color=blue)](LICENSE)

## :handshake: Sponsors

<table width="100%">
  <tbody>
    <tr>
      <td width="380" align="center" valign="middle">
        <a href="https://infistar.cc/register?aff=OPENREVERSELAB&amp;ref_source=link">
          <img src="assets/sponsors/infistar-banner-en.png" width="360" alt="Infistar.cc — Unified Multi-Model API Gateway">
        </a>
      </td>
      <td valign="middle">
        <strong><a href="https://infistar.cc/register?aff=OPENREVERSELAB&amp;ref_source=link">Infistar.cc</a></strong><br /><br />
        Unified multi-model API gateway (Claude, GPT, Gemini, Grok, DeepSeek &amp; more) — 1,000+ redundant routes with auto failover.<br /><br />
        <code>open-reverselab</code> users receive <strong>¥5 free sign-up credit</strong> → <a href="https://infistar.cc/register?aff=OPENREVERSELAB&amp;ref_source=link">Try Infistar.cc</a>
      </td>
    </tr>
    <tr>
      <td width="380" align="center" valign="middle">
        <a href="https://sentry.io"><picture>
          <source media="(prefers-color-scheme: dark)" srcset="assets/sponsors/sentry-wordmark-dark.svg">
          <img src="assets/sponsors/sentry-wordmark-light.svg" width="180" alt="Sentry">
        </picture></a>
      </td>
      <td valign="middle">
        <strong><a href="https://sentry.io">Sentry</a></strong><br /><br />
        Sponsored account — error monitoring and performance tracing for <code>openreverselab</code>'s automated toolchains.
      </td>
    </tr>
  </tbody>
</table>

<p align="center"><sub>See <a href="SPONSORS.md">SPONSORS.md</a> for the full sponsor list and how to become one.</sub></p>

---

## Desktop

Select `red / blue / both` in the upper-left corner, choose a workspace, and enter a file, directory, or URL target with a Goal. The live canvas shows execution branches; activity, logs, reports, and health views retain the evidence behind the result.

![ReverseLab Desktop knowledge reader](assets/desktop/knowledge-light.png)

- **Independent strategies.** `red` and `blue` use separate analysis policies. `both` runs the branches in parallel and joins their results.
- **Concurrent Goals.** Each workspace runs up to two Goals at once by default. Switching views, tasks, or workspaces does not redirect a running task's output.
- **Managed workspaces.** First launch creates a default workspace. Open or create others, import samples, and keep original and working copies separate.
- **Bounded execution.** Optional limits default to 10 minutes and 32,000 tokens per Goal. Failed routes and repeated actions feed back into planning; independent verification decides whether the target objective was met.
- **Knowledge and usability.** Browse defense articles and paired references, switch light/dark themes, and retain unsent drafts, reading positions, and filters during navigation.

### Download and start

1. Download and run `ReverseLab-v2.0.0-windows-x64-setup.exe` from the [release](https://github.com/LING71671/open-reverselab/releases/tag/v2.0.0).
2. Install Python 3.10 or newer and make the `python` command available on PATH. Windows also needs the Microsoft Edge WebView2 runtime.
3. Launch ReverseLab. The installer includes its knowledge base and scripts; keep personal workspaces outside the installation directory.
4. Open Settings and configure an OpenAI-compatible chat-completions endpoint and model, then enter a target and objective. SHA256 verification can run locally without a model.

Settings includes version checks, release notes and signed updates for installed builds. Portable ZIP users can check versions and migrate using the installer; extract the full ZIP with `kb/` and `scripts/` beside `ReverseLab.exe`. See [application updates](desktop/UPDATES.md).

The release includes a Windows x64 application and the corresponding project source, scripts, and KB. Python and third-party tools such as Ghidra, Frida, and x64dbg are installed separately. macOS/Linux retain the source-based CLI/MCP workflow; this release does not include native desktop builds for those platforms.

The desktop currently executes bounded Python observations. MCP tool references in KB articles do not automatically become desktop adapters for debuggers, devices, or hardening tools. Workspace files stay on disk, while model-assisted runs send task context and selected evidence to the endpoint you configure. Python actions run with the current user's permissions. See the [desktop guide](desktop/README.md) for configuration, data handling, and limits.

## Knowledge base and MCP

The knowledge base covers Web/CTF, Android/APK, Windows/PE, and general topics such as cryptography and protocols. Articles carry `track: red | blue | both`; `both` articles are shared. Related attack and defense articles are linked through index metadata and `defends` references. The current catalog is the source of truth; not every article has a one-to-one counterpart.

| Area | Knowledge entry | Tool examples |
| --- | --- | --- |
| Web / CTF | [Web knowledge](kb/ctf-website/README.md) | `kb_router`, `http_probe`, `run_ctf_tool` |
| Android / APK | [APK knowledge](kb/apk-reverse/README.md) | `android_app_baseline`, `android_crypto_unpack_recipe` |
| Windows / PE | [PE knowledge](kb/pe-reverse/README.md) | `triage_pe`, `ghidra_headless_analyze`, `sample_full_workup` |
| General | [Cross-domain knowledge](kb/general/README.md) | `solve_crypto_from_evidence`, `rizin_*` |

CLI/MCP track selection defaults to `blue`; select `red` or `both` explicitly through `REVERSELAB_MODE`, `--track`, or the MCP track tools. Desktop selection is scoped to its Goals and does not rewrite another client's environment.

```sh
python scripts/misc/kb_router.py "JWT" --track blue
python scripts/misc/desktop_kb.py list --track both
```

## CLI and AI-agent setup

Clone the repository, then use `START_HERE.bat` / `START_HERE.cmd` on Windows or `./START_HERE.sh` on macOS/Linux. These are setup and MCP checks, not the desktop launcher. The reports are written under `reports/misc/`.

```sh
git clone https://github.com/LING71671/open-reverselab.git
cd open-reverselab
```

Open this directory in your AI client and read [AI-USAGE.md](AI-USAGE.md). The context chain is `CLAUDE.md → AGENTS.md → AI-USAGE.md → boards/<board>/AI-USAGE.md`. For guided installation, use the [English](templates/prompts/ai-install.en.md) or [Chinese](templates/prompts/ai-install.zh.md) prompt. MCP clients need `uv` and the dependencies in `tools/skills/mcp/ReverseLabToolsMCP`.

```sh
uv sync --project tools/skills/mcp/ReverseLabToolsMCP
uv run --project tools/skills/mcp/ReverseLabToolsMCP python scripts/misc/mcp_smoke_check.py --write-report
python scripts/misc/lab_healthcheck.py
python scripts/misc/ai_toolcheck.py --board misc
```

Install only the tool groups needed for the task. Windows provides `scripts/misc/install_tools.ps1 -CTF`, `-Android`, `-Windows`, and `-Common`; POSIX wrappers are generated by `scripts/misc/bootstrap.sh`. See [START.md](START.md) and [tools/README.md](tools/README.md).

## Build the desktop

With Node 22+, pnpm, Python, Rust, and the platform Tauri prerequisites installed:

```sh
cd desktop
pnpm install --frozen-lockfile
pnpm tauri dev
# Or create a production executable:
pnpm tauri build --no-bundle
```

`pnpm dev` is the browser preview. See [development](desktop/DEV_GUIDE.md), [architecture](desktop/ARCHITECTURE.md), [Agent contracts](desktop/AGENT_SYSTEM.md), [error codes](desktop/ERROR_CODES.md), and [release instructions](RELEASING.md).

## Data and repository layout

| Location | Purpose |
| --- | --- |
| `desktop/` | Desktop UI, queue, execution engine, and Tauri host |
| `kb/` | Reusable techniques and defense references |
| `scripts/`, `tools/`, `templates/` | Automation, adapters, and templates |
| `boards/` | Task routing for external AI clients |
| `site/` | Documentation-site source |
| Selected workspace's `.reverselab/` | Desktop originals/work copies, Goal records, exports, and reports |
| Repository `cases/`, `samples/`, `notes/`, `exports/`, `reports/` | Local CLI analysis artifacts; excluded from publication |

Desktop data defaults to `~/.open-reverselab/workspaces/Default`. The host environment snapshot is separate at `~/.open-reverselab/env/env.md`. Neither belongs in a public commit. See [workspace storage](desktop/WORKSPACES.md).

## Contributing and publication

Read [Contributing](.github/CONTRIBUTING.md), [Security](SECURITY.md), and [Publication](PUBLICATION.md). Publish general implementations and synthetic examples; keep real targets, samples, credentials, and case evidence private. Before submitting, run `python scripts/misc/public_release_check.py` and the checks relevant to the changed module. Release history is in [CHANGELOG.md](CHANGELOG.md).

## Sponsors

ReverseLab is sustained by people and organizations that fund the infrastructure, tooling, and review time.

<table width="100%">
  <thead>
    <tr>
      <th width="180" align="left">Logo</th>
      <th align="left">Sponsor / 赞助方</th>
      <th width="110" align="left">Since / 时间</th>
      <th align="left">Support / 支持内容</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td align="left" valign="middle">
        <a href="https://infistar.cc/register?aff=OPENREVERSELAB&amp;ref_source=link"><img src="assets/sponsors/infistar-banner-en.png" width="160" alt="Infistar.cc"></a>
      </td>
      <td valign="middle"><strong><a href="https://infistar.cc/register?aff=OPENREVERSELAB&amp;ref_source=link">Infistar.cc</a></strong></td>
      <td valign="middle">2026-11</td>
      <td valign="middle">Unified multi-model API gateway (Claude, GPT, Gemini, Grok, DeepSeek &amp; more) · ¥5 free sign-up credit via referral link</td>
    </tr>
    <tr>
      <td align="left" valign="middle">
        <a href="https://sentry.io"><picture>
          <source media="(prefers-color-scheme: dark)" srcset="assets/sponsors/sentry-wordmark-dark.svg">
          <img src="assets/sponsors/sentry-wordmark-light.svg" width="150" alt="Sentry">
        </picture></a>
      </td>
      <td valign="middle"><strong><a href="https://sentry.io">Sentry</a></strong></td>
      <td valign="middle">2026-08</td>
      <td valign="middle">Sponsored account — error monitoring &amp; performance tracing platform（错误监控与性能追踪平台）</td>
    </tr>
  </tbody>
</table>

**Want to sponsor?** See [SPONSORS.md](SPONSORS.md) or email **belloshehubz@gmail.com** — we list every sponsor, big or small, with the support they provide.

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

## Disclaimer

By accessing or using this project, you agree to be bound by the full disclaimer — covering all versions and branches, all users (direct and indirect), all derivatives, legal compliance across all jurisdictions (including export controls and data protection laws), authorized purposes only, prohibited uses, no warranty, limitation of liability, mandatory disclaimer retention in derivatives, AI/ML training protections, and more.

> :page_facing_up: Full legal text: [DISCLAIMER.md](DISCLAIMER.md) · [中文版](DISCLAIMER.zh.md)

## License

**GPL-3.0-only.** See [LICENSE](LICENSE). By contributing, you agree your contributions are licensed under the same terms.
