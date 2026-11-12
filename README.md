<div align="center">

# Open-ReverseLab — AI Reverse Engineering Agent & MCP Lab

**Open-source AI-powered reverse-engineering platform for autonomous binary analysis, built for Claude Code, Codex, OpenCode and any MCP-compatible agent.**

Ghidra · Frida · x64dbg · Rizin · PE · APK · Cryptography · Blue-Team Hardening · Dual-Track Analysis

---

**An open-source reverse-engineering lab — executable 1:1 RED/BLUE knowledge base, 110+ MCP tools, Agent-native.**

*From an input signal to an evidence chain, every step is runnable.*

<br />

[![Ask DeepWiki](assets/badges/ask-deepwiki.svg)](https://deepwiki.com/LING71671/open-reverselab)
[![License: GPL-3.0](https://img.shields.io/github/license/LING71671/open-reverselab?style=flat-square&color=blue)](LICENSE)
[![Sponsor: Sentry](https://img.shields.io/badge/sponsored%20by-Sentry-362D59?style=flat-square&logo=sentry&logoColor=white)](#sponsors)

**English** · [简体中文](README.zh.md)

</div>

---

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

## What is ReverseLab

ReverseLab is an opinionated, runnable **BLUE / RED / BOTH dual-track** reverse-engineering and security knowledge base for reverse engineers, blue-team defenders, security researchers, and AI Agents. Every offensive technique pairs **1:1** with a defensive hardening/detection counterpart (`Scenario → Input signal → Method → Workflow → MCP tool mapping`), defaulting to **`BLUE`** (static analysis, cryptography, detection & hardening) with explicit switching to **`RED`** (offense & dynamic exploitation) or **`BOTH`** (purple-team paired view).

- **5 boards** spanning web, mobile, Windows, and cross-domain reverse work.
- **320+ articles** with 1:1 offensive ↔ defensive pairing (`track: blue | red | both`, `defends`).
- **110+ MCP tools** exposed through `reverse_lab_tools` — `triage_pe`, `ghidra_*`, `rizin_*`, `make_yara_stub`, `solve_crypto_from_evidence`, `kb_router`, `route_track`, `set_track`, … with track gating (`REVERSELAB_MODE=blue|red|both`).
- **Directory-as-convention**: every artifact has a fixed home (`samples/`, `exports/`, `patches/`, `kb/`, `reports/`). Drop-in a sample, follow the chain, ship the report.

The lab is built to be run, not browsed. If a step can't be executed, it doesn't belong in the KB.

## Who is this for

| You are … | Start here |
| --- | --- |
| A **blue-team defender** hardening services or auditing samples | Default `BLUE` track (`REVERSELAB_MODE=blue`) → `python scripts/misc/kb_router.py "<signal>" --track blue` → `triage_pe` / `make_yara_stub` |
| A **CTF / red-team researcher** validating exploit chains | Switch to `RED` (`set_track("red")` or `--track red`) → [CTF Website](kb/ctf-website/README.md), [APK Reverse](kb/apk-reverse/README.md), or [PE Reverse](kb/pe-reverse/README.md) |
| A **security researcher** triaging a sample | [Quick start](#quick-start) → `boards/<board>/AI-USAGE.md` → `sample_full_workup` MCP tool |
| A **reverse engineer** who wants a workspace, not a tutorial | [Repository layout](#repository-layout) — clone and start |
| An **AI Agent** developer wiring up reverse-engineering tools | [For AI Agents](#for-ai-agents) — context chain, `route_track`, MCP smoke test, env snapshot protocol |

## Quick links

<div align="center">

[ :book: Knowledge Base ](#knowledge-at-a-glance)
&nbsp;&nbsp;[ :rocket: Quick start ](#quick-start)
&nbsp;&nbsp;[ :handshake: Contributing ](.github/CONTRIBUTING.md)

</div>

---

## Knowledge at a glance

```
kb/                                320+ articles, 5 boards (RED ↔ BLUE 1:1 paired)
├── ctf-website/techniques/        23 categories, 191 articles — Web attack surface & 1:1 BLUE defense
├── apk-reverse/techniques/         9 categories,  36 articles — Android & hybrid reverse + 1:1 BLUE defense
├── pe-reverse/techniques/         10 categories,  49 articles — Windows PE / binary + 1:1 BLUE defense
├── general/techniques/             6 categories,  45 articles — Crypto · Signature · Protocol · Kernel · 1:1 defense
└── windows/techniques/             platform-specific PE / config topics
```

| Board | Trigger signals | MCP entry points |
| --- | --- | --- |
| `ctf-website` | URL · HTTP · JWT · SQLi · SSRF · CVE · API · CSP · OAuth · Hardening · DoS | `route_track`, `kb_router`, `http_probe`, `run_ctf_tool` |
| `apk-reverse` | APK · DEX · adb · Frida · jadx · smali · SO · WebView · RN/Flutter | `android_app_baseline`, `android_crypto_unpack_recipe`, `android_frida_*` |
| `pe-reverse` | PE · EXE · DLL · asar · x64dbg · Ghidra · Procmon · packer · YARA/Sigma | `triage_pe`, `ghidra_headless_analyze`, `make_yara_stub`, `sample_full_workup` |
| `general` | AES · RSA · Signature · Protobuf · gRPC · JS runtime · Kernel · Anti-cheat | `die_scan`, `solve_crypto_from_evidence`, `ghidra_*`, `rizin_*` |
| `misc` | Dual-track gate (`BLUE`/`RED`/`BOTH`) · MCP config · env health check | `get_track_status`, `set_track`, `mcp_smoke_check`, `lab_healthcheck` |

The complete directory tree is available under [kb/](kb/).

---

## Quick start

Pick the path that matches your role, not your platform — the platform differences are below the role split.

### For humans

**Windows (recommended for first run)** — double-click `START_HERE.bat` (or `START_HERE.cmd`) in the repo root. It checks Python, `uv`, Git, the `reverse_lab_tools` MCP server, runs real MCP smoke calls, and writes `reports/misc/first-run-report.json` plus `reports/misc/mcp-smoke-report.json`.

**macOS / Linux** — run `./START_HERE.sh` from the repo root. It does the same first-run checks using POSIX shell wrappers under `tools/bin/`. Windows-only GUI/PE tools are skipped or reported as such.

<details>
<summary><b>Per-board install (after first-run passes)</b></summary>

```powershell
# Pick the boards you actually need — the lab is modular.
.\scripts\misc\bootstrap.ps1                # core script wrappers (no downloads)
.\scripts\misc\install_tools.ps1 -CTF       # Web tools (sqlmap, nuclei, ffuf, jwt_tool, …)
.\scripts\misc\install_tools.ps1 -Android   # APK tools (apktool, jadx, frida, uber-apk-signer, …)
.\scripts\misc\install_tools.ps1 -Windows   # PE tools (cutter, pe-bear, procmon, …)
.\scripts\misc\install_tools.ps1 -Common    # Ghidra + Maven
```

macOS / Linux equivalent:

```sh
./scripts/misc/bootstrap.sh
export PATH="$PWD/tools/bin:$PWD/tools/ctf-website/bin:$PATH"
python scripts/misc/ai_toolcheck.py --board misc    # verify the fresh-clone core
```

Install only the boards you need. Don't dump the full toolchain if you're only doing web CTF.

</details>

<details>
<summary><b>Windows Defender / antivirus note</b></summary>

After installing CTF / ExploitDB tools, Windows Defender may flag exploit samples or payload documentation — e.g. `tools/ctf-website/exploitdb`, `kb/ctf-website/techniques/24-database/03-nosql-injection.md`, `docs/llms-full.txt`. These contain security test payloads, webshells, shellcode, or ExploitDB samples and are **expected components**.

We recommend **minimal path exclusions** rather than excluding the entire repo:

```powershell
Add-MpPreference -ExclusionPath "D:\open-reverselab\tools\ctf-website\exploitdb"
```

If individual documents are flagged, handle them case-by-case.

</details>

### For AI Agents

1. Clone into a dedicated local directory, e.g. `<workspace>/open-reverselab`.
2. **Claude Code**: `cd <workspace>/open-reverselab`, then start your session.
3. **Codex APP**: Open the existing `open-reverselab` folder directly (no re-clone needed).
4. Automated AI install: send the contents of [`templates/prompts/ai-install.en.md`](templates/prompts/ai-install.en.md) to your Agent.
5. Create a task: `python scripts/misc/new_task.py --board windows --name <name>` (or route KB by track: `python scripts/misc/kb_router.py "<signal>" --track blue|red|both`).
6. Verify real MCP invocation whenever switching machines or updating configs:
   ```sh
   uv run --project tools/skills/mcp/ReverseLabToolsMCP \
     python scripts/misc/mcp_smoke_check.py --write-report
   ```

**Context chain** — Agents load context through this sequence:

```
CLAUDE.md → AGENTS.md → AI-USAGE.md → boards/<board>/AI-USAGE.md
```

Use [codex-session-patcher](https://github.com/ryfineZ/codex-session-patcher) for one-click configuration of project-level `.codex/` and MCP servers.

<details>
<summary><b>Environment snapshot protocol (host-level, shared across projects)</b></summary>

When first opening this project with an AI Agent, it inspects your local environment (OS, toolchains, reverse-engineering libraries, devices, sanitized env vars, network, workspace) following the protocol in [AGENTS.md](AGENTS.md), and caches a snapshot at `~/.open-reverselab/env/env.md` (`%USERPROFILE%\.open-reverselab\env\env.md` on Windows).

This file is **host-level** and **shared across sessions**: subsequent sessions read it directly without re-probing, unless 7 days have passed or the protocol version has bumped. It remains local and is never committed. Sensitive variables are redacted (keys marked "SET", proxies stripped of credentials).

</details>

### Post-install verification

```sh
python scripts/misc/lab_healthcheck.py
python scripts/misc/ai_toolcheck.py --board misc
python scripts/misc/public_release_check.py
```

`--board misc` checks the fresh-clone core Agent scripts and lightweight tools. Run full `python scripts/misc/ai_toolcheck.py` only after installing Android / Windows / CTF boards.

---

## Repository layout

The repository uses **directory-as-convention**. Put artifacts where they belong and the tooling finds them automatically.

```
samples/      Original samples + _quarantine/ + unpacked/   — never modified
exports/      Tool outputs (triage / IOC / YARA / Sigma / Procmon / Ghidra summaries)
patches/      Patch artifacts (originals are never modified)
notes/        Analysis notes
reports/      Final reports
scripts/      Automation scripts
projects/     Ghidra project files
templates/    Note / report / rule templates · AI install prompts
kb/           Reusable RED/BLUE dual-track knowledge base — see "Knowledge at a glance"
tools/        Toolchain (binaries, wrappers, registry, MCP)
cases/        Lightweight index — no large file copies
```

> Don't commit large samples, full PCAPs, or memory dumps. Index them in `cases/` and link to a private store.

---

## Community & contributing

- **Contributing** — see [`.github/CONTRIBUTING.md`](.github/CONTRIBUTING.md). Bug reports, KB article PRs, new MCP tool wrappers, and board additions are all welcome.
- **Code of Conduct** — [`.github/CODE_OF_CONDUCT.md`](.github/CODE_OF_CONDUCT.md) (Contributor Covenant).
- **Security issues** — read [SECURITY policy](SECURITY.md) before opening a public issue.
- **Publication guidance** — [PUBLICATION.md](PUBLICATION.md) covers what is OK to publish, what stays in private cases, and AI/ML training protections.

---

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
