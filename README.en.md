<div align="center">

# ReverseLab

**An open-source reverse-engineering lab — executable knowledge base, 100+ MCP tools, Agent-native.**

*From an input signal to an evidence chain, every step is runnable.*

<br />

[![Docs](https://img.shields.io/badge/docs-reverselab.int0.cc-3D4F8C?style=flat-square&logo=gitbook&logoColor=white)](https://reverselab.int0.cc)
[![Discord](https://img.shields.io/badge/Discord-join-5865F2?style=flat-square&logo=discord&logoColor=white)](https://discord.gg/But5j58J2f)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/LING71671/open-reverselab)
[![License: GPL-3.0](https://img.shields.io/github/license/LING71671/open-reverselab?style=flat-square&color=blue)](LICENSE)
[![Sponsor: Sentry](https://img.shields.io/badge/sponsored%20by-Sentry-362D59?style=flat-square&logo=sentry&logoColor=white)](#sponsors)

English · **[简体中文](README.md)**

</div>

---

## :handshake: Sponsored by Sentry

<div align="center">

**[Sentry](https://sentry.io)** supports `openreverselab` with a sponsored account — error monitoring and performance tracing for the lab's toolchain.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/sponsors/sentry-wordmark-dark.svg">
  <img src="assets/sponsors/sentry-wordmark-light.svg" width="220" alt="Sentry">
</picture>

<sub>Since Aug 2026 — see <a href="SPONSORS.md">SPONSORS.md</a> for the full sponsor list and how to become one.</sub>

</div>

---

## What is ReverseLab

ReverseLab is an opinionated, runnable attack-knowledge base for reverse engineers, security researchers, CTF players, and AI Agents. Every article is structured as **`Scenario → Input signal → Method → Attack chain → MCP tool mapping`**, so a human or an Agent can pick up at any entry signal and walk the chain to evidence.

- **5 boards** spanning web, mobile, Windows, and cross-domain reverse work.
- **180+ articles** organized by attack surface, not by tooling.
- **100+ MCP tools** exposed through `reverse_lab_tools` — curl, frida, ghidra, rizin, yara, triage, kb_router, … all callable from Claude Code, Codex, or any MCP-aware Agent.
- **Directory-as-convention**: every artifact has a fixed home (`samples/`, `exports/`, `patches/`, `kb/`, `reports/`). Drop-in a sample, follow the chain, ship the report.

The lab is built to be run, not browsed. If a step can't be executed, it doesn't belong in the KB.

## Who is this for

| You are … | Start here |
| --- | --- |
| A **CTF player** stuck on a web/Android/PE challenge | Browse the [CTF Website](https://reverselab.int0.cc/kb/ctf-website/README), [APK Reverse](https://reverselab.int0.cc/kb/apk-reverse/README), or [PE Reverse](https://reverselab.int0.cc/kb/pe-reverse/README) board |
| A **security researcher** triaging a sample | [Quick start](#quick-start) → `boards/<board>/AI-USAGE.md` → `sample_full_workup` MCP tool |
| A **reverse engineer** who wants a workspace, not a tutorial | [Repository layout](#repository-layout) — clone and start |
| An **AI Agent** developer wiring up reverse-engineering tools | [For AI Agents](#for-ai-agents) — context chain, MCP smoke test, env snapshot protocol |

## Quick links

<div align="center">

[ :book: Docs site ](https://reverselab.int0.cc)
&nbsp;&nbsp;[ :rocket: Quick start ](#quick-start)
&nbsp;&nbsp;[ :toolbox: MCP tools ](https://reverselab.int0.cc/mcp-tools)
&nbsp;&nbsp;[ :question: FAQ ](https://reverselab.int0.cc/faq)
&nbsp;&nbsp;[ :handshake: Contributing ](.github/CONTRIBUTING.md)
&nbsp;&nbsp;[ :speech_balloon: Discord ](https://discord.gg/But5j58J2f)

</div>

---

## Knowledge at a glance

```
kb/                                180+ articles, 5 boards
├── ctf-website/techniques/        26 categories, 118 articles — Web attack surface
├── apk-reverse/techniques/         8 categories,  23 articles — Android reverse
├── pe-reverse/techniques/          9 categories,  24 articles — Windows PE / binary
├── general/techniques/             5 categories,  17 articles — Crypto · Protocol · Cheat · IoT · SDR
└── windows/techniques/             platform-specific PE / config topics
```

| Board | Trigger signals | MCP entry points |
| --- | --- | --- |
| `ctf-website` | URL · HTTP · JWT · SQLi · SSRF · CVE · API · CSP · OAuth · CAPTCHA · Cloudflare · ReDoS · Slowloris · DoS · Paywall | `http_probe`, `run_ctf_tool`, `kb_router` |
| `apk-reverse` | APK · DEX · adb · Frida · jadx · smali · SO · native | `android_app_baseline`, `android_crypto_unpack_recipe`, `android_frida_*` |
| `pe-reverse` | PE · EXE · DLL · x64dbg · Ghidra · Procmon · packer · malware | `triage_pe`, `ghidra_headless_analyze`, `make_x64dbg_breakpoint_script`, `sample_full_workup` |
| `general` | AES · DES · RSA · protobuf · game cheat · EAC / BE / Vanguard · firmware · JTAG · SDR | `die_scan`, `ghidra_*`, `rizin_*`, `python_re_tool_*` |
| `misc` | MCP config · skill install · env health check | `mcp_smoke_check`, `ai_toolcheck`, `lab_healthcheck` |

The full, auto-regenerated tree is at <https://reverselab.int0.cc/kb>.

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

After installing the CTF / ExploitDB toolchains, Windows Security may flag vulnerability samples and payload documents — e.g. `tools/ctf-website/exploitdb`, `kb/ctf-website/techniques/24-database/03-nosql-injection.md`, `docs/llms-full.txt`. These contain security-test payloads, webshells, shellcode, or ExploitDB samples and are **expected content**.

Prefer a **minimal exclusion** over excluding the whole repo:

```powershell
Add-MpPreference -ExclusionPath "D:\open-reverselab\tools\ctf-website\exploitdb"
```

If a specific document is also blocked, exclude just that file.

</details>

### For AI Agents

1. Clone into a stable local directory, e.g. `<workspace>/open-reverselab`.
2. **Claude Code:** `cd <workspace>/open-reverselab` before starting the session.
3. **Codex APP:** open the existing `open-reverselab` folder directly (no clone needed).
4. AI-assisted setup: paste [`templates/prompts/ai-install.en.md`](templates/prompts/ai-install.en.md) into the Agent.
5. Create a task: `python scripts/misc/new_task.py --board ctf-website --name <name>`.
6. After moving machines or changing MCP settings, confirm MCP tool calls pass:
   ```sh
   uv run --project tools/skills/mcp/ReverseLabToolsMCP \
     python scripts/misc/mcp_smoke_check.py --write-report
   ```

**Context chain** — the Agent loads context along this path on startup:

```
CLAUDE.md → AGENTS.md → AI-USAGE.md → boards/<board>/AI-USAGE.md
```

Pair with [codex-session-patcher](https://github.com/ryfineZ/codex-session-patcher) for one-click project-level `.codex/` and MCP server config.

<details>
<summary><b>Environment Snapshot protocol (machine-level, shared across projects)</b></summary>

When you first open this project with an AI Agent, the Agent follows the [Environment Snapshot Protocol in AGENTS.md](AGENTS.md): it probes this machine (OS, dev toolchain, RE tools, Python RE libs, devices, sanitized env vars, network, workspace) and writes the result to `~/.open-reverselab/env/env.md` (Windows: `%USERPROFILE%\.open-reverselab\env\env.md`).

The snapshot is **machine-level** and shared across projects. The Agent reads it directly on every new session / new folder and only re-probes when the file is older than 7 days or the protocol version changed. It never enters the repo, and env vars are sanitized per the protocol (secret-like names are marked "set (masked)", proxy URLs have userinfo stripped).

</details>

### Verify after install

```sh
python scripts/misc/lab_healthcheck.py
python scripts/misc/ai_toolcheck.py --board misc
python scripts/misc/public_release_check.py
```

`--board misc` verifies the fresh-clone core Agent scripts and lightweight tools. Run the full `python scripts/misc/ai_toolcheck.py` only after installing the Android, Windows, and CTF board toolchains you need.

---

## Repository layout

The repo follows **directory-as-convention**. Drop artifacts in the right place and the rest of the toolchain finds them.

```
samples/      Original samples + _quarantine/ + unpacked/   — never modified
exports/      Tool outputs (triage / IOC / YARA / Sigma / Procmon / Ghidra summaries)
patches/      Patch artifacts (originals are never modified)
notes/        Analysis notes
reports/      Final reports
scripts/      Automation scripts
projects/     Ghidra project files
templates/    Note / report / rule templates · AI install prompts
kb/           Reusable attack knowledge base — see "Knowledge at a glance"
tools/        Toolchain (binaries, wrappers, registry, MCP)
cases/        Lightweight index — no large file copies
```

> Don't commit large samples, full PCAPs, or memory dumps. Index them in `cases/` and link to a private store.

---

## Documentation

The full, versioned docs site is at **[reverselab.int0.cc](https://reverselab.int0.cc)** — it is auto-built from the `site/` folder on every push to `main` and includes:

- The full KB tree (every board, category, and article)
- The MCP tool catalog with install status per board
- A FAQ for common setup questions
- A 404 page that points back to GitHub when pages are renamed

If something here disagrees with the site, **the site wins** — it is regenerated from the source files on every deploy.

---

## Community & contributing

- **Discord** — [discord.gg/But5j58J2f](https://discord.gg/But5j58J2f). Best place for "how do I do X" questions.
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

## Disclaimer

By accessing or using this project, you agree to be bound by the full disclaimer — covering all versions and branches, all users (direct and indirect), all derivatives, legal compliance across all jurisdictions (including export controls and data protection laws), authorized purposes only, prohibited uses, no warranty, limitation of liability, mandatory disclaimer retention in derivatives, AI/ML training protections, and more.

> :page_facing_up: Full legal text: [DISCLAIMER.md](DISCLAIMER.md) · [中文版](DISCLAIMER.zh.md)

## License

**GPL-3.0-only.** See [LICENSE](LICENSE) for the full text. By contributing, you agree your contributions are licensed under the same terms.
