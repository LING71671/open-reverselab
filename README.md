# ReverseLab

Open-source reverse engineering lab — 178-article knowledge base, 100+ MCP automation tools, covering CTF pentesting / APK reverse engineering / PE binary analysis / cryptography & protocol cracking / game cheating analysis. Agent-native, directory-as-convention.

> [中文版](README.zh.md)

## Routing

```
Signal → kb_router(board=) → kb_read_file → Attack chain → MCP tool mapping → Execution
```

| Signal Type | Board | KB Categories / Files | MCP Tool Family |
|---|---|---|---|
| HTTP/Web/API/CVE/Cloud/CAPTCHA | `ctf-website` | 26/118 | `http_probe` `run_ctf_tool` `kb_router` |
| APK/DEX/SO/Frida/Java | `apk-reverse` | 8/20 | `android_app_baseline` `android_crypto_unpack_recipe` `android_frida_*` |
| PE/x64/x86/malware/driver | `pe-reverse` | 9/22 | `triage_pe` `ghidra_headless_analyze` `make_x64dbg_breakpoint_script` `sample_full_workup` |
| Crypto/Protocol/Cheat/IoT/Radio | `general` | 5/17 | `die_scan` `ghidra_*` `rizin_*` `python_re_tool_*` |

## Knowledge Base

```
kb/
├── ctf-website/techniques/   26 categories, 118 articles — Full web attack surface
├── apk-reverse/techniques/    8 categories, 20 articles — APK/DEX reverse engineering
├── pe-reverse/techniques/     9 categories, 22 articles — PE binary analysis
└── general/techniques/        5 categories, 17 articles — Cryptography / Protocols / Kernel / Cheating / Methodology
```

Each technique file follows this structure: `Scenario → Input signal → Method → Attack chain → MCP tool mapping`

Agent workflow: detect signal → `kb_router` lookup → `kb_read_file` → execute via MCP tool mapping.

## Boards

| Board | Trigger Signals |
|---|---|
| `boards/ctf-website` | URL, HTTP, JWT, SQLi, SSRF, CVE, API, CSP, OAuth, CAPTCHA, Cloudflare, ReDoS, Slowloris, DoS, Paywall |
| `boards/android` | APK, DEX, adb, Frida, jadx, smali, SO, native |
| `boards/windows` | PE, EXE, DLL, x64dbg, Ghidra, Procmon, packer, malware |
| `boards/general` | AES/DES/RSA, protobuf, game cheat, EAC/BE/Vanguard, firmware, JTAG, SDR |
| `boards/misc` | MCP config, skill installation, environment health check |

## Directory Convention

```
samples/      → Original samples + _quarantine/ + unpacked/
exports/      → Tool outputs (triage / IOC / YARA / Sigma / Procmon / Ghidra summaries)
patches/      → Patch artifacts (original samples are never modified)
notes/        → Analysis notes
reports/      → Final reports
scripts/      → Automation scripts
projects/     → Ghidra project files
templates/    → Note / report / rule templates
kb/           → Reusable attack knowledge base
tools/        → Toolchain
cases/        → Lightweight index — no large file copies
```

## Installation

On Windows, beginners can double-click `START_HERE.bat` or `START_HERE.cmd`
from the repository root. It checks Python, uv, Git, workspace layout, and
`reverse_lab_tools` MCP; creates core wrappers; runs real MCP tool calls; gives
install advice for missing items; and writes `reports/misc/first-run-report.json`
plus `reports/misc/mcp-smoke-report.json`.

On macOS/Linux, run `./START_HERE.sh` from the repository root. It performs the
same first-run checks and uses POSIX shell wrappers under `tools/bin/`; optional
Windows GUI/PE tools are skipped or reported as Windows-only. Platform-specific
release artifacts can stay separate: Windows full-toolchain releases ship
`.bat`/PowerShell and GUI tools, while macOS/Linux releases ship the Python,
MCP, shell-wrapper, and native CLI paths.

To have an AI Agent perform setup for you, copy the [AI install prompt](templates/prompts/ai-install.en.md) into Codex or Claude Code.
If you are not sure where to start, open [START.md](START.md).

```powershell
git clone https://github.com/LING71671/open-reverselab.git
cd open-reverselab
python scripts/misc/first_run_check.py       # Check workspace + reverse_lab_tools MCP
uv run --project tools/skills/mcp/ReverseLabToolsMCP python scripts/misc/mcp_smoke_check.py --write-report
.\scripts\misc\bootstrap.ps1              # Core script wrappers (no downloads)
.\scripts\misc\install_tools.ps1 -CTF       # Web tools
.\scripts\misc\install_tools.ps1 -Android   # APK tools
.\scripts\misc\install_tools.ps1 -Windows   # PE tools
.\scripts\misc\install_tools.ps1 -Common    # Ghidra + Maven
```

macOS/Linux quick start:

```sh
./START_HERE.sh
./scripts/misc/bootstrap.sh
export PATH="$PWD/tools/bin:$PWD/tools/ctf-website/bin:$PATH"
python scripts/misc/ai_toolcheck.py --board misc
```

## Agent Quick Start

1. Clone into a stable local directory, for example `<workspace>/open-reverselab`.
2. Windows: double-click `START_HERE.bat` or `START_HERE.cmd` for the first-run check. macOS/Linux: run `./START_HERE.sh`.
3. Claude Code: `cd <workspace>/open-reverselab` before starting the session.
4. Codex APP: open the existing `open-reverselab` folder directly.
5. AI-assisted setup: copy [templates/prompts/ai-install.en.md](templates/prompts/ai-install.en.md) into your AI Agent.
6. Create a task: `python scripts/misc/new_task.py --board ctf-website --name <name>`.
7. After moving machines or changing MCP settings, run `uv run --project tools/skills/mcp/ReverseLabToolsMCP python scripts/misc/mcp_smoke_check.py --write-report` and confirm MCP tool calls pass.

Post-install verification:

```powershell
python scripts/misc/lab_healthcheck.py
python scripts/misc/ai_toolcheck.py --board misc
python scripts/misc/public_release_check.py
```

`--board misc` verifies the fresh-clone core Agent scripts and lightweight tools. Run the full `python scripts/misc/ai_toolcheck.py` only after installing the Android, Windows, and CTF board toolchains you need.

## Context Chain

On startup the Agent loads context along this chain:

```
CLAUDE.md → AGENTS.md → AI-USAGE.md → boards/<board>/AI-USAGE.md
```

Pair with [codex-session-patcher](https://github.com/ryfineZ/codex-session-patcher) for one-click project-level `.codex/` environment and MCP server configuration.

## Disclaimer

**By accessing or using this project, you agree to be bound by the full disclaimer.**

The disclaimer covers: all versions and branches (retroactive and prospective), all users (direct and indirect), all derivatives (forks, copies, redistributions), legal compliance across all jurisdictions (including export controls and data protection laws), authorized purposes only, prohibited uses, no warranty, limitation of liability, indemnification, mandatory disclaimer retention in derivatives, anti-removal provisions, and educational communication protections, third-party transaction protections, and unauthorized distribution & impersonation protections, and AI/ML training protections.

> 📄 Read the full legal disclaimer: [DISCLAIMER.md](DISCLAIMER.md) | [中文版](DISCLAIMER.zh.md)

## License

GPL-3.0-only. See [LICENSE](LICENSE) for details.
