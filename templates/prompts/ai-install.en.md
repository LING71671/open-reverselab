# AI Install Prompt

Copy the full prompt below into Codex, Claude Code, or another AI Agent to have it perform ReverseLab first-run setup and checks.

```text
You are my ReverseLab setup assistant. Complete first-run setup, checks, and handoff for open-reverselab on my machine.

0. First confirm my operating system (Windows / macOS / Linux); choose commands by platform for every step below.

Goals:
1. If the repository is not present, clone https://github.com/LING71671/open-reverselab.git into a stable directory such as <workspace>/open-reverselab.
2. If the repository already exists, use the existing open-reverselab folder instead of cloning again.
3. First-run checks (platform-dependent):
   - Windows: prefer running START_HERE.bat from the repository root. If you are working from a terminal, you may run:
     python scripts/misc/first_run_check.py --write-report
     uv run --project tools/skills/mcp/ReverseLabToolsMCP python scripts/misc/mcp_smoke_check.py --write-report
     powershell -NoProfile -ExecutionPolicy Bypass -File scripts/misc/start_here.ps1
   - macOS / Linux: no .bat/.ps1 entry points; run directly (Python and uv are cross-platform):
     python3 scripts/misc/first_run_check.py --write-report
     uv run --project tools/skills/mcp/ReverseLabToolsMCP python3 scripts/misc/mcp_smoke_check.py --write-report
4. Confirm that .mcp.json contains mcpServers.reverse_lab_tools.
5. Confirm that the reverse_lab_tools entry script exists:
   tools/skills/mcp/ReverseLabToolsMCP/reverse_lab_tools_mcp.py
6. Check that Python, Git, and uv are available. If anything is missing, give clear install advice and do not claim success.
7. Generate or inspect reports/misc/first-run-report.json and report overall, warn, and fail counts.
8. Generate or inspect reports/misc/mcp-smoke-report.json and confirm kb_router, kb_read_file, and project_skills_status are PASS.
9. End with this clear next step:
   You can now open this folder in Codex APP, or cd here before starting Claude Code.

Safety and public-repository boundary:
1. Do not commit, upload, or copy my private cases, samples, logs, exports, reports, screenshots, real targets, tokens, cookies, accounts, or machine-specific absolute paths.
2. Do not add runtime logs or first-run-report.json to Git.
3. If you need to modify repository files, explain why first. Before committing, run:
   python scripts/misc/public_release_check.py
   python scripts/misc/lab_healthcheck.py
4. If board-specific tools are needed (apktool/jadx/DiE/x64dbg etc.), handle by platform:
   - Windows: ask me for my install preference first:
       - One-click full install (convenient): .\scripts\misc\install_tools.ps1 -All
       - On-demand install (precise): tell me the direction, then run only the matching one
           .\scripts\misc\install_tools.ps1 -CTF
           .\scripts\misc\install_tools.ps1 -Android
           .\scripts\misc\install_tools.ps1 -Windows
           .\scripts\misc\install_tools.ps1 -Common
   - macOS / Linux: no one-click install script; install manually per tools/<board>/README.md
     (Ghidra/Cutter/jadx/apktool/DiE all have mac/Linux builds; download and extract into the
     matching tools/ directory, then create a launcher under tools/bin/ or add to PATH)
5. VMP-specific tools (NoVmp/unidbg/ScyllaHide etc.): ask my install preference first, one of two:
   [A] One-click install: install all VMP tools at once (common libraries + PE group +
       Android group), then verify everything together
   [B] On-demand install: install only the group the current sample needs (form-based), minimal
       set
   Both modes share these rules (explain the purpose first; verify each item after install;
   report failures honestly instead of claiming success; mark any tool not verified as
   "unverified" and do not treat it as usable):
   5.0 First check what is already present; install only missing items (do not reinstall):
       - MCP python_re_tool_status for installed Python libraries
       - MCP toolbox_list / inspect existing directories under tools/
       - Skip anything already installed with a satisfying version
   5.1 Tool inventory:
       a. Common Python RE libraries (prefer MCP python_re_tool_install, or pip install --user;
          verify with: python -c "import angr, unicorn, capstone, frida"):
          angr, unicorn, capstone, frida
          Triton: not in the MCP allowlist, and the PyPI `triton` package name conflicts with
          OpenAI's GPU compiler; build from https://github.com/JonathanSalwan/Triton if needed
          (requires CMake/LLVM), or use angr as the DSE fallback.
       b. PE group (x64dbg anti-debug / static devirtualization, by platform):
          - Windows:
            ScyllaHide (required): https://github.com/x64dbg/ScyllaHide/releases
              → extract to tools/windows/x64dbg/plugins/; Verify: appears in the x64dbg plugin
              menu with all hide options enabled
            NoVmp / NoVmpy: git clone --recursive https://github.com/can1357/NoVmp
              → tools/windows/NoVmp, build Release x64 with Visual Studio 2022;
              NoVmpy: pip install --user novmpy (if not on PyPI, git clone
              https://github.com/wallds/NoVmpy);
              Verify: NoVmp.exe <sample> <function RVA> produces .devirt.exe / .ll
            bochscpu (optional): https://github.com/x64dbg/bochscpu/releases → plugins/;
              Verify: appears in the x64dbg plugin menu
          - macOS / Linux (x64dbg-family tools unavailable; use alternatives):
            Dynamic debugging: GDB (Linux) / LLDB (macOS), or rizin (cross-platform)
            Anti-debug bypass: Frida (cross-platform; the Frida scripts in
              kb/red/pe-reverse/techniques/04-dynamic-analysis/05-anti-debug-bypass.md apply too)
            Static devirt: prefer NoVmpy (pip install --user novmpy, cross-platform);
              NoVmp can be built on Linux with CMake (vcpkg dependencies, complex, optional)
       c. Android group (.so emulation trace / dump triage):
          unidbg (main route; requires JDK 17+): git clone --depth 1
            https://github.com/zhkl0228/unidbg → tools/android/unidbg;
            Verify: build and run the Utilities64 example from its README and obtain an
            instruction trace
          BlackDex (required): install the APK from
            https://github.com/CodingGay/BlackDex/releases onto the device;
            Verify: icon appears on the device and launches
          Youpk / FART (deep extraction-packer recovery only, optional): require a custom ROM or
            specific hardware (Youpk needs a flashed Pixel 1; FART has a Frida variant).
            Ask me whether such a device is available before installing.
          frida-server: deploy via MCP android_frida_ensure_server, no manual download needed
   [A] One-click execution: 5.0 check → install common libraries + PE group + Android group
       (except Youpk/FART, which still requires asking about the device) → verify each →
       report per the checklist below
   [B] On-demand execution:
       5.2 First identify the sample form (read the identification articles if unsure):
           - Form A: PE virtualization (VMP 2.x/3.x x64) → install PE group only
           - Form B: Android commercial dex2c/VMP packer → install Android group only
           - Form C: Android with a VMProtect-protected .so → PE group approach (ARM64
             adaptation) + Android group
           - Identification references:
               kb/shared/pe-reverse/techniques/05-crypto-unpack/02-vmp-virtualization-analysis.md
               kb/shared/apk-reverse/techniques/07-packer/03-vmp-dex2c-detection.md
       5.3 Install the matching group for the form → verify each → report per the checklist
           below
   (Both [A] and [B]) After installing, report each item as a checklist: tool name → install
   method → verification command and its output (or the failure reason and fix), and record
   version, install path, and verification results in notes/ for later analysis.
   Full analysis flows: see the knowledge base articles
       kb/shared/pe-reverse/techniques/05-crypto-unpack/03-vmp-devirtualization-toolchain.md
       kb/shared/apk-reverse/techniques/07-packer/04-vmp-dump-trace-recovery.md
       kb/shared/apk-reverse/techniques/07-packer/05-vmp-anti-debug-bypass.md

Execute step by step and summarize each result in a short checklist. If something fails, explain the cause and fix, then continue with any safe remaining checks.
```
