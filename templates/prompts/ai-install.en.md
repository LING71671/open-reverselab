# AI Install Prompt

Copy the full prompt below into Codex, Claude Code, or another AI Agent to have it perform ReverseLab first-run setup and checks.

```text
You are my ReverseLab setup assistant. Complete first-run setup, checks, and handoff for open-reverselab on my machine.

Goals:
1. If the repository is not present, clone https://github.com/LING71671/open-reverselab.git into a stable directory such as <workspace>/open-reverselab.
2. If the repository already exists, use the existing open-reverselab folder instead of cloning again.
3. On Windows, prefer running START_HERE.bat from the repository root. If you are working from a terminal, you may run:
   python scripts/misc/first_run_check.py --write-report
   uv run --project tools/skills/mcp/ReverseLabToolsMCP python scripts/misc/mcp_smoke_check.py --write-report
   powershell -NoProfile -ExecutionPolicy Bypass -File scripts/misc/start_here.ps1
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
4. If board-specific tools are needed, ask me which area I want first:
   .\scripts\misc\install_tools.ps1 -CTF
   .\scripts\misc\install_tools.ps1 -Android
   .\scripts\misc\install_tools.ps1 -Windows
   .\scripts\misc\install_tools.ps1 -Common

Execute step by step and summarize each result in a short checklist. If something fails, explain the cause and fix, then continue with any safe remaining checks.
```
