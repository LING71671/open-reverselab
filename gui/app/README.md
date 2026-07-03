# ReverseLab GUI App

This is the ReverseLab product layer. It should become the thing users open every day.

The app depends on OpenCode as a runtime, but the user experience belongs to ReverseLab:

- CTF Website workbench
- evidence-first tool execution
- KB and attack-network navigation
- notes and reports
- sample and case management

## First Screen: CTF Website Workbench

The first usable screen should load directly into a CTF workflow:

1. **Case header** - target URL, case name, board, status
2. **Signal input** - user enters JWT, SQLi hint, route, header, product/version, error text, or other observed signal
3. **KB router panel** - calls `kb_router` and ranks technique files
4. **Technique reader** - opens the selected KB file and shows method, pseudo-code, and MCP tool mapping
5. **Tool run panel** - runs existing scripts/MCP tools and streams output
6. **Evidence browser** - shows files written to `exports/ctf-website/`, `notes/ctf-website/`, and `reports/ctf-website/`
7. **AI operator chat** - talks to the `reverselab-ctf` agent through OpenCode

## Non-goals For V1

- Do not rewrite the CTF methodology.
- Do not create a separate evidence format.
- Do not require users to know OpenCode.
- Do not expose the local server beyond loopback by default.

