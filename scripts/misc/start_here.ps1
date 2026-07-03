<#
.SYNOPSIS
    Double-click first-run helper for Windows users.

.DESCRIPTION
    Runs the lightweight checks a new operator needs before opening the
    workspace in Codex APP or Claude Code. This script does not download large
    board toolchains; use install_tools.ps1 for that after the core setup is OK.
#>

param(
    [string]$Root = (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
)

$ErrorActionPreference = "Stop"

function Invoke-Step {
    param(
        [string]$Title,
        [scriptblock]$Action
    )

    Write-Host ""
    Write-Host "== $Title ==" -ForegroundColor Cyan
    & $Action
}

Set-Location -LiteralPath $Root

Write-Host "ReverseLab first-run helper" -ForegroundColor Green
Write-Host "Workspace: $Root"
Write-Host ""
Write-Host "This helper checks the workspace, verifies reverse_lab_tools MCP, and creates core wrappers."
Write-Host "It will not install large Android/Windows/CTF toolchains."

Invoke-Step "1. Check workspace and MCP" {
    python "scripts\misc\first_run_check.py"
}

Invoke-Step "2. Create core command wrappers" {
    & "$Root\scripts\misc\bootstrap.ps1"
}

Invoke-Step "3. Run lightweight lab health check" {
    python "scripts\misc\lab_healthcheck.py"
}

Write-Host ""
Write-Host "Next steps" -ForegroundColor Green
Write-Host "- Codex APP: open this folder directly: $Root"
Write-Host "- Claude Code: cd into this folder before starting the session."
Write-Host "- Optional board tools:"
Write-Host "  .\scripts\misc\install_tools.ps1 -CTF"
Write-Host "  .\scripts\misc\install_tools.ps1 -Android"
Write-Host "  .\scripts\misc\install_tools.ps1 -Windows"
Write-Host "  .\scripts\misc\install_tools.ps1 -Common"
