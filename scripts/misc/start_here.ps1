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

function Resolve-Python {
    $python = Get-Command python -ErrorAction SilentlyContinue
    if ($python) {
        return @{ Exe = $python.Source; Args = @() }
    }

    $py = Get-Command py -ErrorAction SilentlyContinue
    if ($py) {
        return @{ Exe = $py.Source; Args = @("-3") }
    }

    return $null
}

function Resolve-Uv {
    $uv = Get-Command uv -ErrorAction SilentlyContinue
    if ($uv) {
        return $uv.Source
    }
    return $null
}

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
$pythonCommand = Resolve-Python
$uvCommand = Resolve-Uv

Write-Host "ReverseLab first-run helper" -ForegroundColor Green
Write-Host "Workspace: $Root"
Write-Host ""
Write-Host "This helper checks the workspace, verifies reverse_lab_tools MCP, and creates core wrappers."
Write-Host "It will not install large Android/Windows/CTF toolchains."

if (-not $pythonCommand) {
    $reportDir = Join-Path $Root "reports\misc"
    $reportPath = Join-Path $reportDir "first-run-report.json"
    New-Item -ItemType Directory -Force -Path $reportDir | Out-Null
    $payload = [ordered]@{
        schema = 1
        generated_at = (Get-Date).ToUniversalTime().ToString("o")
        root = $Root
        report_path = $reportPath
        overall = "FAIL"
        summary = [ordered]@{ pass = 0; warn = 0; fail = 1 }
        checks = @(
            [ordered]@{
                level = "FAIL"
                name = "Python"
                detail = "not found in PATH"
                recommendation = "Install Python 3.10+ from https://www.python.org/downloads/windows/ and enable 'Add python.exe to PATH'."
            }
        )
        recommendations = @(
            [ordered]@{
                name = "Python"
                level = "FAIL"
                recommendation = "Install Python 3.10+ from https://www.python.org/downloads/windows/ and enable 'Add python.exe to PATH'."
            }
        )
        next_steps = @(
            "Install Python 3.10+ and double-click START_HERE.bat again.",
            "After this wizard passes, open this folder in Codex APP or cd here before starting Claude Code."
        )
    }
    $payload | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $reportPath -Encoding UTF8

    Write-Host ""
    Write-Host "Missing requirement: Python" -ForegroundColor Red
    Write-Host "Install Python 3.10+ from https://www.python.org/downloads/windows/"
    Write-Host "During installation, enable 'Add python.exe to PATH', then double-click START_HERE.bat again."
    Write-Host "Report written: $reportPath"
    exit 1
}

Invoke-Step "1. Check workspace and MCP" {
    & $pythonCommand.Exe @($pythonCommand.Args) "scripts\misc\first_run_check.py" --write-report
}

Invoke-Step "2. Create core command wrappers" {
    & "$Root\scripts\misc\bootstrap.ps1"
}

Invoke-Step "3. Run real MCP smoke check" {
    if ($uvCommand) {
        & $uvCommand "run" "--project" "tools/skills/mcp/ReverseLabToolsMCP" "python" "scripts/misc/mcp_smoke_check.py" "--write-report"
    } else {
        & $pythonCommand.Exe @($pythonCommand.Args) "scripts\misc\mcp_smoke_check.py" --write-report
    }
}

Invoke-Step "4. Run lightweight lab health check" {
    & $pythonCommand.Exe @($pythonCommand.Args) "scripts\misc\lab_healthcheck.py"
}

Write-Host ""
Write-Host "Next steps" -ForegroundColor Green
Write-Host "现在可以用 Codex APP 打开这个文件夹，或在 Claude Code 中 cd 到这里。"
Write-Host ""
Write-Host "- Codex APP: open this folder directly: $Root"
Write-Host "- Claude Code: cd into this folder before starting the session."
Write-Host "- First-run report: $Root\reports\misc\first-run-report.json"
Write-Host "- MCP smoke report: $Root\reports\misc\mcp-smoke-report.json"
Write-Host "- Task guide: $Root\START.md"
Write-Host "- Optional board tools:"
Write-Host "  .\scripts\misc\install_tools.ps1 -CTF"
Write-Host "  .\scripts\misc\install_tools.ps1 -Android"
Write-Host "  .\scripts\misc\install_tools.ps1 -Windows"
Write-Host "  .\scripts\misc\install_tools.ps1 -Common"
