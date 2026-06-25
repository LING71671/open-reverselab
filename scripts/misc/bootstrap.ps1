<#
.SYNOPSIS
    Create portable tools/bin wrappers for core lab scripts (no downloads).

.DESCRIPTION
    Fresh clones need tools/bin/*.bat for ai_context, ai_tool, ai_finding, and
    ai_toolcheck. External board tools still require install_tools.ps1.

.EXAMPLE
    .\scripts\misc\bootstrap.ps1
    .\scripts\misc\bootstrap.ps1 -Force
#>

param(
    [string]$Root = (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)),
    [switch]$Force
)

$ErrorActionPreference = "Stop"

$binDir = Join-Path $Root "tools\bin"
New-Item -ItemType Directory -Force -Path $binDir | Out-Null

$wrappers = @(
    @{ Name = "ai_context"; Script = "scripts\misc\ai_context.py" },
    @{ Name = "ai_tool"; Script = "scripts\misc\ai_tool.py" },
    @{ Name = "ai_finding"; Script = "scripts\misc\ai_finding.py" },
    @{ Name = "ai_toolcheck"; Script = "scripts\misc\ai_toolcheck.py" }
)

foreach ($item in $wrappers) {
    $batPath = Join-Path $binDir "$($item.Name).bat"
    if ((Test-Path -LiteralPath $batPath) -and -not $Force) {
        Write-Host "[SKIP] $batPath (use -Force to overwrite)" -ForegroundColor Yellow
        continue
    }

    $relScript = $item.Script -replace '/', '\'
    $content = "@echo off`r`npython `"%~dp0..\..\$relScript`" %*"
    Set-Content -LiteralPath $batPath -Value $content -Encoding Ascii
    Write-Host "[OK] $batPath -> $($item.Script)" -ForegroundColor Green
}

Write-Host "`nCore wrappers ready. Run install_tools.ps1 for board-specific tools." -ForegroundColor Cyan
