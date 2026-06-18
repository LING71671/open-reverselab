<#
.SYNOPSIS
    Plan or install missing CTF-website tools for ReverseLab.

.DESCRIPTION
    Default mode is DRY RUN. It writes an installation plan and performs no
    network download, clone, wrapper overwrite, or PATH mutation unless -Execute
    is explicitly supplied.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\scripts\ctf-website\install_missing_tools.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\scripts\ctf-website\install_missing_tools.ps1 -Execute -CreateWrappers
#>

param(
    [string]$Root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..")).Path,
    [switch]$Execute,
    [switch]$SkipGo,
    [switch]$SkipPython,
    [switch]$CreateWrappers,
    [switch]$Force,
    [string]$GoProxy = "https://goproxy.cn,direct",
    [string]$LocalBin = (Join-Path (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..")).Path "tools\ctf-website\bin")
)

$ErrorActionPreference = "Continue"

function Test-Cmd {
    param([Parameter(Mandatory = $true)][string]$Name)
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Add-PlanLine {
    param(
        [System.Collections.Generic.List[string]]$Lines,
        [string]$Line
    )
    $Lines.Add($Line) | Out-Null
}

function Invoke-CheckedCommand {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$ArgumentList,
        [Parameter(Mandatory = $true)][string]$Description
    )

    Write-Host "[EXEC] $Description"
    Write-Host "       $FilePath $($ArgumentList -join ' ')"
    & $FilePath @ArgumentList
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Command failed ($LASTEXITCODE): $Description"
        return $false
    }
    return $true
}

function New-PythonWrapper {
    param(
        [Parameter(Mandatory = $true)][string]$CmdName,
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [Parameter(Mandatory = $true)][string]$BinDir,
        [switch]$Overwrite
    )

    if (-not (Test-Path -LiteralPath $BinDir)) {
        New-Item -ItemType Directory -Path $BinDir -Force | Out-Null
    }

    $batPath = Join-Path $BinDir "$CmdName.bat"
    if ((Test-Path -LiteralPath $batPath) -and -not $Overwrite) {
        Write-Host "[SKIP] Wrapper exists: $batPath (use -Force to overwrite)"
        return
    }

    $fullScriptPath = (Resolve-Path -LiteralPath $ScriptPath -ErrorAction SilentlyContinue).Path
    if (-not $fullScriptPath) {
        $fullScriptPath = $ScriptPath
    }

    $content = "@echo off`r`npython `"$fullScriptPath`" %*"
    Set-Content -LiteralPath $batPath -Value $content -Encoding Ascii
    Write-Host "[OK] Wrapper: $batPath -> $fullScriptPath"
}

$toolsDir = Join-Path $Root "tools\ctf-website"
$reportDir = Join-Path $Root "reports\ctf-website\toolcheck"
$goBin = Join-Path $toolsDir "bin"
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$planPath = Join-Path $reportDir "install_plan_$timestamp.md"

New-Item -ItemType Directory -Path $toolsDir -Force | Out-Null
New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
New-Item -ItemType Directory -Path $goBin -Force | Out-Null

$goTools = @(
    @{ Name = "ffuf";     Module = "github.com/ffuf/ffuf/v2@latest" },
    @{ Name = "gobuster"; Module = "github.com/OJ/gobuster/v3@latest" },
    @{ Name = "katana";   Module = "github.com/projectdiscovery/katana/cmd/katana@latest" },
    @{ Name = "nuclei";   Module = "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest" },
    @{ Name = "httpx";    Module = "github.com/projectdiscovery/httpx/cmd/httpx@latest" }
)

$pythonRepos = @(
    @{ Name = "sqlmap";    Url = "https://github.com/sqlmapproject/sqlmap.git"; Script = "sqlmap.py" },
    @{ Name = "dirsearch"; Url = "https://github.com/maurosoria/dirsearch.git"; Script = "dirsearch.py" },
    @{ Name = "jwt_tool";  Url = "https://github.com/ticarpi/jwt_tool.git"; Script = "jwt_tool.py" },
    @{ Name = "tplmap";    Url = "https://github.com/epinna/tplmap.git"; Script = "tplmap.py" }
)

$plan = [System.Collections.Generic.List[string]]::new()
Add-PlanLine $plan "# CTF Website Tool Install Plan"
Add-PlanLine $plan ""
Add-PlanLine $plan "- Root: ``$Root``"
Add-PlanLine $plan "- Mode: $(if ($Execute) { 'EXECUTE' } else { 'DRY RUN' })"
Add-PlanLine $plan "- Tools dir: ``$toolsDir``"
Add-PlanLine $plan "- Local bin: ``$LocalBin``"
Add-PlanLine $plan "- Generated: $(Get-Date -Format o)"
Add-PlanLine $plan ""

Write-Host "=== ReverseLab CTF Website Tool Enrichment ==="
Write-Host "Root: $Root"
if (-not $Execute) {
    Write-Host "Mode: DRY RUN (no install/clone/write wrappers). Re-run with -Execute to apply." -ForegroundColor Yellow
} else {
    Write-Host "Mode: EXECUTE" -ForegroundColor Green
}

if (-not $SkipGo) {
    Add-PlanLine $plan "## Go-based tools"
    if (-not (Test-Cmd "go")) {
        Write-Warning "go not found; Go-based tools cannot be installed."
        Add-PlanLine $plan "- [BLOCKED] ``go`` not found in PATH."
    } else {
        foreach ($tool in $goTools) {
            $existing = Get-Command $tool.Name -ErrorAction SilentlyContinue
            $existingSource = if ($existing) { [string]$existing.Source } else { "" }
            $isExpectedGoBin = $existingSource.StartsWith($goBin, [System.StringComparison]::OrdinalIgnoreCase)
            if ($existing -and $isExpectedGoBin) {
                Add-PlanLine $plan "- [PRESENT] ``$($tool.Name)`` -> ``$($existing.Source)``"
                Write-Host "[PRESENT] $($tool.Name): $($existing.Source)"
                continue
            }
            if ($existing -and -not $isExpectedGoBin) {
                Add-PlanLine $plan "- [PATH-CONFLICT] ``$($tool.Name)`` currently resolves to ``$existingSource``; still plan Go install into ``$goBin``."
                Write-Warning "$($tool.Name) resolves outside Go bin: $existingSource"
            }
            Add-PlanLine $plan "- [INSTALL] ``go install $($tool.Module)``"
            if ($Execute) {
                $oldGoProxy = $env:GOPROXY
                $oldGoBin = $env:GOBIN
                $env:GOPROXY = $GoProxy
                $env:GOBIN = $goBin
                Invoke-CheckedCommand -FilePath "go" -ArgumentList @("install", $tool.Module) -Description "install $($tool.Name)" | Out-Null
                $env:GOPROXY = $oldGoProxy
                $env:GOBIN = $oldGoBin
            } else {
                Write-Host "[PLAN] go install $($tool.Module)"
            }
        }
    }
    Add-PlanLine $plan ""
}

if (-not $SkipPython) {
    Add-PlanLine $plan "## Python/Git tools"
    if (-not (Test-Cmd "git")) {
        Write-Warning "git not found; Python repository tools cannot be cloned."
        Add-PlanLine $plan "- [BLOCKED] ``git`` not found in PATH."
    } else {
        foreach ($repo in $pythonRepos) {
            $targetPath = Join-Path $toolsDir $repo.Name
            if (Test-Path -LiteralPath $targetPath) {
                Add-PlanLine $plan "- [PRESENT] ``$($repo.Name)`` -> ``$targetPath``"
                Write-Host "[PRESENT] $($repo.Name): $targetPath"
                continue
            }
            Add-PlanLine $plan "- [CLONE] ``git clone --depth 1 $($repo.Url) $targetPath``"
            if ($Execute) {
                Invoke-CheckedCommand -FilePath "git" -ArgumentList @("clone", "--depth", "1", $repo.Url, $targetPath) -Description "clone $($repo.Name)" | Out-Null
            } else {
                Write-Host "[PLAN] git clone --depth 1 $($repo.Url) $targetPath"
            }
        }
    }
    Add-PlanLine $plan ""
}

Add-PlanLine $plan "## Wrappers"
if ($CreateWrappers) {
    if (-not $Execute) {
        Add-PlanLine $plan "- [PLAN] Wrapper creation requested but deferred because mode is DRY RUN."
    }
    foreach ($repo in $pythonRepos) {
        $scriptPath = Join-Path (Join-Path $toolsDir $repo.Name) $repo.Script
        $wrapperPath = Join-Path $LocalBin "$($repo.Name).bat"
        Add-PlanLine $plan "- [WRAPPER] ``$wrapperPath`` -> ``$scriptPath``"
        if ($Execute) {
            New-PythonWrapper -CmdName $repo.Name -ScriptPath $scriptPath -BinDir $LocalBin -Overwrite:$Force
        } else {
            Write-Host "[PLAN] wrapper $wrapperPath -> $scriptPath"
        }
    }
} else {
    Add-PlanLine $plan "- [SKIP] Wrapper creation disabled. Use ``-CreateWrappers`` when needed."
}

Add-PlanLine $plan ""
Add-PlanLine $plan "## PATH hints"
Add-PlanLine $plan "- Go bin: ``$goBin``"
Add-PlanLine $plan "- Local bin: ``$LocalBin``"
Add-PlanLine $plan "- This script does not mutate PATH automatically."

Set-Content -LiteralPath $planPath -Value ($plan -join "`r`n") -Encoding UTF8

Write-Host ""
Write-Host "Install plan written to: $planPath"
if (-not $Execute) {
    Write-Host "No changes applied. To install: powershell -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Execute -CreateWrappers" -ForegroundColor Yellow
}
