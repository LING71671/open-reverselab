<#
.SYNOPSIS
Check or install the optional external tools used by Open-ReverseLab.

.DESCRIPTION
The lab works without any of these. Each tool only adds coverage:

  Wireshark    tshark/capinfos for pcap_summary / pcap_extract_http
  ilspycmd     dotnet_list_types / dotnet_decompile_type
  WABT         wasm_info

Default is a dry run: it prints what it would run and what is already present.
Pass -Apply to execute installs.

.EXAMPLE
powershell -ExecutionPolicy Bypass -File scripts/misc/install_engines.ps1
powershell -ExecutionPolicy Bypass -File scripts/misc/install_engines.ps1 -Wireshark -Apply
#>
[CmdletBinding()]
param(
    [switch]$Wireshark,
    [switch]$DotnetTools,
    [switch]$WABT,
    [switch]$All,
    [switch]$Apply
)

$ErrorActionPreference = 'Continue'
if ($All) { $Wireshark = $true; $DotnetTools = $true; $WABT = $true }
if (-not ($Wireshark -or $DotnetTools -or $WABT)) {
    $Wireshark = $true; $DotnetTools = $true; $WABT = $true
}

function Get-CommandPath([string]$Name) {
    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return $null
}

function Step([string]$Title, [string]$State, [string]$Detail) {
    Write-Host ("[{0}] {1}" -f $State, $Title) -ForegroundColor $(if ($State -eq 'OK') { 'Green' } elseif ($State -eq 'MISSING') { 'Yellow' } else { 'Cyan' })
    if ($Detail) { Write-Host "      $Detail" -ForegroundColor Gray }
}

Write-Host "Open-ReverseLab optional external tools (dry run: $(-not $Apply))" -ForegroundColor Cyan
Write-Host ""

if ($Wireshark) {
    $tshark = Get-CommandPath 'tshark'
    if ($tshark) {
        Step 'Wireshark / tshark' 'OK' $tshark
    } else {
        Step 'Wireshark / tshark' 'MISSING' 'winget install --id Wireshark.Wireshark -e'
        if ($Apply) { & winget install --id Wireshark.Wireshark -e --accept-source-agreements --accept-package-agreements }
    }
}

if ($DotnetTools) {
    $ilspy = Get-CommandPath 'ilspycmd'
    if ($ilspy) {
        Step 'ilspycmd' 'OK' $ilspy
    } else {
        Step 'ilspycmd' 'MISSING' 'dotnet tool install -g ilspycmd'
        if ($Apply) { & dotnet tool install -g ilspycmd }
    }
}

if ($WABT) {
    $objdump = Get-CommandPath 'wasm-objdump'
    if ($objdump) {
        Step 'WABT' 'OK' $objdump
    } else {
        Step 'WABT' 'MISSING' 'choco install wabt -y (or download WABT and add it to PATH)'
        if ($Apply) {
            if (Get-CommandPath 'choco') { & choco install wabt -y } else { Write-Host '      chocolatey is not installed; install WABT manually.' -ForegroundColor Yellow }
        }
    }
}

Write-Host ""
Write-Host "Nothing here is required for the core lab. Missing tools surface as missing_engine envelopes." -ForegroundColor Gray
