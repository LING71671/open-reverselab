<#
.SYNOPSIS
    Web CTF 工具可用性检查
.DESCRIPTION
    检查 tools/ctf-website/ 下各工具的安装状态。
#>

param(
    [switch]$SkipVersionProbe
)

$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$ctfTools = Join-Path $root "tools\ctf-website"

Write-Host "`n=== CTF Website Tool Check ===`n" -ForegroundColor Cyan

$tools = @{
    "sqlmap"     = "sqlmap\sqlmap.py"
    "dirsearch"  = "dirsearch\dirsearch.py"
    "jwt_tool"   = "jwt_tool\jwt_tool.py"
    "tplmap"     = "tplmap\tplmap.py"
    "exploitdb"  = "exploitdb\searchsploit"
    "nmap"       = "nmap\nmap.exe"
    "Burp Suite" = "burp\burpsuite_community_*.jar"
}

foreach ($tool in $tools.GetEnumerator()) {
    $path = Join-Path $ctfTools $tool.Value
    $found = if ($tool.Value -match '\*') {
        Get-ChildItem -Path (Split-Path $path -Parent) -Name $tool.Value -ErrorAction SilentlyContinue
    } else {
        Test-Path $path
    }
    $status = if ($found) { "✓ Installed" } else { "✗ Missing — run: .\scripts\misc\install_tools.ps1 -CTF" }
    Write-Host "  $($tool.Key): $status"
}

Write-Host "`nDone.`n"
