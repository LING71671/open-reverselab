<#
.SYNOPSIS
    快速 MCP 检查入口：包装 mcp_smoke_check.py，输出简短 PASS/FAIL 摘要。

.DESCRIPTION
    等价于完整命令：
      uv run --project tools/skills/mcp/ReverseLabToolsMCP python scripts/misc/mcp_smoke_check.py --write-report
    但输出更短的摘要（MCP / Tools / 各 required tool 的 PASS/FAIL），
    方便新手快速确认 MCP 是否已可用。始终写入 reports/misc/mcp-smoke-report.json。

.EXAMPLE
    .\scripts\misc\check_mcp.ps1
    .\scripts\misc\check_mcp.ps1 -Json   # 输出原始 JSON，便于脚本消费
#>

param(
    [switch]$Json
)

$ErrorActionPreference = "Stop"
# Windows PowerShell 5.1 按 ANSI 解码 native stdout，这里强制 UTF-8 避免中文 JSON 乱码
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Set-Location -LiteralPath $root

$script = "scripts\misc\mcp_smoke_check.py"
$python = Get-Command python -ErrorAction SilentlyContinue
$uv = Get-Command uv -ErrorAction SilentlyContinue

if (-not $python -and -not $uv) {
    Write-Host "MCP: FAIL (python not found in PATH)" -ForegroundColor Red
    Write-Host "请先安装 Python 3.10+（勾选 Add python.exe to PATH）：https://www.python.org/downloads/windows/"
    exit 1
}

$report = if ($uv) {
    & $uv run --project tools/skills/mcp/ReverseLabToolsMCP python $script --json --write-report
} else {
    & $python.Source $script --json --write-report
}

if ($LASTEXITCODE -ne 0) {
    Write-Host "MCP: FAIL (smoke check 运行失败)" -ForegroundColor Red
    Write-Host "可尝试完整命令获取详情："
    Write-Host "  uv run --project tools/skills/mcp/ReverseLabToolsMCP python scripts/misc/mcp_smoke_check.py --write-report"
    exit 1
}

if ($Json) {
    $report | Write-Output
    exit 0
}

# native stdout 是多行 string[]；先 join 再解析（兼容 Windows PowerShell 5.1）
$payload = ($report -join "`n") | ConvertFrom-Json
$passColor = if ($payload.overall -eq "PASS") { "Green" } else { "Red" }
Write-Host "MCP: $($payload.overall)" -ForegroundColor $passColor
Write-Host "Tools: $($payload.tool_count)"
foreach ($check in $payload.checks) {
    $color = if ($check.level -eq "PASS") { "Green" } else { "Red" }
    Write-Host "$($check.name): $($check.level)" -ForegroundColor $color
}
if ($payload.overall -eq "FAIL") {
    Write-Host ""
    Write-Host "修复建议：运行完整检查并查看报告："
    Write-Host "  uv run --project tools/skills/mcp/ReverseLabToolsMCP python scripts/misc/mcp_smoke_check.py --write-report"
    Write-Host "  reports\misc\mcp-smoke-report.json"
    exit 1
}
exit 0
