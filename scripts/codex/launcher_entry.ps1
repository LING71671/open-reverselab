param()

$ErrorActionPreference = "Stop"
[Console]::InputEncoding = [System.Text.UTF8Encoding]::new()
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()
$OutputEncoding = [Console]::OutputEncoding

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$codexEntry = Join-Path $PSScriptRoot "codex_entry.ps1"
$startHere = Join-Path $repoRoot "scripts\misc\start_here.ps1"

function Pause-Continue {
    Write-Host ""
    Read-Host "按回车继续"
}

function Show-Title {
    Clear-Host
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host " open-reverselab 启动工作台" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Show-Intro {
    Write-Host "你现在只需要记这三个入口：" -ForegroundColor Yellow
    Write-Host "- CODEX.bat：Codex 专用入口。"
    Write-Host "- LAUNCHER.bat：总工作台入口。"
    Write-Host "- START_HERE.bat：原作者原版入口，保持不动。"
    Write-Host ""
}

function Show-Menu {
    Write-Host "主菜单" -ForegroundColor Green
    Write-Host "1. Codex"
    Write-Host "   说明：进入 Codex 专用工作台，只处理 Codex 的安装、检查、项目管理。"
    Write-Host "2. Claude"
    Write-Host "   说明：运行原版 START_HERE 首检流程，适合 Claude Code。"
    Write-Host "3. 其他 CLI"
    Write-Host "   说明：运行原版 START_HERE 首检流程，适合 Opencode / 其他兼容 CLI。"
    Write-Host "4. 全部"
    Write-Host "   说明：先跑原版 START_HERE 首检，再进入 Codex 工作台。"
    Write-Host "5. 使用说明"
    Write-Host "   说明：告诉你不同入口分别在什么场景使用。"
    Write-Host "0. 退出"
    Write-Host ""
}

function Invoke-StartHere {
    Write-Host "正在运行原版 START_HERE 流程..." -ForegroundColor Green
    Write-Host ""
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $startHere
    $exitCode = $LASTEXITCODE
    Write-Host ""
    if ($exitCode -eq 0) {
        Write-Host "原版 START_HERE 流程已完成。" -ForegroundColor Green
    } else {
        Write-Host "原版 START_HERE 返回非零退出码：$exitCode" -ForegroundColor Yellow
    }
    Pause-Continue
}

function Show-Usage {
    Write-Host "入口分工" -ForegroundColor Green
    Write-Host "- 如果你现在只做 Codex：直接用 CODEX.bat。"
    Write-Host "- 如果你想通过一个总菜单来分流：用 LAUNCHER.bat。"
    Write-Host "- 如果你只想保留原作者原版流程：用 START_HERE.bat。"
    Write-Host ""
    Write-Host "推荐习惯" -ForegroundColor Yellow
    Write-Host "- Codex 用户：以后优先双击 CODEX.bat。"
    Write-Host "- Claude / 其他 CLI 用户：优先走 START_HERE.bat 或 LAUNCHER.bat 里的对应入口。"
    Write-Host "- 需要同时核对原版首检和 Codex 接入：选 4. 全部。"
    Pause-Continue
}

while ($true) {
    Show-Title
    Show-Intro
    Show-Menu
    $choice = Read-Host "请选择"
    switch ($choice) {
        "1" {
            & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $codexEntry
        }
        "2" { Invoke-StartHere }
        "3" { Invoke-StartHere }
        "4" {
            & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $startHere
            Write-Host ""
            Write-Host "接下来进入 Codex 工作台..." -ForegroundColor Green
            Start-Sleep -Milliseconds 700
            & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $codexEntry
        }
        "5" {
            Show-Title
            Show-Usage
        }
        "0" { break }
        default {
            Write-Host "无效选项。" -ForegroundColor Yellow
            Start-Sleep -Milliseconds 700
        }
    }
}

