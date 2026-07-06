param(
    [switch]$NonInteractive
)

$ErrorActionPreference = "Stop"
[Console]::InputEncoding = [System.Text.UTF8Encoding]::new()
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()
$OutputEncoding = [Console]::OutputEncoding

function Resolve-PythonCommand {
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

function Get-LocalContext {
    $repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $localRoot = Join-Path $repoRoot ".open-reverselab-local"
    return [ordered]@{
        RepoRoot = $repoRoot
        LocalRoot = $localRoot
        PythonRoot = Join-Path $repoRoot "scripts\codex\python"
        ReportsRoot = Join-Path $localRoot "reports"
        ManagerScript = Join-Path (Join-Path $repoRoot "scripts\codex\python") "open_reverselab_codex_manager.py"
        FirstRunScript = Join-Path $repoRoot "scripts\misc\first_run_check.py"
        StartHereScript = Join-Path $repoRoot "scripts\misc\start_here.ps1"
        GlobalCodexConfig = Join-Path (Join-Path $HOME ".codex") "config.toml"
    }
}

function Invoke-ManagerJson {
    param(
        [hashtable]$Context,
        [string[]]$ManagerArgs
    )

    $python = Resolve-PythonCommand
    if (-not $python) {
        throw "Python 3.10+ 未找到。请先安装 Python，并确保 PATH 中可以使用 python 或 py -3。"
    }

    $commandArgs = @()
    $commandArgs += $python.Args
    $commandArgs += $Context.ManagerScript
    $commandArgs += $ManagerArgs

    $output = & $python.Exe @commandArgs 2>&1 | Out-String
    $exitCode = $LASTEXITCODE
    $payload = $null
    try {
        $payload = $output | ConvertFrom-Json -ErrorAction Stop
    } catch {
        $payload = [ordered]@{
            raw_output = $output.Trim()
            parse_error = $_.Exception.Message
        }
    }

    return [ordered]@{
        ExitCode = $exitCode
        Output = $output.Trim()
        Payload = $payload
    }
}

function Invoke-PythonJson {
    param(
        [hashtable]$Context,
        [string]$ScriptPath,
        [string[]]$ScriptArgs = @()
    )

    $python = Resolve-PythonCommand
    if (-not $python) {
        throw "Python 3.10+ 未找到。请先安装 Python，并确保 PATH 中可以使用 python 或 py -3。"
    }

    $commandArgs = @()
    $commandArgs += $python.Args
    $commandArgs += $ScriptPath
    $commandArgs += $ScriptArgs

    $output = & $python.Exe @commandArgs 2>&1 | Out-String
    $exitCode = $LASTEXITCODE
    $payload = $null
    try {
        $payload = $output | ConvertFrom-Json -ErrorAction Stop
    } catch {
        $payload = [ordered]@{
            raw_output = $output.Trim()
            parse_error = $_.Exception.Message
        }
    }

    return [ordered]@{
        ExitCode = $exitCode
        Output = $output.Trim()
        Payload = $payload
    }
}

function Pause-Continue {
    Write-Host ""
    Read-Host "按回车继续"
}

function Show-Title {
    Clear-Host
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host " open-reverselab Codex 工作台" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Get-StartupSnapshot {
    param([hashtable]$Context)

    $status = Invoke-ManagerJson -Context $Context -ManagerArgs @("status")
    $firstRun = Invoke-PythonJson -Context $Context -ScriptPath $Context.FirstRunScript -ScriptArgs @("--json")

    return [ordered]@{
        Status = $status
        FirstRun = $firstRun
    }
}

function Show-StartupSummary {
    param([hashtable]$Context)

    $snapshot = Get-StartupSnapshot -Context $Context
    $statusPayload = $snapshot.Status.Payload
    $firstRunPayload = $snapshot.FirstRun.Payload

    Write-Host "启动快速检查" -ForegroundColor Green

    if ($statusPayload.global_install_ready) {
        Write-Host "- Codex 全局接入：PASS" -ForegroundColor Green
    } else {
        Write-Host "- Codex 全局接入：FAIL" -ForegroundColor Red
    }

    if ($statusPayload.wrapper_exists -and $statusPayload.manager_exists) {
        Write-Host "- Codex 本地桥接：PASS" -ForegroundColor Green
    } else {
        Write-Host "- Codex 本地桥接：FAIL" -ForegroundColor Red
    }

    $failCount = 0
    $warnCount = 0
    if ($firstRunPayload.summary) {
        $failCount = [int]$firstRunPayload.summary.fail
        $warnCount = [int]$firstRunPayload.summary.warn
    }
    if ($failCount -gt 0) {
        Write-Host "- 原版首检关键项：FAIL（FAIL=$failCount, WARN=$warnCount）" -ForegroundColor Red
    } elseif ($warnCount -gt 0) {
        Write-Host "- 原版首检关键项：WARN（WARN=$warnCount）" -ForegroundColor Yellow
    } else {
        Write-Host "- 原版首检关键项：PASS" -ForegroundColor Green
    }

    Write-Host "- 当前仓库 .codex/config.toml：" -NoNewline
    if ($statusPayload.workspace_codex_config_exists) {
        Write-Host " 已存在（已保留，不会被本工作台删除）" -ForegroundColor Yellow
    } else {
        Write-Host " 未发现" -ForegroundColor DarkYellow
    }

    Write-Host "- 已绑定项目数：$($statusPayload.bound_project_count)"
    Write-Host "- 公开版适配版本：$($statusPayload.adapter_version)"
    if ($statusPayload.replaceable_related_mcp_sections -and $statusPayload.replaceable_related_mcp_sections.Count -gt 0) {
        Write-Host "- 检测到待替换旧 MCP 条目：$($statusPayload.replaceable_related_mcp_sections.Count) 个" -ForegroundColor Yellow
    }
    if ($statusPayload.available_upgrade_batches -and $statusPayload.available_upgrade_batches.Count -gt 0) {
        Write-Host "- 可用升级批次：$($statusPayload.available_upgrade_batches.Count) 个"
    }

    if ($failCount -gt 0) {
        Write-Host ""
        Write-Host "提示：原版首检有缺项，但不会阻止你进入 Codex 菜单。" -ForegroundColor Yellow
        Write-Host "如需生成原版报告，请选 3. 完整首检 / 生成原版报告。" -ForegroundColor Yellow
    }
    Write-Host ""
}

function Show-FirstUseGuide {
    param([hashtable]$Context)

    Write-Host "初次使用流程" -ForegroundColor Yellow
    Write-Host "1. 先选 1. 安装/修复 全局 Codex MCP。"
    Write-Host "2. 安装完成后，完全关闭并重新打开 Codex App；Codex CLI 也建议重开。"
    Write-Host "3. 打开你真正要工作的目标项目。"
    Write-Host "4. 在新项目会话里输入：启用 open-reverselab Codex 模式。"
    Write-Host "5. 首次启用会先预览改动，再要求你输入精确确认短语。"
    Write-Host "6. 以后版本升级时，先关闭相关 Codex 会话，再运行 1. 安装/修复。"
    Write-Host ""
    Write-Host "当前仓库：" -NoNewline
    Write-Host " $($Context.RepoRoot)" -ForegroundColor Green
    Write-Host ""
}

function Show-MainMenu {
    Write-Host "主菜单" -ForegroundColor Green
    Write-Host "1. 安装/修复 全局 Codex MCP"
    Write-Host "   说明：写入用户目录下的 .codex/config.toml，注册 open_reverselab_codex，并自动升级已登记公开版项目。"
    Write-Host "2. 启动前快速自检 / 状态查看"
    Write-Host "   说明：查看 Codex 启动关键项，以及原版 first-run 关键摘要。"
    Write-Host "3. 完整首检 / 生成原版报告"
    Write-Host "   说明：调用原版 START_HERE 流程，生成 first-run-report.json 和 mcp-smoke-report.json。"
    Write-Host "4. 项目管理"
    Write-Host "   说明：给其他项目做绑定、状态、修复、解绑，并管理项目级 .codex 运行层。"
    Write-Host "5. 备份 / 恢复"
    Write-Host "   说明：优先按升级批次查看和回退，也支持底层 backup_id 恢复；不覆盖分析产物。"
    Write-Host "6. 使用说明"
    Write-Host "   说明：告诉你该先启动哪个 BAT、接着做什么、会话里输入什么。"
    Write-Host "0. 退出"
    Write-Host ""
}

function Show-UsageGuide {
    param([hashtable]$Context)

    Write-Host "推荐使用顺序" -ForegroundColor Green
    Write-Host "1. 只用 Codex 时，双击 CODEX.bat。"
    Write-Host "2. 如果你想看总入口，双击 LAUNCHER.bat。"
    Write-Host "3. 在 CODEX.bat 里先选 1. 安装/修复 全局 Codex MCP。"
    Write-Host "4. 安装后关闭并重新打开 Codex App；Codex CLI 也重新打开。"
    Write-Host "5. 打开你真正要工作的目标项目。"
    Write-Host "6. 在目标项目会话里输入：启用 open-reverselab Codex 模式。"
    Write-Host "7. 查看状态时输入：查看 open-reverselab Codex 状态。"
    Write-Host "8. 取消接入时输入：停用 open-reverselab Codex 模式。"
    Write-Host ""
    Write-Host "当前结构说明" -ForegroundColor Yellow
    Write-Host "- START_HERE.bat：原作者原版入口，保持不动。"
    Write-Host "- LAUNCHER.bat：总工作台入口，用于 Codex / Claude / 其他 CLI 分流。"
    Write-Host "- CODEX.bat：Codex 专用入口，只做 Codex 相关操作。"
    Write-Host "- 项目首次接入后，会在目标项目生成 .codex/ 受管文件；停用时默认保留这些文件。"
    Write-Host "- 本地运行状态会写到 .open-reverselab-local/，这是本地目录，不提交到仓库。"
    Write-Host ""
    Write-Host "目标项目常用目录" -ForegroundColor Yellow
    Write-Host "- notes/open-reverselab"
    Write-Host "- reports/open-reverselab"
    Write-Host "- exports/open-reverselab"
    Write-Host "- .open-reverselab-codex"
    Write-Host "- .codex"
}

function Confirm-And-Install {
    param([hashtable]$Context)

    Write-Host "正在执行全局安装/修复..." -ForegroundColor Green
    $managerArgs = @("install")
    while ($true) {
        $result = Invoke-ManagerJson -Context $Context -ManagerArgs $managerArgs
        if ($result.ExitCode -ne 2) {
            break
        }

        if ($result.Payload.confirmation_kind -eq "replace_related") {
            Write-Host ""
            Write-Host "检测到旧的相关 MCP 条目，需要你明确确认后才能替换。" -ForegroundColor Yellow
            if ($result.Payload.related_entries) {
                foreach ($entry in $result.Payload.related_entries) {
                    Write-Host ""
                    Write-Host "旧条目：" -ForegroundColor Yellow
                    Write-Host $entry.header
                    Write-Host $entry.text
                }
            }
            Write-Host ""
            Write-Host "新条目将注册为：" -ForegroundColor Green
            $desired = $result.Payload.desired_server
            Write-Host "名称：$($desired.name)"
            Write-Host "命令：$($desired.command)"
            Write-Host "参数：$([string]::Join(' ', $desired.args))"
            Write-Host ""
            $confirm = Read-Host "输入 YES 才继续替换旧条目"
            if ($confirm -ne "YES") {
                Write-Host "已取消替换。" -ForegroundColor Yellow
                Pause-Continue
                return
            }
            if ("--replace-related" -notin $managerArgs) {
                $managerArgs += "--replace-related"
            }
            continue
        }

        if ($result.Payload.confirmation_kind -eq "project_upgrades") {
            Write-Host ""
            Write-Host "检测到已登记公开版项目需要升级。" -ForegroundColor Yellow
            Write-Host "请先关闭相关 Codex App / Codex CLI / 其他会话，再继续。" -ForegroundColor Yellow
            Write-Host ""
            Write-Host "升级摘要：" -ForegroundColor Green
            Write-Host "- 需要升级：$($result.Payload.project_upgrade_summary.upgrade_needed)"
            Write-Host "- 离线/缺失：$($result.Payload.project_upgrade_summary.offline_missing)"
            Write-Host "- 标记缺失：$($result.Payload.project_upgrade_summary.marker_missing)"
            Write-Host "- 已是最新：$($result.Payload.project_upgrade_summary.already_current)"
            if ($result.Payload.project_upgrade_candidates) {
                Write-Host ""
                Write-Host "将升级这些项目：" -ForegroundColor Green
                foreach ($item in $result.Payload.project_upgrade_candidates) {
                    Write-Host "- $($item.project_root)  (当前版本 $($item.current_adapter_version))"
                }
            }
            Write-Host ""
            $confirm = Read-Host "确认你已经关闭相关会话，并输入 YES 继续"
            if ($confirm -ne "YES") {
                Write-Host "已取消升级。" -ForegroundColor Yellow
                Pause-Continue
                return
            }
            if ("--confirm-project-upgrades" -notin $managerArgs) {
                $managerArgs += "--confirm-project-upgrades"
            }
            continue
        }

        break
    }

    Write-Host ""
    Write-Host $result.Output
    Write-Host ""
    if ($result.ExitCode -eq 0) {
        Write-Host "安装/修复完成。" -ForegroundColor Green
        if ($result.Payload.project_upgrade_batch) {
            $summary = $result.Payload.project_upgrade_batch.summary
            Write-Host "项目升级摘要：" -ForegroundColor Green
            Write-Host "- 成功升级：$($summary.upgraded)"
            Write-Host "- 已是最新：$($summary.already_current)"
            Write-Host "- 离线跳过：$($summary.offline_missing)"
            Write-Host "- 标记缺失：$($summary.marker_missing)"
            Write-Host "- 升级失败：$($summary.upgrade_failed)"
        }
        Write-Host "请现在重启 Codex App；Codex CLI 也建议重新打开。" -ForegroundColor Green
    } else {
        Write-Host "安装/修复失败，请先看上面的 JSON 结果。" -ForegroundColor Red
    }
    Pause-Continue
}

function Show-DoctorStatus {
    param([hashtable]$Context)

    $snapshot = Get-StartupSnapshot -Context $Context
    $status = $snapshot.Status
    $firstRun = $snapshot.FirstRun

    Write-Host "Codex 状态摘要" -ForegroundColor Green
    Write-Host $status.Output
    Write-Host ""
    Write-Host "原版 first-run 摘要" -ForegroundColor Green
    Write-Host $firstRun.Output
    Pause-Continue
}

function Invoke-FullCheck {
    param([hashtable]$Context)

    Write-Host "即将运行原版 START_HERE 首检流程..." -ForegroundColor Green
    Write-Host "这会生成原版报告，并真实执行 MCP smoke check。" -ForegroundColor Yellow
    Write-Host ""
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $Context.StartHereScript
    $exitCode = $LASTEXITCODE
    Write-Host ""
    if ($exitCode -eq 0) {
        Write-Host "原版完整首检已完成。" -ForegroundColor Green
    } else {
        Write-Host "原版完整首检返回非零退出码：$exitCode" -ForegroundColor Yellow
    }
    Pause-Continue
}

function Read-ProjectPath {
    $projectPath = Read-Host "请输入目标项目完整路径"
    return $projectPath.Trim()
}

function Show-PreviewAndConfirm {
    param(
        [hashtable]$Context,
        [string[]]$CommandArgs,
        [string]$ActionLabel
    )

    $result = Invoke-ManagerJson -Context $Context -ManagerArgs $CommandArgs
    if ($result.ExitCode -eq 2) {
        $preview = $result.Payload.preview
        Write-Host ""
        Write-Host "$ActionLabel 预览" -ForegroundColor Yellow
        Write-Host "项目路径：$($preview.project_root)"
        Write-Host "将执行改动："
        foreach ($item in $preview.changes) {
            Write-Host "- $item"
        }
        Write-Host ""
        Write-Host "精确确认短语：" -ForegroundColor Green
        Write-Host $result.Payload.confirmation_text
        $confirmText = Read-Host "请原样输入确认短语；留空则取消"
        if ([string]::IsNullOrWhiteSpace($confirmText)) {
            Write-Host "已取消。" -ForegroundColor Yellow
            Pause-Continue
            return
        }
        $retryArgs = @($CommandArgs + @("--confirm-text", $confirmText))
        $result = Invoke-ManagerJson -Context $Context -ManagerArgs $retryArgs
    }

    Write-Host ""
    Write-Host $result.Output
    if ($result.ExitCode -eq 0) {
        Write-Host "$ActionLabel 完成。" -ForegroundColor Green
    } else {
        Write-Host "$ActionLabel 失败。" -ForegroundColor Red
    }
    Pause-Continue
}

function Show-ProjectMenu {
    param([hashtable]$Context)

    while ($true) {
        Show-Title
        Write-Host "项目管理" -ForegroundColor Green
        Write-Host "1. 绑定/启用 指定项目"
        Write-Host "2. 查看 指定项目状态"
        Write-Host "3. 修复 指定项目接入"
        Write-Host "4. 解绑/停用 指定项目"
        Write-Host "0. 返回上一级"
        Write-Host ""
        $choice = Read-Host "请选择"
        switch ($choice) {
            "1" {
                $path = Read-ProjectPath
                if ($path) {
                    Show-PreviewAndConfirm -Context $Context -CommandArgs @("bind-project", $path) -ActionLabel "项目绑定"
                }
            }
            "2" {
                $path = Read-ProjectPath
                if ($path) {
                    $result = Invoke-ManagerJson -Context $Context -ManagerArgs @("project-status", $path)
                    Write-Host ""
                    Write-Host $result.Output
                    Pause-Continue
                }
            }
            "3" {
                $path = Read-ProjectPath
                if ($path) {
                    Show-PreviewAndConfirm -Context $Context -CommandArgs @("repair-project", $path) -ActionLabel "项目修复"
                }
            }
            "4" {
                $path = Read-ProjectPath
                if ($path) {
                    Show-PreviewAndConfirm -Context $Context -CommandArgs @("unbind-project", $path) -ActionLabel "项目解绑"
                }
            }
            "0" { return }
            default {
                Write-Host "无效选项。" -ForegroundColor Yellow
                Start-Sleep -Milliseconds 700
            }
        }
    }
}

function Show-BackupMenu {
    param([hashtable]$Context)

    while ($true) {
        Show-Title
        Write-Host "备份 / 恢复" -ForegroundColor Green
        Write-Host "1. 查看升级批次"
        Write-Host "2. 按升级批次恢复单个项目"
        Write-Host "3. 查看底层备份列表"
        Write-Host "4. 按 backup_id 直接恢复"
        Write-Host "0. 返回上一级"
        Write-Host ""
        $choice = Read-Host "请选择"
        switch ($choice) {
            "1" {
                $result = Invoke-ManagerJson -Context $Context -ManagerArgs @("upgrade-batch-list")
                Write-Host ""
                Write-Host $result.Output
                Pause-Continue
            }
            "2" {
                $batchId = Read-Host "请输入升级批次 batch_id"
                if ([string]::IsNullOrWhiteSpace($batchId)) {
                    continue
                }
                $projectId = Read-Host "请输入该批次里的 project_id"
                if ([string]::IsNullOrWhiteSpace($projectId)) {
                    continue
                }
                $confirm = Read-Host "输入 RESTORE $batchId $projectId 才继续恢复"
                if ($confirm -ne "RESTORE $batchId $projectId") {
                    Write-Host "已取消恢复。" -ForegroundColor Yellow
                    Pause-Continue
                    continue
                }
                $result = Invoke-ManagerJson -Context $Context -ManagerArgs @("upgrade-batch-restore", $batchId, $projectId)
                Write-Host ""
                Write-Host $result.Output
                if ($result.ExitCode -eq 0) {
                    Write-Host "项目恢复完成。" -ForegroundColor Green
                } else {
                    Write-Host "项目恢复失败。" -ForegroundColor Red
                }
                Pause-Continue
            }
            "3" {
                $result = Invoke-ManagerJson -Context $Context -ManagerArgs @("backup-list")
                Write-Host ""
                Write-Host $result.Output
                Pause-Continue
            }
            "4" {
                $backupId = Read-Host "请输入要恢复的 backup_id"
                if ([string]::IsNullOrWhiteSpace($backupId)) {
                    continue
                }
                $confirm = Read-Host "输入 RESTORE $backupId 才继续恢复"
                if ($confirm -ne "RESTORE $backupId") {
                    Write-Host "已取消恢复。" -ForegroundColor Yellow
                    Pause-Continue
                    continue
                }
                $result = Invoke-ManagerJson -Context $Context -ManagerArgs @("backup-restore", $backupId)
                Write-Host ""
                Write-Host $result.Output
                if ($result.ExitCode -eq 0) {
                    Write-Host "恢复完成。" -ForegroundColor Green
                } else {
                    Write-Host "恢复失败。" -ForegroundColor Red
                }
                Pause-Continue
            }
            "0" { return }
            default {
                Write-Host "无效选项。" -ForegroundColor Yellow
                Start-Sleep -Milliseconds 700
            }
        }
    }
}

$context = Get-LocalContext

if ($NonInteractive) {
    Show-Title
    Show-StartupSummary -Context $context
    Show-FirstUseGuide -Context $context
    Show-MainMenu
    return
}

while ($true) {
    Show-Title
    Show-StartupSummary -Context $context
    Show-FirstUseGuide -Context $context
    Show-MainMenu
    $mainChoice = Read-Host "请选择"
    switch ($mainChoice) {
        "1" { Confirm-And-Install -Context $context }
        "2" { Show-DoctorStatus -Context $context }
        "3" { Invoke-FullCheck -Context $context }
        "4" { Show-ProjectMenu -Context $context }
        "5" { Show-BackupMenu -Context $context }
        "6" {
            Show-Title
            Show-UsageGuide -Context $context
            Pause-Continue
        }
        "0" { break }
        default {
            Write-Host "无效选项。" -ForegroundColor Yellow
            Start-Sleep -Milliseconds 700
        }
    }
}

