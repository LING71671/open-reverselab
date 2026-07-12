param(
    [string]$Root = (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
)

$ErrorActionPreference = "Stop"
$projectConfig = Join-Path $Root ".codex\config.toml"
$projectCtfConfig = Join-Path $Root ".codex\ctf.config.toml"
$projectPrompt = Join-Path $Root "CODEX.md"
$userCtfConfig = Join-Path $env:USERPROFILE ".codex\ctf.config.toml"
$userPrompt = Join-Path $env:USERPROFILE ".codex\prompts\ctf_optimized.md"
$expectedModel = "../CODEX.md"

function Get-ModelInstructionsFile([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $line = Get-Content -LiteralPath $Path | Where-Object { $_ -match '^\s*model_instructions_file\s*=' } | Select-Object -First 1
    if (-not $line) { return $null }
    return (($line -replace '^\s*model_instructions_file\s*=\s*', '').Trim().Trim('"').Trim("'"))
}

$projectModel = Get-ModelInstructionsFile $projectConfig
$projectCtfModel = Get-ModelInstructionsFile $projectCtfConfig
$userModel = Get-ModelInstructionsFile $userCtfConfig

$promptText = if (Test-Path -LiteralPath $projectPrompt) { Get-Content -LiteralPath $projectPrompt -Raw } else { "" }
$hasCodexRules = (
    ($promptText -match 'Presumption of authorization|默认已授权') -and
    ($promptText -match 'AI-USAGE') -and
    ($promptText -match 'kb/|知识库') -and
    ($promptText -match 'Default KB backfill|kb 填补|无 kb 增量')
)
$hasNoDisclaimerMention = -not ($promptText -match 'DISCLAIMER')

$result = [ordered]@{
    Overall = if (
        (Test-Path -LiteralPath $projectConfig) -and
        (Test-Path -LiteralPath $projectCtfConfig) -and
        (Test-Path -LiteralPath $projectPrompt) -and
        ($projectModel -eq $expectedModel) -and
        ($projectCtfModel -eq $expectedModel) -and
        $hasCodexRules -and
        $hasNoDisclaimerMention
    ) { 'PASS' } else { 'FAIL' }
    ProjectConfig = $projectConfig
    ProjectConfigModelInstructionsFile = $projectModel
    ProjectCtfConfig = $projectCtfConfig
    ProjectCtfConfigModelInstructionsFile = $projectCtfModel
    ExpectedModelInstructionsFile = $expectedModel
    ProjectPrompt = $projectPrompt
    ProjectPromptExists = Test-Path -LiteralPath $projectPrompt
    ProjectPromptHasCodexRules = $hasCodexRules
    ProjectPromptOmitsDisclaimer = $hasNoDisclaimerMention
    UserCtfConfig = $userCtfConfig
    UserCtfConfigModelInstructionsFile = $userModel
    UserPrompt = $userPrompt
    UserPromptExists = Test-Path -LiteralPath $userPrompt
}

$result | ConvertTo-Json -Depth 4
if ($result.Overall -ne 'PASS') { exit 1 }
