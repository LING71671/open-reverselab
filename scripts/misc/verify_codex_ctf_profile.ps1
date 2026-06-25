param(
    [string]$Root = (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
)

$ErrorActionPreference = "Stop"
$projectConfig = Join-Path $Root ".codex\config.toml"
$projectCtfConfig = Join-Path $Root ".codex\ctf.config.toml"
$projectPrompt = Join-Path $Root ".codex\ctf_optimized.md"
$userCtfConfig = Join-Path $env:USERPROFILE ".codex\ctf.config.toml"
$userPrompt = Join-Path $env:USERPROFILE ".codex\prompts\ctf_optimized.md"

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
$hasCtfRules = $promptText -match 'CTF game' -and $promptText -match 'Attack Workflow' -and $promptText -match 'CVE'

$result = [ordered]@{
    Overall = if ((Test-Path -LiteralPath $projectConfig) -and (Test-Path -LiteralPath $projectCtfConfig) -and (Test-Path -LiteralPath $projectPrompt) -and $projectModel -eq 'ctf_optimized.md' -and $projectCtfModel -eq 'ctf_optimized.md' -and $hasCtfRules) { 'PASS' } else { 'FAIL' }
    ProjectConfig = $projectConfig
    ProjectConfigModelInstructionsFile = $projectModel
    ProjectCtfConfig = $projectCtfConfig
    ProjectCtfConfigModelInstructionsFile = $projectCtfModel
    ProjectPrompt = $projectPrompt
    ProjectPromptExists = Test-Path -LiteralPath $projectPrompt
    ProjectPromptHasCtfRules = $hasCtfRules
    UserCtfConfig = $userCtfConfig
    UserCtfConfigModelInstructionsFile = $userModel
    UserPrompt = $userPrompt
    UserPromptExists = Test-Path -LiteralPath $userPrompt
}

$result | ConvertTo-Json -Depth 4
if ($result.Overall -ne 'PASS') { exit 1 }
