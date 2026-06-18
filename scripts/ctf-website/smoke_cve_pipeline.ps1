param(
    [string]$Root = (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)),
    [switch]$RunNetwork
)

$ErrorActionPreference = "Stop"

function New-Dir([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Force -Path $Path | Out-Null
    }
}

$caseDir = Join-Path $Root "cases\2026-06-cve-pipeline-smoke"
$reportDir = Join-Path $Root "reports\ctf-website\smoke"
$fixtureDir = Join-Path $Root "tests\fixtures\cve-chain"
$plannerOut = Join-Path $reportDir "chain"
New-Dir $caseDir
New-Dir $reportDir
New-Dir $plannerOut

$fingerprints = Join-Path $caseDir "fingerprints.json"
if (-not (Test-Path -LiteralPath $fingerprints)) {
    Copy-Item -LiteralPath (Join-Path $Root "templates\cases\fingerprints.json") -Destination $fingerprints
}

$manifestPath = Join-Path $reportDir "ai_manifest.smoke.json"
$nextMd = Join-Path $reportDir "ai_next.smoke.md"
$manifest = [ordered]@{
    schema = "reverselab.ctf_website.ai_manifest.v1"
    case = "2026-06-cve-pipeline-smoke"
    board = "ctf-website"
    target = @{ url = "http://127.0.0.1:8080/" }
    paths = @{ case = $caseDir }
    baseline = @{ status = 200; headers = @{ Server = "GeoServer 2.25.1"; "X-Powered-By" = "Spring" } }
    parsed = @{ links = @("/"); scripts = @(); forms = @() }
    evidence = @()
    dead_ends = @()
}
$manifest | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $manifestPath -Encoding UTF8

$aiJsonText = python (Join-Path $Root "scripts\ctf-website\ctf_ai_next.py") $manifestPath --out $nextMd
$ai = $aiJsonText | ConvertFrom-Json
if (-not $ai.actions -or $ai.actions[0].priority -ne "P0" -or $ai.actions[0].command -notmatch "fingerprint_cve_pipeline\.py") {
    throw "ctf_ai_next did not promote fingerprint_cve_pipeline.py to the first P0 action"
}

$chainText = python (Join-Path $Root "scripts\ctf-website\cve_chain_planner.py") --from-dir $fixtureDir --out $plannerOut
$candidateLine = ($chainText | Select-String -Pattern "candidates:\s+(\d+)" | Select-Object -Last 1).Matches.Groups[1].Value
$candidateCount = [int]$candidateLine
if ($candidateCount -lt 1) {
    throw "cve_chain_planner did not generate any chain candidate from fixture input"
}

$networkResult = $null
if ($RunNetwork) {
    $networkText = python (Join-Path $Root "scripts\ctf-website\fingerprint_cve_pipeline.py") --fingerprints $fingerprints --per-fingerprint-limit 5 --max-cves 5 --min-score 20
    $pipelinePath = ($networkText | Select-String -Pattern "pipeline JSON:\s+(.+)$" | Select-Object -Last 1).Matches.Groups[1].Value
    $enriched = ($networkText | Select-String -Pattern "enriched CVEs:\s+(\d+)" | Select-Object -Last 1).Matches.Groups[1].Value
    if (-not $pipelinePath -or [int]$enriched -lt 1) {
        throw "fingerprint_cve_pipeline did not report a pipeline JSON path with enriched CVEs"
    }
    $networkResult = [ordered]@{
        PipelineJson = $pipelinePath
        EnrichedCves = [int]$enriched
    }
}

$result = [ordered]@{
    Overall = "PASS"
    AiNext = $nextMd
    PlannerOut = $plannerOut
    FixtureChains = $candidateCount
    NetworkRun = [bool]$RunNetwork
    NetworkResult = $networkResult
}
$result | ConvertTo-Json -Depth 20
