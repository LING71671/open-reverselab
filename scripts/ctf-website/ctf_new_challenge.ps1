param(
    [Parameter(Mandatory=$true)][string]$Name,
    [string]$Url = "",
    [string]$Board = "ctf-website",
    [string]$Root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..")).Path
)

$ErrorActionPreference = "Stop"

function Convert-Slug {
    param([string]$Text)
    $slug = $Text.ToLowerInvariant() -replace '[^a-z0-9]+','-'
    $slug = $slug.Trim('-')
    if (-not $slug) { throw "invalid challenge name" }
    return $slug
}

$slug = Convert-Slug $Name
$caseName = "$(Get-Date -Format 'yyyy-MM')-$slug"
$caseDir = Join-Path $Root "cases\$caseName"
$paths = @{
    Case = $caseDir
    Samples = Join-Path $Root "samples\$Board\$slug"
    Projects = Join-Path $Root "projects\$Board\$slug"
    Exports = Join-Path $Root "exports\$Board\$slug"
    Patches = Join-Path $Root "patches\$Board\$slug"
    Notes = Join-Path $Root "notes\$Board\$slug"
    Reports = Join-Path $Root "reports\$Board\$slug"
    Scripts = Join-Path $Root "scripts\$Board\$slug"
}

foreach ($p in $paths.Values) {
    if (-not (Test-Path -LiteralPath $p)) { New-Item -ItemType Directory -Path $p | Out-Null }
}

$templateRoot = Join-Path $Root "templates\cases"
Copy-Item -LiteralPath (Join-Path $templateRoot "case-readme.md") -Destination (Join-Path $caseDir "README.md") -Force
Copy-Item -LiteralPath (Join-Path $templateRoot "links.md") -Destination (Join-Path $caseDir "links.md") -Force
Copy-Item -LiteralPath (Join-Path $templateRoot "timeline.md") -Destination (Join-Path $caseDir "timeline.md") -Force
Copy-Item -LiteralPath (Join-Path $templateRoot "findings.md") -Destination (Join-Path $caseDir "findings.md") -Force
Copy-Item -LiteralPath (Join-Path $templateRoot "open-questions.md") -Destination (Join-Path $caseDir "open-questions.md") -Force

$readme = Get-Content -LiteralPath (Join-Path $caseDir "README.md") -Raw
$readme = $readme.Replace("<case-name>", $caseName)
$readme = $readme.Replace("- Board(s):", "- Board(s): $Board")
$readme = $readme.Replace("- Created:", "- Created: $(Get-Date -Format 'yyyy-MM-dd')")
Set-Content -LiteralPath (Join-Path $caseDir "README.md") -Value $readme -Encoding UTF8

$links = @"
# Links

## Target

- $Url

## Samples

- $($paths.Samples)

## Projects

- $($paths.Projects)

## Exports

- $($paths.Exports)

## Patches

- $($paths.Patches)

## Notes

- $($paths.Notes)

## Reports

- $($paths.Reports)

## Scripts

- $($paths.Scripts)
"@
Set-Content -LiteralPath (Join-Path $caseDir "links.md") -Value $links -Encoding UTF8

[pscustomobject]@{
    Case = $caseName
    CaseDir = $caseDir
    Paths = $paths
} | ConvertTo-Json -Depth 4
