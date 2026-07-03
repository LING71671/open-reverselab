param(
  [string]$OutputDir = "dist\ReverseLab-GUI-dev",
  [string]$PythonRoot = "",
  [string]$OpenCodeRoot = "",
  [switch]$Clean,
  [switch]$SkipExe,
  [switch]$Zip
)

$ErrorActionPreference = "Stop"
$root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$out = Join-Path $root $OutputDir
$excludeDirs = @(
  ".git",
  ".venv",
  "venv",
  "__pycache__",
  ".pytest_cache",
  ".mypy_cache",
  ".reverselab-local",
  "node_modules",
  "dist",
  "tmp"
)
$excludeFiles = @("*.pyc", "*.pyo", "*.pyd", "*.log")

function Copy-PublicItem {
  param(
    [string]$Source,
    [string]$Destination
  )

  $item = Get-Item -LiteralPath $Source
  if ($item.PSIsContainer) {
    New-Item -ItemType Directory -Force -Path $Destination | Out-Null
    $robocopyArgs = @($Source, $Destination, "/E", "/NFL", "/NDL", "/NJH", "/NJS", "/NP", "/XD")
    $robocopyArgs += $excludeDirs
    $robocopyArgs += "/XF"
    $robocopyArgs += $excludeFiles
    & robocopy @robocopyArgs | Out-Null
    if ($LASTEXITCODE -gt 7) {
      throw "robocopy failed for $Source -> $Destination with exit code $LASTEXITCODE"
    }
    $global:LASTEXITCODE = 0
  } else {
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Destination) | Out-Null
    Copy-Item -LiteralPath $Source -Destination $Destination -Force
  }
}

if ($Clean -and (Test-Path -LiteralPath $out)) {
  Remove-Item -LiteralPath $out -Recurse -Force
}

New-Item -ItemType Directory -Force -Path $out | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $out "workspace") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $out "app\gui") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $out "app\opencode-runtime") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $out "data") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $out "runtime") | Out-Null

$include = @(
  "AI-USAGE.md",
  "AGENTS.md",
  ".mcp.json",
  "PUBLICATION.md",
  "gui/PRODUCT.md",
  "README.md",
  "README.zh.md",
  "boards",
  "kb",
  "scripts",
  "tools",
  "templates",
  "gui"
)

foreach ($item in $include) {
  $src = Join-Path $root $item
  $dst = Join-Path (Join-Path $out "workspace") $item
  if (Test-Path -LiteralPath $src) {
    Copy-PublicItem -Source $src -Destination $dst
  }
}

foreach ($dir in @("cases", "exports", "notes", "reports", "samples")) {
  New-Item -ItemType Directory -Force -Path (Join-Path $out "data\$dir") | Out-Null
}

if ($PythonRoot) {
  $resolvedPython = Resolve-Path -LiteralPath $PythonRoot
  Copy-PublicItem -Source $resolvedPython.Path -Destination (Join-Path $out "runtime\python")
}

if ($OpenCodeRoot) {
  $resolvedOpenCode = Resolve-Path -LiteralPath $OpenCodeRoot
  Copy-PublicItem -Source $resolvedOpenCode.Path -Destination (Join-Path $out "runtime\opencode")
}

Copy-Item -LiteralPath (Join-Path $root "gui\opencode\packaging\reverselab-gui.manifest.json") -Destination (Join-Path $out "manifest.json") -Force
Copy-Item -LiteralPath (Join-Path $root "gui\opencode\packaging\windows\ReverseLabGUI.ps1") -Destination (Join-Path $out "ReverseLabGUI.ps1") -Force
Copy-Item -LiteralPath (Join-Path $root "gui\app") -Destination (Join-Path $out "app\gui\spec") -Recurse -Force
Copy-Item -LiteralPath (Join-Path $root "gui\opencode") -Destination (Join-Path $out "app\opencode-runtime\adapter") -Recurse -Force

if (-not $SkipExe) {
  $exePath = Join-Path $out "ReverseLabGUI.exe"
  $builder = Join-Path $root "scripts\gui\build_reverselab_gui_launcher.ps1"
  try {
    & powershell -NoProfile -ExecutionPolicy Bypass -File $builder -OutputPath $exePath
  } catch {
    Write-Warning "ReverseLabGUI.exe was not built: $($_.Exception.Message)"
    Write-Warning "The portable package still includes ReverseLabGUI.ps1 as a fallback launcher."
  }
}

if ($Zip) {
  $zipPath = Join-Path $root "dist\ReverseLab-GUI-dev-windows-x64.zip"
  if (Test-Path -LiteralPath $zipPath) {
    Remove-Item -LiteralPath $zipPath -Force
  }
  Compress-Archive -LiteralPath $out -DestinationPath $zipPath -CompressionLevel Optimal
  Write-Host "Portable zip: $zipPath"
}

Write-Host "ReverseLab GUI package staged: $out"
Write-Host "Launcher: $out\ReverseLabGUI.exe"
Write-Host "Fallback launcher: $out\ReverseLabGUI.ps1"
