param(
  [string]$Workspace = "",
  [int]$GuiPort = 8765,
  [int]$OpenCodePort = 4096,
  [switch]$NoOpenCode,
  [switch]$NoBrowser,
  [switch]$PrintConfigOnly
)

$ErrorActionPreference = "Stop"

$appRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

if (-not $Workspace) {
  $bundleCandidates = @(
    $appRoot,
    (Join-Path $appRoot "..\.."),
    (Join-Path $appRoot "..\..\..\..")
  )

  foreach ($candidateRoot in $bundleCandidates) {
    $resolvedRoot = Resolve-Path $candidateRoot -ErrorAction SilentlyContinue
    if (-not $resolvedRoot) {
      continue
    }

    $bundledWorkspace = Join-Path $resolvedRoot.Path "workspace"
    if (Test-Path (Join-Path $bundledWorkspace "AI-USAGE.md")) {
      $Workspace = $bundledWorkspace
      break
    }

    if (Test-Path (Join-Path $resolvedRoot.Path "AI-USAGE.md")) {
      $Workspace = $resolvedRoot.Path
      break
    }
  }

  if (-not $Workspace) {
    throw "ReverseLab workspace not found. Pass -Workspace <path>."
  }
}

$launcher = Join-Path $Workspace "scripts\gui\reverselab_opencode_gui.ps1"
if (-not (Test-Path -LiteralPath $launcher)) {
  throw "ReverseLab GUI launcher not found in workspace: $launcher"
}

$launcherArgs = @(
  "-NoProfile",
  "-ExecutionPolicy",
  "Bypass",
  "-File",
  $launcher,
  "-GuiPort",
  "$GuiPort",
  "-OpenCodePort",
  "$OpenCodePort"
)

if ($NoOpenCode) {
  $launcherArgs += "-NoOpenCode"
}
if ($NoBrowser) {
  $launcherArgs += "-NoBrowser"
}
if ($PrintConfigOnly) {
  $launcherArgs += "-PrintConfigOnly"
}

& powershell @launcherArgs
exit $LASTEXITCODE
