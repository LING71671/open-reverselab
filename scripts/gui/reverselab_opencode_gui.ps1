param(
  [string]$HostName = "127.0.0.1",
  [Alias("Port")]
  [int]$GuiPort = 8765,
  [int]$OpenCodePort = 4096,
  [switch]$NoBrowser,
  [switch]$NoOpenCode,
  [switch]$InstallOpenCodeIfMissing,
  [switch]$PrintConfigOnly
)

$ErrorActionPreference = "Stop"

$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Resolve-Path (Join-Path $scriptPath "..\..")
$bundleRoot = if ((Split-Path -Leaf $root.Path) -eq "workspace") {
  Split-Path -Parent $root.Path
} else {
  $root.Path
}
$template = Resolve-Path (Join-Path $root "gui\opencode\config\opencode.reverselab.jsonc")
$guiServer = Resolve-Path (Join-Path $root "scripts\gui\reverselab_gui_server.py")
$runtimeDir = Join-Path $root ".reverselab-local\opencode"
$runtimeConfig = Join-Path $runtimeDir "opencode.generated.jsonc"

$env:REVERSELAB_ROOT = $root.Path
$rootForConfig = $root.Path.Replace("\", "/")
New-Item -ItemType Directory -Force -Path $runtimeDir | Out-Null
$templateContent = Get-Content -LiteralPath $template -Raw
$generatedConfig = $templateContent.Replace('${env:REVERSELAB_ROOT}', $rootForConfig).Replace('${env:REVERSELAB_GUI_PORT}', "$GuiPort").Replace('${env:REVERSELAB_OPENCODE_PORT}', "$OpenCodePort")
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($runtimeConfig, $generatedConfig, $utf8NoBom)

$agentSource = Join-Path $root "gui\opencode\config\agent"
$agentDest = Join-Path $runtimeDir "agent"
if (Test-Path -LiteralPath $agentSource) {
  Copy-Item -LiteralPath $agentSource -Destination $agentDest -Recurse -Force
}

$env:OPENCODE_CONFIG = $runtimeConfig
$env:OPENCODE_CLI_NAME = "reverselab-opencode"
$env:REVERSELAB_GUI_PORT = "$GuiPort"
$env:REVERSELAB_OPENCODE_PORT = "$OpenCodePort"

Write-Host "ReverseLab GUI"
Write-Host "  Root:   $($env:REVERSELAB_ROOT)"
Write-Host "  Config: $($env:OPENCODE_CONFIG)"
Write-Host "  GUI:    http://$HostName`:$GuiPort"
Write-Host "  AI RT:  http://$HostName`:$OpenCodePort"
Write-Host ""

if ($PrintConfigOnly) {
  exit 0
}

function Find-CommandOrBundled {
  param(
    [string]$CommandName,
    [string[]]$BundledCandidates
  )

  foreach ($candidate in $BundledCandidates) {
    if ($candidate -and (Test-Path -LiteralPath $candidate)) {
      return (Resolve-Path -LiteralPath $candidate).Path
    }
  }

  $command = Get-Command $CommandName -ErrorAction SilentlyContinue
  if ($command) {
    return $command.Source
  }

  return ""
}

if (-not $NoOpenCode) {
  $opencodePath = Find-CommandOrBundled -CommandName "opencode" -BundledCandidates @(
    (Join-Path $bundleRoot "runtime\opencode\opencode.exe"),
    (Join-Path $bundleRoot "runtime\opencode\opencode.cmd"),
    (Join-Path $bundleRoot "runtime\opencode\bin\opencode.exe"),
    (Join-Path $bundleRoot "runtime\opencode\bin\opencode.cmd")
  )
  if ($opencodePath) {
    $args = @("serve", "--hostname", $HostName, "--port", "$OpenCodePort")
    $proc = Start-Process -FilePath $opencodePath -ArgumentList $args -WindowStyle Hidden -PassThru
    Write-Host "OpenCode runtime started with PID $($proc.Id)"
  } elseif ($InstallOpenCodeIfMissing) {
    $npxPath = Find-CommandOrBundled -CommandName "npx" -BundledCandidates @(
      (Join-Path $bundleRoot "runtime\node\npx.cmd"),
      (Join-Path $bundleRoot "runtime\node\npx.exe"),
      (Join-Path $bundleRoot "runtime\node\nbin\npx.cmd"),
      (Join-Path $bundleRoot "runtime\node\nbin\npx.exe")
    )
    if (-not $npxPath) {
      throw "OpenCode is not installed and npx was not found. Install OpenCode, bundle it, or rerun with -NoOpenCode."
    }
    $args = @("-y", "opencode-ai@1.17.12", "serve", "--hostname", $HostName, "--port", "$OpenCodePort")
    $proc = Start-Process -FilePath $npxPath -ArgumentList $args -WindowStyle Hidden -PassThru
    Write-Host "OpenCode runtime install/start requested with PID $($proc.Id)"
  } else {
    Write-Warning "OpenCode was not found. Continuing with the ReverseLab GUI bridge; rerun with -InstallOpenCodeIfMissing or bundle OpenCode to enable AI runtime."
  }
}

if (-not $NoBrowser) {
  Start-Process "http://$HostName`:$GuiPort"
}

$pythonPath = Find-CommandOrBundled -CommandName "python" -BundledCandidates @(
  (Join-Path $bundleRoot "runtime\python\python.exe"),
  (Join-Path $bundleRoot "runtime\python\python3.exe")
)

if (-not $pythonPath) {
  $pythonPath = Find-CommandOrBundled -CommandName "py" -BundledCandidates @()
}

if (-not $pythonPath) {
  throw "Python was not found. Install Python or use a packaged ReverseLab GUI runtime."
}

& $pythonPath $guiServer --host $HostName --port $GuiPort
exit $LASTEXITCODE
