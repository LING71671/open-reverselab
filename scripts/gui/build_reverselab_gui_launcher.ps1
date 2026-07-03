param(
  [string]$OutputPath = "",
  [switch]$FrameworkDependent
)

$ErrorActionPreference = "Stop"

$root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$source = Resolve-Path (Join-Path $root "gui\opencode\packaging\windows\ReverseLabGUI.cs")

if (-not $OutputPath) {
  $OutputPath = Join-Path $root "dist\ReverseLab-GUI-dev\ReverseLabGUI.exe"
}

$dotnet = Get-Command dotnet -ErrorAction SilentlyContinue
if (-not $dotnet) {
  throw "dotnet SDK was not found. Install .NET SDK or use ReverseLabGUI.ps1."
}

$buildRoot = Join-Path $root ".reverselab-local\build\ReverseLabGuiLauncher"
$publishDir = Join-Path $buildRoot "publish"
$projectFile = Join-Path $buildRoot "ReverseLabGuiLauncher.csproj"
$programFile = Join-Path $buildRoot "Program.cs"

New-Item -ItemType Directory -Force -Path $buildRoot | Out-Null
Copy-Item -LiteralPath $source -Destination $programFile -Force

$projectXml = @"
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>WinExe</OutputType>
    <TargetFramework>net8.0-windows</TargetFramework>
    <UseWindowsForms>true</UseWindowsForms>
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Microsoft.Web.WebView2" Version="1.0.3351.48" />
  </ItemGroup>
</Project>
"@

$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($projectFile, $projectXml, $utf8NoBom)

if (Test-Path -LiteralPath $publishDir) {
  Remove-Item -LiteralPath $publishDir -Recurse -Force
}

$publishArgs = @(
  "publish",
  $projectFile,
  "-c",
  "Release",
  "-r",
  "win-x64",
  "-o",
  $publishDir,
  "/p:PublishSingleFile=true",
  "/p:EnableCompressionInSingleFile=true"
)

if ($FrameworkDependent) {
  $publishArgs += "--self-contained"
  $publishArgs += "false"
} else {
  $publishArgs += "--self-contained"
  $publishArgs += "true"
}

& $dotnet.Source @publishArgs
if ($LASTEXITCODE -ne 0) {
  throw "dotnet publish failed with exit code $LASTEXITCODE"
}

$builtExe = Join-Path $publishDir "ReverseLabGuiLauncher.exe"
if (-not (Test-Path -LiteralPath $builtExe)) {
  throw "Launcher build did not produce $builtExe"
}

New-Item -ItemType Directory -Force -Path (Split-Path -Parent $OutputPath) | Out-Null
Copy-Item -LiteralPath $builtExe -Destination $OutputPath -Force
Write-Host "ReverseLab GUI launcher built: $OutputPath"
