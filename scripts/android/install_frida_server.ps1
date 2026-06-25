param(
    [string]$AdbPath = "C:\Program Files (x86)\Android\android-sdk\platform-tools\adb.exe",
    [string]$Serial = "127.0.0.1:16384",
    [string]$Version = "17.9.8",
    [string]$Arch = "android-x86_64",
    [string]$RemotePath = "/data/local/tmp/frida-server"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $AdbPath)) {
    throw "adb not found: $AdbPath"
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$cacheDir = Join-Path $scriptDir "..\..\tools\android\mobile\frida"
$cacheDir = [System.IO.Path]::GetFullPath($cacheDir)
New-Item -ItemType Directory -Force -Path $cacheDir | Out-Null

$archiveName = "frida-server-$Version-$Arch.xz"
$archivePath = Join-Path $cacheDir $archiveName
$binaryName = "frida-server-$Version-$Arch"
$binaryPath = Join-Path $cacheDir $binaryName
$url = "https://github.com/frida/frida/releases/download/$Version/$archiveName"

if (-not (Test-Path -LiteralPath $archivePath)) {
    Invoke-WebRequest -Uri $url -OutFile $archivePath
}

if (-not (Test-Path -LiteralPath $binaryPath)) {
    @"
import lzma
from pathlib import Path

archive = Path(r"$archivePath")
target = Path(r"$binaryPath")
target.write_bytes(lzma.decompress(archive.read_bytes()))
"@ | python -
}

& $AdbPath connect $Serial | Out-Null
& $AdbPath -s $Serial shell "su -c 'pkill frida-server >/dev/null 2>&1 || true'" | Out-Null
& $AdbPath -s $Serial push $binaryPath $RemotePath | Out-Null
& $AdbPath -s $Serial shell "su -c 'chmod 755 $RemotePath'" | Out-Null
& $AdbPath -s $Serial shell "su -c '$RemotePath >/dev/null 2>&1 &'"

Start-Sleep -Seconds 2

& $AdbPath -s $Serial shell "su -c 'ps -A | grep frida-server'"
