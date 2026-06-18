<#
.SYNOPSIS
    ReverseLab 工具一键安装脚本
.DESCRIPTION
    自动下载和安装所有逆向工程工具到 tools/ 目录。
    支持分类安装：-All | -Android | -Windows | -CTF | -Common | -Skills
.EXAMPLE
    .\install_tools.ps1 -All          # 安装全部工具
    .\install_tools.ps1 -CTF          # 只装 Web CTF 工具
    .\install_tools.ps1 -Android -Windows  # 装 Android + Windows
#>

param(
    [switch]$All,
    [switch]$Android,
    [switch]$Windows,
    [switch]$CTF,
    [switch]$Common,
    [switch]$Skills,
    [switch]$GoTools
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$toolsDir = Join-Path $root "tools"
$downloadsDir = Join-Path $toolsDir "common\downloads"

# Ensure downloads directory exists
New-Item -ItemType Directory -Force -Path $downloadsDir | Out-Null

# If no flag specified, show help
if (-not ($All -or $Android -or $Windows -or $CTF -or $Common -or $Skills -or $GoTools)) {
    Write-Host @"
ReverseLab 工具安装脚本
=======================
用法: .\install_tools.ps1 [选项]

选项:
  -All        安装全部工具
  -Android    安装 Android 工具 (apktool, jadx, uber-apk-signer)
  -Windows    安装 Windows 工具 (Cutter, PE-bear, DiE, HxD, Procmon)
  -CTF        安装 Web CTF 工具 (sqlmap, dirsearch, nmap, jwt_tool 等)
  -Common     安装通用工具 (Ghidra, Maven)
  -GoTools    安装 Go 生态工具 (ffuf, gobuster, httpx, nuclei, katana)
  -Skills     安装 MCP 技能 (GhidraMCP, JSHookLocal, ReverseLabToolsMCP)

示例:
  .\install_tools.ps1 -All
  .\install_tools.ps1 -CTF -GoTools
"@
    exit
}

# ── Helper Functions ──

function Invoke-Download {
    param([string]$Url, [string]$Output)
    Write-Host "  Downloading: $Url" -ForegroundColor Gray
    try {
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $Url -OutFile $Output -UseBasicParsing
    } catch {
        Write-Warning "  Download failed: $Url"
        Write-Warning "  Error: $_"
    }
    $ProgressPreference = 'Continue'
}

function Invoke-GitClone {
    param([string]$Url, [string]$Path, [bool]$Shallow = $true)
    if (Test-Path $Path) {
        Write-Host "  Already exists: $Path, skipping." -ForegroundColor Yellow
        return
    }
    Write-Host "  Cloning: $Url -> $Path" -ForegroundColor Gray
    $depth = if ($Shallow) { @("--depth", "1") } else { @() }
    git clone @depth $Url $Path 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "  Clone failed: $Url"
    }
}

function New-ToolBat {
    param([string]$Name, [string]$Target)
    $batDir = Join-Path $toolsDir "bin"
    New-Item -ItemType Directory -Force -Path $batDir | Out-Null
    $batPath = Join-Path $batDir "$Name.bat"
    $absTarget = (Resolve-Path -Path $Target).Path
    @"
@echo off
"$absTarget" %*
"@ | Out-File -FilePath $batPath -Encoding ASCII
    Write-Host "    Wrapper: $batPath" -ForegroundColor Gray
}

function Get-GitHubLatestRelease {
    param([string]$Repo)
    $url = "https://api.github.com/repos/$Repo/releases/latest"
    try {
        $response = Invoke-RestMethod -Uri $url -UseBasicParsing
        return $response
    } catch {
        Write-Warning "  Failed to fetch latest release for $Repo"
        return $null
    }
}

function Get-GitHubLatestAssetUrl {
    param([string]$Repo, [string]$Pattern)
    $release = Get-GitHubLatestRelease -Repo $Repo
    if (-not $release) { return $null }
    foreach ($asset in $release.assets) {
        if ($asset.name -match $Pattern) {
            return $asset.browser_download_url
        }
    }
    Write-Warning "  No asset matching '$Pattern' found in latest release of $Repo"
    return $null
}

# ═══════════════════════════════════════════
# ANDROID TOOLS
# ═══════════════════════════════════════════

function Install-Apktool {
    Write-Host "`n[Android] apktool" -ForegroundColor Cyan
    $dir = Join-Path $toolsDir "android\apktool"
    New-Item -ItemType Directory -Force -Path $dir | Out-Null

    # Download latest apktool.jar
    $jarUrl = "https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.11.0.jar"
    $jarPath = Join-Path $dir "apktool.jar"
    if (-not (Test-Path $jarPath)) {
        Invoke-Download -Url $jarUrl -Output $jarPath
    } else {
        Write-Host "  apktool.jar exists, skipping." -ForegroundColor Yellow
    }

    # Download apktool.bat wrapper
    $batUrl = "https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/windows/apktool.bat"
    $batPath = Join-Path $dir "apktool.bat"
    if (-not (Test-Path $batPath)) {
        Invoke-Download -Url $batUrl -Output $batPath
    }

    New-ToolBat -Name "apktool" -Target $batPath
    Write-Host "  apktool done." -ForegroundColor Green
}

function Install-Jadx {
    Write-Host "`n[Android] jadx" -ForegroundColor Cyan
    $dir = Join-Path $toolsDir "android\jadx"
    New-Item -ItemType Directory -Force -Path $dir | Out-Null

    $url = Get-GitHubLatestAssetUrl -Repo "skylot/jadx" -Pattern "jadx-gui-.*-with-jre-win\.zip"
    if (-not $url) { return }

    $zip = Join-Path $downloadsDir "jadx-latest.zip"
    Invoke-Download -Url $url -Output $zip
    Write-Host "  Extracting jadx..." -ForegroundColor Gray
    Expand-Archive -Path $zip -DestinationPath $dir -Force

    New-ToolBat -Name "jadx-gui" -Target (Join-Path $dir "bin\jadx-gui.bat")
    New-ToolBat -Name "jadx" -Target (Join-Path $dir "bin\jadx.bat")
    Write-Host "  jadx done." -ForegroundColor Green
}

function Install-UberApkSigner {
    Write-Host "`n[Android] uber-apk-signer" -ForegroundColor Cyan
    $dir = Join-Path $toolsDir "android\uber-apk-signer"
    New-Item -ItemType Directory -Force -Path $dir | Out-Null

    $url = Get-GitHubLatestAssetUrl -Repo "patrickfav/uber-apk-signer" -Pattern "uber-apk-signer-.*\.jar"
    if (-not $url) { return }

    $jarPath = Join-Path $dir "uber-apk-signer.jar"
    Invoke-Download -Url $url -Output $jarPath
    New-ToolBat -Name "uber-apk-signer" -Target $jarPath
    Write-Host "  uber-apk-signer done." -ForegroundColor Green
}

# ═══════════════════════════════════════════
# WINDOWS TOOLS
# ═══════════════════════════════════════════

function Install-Cutter {
    Write-Host "`n[Windows] Cutter" -ForegroundColor Cyan
    $dir = Join-Path $toolsDir "windows\Cutter"
    New-Item -ItemType Directory -Force -Path $dir | Out-Null

    $url = Get-GitHubLatestAssetUrl -Repo "rizinorg/cutter" -Pattern "Cutter-.*-Windows-x86_64\.zip"
    if (-not $url) { return }

    $zip = Join-Path $downloadsDir "cutter-latest.zip"
    Invoke-Download -Url $url -Output $zip
    Write-Host "  Extracting Cutter..." -ForegroundColor Gray
    Expand-Archive -Path $zip -DestinationPath $dir -Force

    # Find cutter.exe
    $exe = Get-ChildItem -Path $dir -Recurse -Name "Cutter.exe" | Select-Object -First 1
    if ($exe) {
        New-ToolBat -Name "cutter" -Target (Join-Path $dir $exe)
    }
    Write-Host "  Cutter done." -ForegroundColor Green
}

function Install-PEBear {
    Write-Host "`n[Windows] PE-bear" -ForegroundColor Cyan
    $dir = Join-Path $toolsDir "windows\PE-bear"
    New-Item -ItemType Directory -Force -Path $dir | Out-Null

    $url = Get-GitHubLatestAssetUrl -Repo "hasherezade/pe-bear" -Pattern "PE-bear_.*_win_.*\.zip"
    if (-not $url) { return }

    $zip = Join-Path $downloadsDir "pebear-latest.zip"
    Invoke-Download -Url $url -Output $zip
    Write-Host "  Extracting PE-bear..." -ForegroundColor Gray
    Expand-Archive -Path $zip -DestinationPath $dir -Force

    New-ToolBat -Name "pe-bear" -Target (Join-Path $dir "PE-bear.exe")
    Write-Host "  PE-bear done." -ForegroundColor Green
}

function Install-DiE {
    Write-Host "`n[Windows] Detect It Easy" -ForegroundColor Cyan
    $dir = Join-Path $toolsDir "windows\die"
    New-Item -ItemType Directory -Force -Path $dir | Out-Null

    $url = Get-GitHubLatestAssetUrl -Repo "horsicq/Detect-It-Easy" -Pattern "die_win64_portable_.*\.zip"
    if (-not $url) { return }

    $zip = Join-Path $downloadsDir "die-latest.zip"
    Invoke-Download -Url $url -Output $zip
    Write-Host "  Extracting DiE..." -ForegroundColor Gray
    Expand-Archive -Path $zip -DestinationPath $dir -Force

    New-ToolBat -Name "diec" -Target (Join-Path $dir "diec.exe")
    New-ToolBat -Name "die" -Target (Join-Path $dir "die.exe")
    Write-Host "  DiE done." -ForegroundColor Green
}

function Install-HxD {
    Write-Host "`n[Windows] HxD" -ForegroundColor Cyan
    Write-Host "  HxD requires manual installation." -ForegroundColor Yellow
    Write-Host "  Download from: https://mh-nexus.de/en/downloads.php?product=HxD20" -ForegroundColor Yellow
    Write-Host "  After install, create shortcut or add to tools/windows/HxD/" -ForegroundColor Yellow
}

function Install-Procmon {
    Write-Host "`n[Windows] Process Monitor" -ForegroundColor Cyan
    $dir = Join-Path $toolsDir "windows\ProcessMonitor"
    New-Item -ItemType Directory -Force -Path $dir | Out-Null

    $url = "https://download.sysinternals.com/files/ProcessMonitor.zip"
    $zip = Join-Path $downloadsDir "procmon.zip"
    Invoke-Download -Url $url -Output $zip
    Write-Host "  Extracting Procmon..." -ForegroundColor Gray
    Expand-Archive -Path $zip -DestinationPath $dir -Force

    New-ToolBat -Name "procmon" -Target (Join-Path $dir "Procmon.exe")
    Write-Host "  Procmon done." -ForegroundColor Green
}

# ═══════════════════════════════════════════
# CTF WEBSITE TOOLS
# ═══════════════════════════════════════════

function Install-Sqlmap {
    Write-Host "`n[CTF] sqlmap" -ForegroundColor Cyan
    $dir = Join-Path $toolsDir "ctf-website\sqlmap"
    Invoke-GitClone -Url "https://github.com/sqlmapproject/sqlmap.git" -Path $dir
    New-ToolBat -Name "sqlmap" -Target (Join-Path $dir "sqlmap.py")
    Write-Host "  sqlmap done." -ForegroundColor Green
}

function Install-Dirsearch {
    Write-Host "`n[CTF] dirsearch" -ForegroundColor Cyan
    $dir = Join-Path $toolsDir "ctf-website\dirsearch"
    Invoke-GitClone -Url "https://github.com/maurosoria/dirsearch.git" -Path $dir
    pip install -r (Join-Path $dir "requirements.txt") 2>&1 | Out-Null
    New-ToolBat -Name "dirsearch" -Target (Join-Path $dir "dirsearch.py")
    Write-Host "  dirsearch done." -ForegroundColor Green
}

function Install-JwtTool {
    Write-Host "`n[CTF] jwt_tool" -ForegroundColor Cyan
    $dir = Join-Path $toolsDir "ctf-website\jwt_tool"
    Invoke-GitClone -Url "https://github.com/ticarpi/jwt_tool.git" -Path $dir
    New-ToolBat -Name "jwt_tool" -Target (Join-Path $dir "jwt_tool.py")
    Write-Host "  jwt_tool done." -ForegroundColor Green
}

function Install-Tplmap {
    Write-Host "`n[CTF] tplmap" -ForegroundColor Cyan
    $dir = Join-Path $toolsDir "ctf-website\tplmap"
    Invoke-GitClone -Url "https://github.com/epinna/tplmap.git" -Path $dir
    pip install -r (Join-Path $dir "requirements.txt") 2>&1 | Out-Null
    New-ToolBat -Name "tplmap" -Target (Join-Path $dir "tplmap.py")
    Write-Host "  tplmap done." -ForegroundColor Green
}

function Install-ExploitDB {
    Write-Host "`n[CTF] exploitdb (searchsploit)" -ForegroundColor Cyan
    $dir = Join-Path $toolsDir "ctf-website\exploitdb"
    Invoke-GitClone -Url "https://gitlab.com/exploit-database/exploitdb.git" -Path $dir -Shallow $false
    New-ToolBat -Name "searchsploit" -Target (Join-Path $dir "searchsploit")
    Write-Host "  exploitdb done." -ForegroundColor Green
}

function Install-Nmap {
    Write-Host "`n[CTF] nmap" -ForegroundColor Cyan
    Write-Host "  nmap requires manual installation." -ForegroundColor Yellow
    Write-Host "  Download from: https://nmap.org/download.html" -ForegroundColor Yellow
    Write-Host "  After install, the 'nmap' command should be in PATH." -ForegroundColor Yellow
}

function Install-Burp {
    Write-Host "`n[CTF] Burp Suite" -ForegroundColor Cyan
    Write-Host "  Burp Suite requires manual download from PortSwigger." -ForegroundColor Yellow
    Write-Host "  Community Edition: https://portswigger.net/burp/releases" -ForegroundColor Yellow
    Write-Host "  Download burpsuite_community_*.jar -> tools/ctf-website/burp/" -ForegroundColor Yellow
}

# ═══════════════════════════════════════════
# GO TOOLS
# ═══════════════════════════════════════════

function Install-GoTool {
    param([string]$Name, [string]$InstallCmd, [string]$ReleaseRepo)
    Write-Host "  [$Name]" -ForegroundColor Cyan
    $binDir = Join-Path $toolsDir "ctf-website\bin"
    New-Item -ItemType Directory -Force -Path $binDir | Out-Null

    $exePath = Join-Path $binDir "$Name.exe"

    # Try go install first
    $go = Get-Command go -ErrorAction SilentlyContinue
    if ($go) {
        Write-Host "    Installing via go..." -ForegroundColor Gray
        Invoke-Expression $InstallCmd 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            $gopath = go env GOPATH
            $src = Join-Path $gopath "bin\$Name.exe"
            if (Test-Path $src) {
                Copy-Item $src $exePath -Force
                New-ToolBat -Name $Name -Target $exePath
                Write-Host "    $Name done." -ForegroundColor Green
                return
            }
        }
    }

    # Fallback: download release binary
    if ($ReleaseRepo) {
        Write-Host "    go not found, downloading pre-built binary..." -ForegroundColor Yellow
        $url = Get-GitHubLatestAssetUrl -Repo $ReleaseRepo -Pattern "${Name}_.*_windows_amd64\.zip"
        if (-not $url) {
            $url = Get-GitHubLatestAssetUrl -Repo $ReleaseRepo -Pattern "${Name}_.*_windows_amd64\.exe"
        }
        if ($url) {
            $tmp = Join-Path $downloadsDir "$Name-latest"
            Invoke-Download -Url $url -Output $tmp
            if ($tmp -match '\.zip$') {
                Expand-Archive -Path $tmp -DestinationPath $binDir -Force
            } else {
                Copy-Item $tmp $exePath -Force
            }
            New-ToolBat -Name $Name -Target $exePath
            Write-Host "    $Name done." -ForegroundColor Green
        } else {
            Write-Warning "    Could not find release for $Name"
        }
    }
}

function Install-GoTools {
    Write-Host "`n[Go Tools]" -ForegroundColor Cyan
    Install-GoTool -Name "ffuf" `
        -InstallCmd "go install github.com/ffuf/ffuf/v2@latest" `
        -ReleaseRepo "ffuf/ffuf"

    Install-GoTool -Name "gobuster" `
        -InstallCmd "go install github.com/OJ/gobuster/v3@latest" `
        -ReleaseRepo "OJ/gobuster"

    Install-GoTool -Name "httpx" `
        -InstallCmd "go install github.com/projectdiscovery/httpx/cmd/httpx@latest" `
        -ReleaseRepo "projectdiscovery/httpx"

    Install-GoTool -Name "nuclei" `
        -InstallCmd "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest" `
        -ReleaseRepo "projectdiscovery/nuclei"

    Install-GoTool -Name "katana" `
        -InstallCmd "go install github.com/projectdiscovery/katana/cmd/katana@latest" `
        -ReleaseRepo "projectdiscovery/katana"
}

# ═══════════════════════════════════════════
# COMMON TOOLS
# ═══════════════════════════════════════════

function Install-Ghidra {
    Write-Host "`n[Common] Ghidra" -ForegroundColor Cyan
    Write-Host "  Ghidra requires manual download." -ForegroundColor Yellow
    Write-Host "  Download from: https://github.com/NationalSecurityAgency/ghidra/releases" -ForegroundColor Yellow
    Write-Host "  Extract to: tools/common/ghidra_*/" -ForegroundColor Yellow
}

function Install-Maven {
    Write-Host "`n[Common] Apache Maven" -ForegroundColor Cyan
    $url = "https://dlcdn.apache.org/maven/maven-3/3.9.9/binaries/apache-maven-3.9.9-bin.zip"
    $dir = Join-Path $toolsDir "common\apache-maven-3.9.9"
    if (Test-Path $dir) {
        Write-Host "  Maven already installed, skipping." -ForegroundColor Yellow
        return
    }

    $zip = Join-Path $downloadsDir "maven.zip"
    Invoke-Download -Url $url -Output $zip
    Write-Host "  Extracting Maven..." -ForegroundColor Gray
    Expand-Archive -Path $zip -DestinationPath (Join-Path $toolsDir "common") -Force
    Write-Host "  Maven done." -ForegroundColor Green
}

# ═══════════════════════════════════════════
# MCP SKILLS
# ═══════════════════════════════════════════

function Install-McpSkills {
    Write-Host "`n[Skills] MCP Servers" -ForegroundColor Cyan
    $coreProject = Join-Path $toolsDir "skills\mcp\ReverseLabToolsMCP"
    if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
        throw "uv is required for ReverseLabToolsMCP. Install from https://docs.astral.sh/uv/"
    }
    & uv sync --project $coreProject
    if ($LASTEXITCODE -ne 0) { throw "ReverseLabToolsMCP dependency installation failed" }
    Write-Host "  ReverseLabToolsMCP ready." -ForegroundColor Green
    Write-Host "  Optional GhidraMCP/JSHookLocal are not enabled by default." -ForegroundColor Yellow
    Write-Host "  Follow tools/skills/mcp/<name>/README.md, then merge .mcp.optional.example.json." -ForegroundColor Yellow
}

# ═══════════════════════════════════════════
# MAIN DISPATCH
# ═══════════════════════════════════════════

Write-Host @"

╔═══════════════════════════════════════════╗
║     ReverseLab Tool Installer            ║
╚═══════════════════════════════════════════╝

"@ -ForegroundColor Magenta

# Check prerequisites
if (-not (Get-Command git -ErrorAction SilentlyContinue)) { Write-Warning "git not found. Some tools require git." }
if (-not (Get-Command python -ErrorAction SilentlyContinue)) { Write-Warning "python not found. Some CTF tools require Python." }
if (-not (Get-Command java -ErrorAction SilentlyContinue)) { Write-Warning "java not found. Some Android tools require Java." }

$installAndroid = $All -or $Android
$installWindows = $All -or $Windows
$installCTF = $All -or $CTF
$installCommon = $All -or $Common
$installSkills = $All -or $Skills
$installGoTools = $All -or $GoTools

if ($installAndroid) {
    Write-Host "`n═══ Android Tools ═══" -ForegroundColor Magenta
    Install-Apktool
    Install-Jadx
    Install-UberApkSigner
}

if ($installWindows) {
    Write-Host "`n═══ Windows Tools ═══" -ForegroundColor Magenta
    Install-Cutter
    Install-PEBear
    Install-DiE
    Install-HxD
    Install-Procmon
}

if ($installCTF) {
    Write-Host "`n═══ Web CTF Tools ═══" -ForegroundColor Magenta
    Install-Sqlmap
    Install-Dirsearch
    Install-JwtTool
    Install-Tplmap
    Install-ExploitDB
    Install-Nmap
    Install-Burp
}

if ($installGoTools) {
    Write-Host "`n═══ Go Tools ═══" -ForegroundColor Magenta
    Install-GoTools
}

if ($installCommon) {
    Write-Host "`n═══ Common Tools ═══" -ForegroundColor Magenta
    Install-Ghidra
    Install-Maven
}

if ($installSkills) {
    Write-Host "`n═══ MCP Skills ═══" -ForegroundColor Magenta
    Install-McpSkills
}

Write-Host @"

═══════════════════════════════════════════
  Installation complete!
  Wrappers created in: tools/bin/
  Run 'python scripts/misc/ai_toolcheck.py' to verify.
═══════════════════════════════════════════

"@ -ForegroundColor Green
