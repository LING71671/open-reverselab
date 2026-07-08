from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path


SERVER_NAME = "reverse_lab_tools"
IS_WINDOWS = os.name == "nt"

# ── Project root discovery ──
PACKAGE_ROOT = Path(__file__).resolve().parents[1]
REVERSE_ROOT = next(
    (
        parent
        for parent in [PACKAGE_ROOT, *PACKAGE_ROOT.parents]
        if (parent / "AGENTS.md").exists() and (parent / ".mcp.json").exists()
    ),
    PACKAGE_ROOT.parents[4],
)

# ── Directory shortcuts ──
TOOLS_DIR = REVERSE_ROOT / "tools"
TOOLS_COMMON_DIR = TOOLS_DIR / "common"
TOOLS_WINDOWS_DIR = TOOLS_DIR / "windows"
TOOLS_ANDROID_DIR = TOOLS_DIR / "android"

EXPORTS_DIR = REVERSE_ROOT / "exports" / "windows" / "triage"
EXPORTS_ROOT = REVERSE_ROOT / "exports"
AUDIT_DIR = REVERSE_ROOT / "exports" / "misc" / "audit"
AUDIT_LOG = AUDIT_DIR / "reverse_lab_tools_audit.jsonl"
GHIDRA_EXPORTS_DIR = REVERSE_ROOT / "exports" / "windows" / "ghidra"
GHIDRA_PROJECTS_DIR = REVERSE_ROOT / "projects" / "windows" / "ghidra-headless"
GHIDRA_SCRIPT_DIR = REVERSE_ROOT / "scripts" / "_shared" / "ghidra"
PATCHES_DIR = REVERSE_ROOT / "patches"
PROJECTS_DIR = REVERSE_ROOT / "projects"
REPORTS_DIR = REVERSE_ROOT / "reports"
SAMPLES_DIR = REVERSE_ROOT / "samples"
SAMPLE_QUARANTINE_DIR = SAMPLES_DIR / "_quarantine"
PROCMON_EXPORTS_DIR = REVERSE_ROOT / "exports" / "windows" / "procmon"
IOC_EXPORTS_DIR = REVERSE_ROOT / "exports" / "windows" / "iocs"
YARA_EXPORTS_DIR = REVERSE_ROOT / "exports" / "windows" / "yara"
SIGMA_EXPORTS_DIR = REVERSE_ROOT / "exports" / "windows" / "sigma"
ANDROID_EXPORTS_DIR = REVERSE_ROOT / "exports" / "android"
DEBUG_SCRIPTS_DIR = REVERSE_ROOT / "scripts" / "windows" / "debug"
PROCMON_FILTERS_DIR = REVERSE_ROOT / "scripts" / "windows" / "procmon"
SCRIPTS_DIR = REVERSE_ROOT / "scripts"
NOTES_DIR = REVERSE_ROOT / "notes"


# ── Tool autodiscovery ──
def _find_glob(dir_path: Path, pattern: str, name: str) -> Path:
    """Find first match for glob pattern, raise if not found."""
    candidates = sorted(dir_path.glob(pattern))
    if not candidates:
        raise FileNotFoundError(
            f"{name} not found at {dir_path / pattern}. "
            f"Run install_tools.ps1 on Windows or install the native tool on PATH for macOS/Linux."
        )
    return candidates[0]


def _find_exe(base: Path, names: list[str], label: str) -> Path:
    """Find executable by trying multiple possible names."""
    for name in names:
        candidate = base / name
        if candidate.exists():
            return candidate
        path_candidate = shutil.which(name)
        if path_candidate:
            return Path(path_candidate)
    raise FileNotFoundError(
        f"{label} not found in {base}. Tried: {names}. "
        f"Run install_tools.ps1 on Windows or install the native tool on PATH for macOS/Linux."
    )


def _first_existing(*candidates: Path) -> Path:
    return next((candidate for candidate in candidates if candidate.exists()), candidates[0])


# Ghidra (version-flexible)
try:
    GHIDRA_ROOT = _find_glob(TOOLS_COMMON_DIR, "ghidra_*/ghidra_*_PUBLIC", "Ghidra")
    GHIDRA_HEADLESS_BAT = _first_existing(
        GHIDRA_ROOT / "support" / ("analyzeHeadless.bat" if IS_WINDOWS else "analyzeHeadless"),
        GHIDRA_ROOT / "support" / "analyzeHeadless",
        GHIDRA_ROOT / "support" / "analyzeHeadless.bat",
    )
except FileNotFoundError:
    GHIDRA_ROOT = TOOLS_COMMON_DIR / "ghidra_placeholder"
    GHIDRA_HEADLESS_BAT = GHIDRA_ROOT / "support" / ("analyzeHeadless.bat" if IS_WINDOWS else "analyzeHeadless")

# Cutter / Rizin (version-flexible)
try:
    CUTTER_ROOT = _find_glob(TOOLS_WINDOWS_DIR / "Cutter", "Cutter-*/Cutter-*", "Cutter")
except FileNotFoundError:
    CUTTER_ROOT = TOOLS_WINDOWS_DIR / "Cutter" / "Cutter-placeholder"
try:
    RIZIN_EXE = _find_exe(CUTTER_ROOT, ["rizin.exe", "rizin"], "rizin")
    RZ_BIN_EXE = _find_exe(CUTTER_ROOT, ["rz-bin.exe", "rz-bin", "rizin.exe", "rizin"], "rz-bin")
    RZ_HASH_EXE = _find_exe(CUTTER_ROOT, ["rz-hash.exe", "rz-hash"], "rz-hash")
    RZ_ASM_EXE = _find_exe(CUTTER_ROOT, ["rz-asm.exe", "rz-asm"], "rz-asm")
except FileNotFoundError:
    # Optional external tools must not prevent the MCP server from starting.
    # Individual tools report the actionable install error when invoked.
    RIZIN_EXE = CUTTER_ROOT / ("rizin.exe" if IS_WINDOWS else "rizin")
    RZ_BIN_EXE = CUTTER_ROOT / ("rz-bin.exe" if IS_WINDOWS else "rz-bin")
    RZ_HASH_EXE = CUTTER_ROOT / ("rz-hash.exe" if IS_WINDOWS else "rz-hash")
    RZ_ASM_EXE = CUTTER_ROOT / ("rz-asm.exe" if IS_WINDOWS else "rz-asm")

# DiE (version-flexible)
try:
    DIE_ROOT = _find_glob(TOOLS_WINDOWS_DIR / "die", "die*/", "DiE")
except FileNotFoundError:
    DIE_ROOT = TOOLS_WINDOWS_DIR / "die" / "die"
try:
    DIEC_EXE = _find_exe(DIE_ROOT, ["diec.exe", "diec"], "diec")
except FileNotFoundError:
    DIEC_EXE = DIE_ROOT / ("diec.exe" if IS_WINDOWS else "diec")

# PE-bear (version-flexible)
try:
    PE_BEAR_EXE = _find_glob(
        TOOLS_WINDOWS_DIR / "PE-bear", "PE-bear*.exe", "PE-bear"
    )
except FileNotFoundError:
    PE_BEAR_EXE = TOOLS_WINDOWS_DIR / "PE-bear" / "PE-bear.exe"

# Procmon
PROCMON_ROOT = TOOLS_WINDOWS_DIR / "ProcessMonitor"

# x64dbg (version-flexible)
try:
    X64DBG_ROOT = _find_glob(TOOLS_WINDOWS_DIR, "snapshot_*/release", "x64dbg")
except FileNotFoundError:
    X64DBG_ROOT = TOOLS_WINDOWS_DIR / "x64dbg"

# Android
ANDROID_SDK_PLATFORM_TOOLS = Path(
    os.environ.get(
        "ANDROID_SDK_PLATFORM_TOOLS",
        os.environ.get(
            "ANDROID_HOME",
            r"C:\Program Files (x86)\Android\android-sdk" if IS_WINDOWS else str(Path.home() / "Android" / "Sdk"),
        )
        + ("" if os.environ.get("ANDROID_SDK_PLATFORM_TOOLS") else os.sep + "platform-tools"),
    )
)
ADB_EXE = Path(shutil.which("adb") or ANDROID_SDK_PLATFORM_TOOLS / ("adb.exe" if IS_WINDOWS else "adb"))
MUMU_DEFAULT_SERIAL = os.environ.get("MUMU_SERIAL", "127.0.0.1:16384")
MUMU_CLI_EXE = (
    REVERSE_ROOT.parents[0] / "MuMuPlayer" / "nx_main" / "mumu-cli.exe"
    if IS_WINDOWS
    else Path("mumu-cli")
)

# ── Host Python discovery ──
_host_python_candidates = []
if os.environ.get("REVERSELAB_HOST_PYTHON"):
    _host_python_candidates.append(Path(os.environ["REVERSELAB_HOST_PYTHON"]))
if os.environ.get("LOCALAPPDATA"):
    _host_python_candidates.append(
        Path(os.environ["LOCALAPPDATA"]) / "Programs" / "Python" / "Python313" / "python.exe"
    )
_host_python_candidates.append(Path(sys.executable))
HOST_PYTHON_EXE = next(
    (c for c in _host_python_candidates if c and c.exists()),
    Path(sys.executable).resolve(),
)

# ── Security: allow-listed roots ──
ALLOWED_ROOTS = [
    REVERSE_ROOT,
]

GENERATED_ROOTS = [
    REVERSE_ROOT / "exports",
    PATCHES_DIR,
    PROJECTS_DIR,
    REPORTS_DIR,
]
