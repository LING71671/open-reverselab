#!/usr/bin/env python3
"""
AI 工具可用性检查。

Usage:
    python scripts/misc/ai_toolcheck.py

Checks which tools are installed in tools/ and reports missing ones.
"""

import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
TOOLS = os.path.join(ROOT, "tools")


TOOL_CHECKS = {
    # Android
    "apktool":          "android/apktool/apktool.jar",
    "jadx":             "android/jadx/bin/jadx.bat",
    "uber-apk-signer":  "android/uber-apk-signer/uber-apk-signer.jar",
    # Windows
    "cutter":           "windows/Cutter/Cutter.exe",
    "pe-bear":          "windows/PE-bear/PE-bear.exe",
    "die":              "windows/die/diec.exe",
    "hxd":              "windows/HxD/HxD.exe",
    "procmon":          "windows/ProcessMonitor/Procmon.exe",
    # CTF Website
    "sqlmap":           "ctf-website/sqlmap/sqlmap.py",
    "dirsearch":        "ctf-website/dirsearch/dirsearch.py",
    "jwt_tool":         "ctf-website/jwt_tool/jwt_tool.py",
    "tplmap":           "ctf-website/tplmap/tplmap.py",
    "exploitdb":        "ctf-website/exploitdb/searchsploit",
    "nmap":             "ctf-website/nmap/nmap.exe",
    # Common
    "ghidra":           "common/ghidra_*/ghidraRun.bat",
}


def main():
    print("\n=== Tool Availability Check ===\n")

    installed = 0
    missing = 0

    for name, relpath in TOOL_CHECKS.items():
        fullpath = os.path.join(TOOLS, relpath)
        if "*" in fullpath:
            import glob
            matches = glob.glob(fullpath)
            found = len(matches) > 0
        else:
            found = os.path.exists(fullpath)

        if found:
            print(f"  [OK] {name}")
            installed += 1
        else:
            print(f"  [MISSING] {name} - install: .\\scripts\\misc\\install_tools.ps1")
            missing += 1

    print(f"\n  {installed} installed, {missing} missing")
    print(f"  Run: .\\scripts\\misc\\install_tools.ps1 -All  to install all")


if __name__ == "__main__":
    main()
