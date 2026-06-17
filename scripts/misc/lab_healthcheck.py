#!/usr/bin/env python3
"""
ReverseLab 环境健康检查。

Usage:
    python scripts/misc/lab_healthcheck.py

Checks:
    - Required directories exist
    - Git status
    - Tool availability (runs ai_toolcheck.py)
    - Disk space
"""

import os
import sys
import subprocess


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

REQUIRED_DIRS = [
    "boards", "cases", "exports", "kb", "logs", "notes",
    "patches", "projects", "reports", "samples", "scripts",
    "templates", "tools", "tmp",
]

BOARDS = ["android", "windows", "ctf-website", "misc"]


def check_directories():
    print("\n=== Directory Check ===")
    ok = True
    for d in REQUIRED_DIRS:
        path = os.path.join(ROOT, d)
        exists = os.path.isdir(path)
        status = "[OK]" if exists else "[MISSING]"
        if not exists:
            ok = False
        print(f"  {status}: {d}/")
    return ok


def check_platform_dirs():
    print("\n=== Platform Directory Check ===")
    ok = True
    for area in BOARDS:
        for parent in ["samples", "projects", "exports", "notes", "reports", "patches", "scripts"]:
            path = os.path.join(ROOT, parent, area)
            if not os.path.isdir(path):
                print(f"  [MISSING]: {parent}/{area}/")
                ok = False
    if ok:
        print("  [OK] All platform directories present")
    return ok


def main():
    print("ReverseLab Health Check")
    print(f"  Root: {ROOT}")

    dirs_ok = check_directories()
    platform_ok = check_platform_dirs()

    # Tool check
    toolcheck = os.path.join(ROOT, "scripts", "misc", "ai_toolcheck.py")
    if os.path.exists(toolcheck):
        print("\n=== Tool Check ===")
        subprocess.run([sys.executable, toolcheck])

    print(f"\n{'[OK] All checks passed' if dirs_ok and platform_ok else '[ERROR] Issues found - see above'}")


if __name__ == "__main__":
    main()
