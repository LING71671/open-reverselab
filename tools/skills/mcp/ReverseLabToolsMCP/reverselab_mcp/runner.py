from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any

from .config import REVERSE_ROOT


def run(args: list[str], timeout: int = 60, env: dict[str, str] | None = None) -> tuple[int, str, str]:
    startupinfo = None
    creationflags = 0
    if os.name == "nt":
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        creationflags = subprocess.CREATE_NO_WINDOW

    proc = subprocess.run(
        args,
        cwd=str(REVERSE_ROOT),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        env=env,
        startupinfo=startupinfo,
        creationflags=creationflags,
    )
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()


def run_component(args: list[str], timeout: int) -> tuple[str, dict[str, Any]]:
    """Return stdout or a serializable failure for one external analysis step."""
    try:
        code, out, err = run(args, timeout=timeout)
    except subprocess.TimeoutExpired:
        return "", {"kind": "timeout", "error": f"exceeded {timeout}s"}
    except (OSError, ValueError) as exc:
        return "", {"kind": "internal", "error": str(exc)}
    if code:
        return "", {"kind": "unsupported", "exit": code, "error": (err or out).strip()[:500] or f"exit {code}"}
    return out, {}


def launch(args: list[str], visible: bool = True, cwd: Path | None = None) -> int:
    startupinfo = None
    creationflags = 0
    if os.name == "nt" and not visible:
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        creationflags = subprocess.CREATE_NO_WINDOW

    proc = subprocess.Popen(
        args,
        cwd=str(cwd or REVERSE_ROOT),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        startupinfo=startupinfo,
        creationflags=creationflags,
    )
    return proc.pid
