"""Optional static-analysis backends; machine paths never belong in the repo."""
from __future__ import annotations

import os
import shutil
from pathlib import Path

from .config import REVERSE_ROOT

IDA_EXPORTS_DIR = REVERSE_ROOT / "exports" / "windows" / "ida"
IDA_PROJECTS_DIR = REVERSE_ROOT / "projects" / "windows" / "ida-headless"
IDA_SCRIPT = REVERSE_ROOT / "scripts" / "_shared" / "ida" / "export_summary.py"


def find_ida_executable() -> Path | None:
    """Prefer an explicit override, then PATH, then local install discovery."""
    override = os.environ.get("REVERSELAB_IDA_EXE", "").strip()
    if override:
        # An invalid override is reported, not silently replaced by another IDA.
        return Path(override).expanduser()
    names = ["idat.exe", "idat64.exe", "ida.exe", "ida64.exe"] if os.name == "nt" else ["idat", "idat64", "ida", "ida64"]
    homes = []
    if os.environ.get("IDA_HOME"):
        homes.append(Path(os.environ["IDA_HOME"]).expanduser())
    for name in names:
        found = shutil.which(name)
        if found:
            return Path(found)
    if os.name == "nt":
        import winreg
        for hive in [winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE]:
            for view in [winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY]:
                try:
                    with winreg.OpenKey(hive, r"Software\Microsoft\Windows\CurrentVersion\Uninstall", 0, winreg.KEY_READ | view) as parent:
                        for i in range(winreg.QueryInfoKey(parent)[0]):
                            try:
                                with winreg.OpenKey(parent, winreg.EnumKey(parent, i)) as key:
                                    label = str(winreg.QueryValueEx(key, "DisplayName")[0])
                                    if label.startswith("IDA Professional") or label.startswith("IDA Pro "):
                                        homes.append(Path(str(winreg.QueryValueEx(key, "InstallLocation")[0])))
                            except OSError:
                                continue
                except OSError:
                    continue
        for variable in ["ProgramFiles", "ProgramFiles(x86)"]:
            if os.environ.get(variable):
                homes.extend(sorted(Path(os.environ[variable]).glob("IDA*"), reverse=True))
    else:
        homes.extend(sorted(Path("/Applications").glob("IDA*.app/Contents/MacOS"), reverse=True))
    for home in homes:
        for name in names:
            candidate = home / name
            if candidate.is_file():
                return candidate
    return None
