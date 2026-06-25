from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from ..config import DIEC_EXE, EXPORTS_DIR, RZ_BIN_EXE
from ..paths import check_tool, resolve_file
from ..runner import run
from ..utils import json_or_text, limited_list, sanitize_line


def hashes(path: Path) -> dict[str, Any]:
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    stat = path.stat()
    return {
        "path": str(path),
        "name": path.name,
        "size": stat.st_size,
        "md5": md5.hexdigest().upper(),
        "sha1": sha1.hexdigest().upper(),
        "sha256": sha256.hexdigest().upper(),
    }


def rz_bin_json(path: Path, option: str, timeout: int = 60) -> dict[str, Any]:
    check_tool(RZ_BIN_EXE, "rz-bin.exe")
    code, stdout, stderr = run([str(RZ_BIN_EXE), "-j", option, str(path)], timeout=timeout)
    return {
        "tool": "rz-bin",
        "option": option,
        "returncode": code,
        "stdout": json_or_text(stdout),
        "stderr": stderr,
    }


def die_json(path: Path, args: list[str], timeout: int = 60) -> dict[str, Any]:
    check_tool(DIEC_EXE, "diec.exe")
    code, stdout, stderr = run([str(DIEC_EXE), *args, str(path)], timeout=timeout)
    return {
        "tool": "diec",
        "args": args,
        "returncode": code,
        "stdout": json_or_text(stdout),
        "stderr": stderr,
    }


def rz_strings_text(path: Path, limit: int, timeout: int = 60) -> dict[str, Any]:
    check_tool(RZ_BIN_EXE, "rz-bin.exe")
    code, stdout, stderr = run([str(RZ_BIN_EXE), "-zz", str(path)], timeout=timeout)
    lines = [sanitize_line(line) for line in stdout.splitlines() if line.strip()]
    return {
        "tool": "rz-bin",
        "option": "-zz",
        "returncode": code,
        "stdout": {
            "strings": lines[: max(0, limit)],
            "strings_total": len(lines),
            "format": "rz-bin text lines",
        },
        "stderr": stderr,
    }


def markdown_triage(result: dict[str, Any]) -> str:
    file_hashes = result["hashes"]
    rz_info = result.get("rizin_info", {}).get("stdout") or {}
    info = rz_info.get("info", {}) if isinstance(rz_info, dict) else {}
    die_scan_result = result.get("die_scan", {}).get("stdout")
    die_entropy = result.get("die_entropy", {}).get("stdout")
    sections = result.get("sections", {}).get("stdout") or {}
    imports = result.get("imports", {}).get("stdout") or {}
    strings = result.get("strings", {}).get("stdout") or {}

    section_items = sections.get("sections", []) if isinstance(sections, dict) else []
    import_items = imports.get("imports", []) if isinstance(imports, dict) else []
    string_items = strings.get("strings", []) if isinstance(strings, dict) else []

    lines = [
        f"# 初筛：{file_hashes['name']}",
        "",
        "## 1. Basic Info",
        "",
        f"- Path: `{file_hashes['path']}`",
        f"- Size: `{file_hashes['size']}` bytes",
        f"- MD5: `{file_hashes['md5']}`",
        f"- SHA1: `{file_hashes['sha1']}`",
        f"- SHA256: `{file_hashes['sha256']}`",
        f"- Type: `{info.get('bintype', '')}` / `{info.get('class', '')}`",
        f"- Architecture: `{info.get('arch', '')}` `{info.get('bits', '')}`",
        f"- Subsystem: `{info.get('subsys', '')}`",
        f"- Base Address: `{info.get('baddr', '')}`",
        f"- Entry Point: `{info.get('intrp', info.get('entry', ''))}`",
        f"- Compiler: `{info.get('compiler', '')}`",
        f"- PDB: `{info.get('dbg_file', '')}`",
        f"- NX: `{info.get('NX', '')}`",
        f"- PIE: `{info.get('PIE', '')}`",
        "",
        "## 2. DiE 扫描",
        "",
        "```json",
        json.dumps(die_scan_result, ensure_ascii=False, indent=2),
        "```",
        "",
        "## 3. Entropy",
        "",
        "```json",
        json.dumps(die_entropy, ensure_ascii=False, indent=2),
        "```",
        "",
        "## 4. Sections",
        "",
        "| Name | PAddr | VAddr | Size | VSize | Perm | Flags |",
        "|---|---:|---:|---:|---:|---|---|",
    ]

    for sec in section_items:
        flags = ", ".join(sec.get("flags", [])) if isinstance(sec.get("flags"), list) else sec.get("flags", "")
        lines.append(
            f"| `{sec.get('name', '')}` | `{sec.get('paddr', '')}` | `{sec.get('vaddr', '')}` | "
            f"`{sec.get('size', '')}` | `{sec.get('vsize', '')}` | `{sec.get('perm', '')}` | `{flags}` |"
        )

    lines.extend(["", "## 5. Imports 快照", ""])
    for imp in import_items[:80]:
        lines.append(f"- `{imp.get('libname', '')}!{imp.get('name', '')}`")
    if len(import_items) > 80:
        lines.append(f"- ... truncated, total imports: `{len(import_items)}`")

    lines.extend(["", "## 6. Strings 快照", ""])
    for item in string_items[:80]:
        if isinstance(item, dict):
            addr = item.get("vaddr", item.get("paddr", ""))
            text = item.get("string", item.get("text", ""))
            lines.append(f"- `{addr}`: `{str(text)[:180]}`")
        else:
            lines.append(f"- `{str(item)[:220]}`")
    if len(string_items) > 80:
        lines.append(f"- ... truncated, total strings: `{len(string_items)}`")

    lines.extend(["", "## 7. 初步结论", "", "- 待人工/AI 结合 imports、strings、sections 继续判断。"])
    return "\n".join(lines) + "\n"


def hash_file(path: str) -> dict[str, Any]:
    return hashes(resolve_file(path))


def die_scan(path: str, deep: bool = False, heuristic: bool = False, entropy: bool = False) -> dict[str, Any]:
    target = resolve_file(path)
    args = ["-j"]
    if deep:
        args.append("-d")
    if heuristic:
        args.append("-u")
    if entropy:
        args.append("-e")
    return die_json(target, args)


def rizin_bin_info(path: str) -> dict[str, Any]:
    return rz_bin_json(resolve_file(path), "-I")


def rizin_sections(path: str) -> dict[str, Any]:
    return rz_bin_json(resolve_file(path), "-S")


def rizin_imports(path: str, limit: int = 300) -> dict[str, Any]:
    result = rz_bin_json(resolve_file(path), "-i")
    result["stdout"] = limited_list(result.get("stdout"), "imports", limit)
    return result


def rizin_strings(path: str, limit: int = 300) -> dict[str, Any]:
    return rz_strings_text(resolve_file(path), limit)


def triage_pe(path: str, write_markdown: bool = False) -> dict[str, Any]:
    target = resolve_file(path)
    result = {
        "hashes": hashes(target),
        "die_scan": die_json(target, ["-j"]),
        "die_entropy": die_json(target, ["-j", "-e"]),
        "rizin_info": rz_bin_json(target, "-I"),
        "sections": rz_bin_json(target, "-S"),
        "imports": rizin_imports(str(target), limit=500),
        "strings": rizin_strings(str(target), limit=500),
    }
    if write_markdown:
        EXPORTS_DIR.mkdir(parents=True, exist_ok=True)
        out_path = EXPORTS_DIR / f"{target.stem}-triage.md"
        out_path.write_text(markdown_triage(result), encoding="utf-8")
        result["markdown_path"] = str(out_path)
    return result
