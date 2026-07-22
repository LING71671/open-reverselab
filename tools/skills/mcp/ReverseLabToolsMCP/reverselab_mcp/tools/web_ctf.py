"""
Web CTF tools for ReverseLabToolsMCP.

HTTP probing, knowledge base routing, CVE lookup, CTF tool execution.
"""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

from ..config import CASES_DIR, DATA_ROOT, EXPORTS_ROOT, REVERSE_ROOT, SCRIPTS_DIR, TOOLS_DIR
from ..paths import ensure_under

# ── KB roots for all boards ──
KB_ROOTS = {
    "ctf-website": REVERSE_ROOT / "kb" / "ctf-website" / "techniques",
    "apk-reverse": REVERSE_ROOT / "kb" / "apk-reverse" / "techniques",
    "pe-reverse": REVERSE_ROOT / "kb" / "pe-reverse" / "techniques",
    "general": REVERSE_ROOT / "kb" / "general" / "techniques",
}

KB_INDEX = REVERSE_ROOT / "kb" / "ctf-website" / "techniques" / "kb-index.json"
TECHNIQUES_DIR = REVERSE_ROOT / "kb" / "ctf-website" / "techniques"
KB_ROUTER = SCRIPTS_DIR / "ctf-website" / "kb_router.py"
CTF_AUTOPILOT = SCRIPTS_DIR / "ctf-website" / "ctf_autopilot.py"
CTF_TOOLS_DIR = REVERSE_ROOT / "tools" / "ctf-website"
CTF_EXPORTS_DIR = EXPORTS_ROOT / "ctf-website"
BIN_DIR = REVERSE_ROOT / "tools" / "bin"
BURP_DIR = CTF_TOOLS_DIR / "burp"


# ── HTTP Probe ──

def http_probe(url: str, timeout: int = 15) -> dict:
    """Probe a URL: GET headers, body preview, cookies, server fingerprint."""
    try:
        import urllib.request
        import urllib.error

        req = urllib.request.Request(url, headers={
            "User-Agent": "ReverseLab/1.0",
            "Accept": "text/html,application/json,*/*",
        })
        resp = urllib.request.urlopen(req, timeout=timeout)

        body = resp.read(8192).decode("utf-8", errors="replace")
        headers = dict(resp.headers)

        return {
            "url": url,
            "status": resp.status,
            "headers": headers,
            "body_preview": body[:2048],
            "server": headers.get("Server", ""),
            "content_type": headers.get("Content-Type", ""),
            "cookies": headers.get("Set-Cookie", ""),
            "redirect_url": resp.url if resp.url != url else "",
        }
    except urllib.error.HTTPError as e:
        return {
            "url": url,
            "status": e.code,
            "headers": dict(e.headers),
            "body_preview": e.read(8192).decode("utf-8", errors="replace")[:2048],
            "error": str(e),
        }
    except Exception as e:
        return {"url": url, "error": str(e)}


# ── KB Router (all boards) ──

def _search_kb(query: str, board: str) -> list[dict]:
    """Search a single KB board's index and return scored results."""
    techniques_dir = KB_ROOTS[board]
    index_path = techniques_dir / "kb-index.json"
    if not index_path.exists():
        return []

    with open(index_path, encoding="utf-8") as f:
        data = json.load(f)

    entries = data.get("entries", [])
    query_lower = query.lower()
    results = []

    for entry in entries:
        score = 0
        if query_lower in entry.get("id", "").lower():
            score += 5
        for sig in entry.get("signals", []):
            if sig.lower() in query_lower or query_lower in sig.lower():
                score += 10
        for f in entry.get("files", []):
            if query_lower in f.lower():
                score += 3
        if score > 0:
            results.append({
                "board": board,
                "id": entry["id"],
                "priority": entry.get("priority", 0),
                "score": score,
                "signals": entry.get("signals", [])[:8],
                "files": [
                    str(techniques_dir / f) for f in entry.get("files", [])
                ],
            })

    results.sort(key=lambda r: r["score"], reverse=True)
    return results


def kb_router(query: str, board: str = "") -> dict:
    """按攻击信号搜索知识库（支持所有板块），返回匹配的技术文件和路径。

    board 参数可选：'ctf-website' | 'apk-reverse' | 'pe-reverse' | ''（全部搜索）
    """
    boards = [board] if board else list(KB_ROOTS.keys())
    all_results = []
    for b in boards:
        if b in KB_ROOTS:
            all_results.extend(_search_kb(query, b))

    # Sort across boards by score
    all_results.sort(key=lambda r: r["score"], reverse=True)

    # Group by board for clarity
    by_board = {}
    for r in all_results[:15]:
        by_board.setdefault(r["board"], []).append(r)

    return {
        "query": query,
        "boards_searched": boards,
        "total": len(all_results),
        "by_board": by_board,
        "top": all_results[:10],
    }


def kb_read_file(technique_path: str, board: str = "") -> dict:
    """读取知识库技术文件内容。自动检测板块或通过 board 参数指定。

    路径格式如 '02-auth/jwt/01-alg-none.md'（ctf-website）
    或 '04-crypto/01-game-encryption-patterns.md'（apk-reverse）
    或 '01-triage/01-aob-signature-scan.md'（pe-reverse）
    """
    # Auto-detect board from path if not specified
    if not board:
        # Try to find which KB has this file
        for b, root in KB_ROOTS.items():
            candidate = (root / technique_path).resolve()
            try:
                ensure_under(candidate, [root], "technique path")
                if candidate.exists() and candidate.is_file():
                    board = b
                    break
            except ValueError:
                continue
        else:
            # Fallback: search all roots for existence
            for b, root in KB_ROOTS.items():
                candidate = root / technique_path
                if candidate.exists() and candidate.is_file():
                    board = b
                    break

    if not board or board not in KB_ROOTS:
        return {
            "error": f"Cannot resolve board for '{technique_path}'. "
            f"Specify board: {', '.join(KB_ROOTS.keys())}"
        }

    resolved = (KB_ROOTS[board] / technique_path).resolve()
    try:
        ensure_under(resolved, [KB_ROOTS[board]], "technique path")
    except ValueError as e:
        return {"error": str(e)}

    if not resolved.exists():
        return {"error": f"file not found: {resolved}"}
    if not resolved.is_file():
        return {"error": f"not a file: {resolved}"}

    content = resolved.read_text(encoding="utf-8", errors="replace")
    return {
        "board": board,
        "path": str(resolved.relative_to(REVERSE_ROOT)),
        "size": len(content),
        "lines": content.count("\n"),
        "content": content[:16384],
        "truncated": len(content) > 16384,
    }


def kb_catalog(board: str = "") -> dict:
    """列出知识库所有板块、分类、条目数和文件数。

    board 参数可选：不传则列出所有板块。
    """
    boards = [board] if board else list(KB_ROOTS.keys())
    all_catalogs = {}

    for b in boards:
        if b not in KB_ROOTS:
            continue
        index_path = KB_ROOTS[b] / "kb-index.json"
        if not index_path.exists():
            all_catalogs[b] = {"error": "kb-index.json not found"}
            continue

        with open(index_path, encoding="utf-8") as f:
            data = json.load(f)

        entries = data.get("entries", [])
        categories = {}
        for entry in entries:
            for f_path in entry.get("files", []):
                cat = f_path.split("/")[0]
                categories.setdefault(cat, {"files": set(), "entry_ids": []})
                categories[cat]["files"].add(f_path)
                if entry["id"] not in categories[cat]["entry_ids"]:
                    categories[cat]["entry_ids"].append(entry["id"])

        all_catalogs[b] = {
            "version": data.get("version", ""),
            "techniques_dir": str(KB_ROOTS[b].relative_to(REVERSE_ROOT)),
            "total_entries": len(entries),
            "total_files": sum(len(e.get("files", [])) for e in entries),
            "categories": {
                cat: {
                    "entry_count": len(info["entry_ids"]),
                    "file_count": len(info["files"]),
                    "entries": info["entry_ids"],
                }
                for cat, info in sorted(categories.items())
            },
        }

    return {"boards": all_catalogs}

def ctf_new_challenge(name: str, url: str = "") -> dict:
    """Create a new CTF challenge case directory."""
    case_dir = CASES_DIR / name
    template_dir = REVERSE_ROOT / "templates" / "cases"

    if case_dir.exists():
        return {"error": f"case already exists: {case_dir}"}

    case_dir.mkdir(parents=True)

    if template_dir.exists():
        for f in template_dir.iterdir():
            if f.is_file():
                (case_dir / f.name).write_text(
                    f.read_text(encoding="utf-8", errors="replace"),
                    encoding="utf-8",
                )

    # Write links.md
    links = case_dir / "links.md"
    links.write_text(
        f"# {name} Links\n\n"
        f"## URL\n{url}\n\n"
        f"## Board\nctf-website\n\n"
        f"## Quick Links\n"
        f"- Exports: `exports/ctf-website/{name}/`\n"
        f"- Notes: `notes/ctf-website/{name}/`\n"
        f"- Reports: `reports/ctf-website/{name}/`\n",
        encoding="utf-8",
    )

    return {
        "case": str(case_dir),
        "url": url,
        "links": str(links),
    }


def _resolve_manifest_file(manifest_path: str) -> Path:
    if not manifest_path:
        raise ValueError("manifest_path is required")
    resolved = Path(manifest_path).expanduser()
    if not resolved.is_absolute():
        resolved = DATA_ROOT / resolved
    resolved = resolved.resolve(strict=True)
    ensure_under(resolved, [DATA_ROOT], "manifest path")
    if not resolved.is_file():
        raise ValueError(f"not a file: {resolved}")
    if resolved.name != "ai_manifest.json":
        raise ValueError(f"expected ai_manifest.json, got: {resolved}")
    return resolved


def ctf_autopilot_round(
    manifest_path: str,
    max_actions: int = 4,
    execute: bool = False,
    allow_network_cve: bool = False,
    timeout: int = 600,
) -> dict:
    """Run one stateful Web CTF autopilot round against an ai_manifest.json."""
    if not CTF_AUTOPILOT.exists():
        return {"error": f"ctf_autopilot.py not found: {CTF_AUTOPILOT}"}
    try:
        resolved = _resolve_manifest_file(manifest_path)
    except Exception as e:
        return {"error": str(e)}

    cmd = [
        sys.executable,
        str(CTF_AUTOPILOT),
        str(resolved),
        "--max-actions",
        str(max_actions),
        "--budget-seconds",
        "1",
        "--command-timeout",
        str(timeout),
    ]
    if execute:
        cmd.append("--execute")
    if allow_network_cve:
        cmd.append("--allow-network-cve")

    try:
        result = subprocess.run(
            cmd,
            cwd=str(REVERSE_ROOT),
            capture_output=True,
            text=True,
            timeout=max(timeout + 30, 60),
        )
    except subprocess.TimeoutExpired:
        return {"error": f"timeout after {timeout}s", "manifest": str(resolved)}

    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        payload = {
            "stdout": result.stdout[-8192:],
            "stderr": result.stderr[-4096:],
        }
    payload.update(
        {
            "exit_code": result.returncode,
            "stderr": result.stderr[-4096:],
        }
    )
    return payload


# ── CTF Tool Runner ──

_CTF_TOOL_MAP: dict[str, dict[str, Path]] = {
    "sqlmap": {
        "script": CTF_TOOLS_DIR / "sqlmap" / "sqlmap.py",
        "wrapper": BIN_DIR / "sqlmap.bat",
    },
    "dirsearch": {
        "script": CTF_TOOLS_DIR / "dirsearch" / "dirsearch.py",
        "wrapper": BIN_DIR / "dirsearch.bat",
    },
    "jwt_tool": {
        "script": CTF_TOOLS_DIR / "jwt_tool" / "jwt_tool.py",
        "wrapper": BIN_DIR / "jwt_tool.bat",
    },
    "tplmap": {
        "script": CTF_TOOLS_DIR / "tplmap" / "tplmap.py",
        "wrapper": BIN_DIR / "tplmap.bat",
    },
}


def _split_args(args: str) -> list[str]:
    """Split a user-supplied command line while preserving quoted URL/request args."""
    if not args:
        return []
    return shlex.split(args, posix=True)


def _display_path(path: Path) -> str:
    try:
        return str(path.relative_to(REVERSE_ROOT))
    except ValueError:
        return str(path)


def _install_cmd() -> str:
    if os.name == "nt":
        return ".\\scripts\\misc\\install_tools.ps1 -CTF"
    return "Install the native CLI tool on PATH, or run scripts/misc/bootstrap.sh for core wrappers."


def _wrapper_candidates(wrapper_path: Path) -> list[Path]:
    if os.name == "nt" or wrapper_path.suffix.lower() not in {".bat", ".cmd"}:
        return [wrapper_path]
    return [wrapper_path.with_suffix(""), wrapper_path.with_suffix(".sh")]


def _tool_command(tool: str) -> tuple[list[str] | None, dict]:
    entry = _CTF_TOOL_MAP[tool]
    script_path = entry["script"]
    wrapper_path = entry["wrapper"]
    if script_path.exists():
        return [sys.executable, str(script_path)], {}
    for candidate in _wrapper_candidates(wrapper_path):
        if candidate.exists():
            if candidate.suffix.lower() in {".bat", ".cmd"}:
                return [os.environ.get("COMSPEC", "cmd.exe"), "/c", str(candidate)], {
                    "warning": f"{tool} source script is missing; using wrapper fallback"
                }
            argv = [str(candidate)] if os.access(candidate, os.X_OK) else [os.environ.get("SHELL", "sh"), str(candidate)]
            return argv, {
                "warning": f"{tool} source script is missing; using POSIX wrapper fallback"
            }
    return None, {
        "error": f"{tool} not installed at {script_path}. "
        f"Run: {_install_cmd()}"
    }


def run_ctf_tool(tool: str, args: str, timeout: int = 120) -> dict:
    """Run a CTF tool (sqlmap, dirsearch, jwt_tool, tplmap)."""
    if tool not in _CTF_TOOL_MAP:
        available = ", ".join(_CTF_TOOL_MAP)
        return {"error": f"unknown tool: {tool}. Available: {available}"}

    base_cmd, meta = _tool_command(tool)
    if base_cmd is None:
        return meta

    try:
        arg_list = _split_args(args)
    except ValueError as e:
        return {"tool": tool, "args": args, "error": f"cannot parse args: {e}"}

    cmd = base_cmd + arg_list
    env = os.environ.copy()
    env["PATH"] = str(BIN_DIR) + os.pathsep + str(CTF_TOOLS_DIR / "bin") + os.pathsep + env.get("PATH", "")
    try:
        result = subprocess.run(
            cmd,
            cwd=str(REVERSE_ROOT),
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return {
            "tool": tool,
            "args": args,
            "exit_code": result.returncode,
            "stdout": result.stdout[-8192:],
            "stderr": result.stderr[-2048:],
            **meta,
        }
    except subprocess.TimeoutExpired:
        return {"tool": tool, "args": args, "error": f"timeout after {timeout}s"}
    except Exception as e:
        return {"tool": tool, "args": args, "error": str(e)}


def ctf_tool_status() -> dict:
    """Check installation status of all CTF tools."""
    status = {}
    for name, entry in _CTF_TOOL_MAP.items():
        status[name] = {
            "script": str(entry["script"].relative_to(REVERSE_ROOT)),
            "wrapper": str(entry["wrapper"].relative_to(REVERSE_ROOT)),
            "wrapper_candidates": [
                str(candidate.relative_to(REVERSE_ROOT))
                for candidate in _wrapper_candidates(entry["wrapper"])
            ],
            "installed": entry["script"].exists(),
            "wrapper_installed": any(candidate.exists() for candidate in _wrapper_candidates(entry["wrapper"])),
        }
    status["burp"] = burp_status()
    return {"tools": status, "install_cmd": _install_cmd()}


def _safe_case_name(case_name: str) -> str:
    safe = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in (case_name or "default"))
    return safe.strip("._") or "default"


def ctf_save_request(raw_request: str, case_name: str = "default", filename: str = "request.txt") -> dict:
    """Save a raw HTTP request under exports/ctf-website for Burp/sqlmap replay."""
    if not raw_request.strip():
        return {"error": "raw_request is required"}
    safe_filename = Path(filename or "request.txt").name
    if not safe_filename.lower().endswith(".txt"):
        safe_filename += ".txt"
    request_dir = (CTF_EXPORTS_DIR / _safe_case_name(case_name) / "requests").resolve()
    try:
        ensure_under(request_dir, [CTF_EXPORTS_DIR], "request output dir")
    except Exception as e:
        return {"error": str(e)}
    request_dir.mkdir(parents=True, exist_ok=True)
    request_path = request_dir / safe_filename
    request_path.write_text(raw_request.replace("\r\n", "\n").replace("\n", "\r\n"), encoding="utf-8")
    return {
        "path": _display_path(request_path),
        "sqlmap_args": f'-r "{request_path}" --batch',
        "burp_note": "Import or paste this raw request into Burp Repeater/Intruder.",
    }


def run_sqlmap_request(request_path: str, extra_args: str = "--batch", timeout: int = 300) -> dict:
    """Run sqlmap against a saved raw HTTP request file."""
    try:
        resolved = Path(request_path).expanduser()
        if not resolved.is_absolute():
            resolved = DATA_ROOT / resolved
        resolved = resolved.resolve(strict=True)
        ensure_under(resolved, [DATA_ROOT], "request path")
    except Exception as e:
        return {"error": str(e)}
    args = f'-r "{resolved}" {extra_args}'.strip()
    return run_ctf_tool("sqlmap", args, timeout)


def _find_burp_jars() -> list[Path]:
    jars: list[Path] = []
    for pattern in ("burpsuite*.jar", "burp*.jar"):
        jars.extend(p for p in BURP_DIR.glob(pattern) if p.is_file())
    return sorted(set(jars), key=lambda p: (p.stat().st_mtime, p.name), reverse=True)


def burp_status() -> dict:
    """Check Burp Suite local jar/wrapper status without launching the GUI."""
    jars = _find_burp_jars()
    wrapper = BIN_DIR / "burp.bat"
    return {
        "installed": bool(jars),
        "wrapper_installed": wrapper.exists(),
        "wrapper": _display_path(wrapper),
        "jars": [
            {
                "path": _display_path(jar),
                "size": jar.stat().st_size,
            }
            for jar in jars
        ],
        "proxy": "http://127.0.0.1:8080",
        "install_note": "Download Burp Community/Professional JAR from PortSwigger into tools/ctf-website/burp/.",
    }


def burp_launch(extra_args: str = "", launch: bool = False) -> dict:
    """Build or optionally launch the Burp Suite command.

    launch defaults to False so smoke tests and agents can inspect the command
    without opening a GUI. Set launch=True only on an explicit user request.
    """
    jars = _find_burp_jars()
    if not jars:
        return {
            "error": f"Burp Suite JAR not found under {BURP_DIR}. "
            "Download from PortSwigger and place burpsuite*.jar there."
        }
    try:
        arg_list = _split_args(extra_args)
    except ValueError as e:
        return {"error": f"cannot parse extra_args: {e}"}
    cmd = ["java", "-jar", str(jars[0]), *arg_list]
    response = {
        "jar": str(jars[0].relative_to(REVERSE_ROOT)),
        "command": cmd,
        "proxy": "http://127.0.0.1:8080",
        "launched": False,
    }
    if launch:
        proc = subprocess.Popen(
            cmd,
            cwd=str(REVERSE_ROOT),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
        )
        response.update({"launched": True, "pid": proc.pid})
    return response
