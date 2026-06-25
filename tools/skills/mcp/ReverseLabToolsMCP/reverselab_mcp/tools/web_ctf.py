"""
Web CTF tools for ReverseLabToolsMCP.

HTTP probing, knowledge base routing, CVE lookup, CTF tool execution.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from ..config import REVERSE_ROOT, SCRIPTS_DIR, TOOLS_DIR
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
CTF_TOOLS_DIR = REVERSE_ROOT / "tools" / "ctf-website"


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
    case_dir = REVERSE_ROOT / "cases" / name
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
        "case": str(case_dir.relative_to(REVERSE_ROOT)),
        "url": url,
        "links": str(links.relative_to(REVERSE_ROOT)),
    }


# ── CTF Tool Runner ──

_CTF_TOOL_MAP = {
    "sqlmap": CTF_TOOLS_DIR / "sqlmap" / "sqlmap.py",
    "dirsearch": CTF_TOOLS_DIR / "dirsearch" / "dirsearch.py",
    "jwt_tool": CTF_TOOLS_DIR / "jwt_tool" / "jwt_tool.py",
    "tplmap": CTF_TOOLS_DIR / "tplmap" / "tplmap.py",
}


def run_ctf_tool(tool: str, args: str, timeout: int = 120) -> dict:
    """Run a CTF tool (sqlmap, dirsearch, jwt_tool, tplmap)."""
    if tool not in _CTF_TOOL_MAP:
        available = ", ".join(_CTF_TOOL_MAP)
        return {"error": f"unknown tool: {tool}. Available: {available}"}

    tool_path = _CTF_TOOL_MAP[tool]
    if not tool_path.exists():
        return {
            "error": f"{tool} not installed at {tool_path}. "
            f"Run: .\\scripts\\misc\\install_tools.ps1 -CTF"
        }

    cmd = [sys.executable, str(tool_path)] + args.split()
    try:
        result = subprocess.run(
            cmd,
            cwd=str(REVERSE_ROOT),
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
        }
    except subprocess.TimeoutExpired:
        return {"tool": tool, "args": args, "error": f"timeout after {timeout}s"}
    except Exception as e:
        return {"tool": tool, "args": args, "error": str(e)}


def ctf_tool_status() -> dict:
    """Check installation status of all CTF tools."""
    status = {}
    for name, path in _CTF_TOOL_MAP.items():
        status[name] = {
            "path": str(path.relative_to(REVERSE_ROOT)),
            "installed": path.exists(),
        }
    return {"tools": status, "install_cmd": ".\\scripts\\misc\\install_tools.ps1 -CTF"}
