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


# ── KB Router ──

def kb_router(query: str) -> dict:
    """Search the knowledge base for techniques matching a signal."""
    if not KB_INDEX.exists():
        return {"error": f"kb-index.json not found at {KB_INDEX}"}

    with open(KB_INDEX, encoding="utf-8") as f:
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
                "id": entry["id"],
                "priority": entry.get("priority", 0),
                "score": score,
                "signals": entry.get("signals", [])[:8],
                "files": [
                    str(TECHNIQUES_DIR / f) for f in entry.get("files", [])
                ],
            })

    results.sort(key=lambda r: r["score"], reverse=True)
    return {"query": query, "results": results[:10], "total": len(results)}


def kb_read_file(technique_path: str) -> dict:
    """Read a technique file from kb/ctf-website/techniques/."""
    resolved = (TECHNIQUES_DIR / technique_path).resolve()
    ensure_under(resolved, [TECHNIQUES_DIR], "technique path")

    if not resolved.exists():
        return {"error": f"file not found: {resolved}"}
    if not resolved.is_file():
        return {"error": f"not a file: {resolved}"}

    content = resolved.read_text(encoding="utf-8", errors="replace")
    return {
        "path": str(resolved.relative_to(REVERSE_ROOT)),
        "size": len(content),
        "lines": content.count("\n"),
        "content": content[:16384],
        "truncated": len(content) > 16384,
    }


# ── Case management ──

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


# ── KB Index Info ──

def kb_catalog() -> dict:
    """List all categories and entry counts in the knowledge base."""
    if not KB_INDEX.exists():
        return {"error": f"kb-index.json not found"}

    with open(KB_INDEX, encoding="utf-8") as f:
        data = json.load(f)

    entries = data.get("entries", [])
    categories = {}
    for entry in entries:
        for f in entry.get("files", []):
            cat = f.split("/")[0]
            categories.setdefault(cat, {"files": set(), "entry_ids": []})
            categories[cat]["files"].add(f)
            if entry["id"] not in categories[cat]["entry_ids"]:
                categories[cat]["entry_ids"].append(entry["id"])

    return {
        "version": data.get("version", ""),
        "total_entries": len(entries),
        "categories": {
            cat: {
                "entry_count": len(info["entry_ids"]),
                "file_count": len(info["files"]),
                "entries": info["entry_ids"],
            }
            for cat, info in sorted(categories.items())
        },
    }
