#!/usr/bin/env python3
"""Fail closed on common privacy leaks and broken public-release entrypoints."""

from __future__ import annotations

import json
import os
import py_compile
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TEXT_EXTS = {".md", ".py", ".ps1", ".json", ".toml", ".yaml", ".yml", ".js", ".txt", ".env"}
SECRET_PATTERNS = {
    "private key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "GitHub token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    "OpenAI-style key": re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    "AWS access key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "Windows user path": re.compile(r"\b[A-Za-z]:\\Users\\[^\\\s]+", re.I),
    "escaped Windows user path": re.compile(r"\b[A-Za-z]:\\\\Users\\\\[^\\\s]+", re.I),
    "Unix user path": re.compile(r"/(?:home|Users)/[^/\s]+"),
}
CRITICAL_FILES = [
    "scripts/misc/ai_context.py", "scripts/misc/ai_tool.py",
    "scripts/ctf-website/ctf_ai_next.py", "scripts/ctf-website/cve_chain_planner.py",
    "scripts/ctf-website/fingerprint_cve_pipeline.py",
]
STUB_MARKERS = ("not yet implemented", "backend not yet configured", "TODO: Plan CVE")


def tracked_files() -> list[Path]:
    out = subprocess.check_output(
        ["git", "-C", str(ROOT), "ls-files", "--cached", "--others", "--exclude-standard"],
        text=True,
        encoding="utf-8",
    )
    return [ROOT / line for line in out.splitlines() if line]


def main() -> int:
    failures: list[str] = []
    files = tracked_files()
    private_roots = [x for x in os.environ.get("REVERSELAB_PRIVATE_ROOTS", "").split(os.pathsep) if x]
    for path in files:
        if path.suffix.lower() not in TEXT_EXTS and path.name not in {"LICENSE", ".env.example"}:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for label, pattern in SECRET_PATTERNS.items():
            if pattern.search(text):
                failures.append(f"{label}: {path.relative_to(ROOT)}")
        for private_root in private_roots:
            variants = {private_root, private_root.replace("\\", "\\\\"), private_root.replace("\\", "/")}
            if any(value and value.lower() in text.lower() for value in variants):
                failures.append(f"private workspace reference: {path.relative_to(ROOT)}")
        # KB pages intentionally contain synthetic attack snippets. Keep strong
        # token/key patterns enabled everywhere, but apply assignment heuristics
        # only to executable/config content to avoid treating examples as leaks.
        rel_parts = path.relative_to(ROOT).parts
        if "kb" not in rel_parts and re.search(
            r"(?im)^[^#\n]*(?:password|passwd|api[_-]?key|token|secret)[ \t]*=[ \t]*[^\s#]+",
            text,
        ):
            failures.append(f"non-empty credential assignment: {path.relative_to(ROOT)}")

    for rel in CRITICAL_FILES:
        path = ROOT / rel
        if not path.exists():
            failures.append(f"missing critical file: {rel}")
            continue
        low = path.read_text(encoding="utf-8", errors="replace").lower()
        for marker in STUB_MARKERS:
            if marker.lower() in low:
                failures.append(f"stub marker in {rel}: {marker}")

    for path in files:
        if path.suffix == ".py":
            try:
                py_compile.compile(str(path), doraise=True)
            except Exception as exc:
                failures.append(f"python syntax: {path.relative_to(ROOT)}: {exc}")
        if path.suffix == ".json":
            try:
                json.loads(path.read_text(encoding="utf-8"))
            except Exception as exc:
                failures.append(f"json parse: {path.relative_to(ROOT)}: {exc}")

    mcp = json.loads((ROOT / ".mcp.json").read_text(encoding="utf-8"))
    for name, entry in mcp.get("mcpServers", {}).items():
        for arg in entry.get("args", []):
            if isinstance(arg, str) and arg.endswith((".py", ".js")) and not (ROOT / arg).is_file():
                failures.append(f"MCP {name} missing local entry: {arg}")

    print(json.dumps({"overall": "PASS" if not failures else "FAIL", "failures": failures}, ensure_ascii=False, indent=2))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
