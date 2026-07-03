#!/usr/bin/env python3
"""
ReverseLab GUI bridge server.

This server is deliberately thin. It serves the GUI and exposes small HTTP
endpoints that call or mirror existing ReverseLab routes. The KB, routing
method, MCP tools, and evidence directories remain unchanged.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import mimetypes
import os
import re
import subprocess
import sys
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse


ROOT = Path(__file__).resolve().parents[2]
APP_DIR = ROOT / "gui" / "app" / "web"
TECHNIQUES_DIR = ROOT / "kb" / "ctf-website" / "techniques"
KB_INDEX = TECHNIQUES_DIR / "kb-index.json"
ATTACK_NETWORK = TECHNIQUES_DIR / "attack-network.md"
CTF_AI_USAGE = ROOT / "boards" / "ctf-website" / "AI-USAGE.md"
GLOBAL_AI_USAGE = ROOT / "AI-USAGE.md"
OPEN_CODE_CONFIG = ROOT / ".reverselab-local" / "opencode" / "opencode.generated.jsonc"
MCP_PACKAGE = ROOT / "tools" / "skills" / "mcp" / "ReverseLabToolsMCP"


def web_ctf_module():
    if str(MCP_PACKAGE) not in sys.path:
        sys.path.insert(0, str(MCP_PACKAGE))
    from reverselab_mcp.tools import web_ctf

    return web_ctf


def read_text(path: Path, max_chars: int = 200_000) -> str:
    content = path.read_text(encoding="utf-8", errors="replace")
    if len(content) > max_chars:
        return content[:max_chars] + "\n\n[truncated]"
    return content


def under(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def load_kb_entries() -> list[dict]:
    data = json.loads(KB_INDEX.read_text(encoding="utf-8"))
    entries = data.get("entries", [])
    return entries if isinstance(entries, list) else []


def score_entry(query: str, entry: dict) -> int:
    query_lower = query.lower()
    score = 0
    if query_lower in str(entry.get("id", "")).lower():
        score += 5
    for signal in entry.get("signals", []) or []:
        signal_lower = str(signal).lower()
        if signal_lower in query_lower or query_lower in signal_lower:
            score += 10
    for file_name in entry.get("files", []) or []:
        if query_lower in str(file_name).lower():
            score += 3
    return score


def route_signal(query: str) -> list[dict]:
    results = []
    for entry in load_kb_entries():
        score = score_entry(query, entry)
        if score <= 0:
            continue
        item = dict(entry)
        item["score"] = score
        item["files"] = [
            {
                "path": file_name,
                "display": f"kb/ctf-website/techniques/{file_name}",
                "exists": (TECHNIQUES_DIR / str(file_name)).is_file(),
            }
            for file_name in entry.get("files", []) or []
        ]
        results.append(item)
    results.sort(key=lambda item: item.get("score", 0), reverse=True)
    return results[:10]


def parse_mcp_mapping(content: str) -> list[dict]:
    lines = content.splitlines()
    start = None
    for index, line in enumerate(lines):
        if line.strip().startswith("## ") and "MCP 工具映射" in line:
            start = index + 1
            break
    if start is None:
        return []

    rows = []
    for line in lines[start:]:
        stripped = line.strip()
        if stripped.startswith("## "):
            break
        if not stripped.startswith("|") or "---" in stripped:
            continue
        cells = [cell.strip().strip("`") for cell in stripped.strip("|").split("|")]
        if len(cells) < 3 or cells[0] == "攻击步骤":
            continue
        command = cells[1].replace("`", "").strip()
        parts = command.split()
        rows.append(
            {
                "step": cells[0],
                "command": command,
                "description": cells[2],
                "tool": parts[0] if parts else "",
                "ctfTool": parts[1] if len(parts) >= 2 and parts[0] == "run_ctf_tool" else "",
                "runnable": bool(parts and parts[0] == "run_ctf_tool" and len(parts) >= 2),
            }
        )
    return rows


def safe_case_name(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", name.strip()).strip(".-")
    return cleaned or "ctf-workbench"


def json_body(handler: BaseHTTPRequestHandler, max_bytes: int = 64_000) -> dict:
    length = int(handler.headers.get("Content-Length", "0") or "0")
    if length <= 0:
        return {}
    if length > max_bytes:
        raise ValueError("request body too large")
    raw = handler.rfile.read(length)
    data = json.loads(raw.decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("request body must be a JSON object")
    return data


def write_artifact(case_name: str, stem: str, payload: object) -> str:
    case_dir = ROOT / "exports" / "ctf-website" / safe_case_name(case_name)
    case_dir.mkdir(parents=True, exist_ok=True)
    timestamp = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    target = case_dir / f"{timestamp}_{stem}.json"
    target.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return target.relative_to(ROOT).as_posix()


def write_note(case_name: str, stem: str, content: str) -> str:
    case_dir = ROOT / "notes" / "ctf-website" / safe_case_name(case_name)
    case_dir.mkdir(parents=True, exist_ok=True)
    timestamp = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    target = case_dir / f"{timestamp}_{stem}.md"
    target.write_text(content, encoding="utf-8")
    return target.relative_to(ROOT).as_posix()


def build_handoff_prompt(payload: dict) -> str:
    mapping = payload.get("mapping") or []
    mapping_lines = []
    for item in mapping:
        mapping_lines.append(f"- {item.get('step', '')}: `{item.get('command', '')}` - {item.get('description', '')}")
    mapping_text = "\n".join(mapping_lines) if mapping_lines else "- 未解析到 MCP 工具映射，先重新读取 technique 文件。"

    return "\n".join(
        [
            "# ReverseLab CTF Handoff",
            "",
            f"- Case: {safe_case_name(str(payload.get('caseName', 'ctf-workbench')))}",
            f"- Target: {payload.get('target', '')}",
            f"- Signal: {payload.get('signal', '')}",
            f"- Technique: {payload.get('techniquePath', '')}",
            "",
            "请按 ReverseLab 现有路线执行，不要改变知识库和 evidence 路径：",
            "",
            "1. 读 `AI-USAGE.md`。",
            "2. 读 `boards/ctf-website/AI-USAGE.md`。",
            "3. 读 `kb/ctf-website/techniques/attack-network.md`。",
            "4. 对每个新信号调用 `kb_router(query, board=\"ctf-website\")` 或 `python scripts/ctf-website/kb_router.py \"<signal>\"`。",
            "5. 用 `kb_read_file` 读取命中的 technique 文件。",
            "6. 优先按 technique 末尾 MCP 工具映射调用工具。",
            "7. 输出保存在 `exports/ctf-website/<case>/`、`notes/ctf-website/<case>/`、`reports/ctf-website/<case>/`。",
            "",
            "## 当前 MCP 工具映射",
            "",
            mapping_text,
            "",
            "## 当前任务",
            "",
            "基于以上 signal 和 technique，给出下一步可执行探测计划；如果可以直接运行 MCP 工具，先运行并把 stdout/stderr、关键响应、证据路径写回 notes。",
        ]
    )


def run_kb_router_raw(query: str) -> dict:
    proc = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "ctf-website" / "kb_router.py"), query],
        cwd=str(ROOT),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
    )
    return {"exit": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}


def list_artifacts() -> dict[str, list[dict]]:
    roots = {
        "exports": ROOT / "exports" / "ctf-website",
        "notes": ROOT / "notes" / "ctf-website",
        "reports": ROOT / "reports" / "ctf-website",
    }
    payload: dict[str, list[dict]] = {}
    for name, folder in roots.items():
        items = []
        if folder.exists():
            for item in sorted(folder.rglob("*"), key=lambda p: p.stat().st_mtime if p.exists() else 0, reverse=True):
                if not item.is_file():
                    continue
                rel = item.relative_to(ROOT).as_posix()
                stat = item.stat()
                items.append({"path": rel, "size": stat.st_size, "mtime": stat.st_mtime})
                if len(items) >= 100:
                    break
        payload[name] = items
    return payload


def json_response(handler: BaseHTTPRequestHandler, payload: object, status: int = 200) -> None:
    data = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("Content-Length", str(len(data)))
    handler.end_headers()
    handler.wfile.write(data)


def text_response(handler: BaseHTTPRequestHandler, payload: str, status: int = 200, content_type: str = "text/plain") -> None:
    data = payload.encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", f"{content_type}; charset=utf-8")
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("Content-Length", str(len(data)))
    handler.end_headers()
    handler.wfile.write(data)


class Handler(BaseHTTPRequestHandler):
    server_version = "ReverseLabGUI/0.1"

    def log_message(self, fmt: str, *args: object) -> None:
        sys.stderr.write("[gui] " + fmt % args + "\n")

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        try:
            if path == "/api/context":
                return json_response(
                    self,
                    {
                        "root": str(ROOT),
                        "board": "ctf-website",
                        "routeInvariant": [
                            "AI-USAGE.md",
                            "boards/ctf-website/AI-USAGE.md",
                            "kb/ctf-website/techniques/attack-network.md",
                            "scripts/ctf-website/kb_router.py",
                            "kb/ctf-website/techniques/kb-index.json",
                            "exports/ctf-website",
                            "notes/ctf-website",
                            "reports/ctf-website",
                        ],
                        "opencodeConfig": str(OPEN_CODE_CONFIG),
                        "opencodeConfigExists": OPEN_CODE_CONFIG.is_file(),
                        "opencodeUrl": f"http://127.0.0.1:{os.environ.get('REVERSELAB_OPENCODE_PORT', '4096')}",
                    },
                )
            if path == "/api/bootstrap-docs":
                return json_response(
                    self,
                    {
                        "globalAiUsage": read_text(GLOBAL_AI_USAGE),
                        "ctfAiUsage": read_text(CTF_AI_USAGE),
                        "attackNetwork": read_text(ATTACK_NETWORK),
                    },
                )
            if path == "/api/kb-route":
                signal = (query.get("signal") or [""])[0].strip()
                if not signal:
                    return json_response(self, {"error": "signal is required"}, HTTPStatus.BAD_REQUEST)
                return json_response(self, {"signal": signal, "results": route_signal(signal), "raw": run_kb_router_raw(signal)})
            if path == "/api/technique":
                rel = unquote((query.get("path") or [""])[0]).replace("\\", "/")
                target = (TECHNIQUES_DIR / rel).resolve()
                if not rel or not under(target, TECHNIQUES_DIR) or not target.is_file():
                    return json_response(self, {"error": "technique file not found"}, HTTPStatus.NOT_FOUND)
                content = read_text(target)
                return json_response(
                    self,
                    {
                        "path": f"kb/ctf-website/techniques/{rel}",
                        "relativePath": rel,
                        "content": content,
                        "mcpMapping": parse_mcp_mapping(content),
                    },
                )
            if path == "/api/ctf-tool-status":
                return json_response(self, web_ctf_module().ctf_tool_status())
            if path == "/api/artifacts":
                return json_response(self, list_artifacts())
            return self.serve_static(path)
        except subprocess.TimeoutExpired:
            return json_response(self, {"error": "command timed out"}, HTTPStatus.GATEWAY_TIMEOUT)
        except Exception as exc:
            return json_response(self, {"error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        try:
            payload = json_body(self)
            if path == "/api/run-ctf-tool":
                tool = str(payload.get("tool", "")).strip()
                args = str(payload.get("args", "")).strip()
                timeout = int(payload.get("timeout", 120))
                case_name = safe_case_name(str(payload.get("caseName", "ctf-workbench")))
                if not tool:
                    return json_response(self, {"error": "tool is required"}, HTTPStatus.BAD_REQUEST)
                result = web_ctf_module().run_ctf_tool(tool, args, timeout)
                artifact = write_artifact(case_name, f"run_ctf_tool_{tool}", {"request": payload, "result": result})
                return json_response(self, {"artifact": artifact, "result": result})
            if path == "/api/ai-handoff":
                prompt = build_handoff_prompt(payload)
                note = write_note(str(payload.get("caseName", "ctf-workbench")), "opencode_handoff", prompt)
                return json_response(self, {"prompt": prompt, "note": note})
            return json_response(self, {"error": "not found"}, HTTPStatus.NOT_FOUND)
        except subprocess.TimeoutExpired:
            return json_response(self, {"error": "command timed out"}, HTTPStatus.GATEWAY_TIMEOUT)
        except Exception as exc:
            return json_response(self, {"error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)

    def serve_static(self, path: str) -> None:
        rel = "index.html" if path in {"", "/"} else unquote(path).lstrip("/")
        target = (APP_DIR / rel).resolve()
        if not under(target, APP_DIR) or not target.is_file():
            return text_response(self, "Not found", HTTPStatus.NOT_FOUND)
        content_type = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
        data = target.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=int(os.environ.get("REVERSELAB_GUI_PORT", "8765")))
    args = parser.parse_args()

    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"ReverseLab GUI listening on http://{args.host}:{args.port}")
    httpd.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
