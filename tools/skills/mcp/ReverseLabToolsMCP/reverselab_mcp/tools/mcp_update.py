from __future__ import annotations

import json
import os
import re
import shutil
import tomllib
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from ..config import REPORTS_DIR, REVERSE_ROOT
from ..runner import run


NPM_TIMEOUT = 45
GIT_TIMEOUT = 60
PYPI_TIMEOUT = 20


def _read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    return value if isinstance(value, dict) else {}


def _read_toml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    with path.open("rb") as handle:
        value = tomllib.load(handle)
    return value if isinstance(value, dict) else {}


def _workspace_mcp_servers() -> dict[str, dict[str, Any]]:
    data = _read_json(REVERSE_ROOT / ".mcp.json")
    servers = data.get("mcpServers", {})
    return servers if isinstance(servers, dict) else {}


def _codex_mcp_servers() -> dict[str, dict[str, Any]]:
    home = Path(os.environ.get("USERPROFILE", str(Path.home())))
    data = _read_toml(home / ".codex" / "config.toml")
    servers = data.get("mcp_servers", {})
    return servers if isinstance(servers, dict) else {}


def _norm_args(entry: dict[str, Any]) -> list[str]:
    args = entry.get("args", [])
    return [str(item) for item in args] if isinstance(args, list) else []


def _strip_npm_spec(spec: str) -> str:
    if spec.startswith("@"):
        parts = spec.split("@")
        if len(parts) >= 3:
            return "@" + parts[1]
        return spec
    return spec.split("@", 1)[0]


def _npm_package(args: list[str]) -> str:
    for arg in args:
        if arg in {"-y", "--yes", "--package", "-p"}:
            continue
        if arg.startswith("-"):
            continue
        return _strip_npm_spec(arg)
    return ""


def _uvx_package(args: list[str]) -> str:
    skip_next = False
    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if arg in {"--from", "-p", "--python"}:
            skip_next = True
            continue
        if arg.startswith("-"):
            continue
        return arg
    return ""


def _json_command(args: list[str], timeout: int) -> tuple[dict[str, Any] | None, str]:
    args = _resolve_command(args)
    code, stdout, stderr = run(args, timeout=timeout)
    if code != 0:
        return None, stderr or stdout
    try:
        value = json.loads(stdout)
    except json.JSONDecodeError:
        return None, stdout
    return value if isinstance(value, dict) else {"value": value}, ""


def _resolve_command(args: list[str]) -> list[str]:
    if not args:
        return args
    executable = shutil.which(args[0])
    return [executable or args[0], *args[1:]]


def _npm_view(package: str) -> dict[str, Any]:
    if not package:
        return {"error": "missing npm package"}
    value, error = _json_command(["npm", "view", package, "version", "deprecated", "repository.url", "--json"], NPM_TIMEOUT)
    if value is None:
        return {"package": package, "error": error}
    value["package"] = package
    return value


def _pypi_view(package: str) -> dict[str, Any]:
    if not package:
        return {"error": "missing PyPI package"}
    url = f"https://pypi.org/pypi/{package}/json"
    try:
        with urllib.request.urlopen(url, timeout=PYPI_TIMEOUT) as response:
            data = json.loads(response.read().decode("utf-8", errors="replace"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        return {"package": package, "error": str(exc)}
    info = data.get("info", {}) if isinstance(data, dict) else {}
    return {
        "package": package,
        "version": str(info.get("version", "")),
        "summary": str(info.get("summary", "")),
        "project_url": f"https://pypi.org/project/{package}/",
    }


def _git_remote_head(repo_path: Path) -> dict[str, Any]:
    if not repo_path.exists():
        return {"error": f"path not found: {repo_path}"}
    code, local_head, stderr = run(_resolve_command(["git", "-C", str(repo_path), "rev-parse", "HEAD"]), timeout=GIT_TIMEOUT)
    if code != 0:
        return {"error": stderr or local_head}
    code, remote_url, stderr = run(_resolve_command(["git", "-C", str(repo_path), "remote", "get-url", "origin"]), timeout=GIT_TIMEOUT)
    if code != 0:
        return {"local_head": local_head, "error": stderr or remote_url}
    code, remote_lines, stderr = run(_resolve_command(["git", "ls-remote", remote_url, "HEAD", "refs/heads/main", "refs/tags/*"]), timeout=GIT_TIMEOUT)
    if code != 0:
        return {"local_head": local_head, "remote_url": remote_url, "error": stderr or remote_lines}
    refs: dict[str, str] = {}
    latest_tag = ""
    for line in remote_lines.splitlines():
        parts = line.split()
        if len(parts) != 2:
            continue
        refs[parts[1]] = parts[0]
        if parts[1].startswith("refs/tags/"):
            latest_tag = parts[1].removeprefix("refs/tags/")
    remote_head = refs.get("refs/heads/main") or refs.get("HEAD", "")
    return {
        "local_head": local_head,
        "remote_url": remote_url,
        "remote_head": remote_head,
        "latest_tag": latest_tag,
        "up_to_date": bool(remote_head) and local_head == remote_head,
    }


def _git_url_refs(url: str) -> dict[str, Any]:
    if not url:
        return {"error": "missing git URL"}
    code, remote_lines, stderr = run(_resolve_command(["git", "ls-remote", url, "HEAD", "refs/heads/main", "refs/tags/*"]), timeout=GIT_TIMEOUT)
    if code != 0:
        return {"remote_url": url, "error": stderr or remote_lines}
    refs: dict[str, str] = {}
    latest_tag = ""
    for line in remote_lines.splitlines():
        parts = line.split()
        if len(parts) != 2:
            continue
        refs[parts[1]] = parts[0]
        if parts[1].startswith("refs/tags/"):
            latest_tag = parts[1].removeprefix("refs/tags/")
    return {
        "remote_url": url,
        "remote_head": refs.get("refs/heads/main") or refs.get("HEAD", ""),
        "latest_tag": latest_tag,
    }


def _package_json_for_args(args: list[str]) -> Path | None:
    for arg in args:
        candidate = Path(arg)
        if candidate.suffix.lower() in {".js", ".mjs", ".cjs"} and candidate.exists():
            for parent in [candidate.parent, *candidate.parents]:
                package_json = parent / "package.json"
                if package_json.exists():
                    return package_json
    return None


def _local_node_project(args: list[str]) -> dict[str, Any] | None:
    package_json = _package_json_for_args(args)
    if not package_json:
        return None
    data = _read_json(package_json)
    repo = data.get("repository", {})
    repo_url = repo.get("url", "") if isinstance(repo, dict) else str(repo)
    repo_url = repo_url.removeprefix("git+")
    if repo_url.endswith(".git"):
        repo_url = repo_url
    local = {
        "package_json": str(package_json),
        "name": str(data.get("name", "")),
        "version": str(data.get("version", "")),
        "repository": repo_url,
    }
    if repo_url.startswith("http"):
        code, refs, stderr = run(_resolve_command(["git", "ls-remote", repo_url, "HEAD", "refs/heads/main", "refs/tags/*"]), timeout=GIT_TIMEOUT)
        local["remote_accessible"] = code == 0
        local["remote_error"] = "" if code == 0 else (stderr or refs)
        if code == 0:
            match = re.search(r"^([0-9a-f]{40})\s+HEAD$", refs, re.MULTILINE)
            local["remote_head"] = match.group(1) if match else ""
    return local


def _entry_audit(name: str, source: str, entry: dict[str, Any]) -> dict[str, Any]:
    command = str(entry.get("command", ""))
    args = _norm_args(entry)
    result: dict[str, Any] = {
        "name": name,
        "source": source,
        "command": command,
        "args": args,
        "status": "unchecked",
    }
    if "url" in entry:
        result.update({"status": "remote_http", "url": entry.get("url"), "note": "HTTP MCP endpoint; verify by token/authenticated /mcp check."})
        return result
    if command == "npx":
        package = _npm_package(args)
        view = _npm_view(package)
        result.update({"status": "npm_checked", "package": package, "latest": view})
        if view.get("deprecated"):
            result["recommendation"] = f"replace deprecated npm package: {view['deprecated']}"
        return result
    if command == "uvx":
        if "--from" in args:
            index = args.index("--from")
            if index + 1 < len(args):
                source = args[index + 1]
                if source.startswith("git+"):
                    result.update({"status": "git_source_checked", "git": _git_url_refs(source.removeprefix("git+"))})
                    return result
        package = _uvx_package(args)
        result.update({"status": "pypi_checked", "package": package, "latest": _pypi_view(package)})
        return result
    local_node = _local_node_project(args)
    if local_node:
        result.update({"status": "local_node_checked", "local_project": local_node})
        if local_node.get("remote_error"):
            result["recommendation"] = "verify repository URL or pin a reachable upstream."
        return result
    for arg in args:
        path = Path(arg)
        if path.exists():
            repo_path = path if path.is_dir() else path.parent
            for parent in [repo_path, *repo_path.parents]:
                if (parent / ".git").exists():
                    result.update({"status": "git_checked", "git": _git_remote_head(parent)})
                    return result
    result["note"] = "No registry or git upstream recognized."
    return result


def mcp_update_audit(include_global: bool = True, include_workspace: bool = True) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    if include_workspace:
        for name, entry in sorted(_workspace_mcp_servers().items()):
            if isinstance(entry, dict):
                entries.append(_entry_audit(name, "workspace:.mcp.json", entry))
    if include_global:
        for name, entry in sorted(_codex_mcp_servers().items()):
            if isinstance(entry, dict):
                entries.append(_entry_audit(name, "global:~/.codex/config.toml", entry))

    deprecated = [item for item in entries if item.get("latest", {}).get("deprecated")]
    not_up_to_date = [
        item for item in entries
        if item.get("status") == "git_checked" and item.get("git", {}).get("up_to_date") is False
    ]
    errors = [item for item in entries if "error" in item.get("latest", {}) or "error" in item.get("git", {})]
    return {
        "workspace_root": str(REVERSE_ROOT),
        "checked_count": len(entries),
        "deprecated_count": len(deprecated),
        "git_behind_count": len(not_up_to_date),
        "error_count": len(errors),
        "entries": entries,
    }


def _report_output_path(output_path: str = "") -> Path:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    if output_path:
        resolved = Path(output_path).expanduser().resolve()
        if not str(resolved).lower().startswith(str(REPORTS_DIR.resolve()).lower()):
            raise ValueError(f"report output must be under {REPORTS_DIR}: {resolved}")
        if resolved.suffix.lower() != ".md":
            raise ValueError(f"report output must use .md suffix: {resolved}")
        resolved.parent.mkdir(parents=True, exist_ok=True)
        return resolved
    from datetime import datetime

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return REPORTS_DIR / f"mcp-update-audit-{stamp}.md"


def _entry_line(entry: dict[str, Any]) -> str:
    name = str(entry.get("name", ""))
    source = str(entry.get("source", ""))
    status = str(entry.get("status", ""))
    evidence = ""
    action = str(entry.get("recommendation", ""))
    if entry.get("latest"):
        latest = entry["latest"]
        evidence = str(latest.get("version", latest.get("error", "")))
        if latest.get("deprecated") and not action:
            action = "replace deprecated package"
    elif entry.get("git"):
        git = entry["git"]
        evidence = f"remote={git.get('remote_head', '')} tag={git.get('latest_tag', '')}".strip()
        if git.get("up_to_date") is False:
            action = "review upstream update"
    elif entry.get("local_project"):
        project = entry["local_project"]
        evidence = f"{project.get('name', '')} {project.get('version', '')}".strip()
    elif entry.get("url"):
        evidence = str(entry.get("url", ""))
    if not action:
        action = str(entry.get("note", "")) or "none"
    return f"| `{name}` | {source} | {status} | {evidence} | {action} |"


def mcp_update_report(output_path: str = "", include_global: bool = True, include_workspace: bool = True) -> dict[str, Any]:
    audit = mcp_update_audit(include_global=include_global, include_workspace=include_workspace)
    output = _report_output_path(output_path)
    lines = [
        "# MCP Update Audit",
        "",
        f"- Workspace root: `{audit['workspace_root']}`",
        f"- Checked entries: `{audit['checked_count']}`",
        f"- Deprecated packages: `{audit['deprecated_count']}`",
        f"- Git behind count: `{audit['git_behind_count']}`",
        f"- Error count: `{audit['error_count']}`",
        "",
        "| Name | Source | Status | Evidence | Action |",
        "|---|---|---|---|---|",
    ]
    lines.extend(_entry_line(entry) for entry in audit["entries"])
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return {
        "output_path": str(output),
        "audit": audit,
    }
