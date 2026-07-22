from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, unquote
from urllib.request import url2pathname


SERVER_NAME = "open_reverselab_codex"
OUTPUT_NAMESPACE = "open-reverselab"
ADAPTER_NAME = "open-reverselab-codex"
ADAPTER_SCHEMA = 1
ADAPTER_VERSION = "1.0.0"
LOCAL_RUNTIME_DIR = ".open-reverselab-local"
PROJECT_MARKER_DIR = ".open-reverselab-codex"
PROJECT_MARKER_FILE = "project.json"
PROJECT_README = "README.md"
PROJECT_QUICK_START = "QUICK_START.md"
PROJECT_TASK_TEMPLATE = "TASK_TEMPLATE.md"
PROJECT_CODEX_DIR = ".codex"
PROJECT_CODEX_CONFIG = "config.toml"
PROJECT_CODEX_MANIFEST = "open-reverselab.config.toml"
PROJECT_CODEX_CTF_CONFIG = "open-reverselab.ctf.config.toml"
PROJECT_CODEX_PROMPT = "open-reverselab.ctf_optimized.md"
GLOBAL_BLOCK_BEGIN = "[OPEN-REVERSELAB-CODEX MANAGED BLOCK BEGIN]"
GLOBAL_BLOCK_END = "[OPEN-REVERSELAB-CODEX MANAGED BLOCK END]"
PROJECT_BLOCK_BEGIN = "<!-- OPEN-REVERSELAB-CODEX MANAGED BLOCK BEGIN -->"
PROJECT_BLOCK_END = "<!-- OPEN-REVERSELAB-CODEX MANAGED BLOCK END -->"
PROJECT_CODEX_BLOCK_BEGIN = "# OPEN-REVERSELAB-CODEX PROJECT CONFIG BEGIN"
PROJECT_CODEX_BLOCK_END = "# OPEN-REVERSELAB-CODEX PROJECT CONFIG END"
MANAGED_IGNORE_HEADER = "# open-reverselab Codex managed ignore entries"
MANAGED_IGNORE_ENTRIES = [
    "/.open-reverselab-codex/",
    "/.codex/open-reverselab.config.toml",
    "/.codex/open-reverselab.ctf.config.toml",
    "/.codex/open-reverselab.ctf_optimized.md",
    "/notes/open-reverselab/",
    "/reports/open-reverselab/",
    "/exports/open-reverselab/",
    "/patches/open-reverselab/",
    "/projects/open-reverselab/",
    "/samples/open-reverselab/",
    "/cases/open-reverselab/",
]
ENABLE_CONFIRM_PREFIX = "确认启用"
DISABLE_CONFIRM_PREFIX = "确认停用"
PROJECT_CODEX_KEYS = (
    "model_instructions_file",
    "approval_policy",
    "sandbox_mode",
)
PROJECT_CODEX_PROMPT_TEXT = """# CTF Optimized Agent Prompt

你当前在一个已经接入 open-reverselab Codex 模式的项目中工作。
默认目标是授权 CTF/lab 自动化，并把产物写回当前项目。

## Working Mode

- 当前项目的 open-reverselab 接入状态由 `.open-reverselab-codex/project.json` 标记。
- 优先使用 open_reverselab_codex MCP 工具推进逆向、CTF 和样本分析。
- 产物默认写入当前项目的 `notes/open-reverselab`、`reports/open-reverselab`、`exports/open-reverselab`。
- 仅在需要时再写入 `patches/open-reverselab`、`projects/open-reverselab`、`samples/open-reverselab`、`cases/open-reverselab`。

## Unattended Loop Protocol

- 不等待人工审批；运行器层面的 approval/sandbox 配置已允许自动执行。
- 24h Web CTF 使用 `/loop + ctf-24h-round + ai_manifest.json` 模式。
- 单轮任务必须有界执行，输出 `STATUS: CONTINUE|DONE|EXHAUSTED`。
- `cases/<case>/ai_manifest.json` 是恢复点；中断后读取它继续，不从头开始。
- 每发现信号先读 `kb/ctf-website/techniques/attack-network.md`，再用 `scripts/ctf-website/kb_router.py "<signal>"` 路由技术文档。
- 非 Python allowlist 动作标记为 `agent_required`，由下一轮 Agent 自动处理，不交给人。

## Evidence

- 原始请求/响应、截图、flag 和日志只写入当前项目内的 case/export/report 目录。
- 不把真实目标、凭据、Cookie、token、flag 或个人路径提交到公开仓库。
"""


@dataclass(frozen=True)
class AdapterPaths:
    repo_root: Path
    local_root: Path
    python_root: Path
    state_root: Path
    backups_root: Path
    batch_root: Path
    reports_root: Path
    docs_root: Path
    global_codex_root: Path
    global_codex_config: Path
    workspace_codex_config: Path
    registry_file: Path
    runtime_state_file: Path
    install_report: Path
    verify_report: Path
    backup_report: Path
    restore_report: Path
    start_report: Path
    menu_report: Path
    local_manifest: Path


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_now_iso() -> str:
    return utc_now().isoformat().replace("+00:00", "Z")


def version_key(value: str) -> tuple[int, ...]:
    parts = [int(item) for item in re.findall(r"\d+", value or "0")]
    return tuple(parts or [0])


def adapter_identity(mode: str = "standard_active") -> dict[str, Any]:
    return {
        "name": ADAPTER_NAME,
        "schema": ADAPTER_SCHEMA,
        "version": ADAPTER_VERSION,
        "mode": mode,
    }


def repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def adapter_paths() -> AdapterPaths:
    root = repo_root()
    local_root = root / LOCAL_RUNTIME_DIR
    state_root = local_root / "state"
    reports_root = local_root / "reports"
    docs_root = root / "docs" / "codex"
    python_root = root / "scripts" / "codex" / "python"
    global_codex_root = Path.home() / ".codex"
    return AdapterPaths(
        repo_root=root,
        local_root=local_root,
        python_root=python_root,
        state_root=state_root,
        backups_root=local_root / "backups",
        batch_root=local_root / "upgrade-batches",
        reports_root=reports_root,
        docs_root=docs_root,
        global_codex_root=global_codex_root,
        global_codex_config=global_codex_root / "config.toml",
        workspace_codex_config=root / ".codex" / "config.toml",
        registry_file=state_root / "project_registry.json",
        runtime_state_file=state_root / "adapter_state.json",
        install_report=reports_root / "codex-install-report.json",
        verify_report=reports_root / "codex-verify-report.json",
        backup_report=reports_root / "codex-backup-report.json",
        restore_report=reports_root / "codex-restore-report.json",
        start_report=reports_root / "codex-start-report.json",
        menu_report=reports_root / "codex-menu-report.json",
        local_manifest=state_root / "manifest.json",
    )


def ensure_layout(paths: AdapterPaths | None = None) -> AdapterPaths:
    paths = paths or adapter_paths()
    for target in (
        paths.local_root,
        paths.state_root,
        paths.backups_root,
        paths.batch_root,
        paths.reports_root,
        paths.docs_root,
    ):
        target.mkdir(parents=True, exist_ok=True)
    return paths


def slug(text: str) -> str:
    value = "".join(ch if ch.isalnum() or ch in "._-" else "-" for ch in text.strip())
    value = re.sub(r"-{2,}", "-", value).strip(".-")
    return value or "default"


def sanitize_component(path: Path) -> str:
    raw = str(path).replace(":", "").replace("\\", "_").replace("/", "_")
    return slug(raw)


def read_text(path: Path, default: str = "") -> str:
    if not path.exists():
        return default
    return path.read_text(encoding="utf-8")


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")


def read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, payload: Any) -> None:
    write_text(path, json.dumps(payload, ensure_ascii=False, indent=2) + "\n")


def detect_python() -> str | None:
    for name in ("python", "py"):
        found = shutil.which(name)
        if found:
            return found
    return None


def detect_uv() -> str | None:
    return shutil.which("uv")


def wrapper_script_path() -> Path:
    return adapter_paths().python_root / "open_reverselab_codex_mcp.py"


def manager_script_path() -> Path:
    return adapter_paths().python_root / "open_reverselab_codex_manager.py"


def upstream_project_dir(paths: AdapterPaths | None = None) -> Path:
    paths = paths or adapter_paths()
    return paths.repo_root / "tools" / "skills" / "mcp" / "ReverseLabToolsMCP"


def upstream_module_dir(paths: AdapterPaths | None = None) -> Path:
    return upstream_project_dir(paths)


def desired_server_config(paths: AdapterPaths | None = None, uv_path: str | None = None) -> dict[str, Any]:
    paths = paths or adapter_paths()
    uv_path = uv_path or detect_uv() or "uv"
    wrapper = wrapper_script_path()
    project_dir = upstream_project_dir(paths)
    return {
        "name": SERVER_NAME,
        "command": uv_path,
        "args": [
            "run",
            "--project",
            str(project_dir),
            "python",
            str(wrapper),
        ],
        "env": {
            "OPEN_REVERSELAB_CODEX_REPO_ROOT": str(paths.repo_root),
        },
    }


def toml_basic_string(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def desired_server_block(paths: AdapterPaths | None = None, uv_path: str | None = None) -> str:
    server = desired_server_config(paths, uv_path)
    lines = [
        f"[mcp_servers.{SERVER_NAME}]",
        f"command = {toml_basic_string(server['command'])}",
        "args = [",
    ]
    for arg in server["args"]:
        lines.append(f"  {toml_basic_string(arg)},")
    lines.append("]")
    lines.append("")
    lines.append(f"[mcp_servers.{SERVER_NAME}.env]")
    for key in sorted(server["env"]):
        lines.append(f"{toml_basic_string(key)} = {toml_basic_string(server['env'][key])}")
    return "\n".join(lines).rstrip() + "\n"


@dataclass
class McpSection:
    dotted_name: str
    start: int
    end: int
    text: str


def find_table_sections(text: str) -> list[McpSection]:
    matches = list(re.finditer(r"(?m)^\[(?P<name>[^\]]+)\]\s*$", text))
    sections: list[McpSection] = []
    for index, match in enumerate(matches):
        start = match.start()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        sections.append(
            McpSection(
                dotted_name=match.group("name").strip(),
                start=start,
                end=end,
                text=text[start:end],
            )
        )
    return sections


def remove_mcp_server_sections(text: str, server_name: str) -> str:
    sections = find_table_sections(text)
    spans: list[tuple[int, int]] = []
    for section in sections:
        if section.dotted_name == f"mcp_servers.{server_name}" or section.dotted_name.startswith(
            f"mcp_servers.{server_name}."
        ):
            spans.append((section.start, section.end))
    if not spans:
        return text
    parts: list[str] = []
    cursor = 0
    for start, end in spans:
        parts.append(text[cursor:start])
        cursor = end
    parts.append(text[cursor:])
    result = "".join(parts)
    return result.strip() + "\n"


def find_related_mcp_sections(text: str, paths: AdapterPaths | None = None) -> list[dict[str, Any]]:
    paths = paths or adapter_paths()
    repo_marker = str(paths.repo_root).lower()
    old_markers = [
        repo_marker,
        "reverse_lab_tools_mcp.py",
        "start_codex.bat",
        "install_codex_mcp.bat",
        str(wrapper_script_path()).lower(),
    ]
    matches: list[dict[str, Any]] = []
    for section in find_table_sections(text):
        if not section.dotted_name.startswith("mcp_servers."):
            continue
        lowered = section.text.lower()
        if any(marker in lowered for marker in old_markers):
            matches.append(
                {
                    "name": section.dotted_name.split(".", 1)[1],
                    "header": section.dotted_name,
                    "text": section.text.strip(),
                }
            )
    return matches


def find_assignment_span(text: str, key: str) -> tuple[int, int, str] | None:
    pattern = re.compile(
        rf'(?ms)^(?P<prefix>\s*{re.escape(key)}\s*=\s*)(?P<quote>"""|\'\'\')(?P<body>.*?)(?P=quote)\s*$'
    )
    match = pattern.search(text)
    if not match:
        return None
    return match.start(), match.end(), match.group("body")


def developer_instruction_block() -> str:
    return "\n".join(
        [
            GLOBAL_BLOCK_BEGIN,
            "This block is idle by default.",
            "Only react when the user says one of these exact phrases:",
            "- 启用 open-reverselab Codex 模式",
            "- enable open-reverselab codex mode",
            "- 停用 open-reverselab Codex 模式",
            "- disable open-reverselab codex mode",
            "- 查看 open-reverselab Codex 状态",
            "- show open-reverselab codex status",
            "",
            "When the enable phrase appears:",
            "- Call the MCP tool codex_enable_project_mode from the open_reverselab_codex server.",
            "- If the current workspace already contains .open-reverselab-codex/project.json, treat the project as already bound.",
            "- If codex_enable_project_mode returns requires_confirmation=true, ask the user to type the exact confirmation text and then call the same tool again with confirm_text.",
            "",
            "When the disable phrase appears:",
            "- Call the MCP tool codex_disable_project_mode from the open_reverselab_codex server.",
            "- If codex_disable_project_mode returns requires_confirmation=true, ask the user to type the exact confirmation text and then call the same tool again with confirm_text.",
            "",
            "When the status phrase appears:",
            "- Call the MCP tool codex_project_mode_status from the open_reverselab_codex server.",
            "",
            "When the current project is bound to open-reverselab Codex mode:",
            "- Prefer tools from the open_reverselab_codex MCP server for reverse engineering, CTF, and analysis automation.",
            "- Keep project outputs inside the current project, not inside the open-reverselab repo.",
            "- Write notes under notes/open-reverselab, reports under reports/open-reverselab, and exports under exports/open-reverselab.",
            "- Create patches/projects/samples/cases under their open-reverselab namespaced subdirectories only when needed.",
            GLOBAL_BLOCK_END,
        ]
    ).strip()


def upsert_developer_instructions(text: str, block: str | None = None) -> str:
    block = block or developer_instruction_block()
    assignment = find_assignment_span(text, "developer_instructions")
    if assignment is not None:
        start, end, body = assignment
        if GLOBAL_BLOCK_BEGIN in body and GLOBAL_BLOCK_END in body:
            updated_body = re.sub(
                rf"{re.escape(GLOBAL_BLOCK_BEGIN)}.*?{re.escape(GLOBAL_BLOCK_END)}",
                block,
                body,
                flags=re.S,
            )
        else:
            updated_body = body.rstrip() + "\n\n" + block + "\n"
        replacement = f'developer_instructions = """\n{updated_body.rstrip()}\n"""'
        return text[:start] + replacement + text[end:]

    header_match = re.search(r"(?m)^\[", text)
    insert_at = header_match.start() if header_match else len(text)
    insertion = f'developer_instructions = """\n{block}\n"""\n\n'
    return text[:insert_at] + insertion + text[insert_at:]


def remove_developer_instruction_block(text: str) -> str:
    assignment = find_assignment_span(text, "developer_instructions")
    if assignment is None:
        return text
    start, end, body = assignment
    if GLOBAL_BLOCK_BEGIN not in body or GLOBAL_BLOCK_END not in body:
        return text
    updated_body = re.sub(
        rf"\n?{re.escape(GLOBAL_BLOCK_BEGIN)}.*?{re.escape(GLOBAL_BLOCK_END)}\n?",
        "\n",
        body,
        flags=re.S,
    ).strip()
    if updated_body:
        replacement = f'developer_instructions = """\n{updated_body}\n"""'
        return text[:start] + replacement + text[end:]
    prefix = text[:start]
    suffix = text[end:]
    merged = prefix.rstrip() + "\n" + suffix.lstrip()
    return merged


def ensure_global_server_and_instructions(text: str, paths: AdapterPaths | None = None, uv_path: str | None = None) -> str:
    text = remove_mcp_server_sections(text, SERVER_NAME)
    text = upsert_developer_instructions(text)
    block = desired_server_block(paths, uv_path)
    stripped = text.rstrip() + "\n\n" + block
    return stripped.rstrip() + "\n"


def remove_global_server_and_instructions(text: str) -> str:
    text = remove_mcp_server_sections(text, SERVER_NAME)
    text = remove_developer_instruction_block(text)
    return text.rstrip() + "\n"


def current_global_status(paths: AdapterPaths | None = None) -> dict[str, Any]:
    paths = paths or adapter_paths()
    config_text = read_text(paths.global_codex_config)
    related = find_related_mcp_sections(config_text, paths)
    desired = desired_server_config(paths)
    return {
        "global_config": str(paths.global_codex_config),
        "config_exists": paths.global_codex_config.exists(),
        "workspace_codex_config_exists": paths.workspace_codex_config.exists(),
        "related_mcp_sections": related,
        "desired_server": desired,
        "developer_block_present": GLOBAL_BLOCK_BEGIN in config_text and GLOBAL_BLOCK_END in config_text,
        "server_block_present": f"[mcp_servers.{SERVER_NAME}]" in config_text,
    }


def file_snapshot(target: Path) -> dict[str, Any]:
    if not target.exists():
        return {"path": str(target), "exists": False, "is_dir": False}
    return {
        "path": str(target),
        "exists": True,
        "is_dir": target.is_dir(),
        "size": target.stat().st_size if target.is_file() else None,
    }


def copy_path_for_backup(source: Path, destination: Path) -> None:
    if source.is_dir():
        if destination.exists():
            shutil.rmtree(destination)
        shutil.copytree(source, destination)
    else:
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)


def trim_backups(paths: AdapterPaths | None = None, keep: int = 10) -> None:
    paths = paths or adapter_paths()
    backups = sorted((item for item in paths.backups_root.iterdir() if item.is_dir()), key=lambda item: item.name, reverse=True)
    for stale in backups[keep:]:
        shutil.rmtree(stale, ignore_errors=True)


def create_backup(
    action: str,
    paths: AdapterPaths | None = None,
    target_project_root: Path | None = None,
    extra_files: list[Path] | None = None,
    include_global_state: bool = True,
) -> dict[str, Any]:
    paths = ensure_layout(paths)
    timestamp = utc_now().strftime("%Y%m%d-%H%M%S-%f")
    backup_id = f"{timestamp}-{slug(action)}"
    backup_root = paths.backups_root / backup_id
    files_root = backup_root / "files"
    manifest = {
        "schema": 1,
        "backup_id": backup_id,
        "action": action,
        "created_at": utc_now_iso(),
        "repo_root": str(paths.repo_root),
        "target_project_root": str(target_project_root) if target_project_root else "",
        "entries": [],
    }
    tracked: list[Path] = []
    if include_global_state:
        tracked.extend(
            [
                paths.global_codex_config,
                paths.registry_file,
                paths.runtime_state_file,
                paths.local_manifest,
            ]
        )
    if target_project_root:
        project_codex = project_codex_paths(target_project_root)
        tracked.extend(
            [
                target_project_root / "AGENTS.md",
                target_project_root / ".gitignore",
                target_project_root / PROJECT_MARKER_DIR,
                project_codex["config"],
                project_codex["manifest"],
                project_codex["ctf_config"],
                project_codex["prompt"],
            ]
        )
    if extra_files:
        tracked.extend(extra_files)

    seen: set[str] = set()
    for item in tracked:
        key = str(item.resolve()) if item.exists() else str(item)
        if key in seen:
            continue
        seen.add(key)
        entry = {
            "path": str(item),
            "exists": item.exists(),
            "is_dir": item.is_dir() if item.exists() else False,
        }
        if item.exists():
            rel_name = sanitize_component(item)
            destination = files_root / rel_name
            copy_path_for_backup(item, destination)
            entry["backup_path"] = str(destination)
        manifest["entries"].append(entry)

    write_json(backup_root / "manifest.json", manifest)
    trim_backups(paths)
    return manifest


def list_backups(paths: AdapterPaths | None = None) -> list[dict[str, Any]]:
    paths = ensure_layout(paths)
    manifests: list[dict[str, Any]] = []
    for folder in sorted((item for item in paths.backups_root.iterdir() if item.is_dir()), key=lambda item: item.name, reverse=True):
        manifest_path = folder / "manifest.json"
        if manifest_path.exists():
            manifests.append(read_json(manifest_path, {}))
    return manifests


def restore_backup(backup_id: str, paths: AdapterPaths | None = None) -> dict[str, Any]:
    paths = ensure_layout(paths)
    backup_root = paths.backups_root / backup_id
    manifest_path = backup_root / "manifest.json"
    if not manifest_path.exists():
        raise FileNotFoundError(f"backup not found: {backup_id}")

    manifest = read_json(manifest_path, {})
    restore_manifest = create_backup(f"pre-restore-{backup_id}", paths=paths)
    restored: list[dict[str, Any]] = []
    for entry in manifest.get("entries", []):
        target = Path(entry["path"])
        exists = entry.get("exists", False)
        backup_path = entry.get("backup_path", "")
        if exists and backup_path:
            source = Path(backup_path)
            if target.exists():
                if target.is_dir():
                    shutil.rmtree(target, ignore_errors=True)
                else:
                    target.unlink()
            copy_path_for_backup(source, target)
            restored.append({"path": str(target), "action": "restored"})
        elif not exists and target.exists():
            if target.is_dir():
                shutil.rmtree(target, ignore_errors=True)
            else:
                target.unlink()
            restored.append({"path": str(target), "action": "removed"})

    payload = {
        "schema": 1,
        "backup_id": backup_id,
        "restored_at": utc_now_iso(),
        "pre_restore_backup": restore_manifest["backup_id"],
        "restored": restored,
    }
    write_json(paths.restore_report, payload)
    return payload


def list_upgrade_batches(paths: AdapterPaths | None = None) -> list[dict[str, Any]]:
    paths = ensure_layout(paths)
    manifests: list[dict[str, Any]] = []
    for manifest_path in sorted(paths.batch_root.glob("*.json"), reverse=True):
        manifests.append(read_json(manifest_path, {}))
    return manifests


def write_upgrade_batch_manifest(
    project_results: list[dict[str, Any]],
    global_backup_id: str = "",
    paths: AdapterPaths | None = None,
) -> dict[str, Any]:
    paths = ensure_layout(paths)
    batch_id = f"{utc_now().strftime('%Y%m%d-%H%M%S-%f')}-upgrade-batch"
    summary = {
        "upgraded": sum(1 for item in project_results if item.get("result") == "upgraded"),
        "already_current": sum(1 for item in project_results if item.get("result") == "already_current"),
        "offline_missing": sum(1 for item in project_results if item.get("result") == "offline_missing"),
        "upgrade_failed": sum(1 for item in project_results if item.get("result") == "upgrade_failed"),
        "marker_missing": sum(1 for item in project_results if item.get("result") == "marker_missing"),
    }
    payload = {
        "schema": 1,
        "adapter_schema": ADAPTER_SCHEMA,
        "adapter_version": ADAPTER_VERSION,
        "batch_id": batch_id,
        "created_at": utc_now_iso(),
        "global_backup_id": global_backup_id,
        "summary": summary,
        "projects": project_results,
    }
    write_json(paths.batch_root / f"{batch_id}.json", payload)
    return payload


def restore_upgrade_batch_project(batch_id: str, project_id: str, paths: AdapterPaths | None = None) -> dict[str, Any]:
    paths = ensure_layout(paths)
    batch = read_json(paths.batch_root / f"{batch_id}.json", {})
    if not batch:
        raise FileNotFoundError(f"upgrade batch not found: {batch_id}")
    for project in batch.get("projects", []):
        if project.get("project_id") == project_id:
            backup_id = project.get("backup_id", "")
            if not backup_id:
                raise FileNotFoundError(f"project backup not found in batch: {project_id}")
            restored = restore_backup(backup_id, paths)
            restored["batch_id"] = batch_id
            restored["project_id"] = project_id
            return restored
    raise FileNotFoundError(f"project not found in upgrade batch: {project_id}")


def default_registry() -> dict[str, Any]:
    return {
        "schema": 1,
        "adapter_schema": ADAPTER_SCHEMA,
        "adapter_version": ADAPTER_VERSION,
        "updated_at": "",
        "projects": {},
    }


def load_registry(paths: AdapterPaths | None = None) -> dict[str, Any]:
    paths = ensure_layout(paths)
    registry = read_json(paths.registry_file, default_registry())
    if not registry:
        registry = default_registry()
    registry.setdefault("schema", 1)
    registry.setdefault("adapter_schema", ADAPTER_SCHEMA)
    registry.setdefault("adapter_version", ADAPTER_VERSION)
    registry.setdefault("projects", {})
    registry.setdefault("updated_at", "")
    return registry


def save_registry(registry: dict[str, Any], paths: AdapterPaths | None = None) -> None:
    paths = ensure_layout(paths)
    registry["adapter_schema"] = ADAPTER_SCHEMA
    registry["adapter_version"] = ADAPTER_VERSION
    registry["updated_at"] = utc_now_iso()
    write_json(paths.registry_file, registry)


def project_marker_root(project_root: Path) -> Path:
    return project_root / PROJECT_MARKER_DIR


def project_marker_path(project_root: Path) -> Path:
    return project_marker_root(project_root) / PROJECT_MARKER_FILE


def namespaced_data_roots(project_root: Path) -> dict[str, Path]:
    return {
        "marker_root": project_marker_root(project_root),
        "notes_root": project_root / "notes" / OUTPUT_NAMESPACE,
        "reports_root": project_root / "reports" / OUTPUT_NAMESPACE,
        "exports_root": project_root / "exports" / OUTPUT_NAMESPACE,
        "patches_root": project_root / "patches" / OUTPUT_NAMESPACE,
        "projects_root": project_root / "projects" / OUTPUT_NAMESPACE,
        "samples_root": project_root / "samples" / OUTPUT_NAMESPACE,
        "cases_root": project_root / "cases" / OUTPUT_NAMESPACE,
    }


def project_codex_paths(project_root: Path) -> dict[str, Path]:
    codex_root = project_root / PROJECT_CODEX_DIR
    return {
        "root": codex_root,
        "config": codex_root / PROJECT_CODEX_CONFIG,
        "manifest": codex_root / PROJECT_CODEX_MANIFEST,
        "ctf_config": codex_root / PROJECT_CODEX_CTF_CONFIG,
        "prompt": codex_root / PROJECT_CODEX_PROMPT,
    }


def project_codex_manifest_text(project_root: Path) -> str:
    return "\n".join(
        [
            "# open-reverselab Codex project manifest",
            "#",
            "# This file is generated for documentation and recovery.",
            "# Codex does not currently support include/import/extends for project config.toml,",
            "# so the active runtime keys are mirrored into .codex/config.toml as a managed block.",
            f'project_root = {toml_basic_string(str(project_root))}',
            f'output_namespace = {toml_basic_string(OUTPUT_NAMESPACE)}',
            f'prompt_file = {toml_basic_string(PROJECT_CODEX_PROMPT)}',
            f'ctf_config_file = {toml_basic_string(PROJECT_CODEX_CTF_CONFIG)}',
        ]
    ) + "\n"


def project_codex_ctf_config_text() -> str:
    return "\n".join(
        [
            "# open-reverselab Codex CTF runtime template",
            f'model_instructions_file = {toml_basic_string(PROJECT_CODEX_PROMPT)}',
            'approval_policy = "never"',
            'sandbox_mode = "danger-full-access"',
            "",
        ]
    )


def project_codex_managed_block() -> str:
    return "\n".join(
        [
            PROJECT_CODEX_BLOCK_BEGIN,
            "# Managed by open-reverselab CODEX.bat / LAUNCHER.bat",
            "# Source reference: .codex/open-reverselab.ctf.config.toml",
            f'model_instructions_file = {toml_basic_string(PROJECT_CODEX_PROMPT)}',
            'approval_policy = "never"',
            'sandbox_mode = "danger-full-access"',
            PROJECT_CODEX_BLOCK_END,
        ]
    ).strip()


def strip_project_codex_block(text: str) -> str:
    if PROJECT_CODEX_BLOCK_BEGIN not in text or PROJECT_CODEX_BLOCK_END not in text:
        return text
    updated = re.sub(
        rf"\n?{re.escape(PROJECT_CODEX_BLOCK_BEGIN)}.*?{re.escape(PROJECT_CODEX_BLOCK_END)}\n?",
        "\n",
        text,
        flags=re.S,
    )
    return updated.strip() + ("\n" if updated.strip() else "")


def capture_project_codex_restore_state(text: str) -> dict[str, str]:
    cleaned = strip_project_codex_block(text)
    restored: dict[str, str] = {}
    for key in PROJECT_CODEX_KEYS:
        match = re.search(rf"(?m)^\s*{re.escape(key)}\s*=.*$", cleaned)
        if match:
            restored[key] = match.group(0).strip()
    return restored


def remove_project_codex_key_lines(text: str) -> str:
    cleaned = strip_project_codex_block(text)
    for key in PROJECT_CODEX_KEYS:
        cleaned = re.sub(rf"(?m)^\s*{re.escape(key)}\s*=.*\n?", "", cleaned)
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned).strip()
    return cleaned + ("\n" if cleaned else "")


def ensure_project_codex_runtime(project_root: Path, restore_state: dict[str, str] | None = None) -> dict[str, Any]:
    codex = project_codex_paths(project_root)
    codex["root"].mkdir(parents=True, exist_ok=True)
    existing_config = read_text(codex["config"])
    preserved = dict(restore_state or capture_project_codex_restore_state(existing_config))
    base = remove_project_codex_key_lines(existing_config)
    block = project_codex_managed_block()
    updated = (base.rstrip() + "\n\n" if base.strip() else "") + block + "\n"
    write_text(codex["config"], updated)
    write_text(codex["manifest"], project_codex_manifest_text(project_root))
    write_text(codex["ctf_config"], project_codex_ctf_config_text())
    write_text(codex["prompt"], PROJECT_CODEX_PROMPT_TEXT)
    return {
        "updated": True,
        "paths": {name: str(path) for name, path in codex.items()},
        "restore_state": preserved,
    }


def disable_project_codex_runtime(project_root: Path, restore_state: dict[str, str] | None = None) -> dict[str, Any]:
    codex = project_codex_paths(project_root)
    codex["root"].mkdir(parents=True, exist_ok=True)
    existing_config = read_text(codex["config"])
    base = remove_project_codex_key_lines(existing_config)
    restored_lines = [restore_state.get(key, "").strip() for key in PROJECT_CODEX_KEYS] if restore_state else []
    restored_lines = [line for line in restored_lines if line]
    updated = base.rstrip()
    if restored_lines:
        updated = (updated + "\n\n" if updated else "") + "\n".join(restored_lines)
    if updated:
        updated += "\n"
    else:
        updated = "# open-reverselab Codex runtime files are retained after disable.\n"
    write_text(codex["config"], updated)
    if not codex["manifest"].exists():
        write_text(codex["manifest"], project_codex_manifest_text(project_root))
    if not codex["ctf_config"].exists():
        write_text(codex["ctf_config"], project_codex_ctf_config_text())
    if not codex["prompt"].exists():
        write_text(codex["prompt"], PROJECT_CODEX_PROMPT_TEXT)
    return {
        "updated": True,
        "paths": {name: str(path) for name, path in codex.items()},
    }


def confirm_text(project_root: Path, action: str) -> str:
    name = project_root.name.strip() or "当前项目"
    prefix = ENABLE_CONFIRM_PREFIX if action == "enable" else DISABLE_CONFIRM_PREFIX
    return f"{prefix} {name} open-reverselab Codex 模式"


def project_doc_readme(project_root: Path) -> str:
    return "\n".join(
        [
            "# open-reverselab Codex 接入说明",
            "",
            "这个目录由 open-reverselab 的 Codex 适配层生成。",
            "",
            "用途：",
            "- 标记当前项目已经接入 open-reverselab Codex 模式。",
            "- 保存当前项目的接入元数据和快速说明。",
            "- 帮助后续会话继续把分析产物写回当前项目，而不是写回 open-reverselab 仓库。",
            "",
            "重要说明：",
            "- 这里不是原版 open-reverselab 的 upstream 文件。",
            "- 删除这个目录会导致项目接入状态丢失，可以通过 CODEX.bat 重新修复。",
            "- 项目级 Codex 运行层位于 .codex/ 目录，停用时默认保留这些文件。",
            "- 分析产物默认写入 notes/open-reverselab、reports/open-reverselab、exports/open-reverselab。",
            "",
        ]
    ) + "\n"


def project_doc_quick_start(project_root: Path) -> str:
    return "\n".join(
        [
            "# QUICK START",
            "",
            "当前项目已经接入 open-reverselab Codex 模式。",
            "",
            "常用会话短语：",
            "- 启用 open-reverselab Codex 模式",
            "- 查看 open-reverselab Codex 状态",
            "- 停用 open-reverselab Codex 模式",
            "",
            "常用产物目录：",
            "- notes/open-reverselab",
            "- reports/open-reverselab",
            "- exports/open-reverselab",
            "",
            "项目级运行层：",
            "- .codex/config.toml",
            "- .codex/open-reverselab.config.toml",
            "- .codex/open-reverselab.ctf.config.toml",
            "- .codex/open-reverselab.ctf_optimized.md",
            "",
            "如果 Codex 没识别到当前接入状态：",
            "- 先说“查看 open-reverselab Codex 状态”",
            "- 如果状态异常，再用 CODEX.bat 的项目修复功能",
            "",
        ]
    ) + "\n"


def project_doc_task_template(project_root: Path) -> str:
    return "\n".join(
        [
            "# TASK TEMPLATE",
            "",
            "参考模板：",
            "",
            "```text",
            "启用 open-reverselab Codex 模式",
            "这是我的 CTF / 逆向 / 样本分析任务。",
            "目标范围是授权的实验环境或竞赛沙箱。",
            "请优先使用 open_reverselab_codex MCP 工具推进，并把产物写到当前项目的 namespaced 目录。",
            "```",
            "",
        ]
    ) + "\n"


def project_agents_block(project_root: Path, project_id: str) -> str:
    return "\n".join(
        [
            PROJECT_BLOCK_BEGIN,
            "## open-reverselab Codex 接入",
            "",
            f"- project_id: `{project_id}`",
            "- 这个受管块由 open-reverselab 的 Codex 适配层写入。",
            "- 当前项目已接入 open_reverselab_codex MCP。",
            "- 分析产物写入当前项目，而不是写回 open-reverselab 仓库。",
            "- 项目级运行层写入 `.codex/`，并在 `.codex/config.toml` 中插入受管块。",
            "- 默认产物目录：`notes/open-reverselab/`、`reports/open-reverselab/`、`exports/open-reverselab/`。",
            "- 启用短语：`启用 open-reverselab Codex 模式` / `enable open-reverselab codex mode`。",
            "- 停用短语：`停用 open-reverselab Codex 模式` / `disable open-reverselab codex mode`。",
            "- 状态短语：`查看 open-reverselab Codex 状态` / `show open-reverselab codex status`。",
            PROJECT_BLOCK_END,
        ]
    ).strip()


def ensure_gitignore_block(project_root: Path) -> dict[str, Any]:
    if not (project_root / ".git").exists():
        return {"updated": False, "reason": "not-a-git-project", "path": str(project_root / ".gitignore")}

    gitignore = project_root / ".gitignore"
    existing = read_text(gitignore)
    block = MANAGED_IGNORE_HEADER + "\n" + "\n".join(MANAGED_IGNORE_ENTRIES)
    if MANAGED_IGNORE_HEADER in existing:
        updated = re.sub(
            rf"{re.escape(MANAGED_IGNORE_HEADER)}.*?(?=\n\n|\Z)",
            block,
            existing,
            flags=re.S,
        ).rstrip() + "\n"
    else:
        updated = existing.rstrip()
        if updated:
            updated += "\n\n"
        updated += block + "\n"
    write_text(gitignore, updated)
    return {"updated": True, "path": str(gitignore)}


def remove_gitignore_block(project_root: Path) -> dict[str, Any]:
    gitignore = project_root / ".gitignore"
    if not gitignore.exists():
        return {"updated": False, "path": str(gitignore)}
    existing = read_text(gitignore)
    if MANAGED_IGNORE_HEADER not in existing:
        return {"updated": False, "path": str(gitignore)}
    updated = re.sub(
        rf"\n?{re.escape(MANAGED_IGNORE_HEADER)}.*?(?=\n\n|\Z)",
        "",
        existing,
        flags=re.S,
    ).strip()
    if updated:
        write_text(gitignore, updated + "\n")
    else:
        gitignore.unlink()
    return {"updated": True, "path": str(gitignore)}


def ensure_agents_block(project_root: Path, project_id: str) -> dict[str, Any]:
    agents = project_root / "AGENTS.md"
    block = project_agents_block(project_root, project_id)
    existing = read_text(agents)
    if existing:
        if PROJECT_BLOCK_BEGIN in existing and PROJECT_BLOCK_END in existing:
            updated = re.sub(
                rf"{re.escape(PROJECT_BLOCK_BEGIN)}.*?{re.escape(PROJECT_BLOCK_END)}",
                block,
                existing,
                flags=re.S,
            )
        else:
            updated = existing.rstrip() + "\n\n" + block + "\n"
    else:
        updated = "# AGENTS\n\n本文件包含当前项目的本地协作说明。\n\n" + block + "\n"
    write_text(agents, updated)
    return {"updated": True, "path": str(agents)}


def remove_agents_block(project_root: Path) -> dict[str, Any]:
    agents = project_root / "AGENTS.md"
    if not agents.exists():
        return {"updated": False, "path": str(agents)}
    existing = read_text(agents)
    if PROJECT_BLOCK_BEGIN not in existing or PROJECT_BLOCK_END not in existing:
        return {"updated": False, "path": str(agents)}
    updated = re.sub(
        rf"\n?{re.escape(PROJECT_BLOCK_BEGIN)}.*?{re.escape(PROJECT_BLOCK_END)}\n?",
        "\n",
        existing,
        flags=re.S,
    ).strip()
    if updated:
        write_text(agents, updated + "\n")
    else:
        agents.unlink()
    return {"updated": True, "path": str(agents)}


def normalize_project_root(project_root: str | Path) -> Path:
    root = Path(project_root).expanduser().resolve()
    if not root.exists():
        raise FileNotFoundError(f"project path does not exist: {root}")
    if not root.is_dir():
        raise NotADirectoryError(f"project path is not a directory: {root}")
    return root


def project_adapter_metadata(marker_data: dict[str, Any]) -> dict[str, Any]:
    adapter = marker_data.get("adapter")
    if isinstance(adapter, dict):
        return {
            "name": adapter.get("name") or ADAPTER_NAME,
            "schema": int(adapter.get("schema") or 0),
            "version": str(adapter.get("version") or "0"),
            "mode": adapter.get("mode") or "standard_active",
        }
    return {
        "name": ADAPTER_NAME,
        "schema": int(marker_data.get("adapter_schema") or 0),
        "version": str(marker_data.get("adapter_version") or "0"),
        "mode": str(marker_data.get("project_mode") or "standard_active"),
    }


def project_requires_upgrade(marker_data: dict[str, Any]) -> bool:
    adapter = project_adapter_metadata(marker_data)
    return (
        adapter["schema"] < ADAPTER_SCHEMA
        or version_key(adapter["version"]) < version_key(ADAPTER_VERSION)
    )


def project_state(project_root: Path, paths: AdapterPaths | None = None) -> dict[str, Any]:
    paths = ensure_layout(paths)
    registry = load_registry(paths)
    marker = project_marker_path(project_root)
    marker_data = read_json(marker, {})
    data_roots = namespaced_data_roots(project_root)
    codex_paths = project_codex_paths(project_root)
    codex_config_text = read_text(codex_paths["config"])
    project_id = marker_data.get("project_id", "")
    adapter = project_adapter_metadata(marker_data)
    registry_entry = registry["projects"].get(project_id, {}) if project_id else {}
    healthy = bool(marker.exists())
    if marker.exists():
        for key in ("notes_root", "reports_root", "exports_root"):
            if not data_roots[key].exists():
                healthy = False
        for key in ("config", "manifest", "ctf_config", "prompt"):
            if not codex_paths[key].exists():
                healthy = False
    if (project_root / "AGENTS.md").exists():
        healthy = healthy and PROJECT_BLOCK_BEGIN in read_text(project_root / "AGENTS.md")
    healthy = healthy and PROJECT_CODEX_BLOCK_BEGIN in codex_config_text and PROJECT_CODEX_BLOCK_END in codex_config_text
    return {
        "project_root": str(project_root),
        "project_id": project_id,
        "bound": marker.exists(),
        "healthy": healthy,
        "project_mode": adapter["mode"],
        "adapter_name": adapter["name"],
        "adapter_schema": adapter["schema"],
        "adapter_version": adapter["version"],
        "upgrade_needed": bool(marker.exists()) and project_requires_upgrade(marker_data),
        "marker_path": str(marker),
        "registry_entry": registry_entry,
        "paths": {name: str(path) for name, path in data_roots.items()},
        "codex_paths": {name: str(path) for name, path in codex_paths.items()},
        "has_agents_block": PROJECT_BLOCK_BEGIN in read_text(project_root / "AGENTS.md"),
        "has_gitignore_block": MANAGED_IGNORE_HEADER in read_text(project_root / ".gitignore"),
        "has_project_codex_block": PROJECT_CODEX_BLOCK_BEGIN in codex_config_text and PROJECT_CODEX_BLOCK_END in codex_config_text,
    }


def build_project_plan(project_root: Path, action: str, paths: AdapterPaths | None = None) -> dict[str, Any]:
    paths = ensure_layout(paths)
    state = project_state(project_root, paths)
    data_roots = namespaced_data_roots(project_root)
    codex_paths = project_codex_paths(project_root)
    project_id = state["project_id"] or str(uuid.uuid4())
    actions: list[str] = []
    if action in {"enable", "repair"}:
        if not project_marker_root(project_root).exists():
            actions.append(f"创建目录 {project_marker_root(project_root)}")
        if not codex_paths["root"].exists():
            actions.append(f"创建目录 {codex_paths['root']}")
        for key in ("notes_root", "reports_root", "exports_root"):
            if not data_roots[key].exists():
                actions.append(f"创建目录 {data_roots[key]}")
        if not state["has_agents_block"]:
            actions.append(f"更新 {project_root / 'AGENTS.md'}")
        if (project_root / ".git").exists() and not state["has_gitignore_block"]:
            actions.append(f"更新 {project_root / '.gitignore'}")
        actions.extend(
            [
                f"写入 {project_marker_root(project_root) / PROJECT_MARKER_FILE}",
                f"写入 {project_marker_root(project_root) / PROJECT_README}",
                f"写入 {project_marker_root(project_root) / PROJECT_QUICK_START}",
                f"写入 {project_marker_root(project_root) / PROJECT_TASK_TEMPLATE}",
                f"写入 {codex_paths['manifest']}",
                f"写入 {codex_paths['ctf_config']}",
                f"写入 {codex_paths['prompt']}",
                f"更新 {codex_paths['config']} 中的 open-reverselab 受管块",
                f"更新本地注册表 {paths.registry_file}",
            ]
        )
    elif action == "disable":
        actions.extend(
            [
                f"删除目录 {project_marker_root(project_root)}",
                f"移除 {project_root / 'AGENTS.md'} 中的受管块",
                f"移除 {project_root / '.gitignore'} 中的受管忽略项",
                f"移除 {codex_paths['config']} 中的 open-reverselab 受管块并保留 .codex 文件",
                f"移除本地注册表 {paths.registry_file} 中的项目绑定",
            ]
        )
    return {
        "action": action,
        "project_root": str(project_root),
        "project_id": project_id,
        "confirmation_text": confirm_text(project_root, "enable" if action != "disable" else "disable"),
        "changes": actions,
        "state": state,
    }


def apply_project_binding(project_root: Path, project_id: str, paths: AdapterPaths | None = None) -> dict[str, Any]:
    paths = ensure_layout(paths)
    data_roots = namespaced_data_roots(project_root)
    codex_runtime = ensure_project_codex_runtime(project_root)
    existing_marker = read_json(project_marker_path(project_root), {})
    project_marker_root(project_root).mkdir(parents=True, exist_ok=True)
    for key in ("notes_root", "reports_root", "exports_root"):
        data_roots[key].mkdir(parents=True, exist_ok=True)
    marker_payload = {
        "schema": 1,
        "adapter_schema": ADAPTER_SCHEMA,
        "adapter_version": ADAPTER_VERSION,
        "adapter": adapter_identity(),
        "project_id": project_id,
        "project_root": str(project_root),
        "repo_root": str(paths.repo_root),
        "output_namespace": OUTPUT_NAMESPACE,
        "bound_at": existing_marker.get("bound_at") or utc_now_iso(),
        "updated_at": utc_now_iso(),
        "project_codex": {
            "restore_state": codex_runtime["restore_state"],
            "paths": codex_runtime["paths"],
        },
        "trigger_phrases": {
            "enable": [
                "启用 open-reverselab Codex 模式",
                "enable open-reverselab codex mode",
            ],
            "disable": [
                "停用 open-reverselab Codex 模式",
                "disable open-reverselab codex mode",
            ],
            "status": [
                "查看 open-reverselab Codex 状态",
                "show open-reverselab codex status",
            ],
        },
    }
    write_json(project_marker_path(project_root), marker_payload)
    write_text(project_marker_root(project_root) / PROJECT_README, project_doc_readme(project_root))
    write_text(project_marker_root(project_root) / PROJECT_QUICK_START, project_doc_quick_start(project_root))
    write_text(project_marker_root(project_root) / PROJECT_TASK_TEMPLATE, project_doc_task_template(project_root))
    ensure_agents_block(project_root, project_id)
    ensure_gitignore_block(project_root)
    registry = load_registry(paths)
    registry["projects"][project_id] = {
        "project_id": project_id,
        "project_root": str(project_root),
        "repo_root": str(paths.repo_root),
        "adapter_schema": ADAPTER_SCHEMA,
        "adapter_version": ADAPTER_VERSION,
        "project_mode": "standard_active",
        "bound_at": marker_payload["bound_at"],
        "updated_at": marker_payload["updated_at"],
    }
    save_registry(registry, paths)
    return project_state(project_root, paths)


def remove_project_binding(project_root: Path, paths: AdapterPaths | None = None) -> dict[str, Any]:
    paths = ensure_layout(paths)
    marker_payload = read_json(project_marker_path(project_root), {})
    project_id = marker_payload.get("project_id", "")
    restore_state = ((marker_payload.get("project_codex") or {}).get("restore_state") or {})
    remove_agents_block(project_root)
    remove_gitignore_block(project_root)
    disable_project_codex_runtime(project_root, restore_state)
    marker_root = project_marker_root(project_root)
    if marker_root.exists():
        shutil.rmtree(marker_root, ignore_errors=True)
    registry = load_registry(paths)
    if project_id and project_id in registry["projects"]:
        registry["projects"].pop(project_id, None)
        save_registry(registry, paths)
    return {
        "project_root": str(project_root),
        "project_id": project_id,
        "bound": False,
        "removed": True,
    }


def rebuild_registry_entry_from_marker(project_root: Path, marker_data: dict[str, Any], paths: AdapterPaths | None = None) -> None:
    paths = ensure_layout(paths)
    project_id = marker_data.get("project_id", "")
    if not project_id:
        return
    registry = load_registry(paths)
    adapter = project_adapter_metadata(marker_data)
    registry["projects"][project_id] = {
        "project_id": project_id,
        "project_root": str(project_root),
        "repo_root": str(paths.repo_root),
        "adapter_schema": adapter["schema"] or ADAPTER_SCHEMA,
        "adapter_version": adapter["version"] or ADAPTER_VERSION,
        "project_mode": adapter["mode"] or "standard_active",
        "bound_at": marker_data.get("bound_at") or utc_now_iso(),
        "updated_at": utc_now_iso(),
    }
    save_registry(registry, paths)


def refresh_bound_project(project_root: Path, paths: AdapterPaths | None = None, reason: str = "status") -> dict[str, Any] | None:
    paths = ensure_layout(paths)
    marker = project_marker_path(project_root)
    if not marker.exists():
        return None
    marker_data = read_json(marker, {})
    rebuild_registry_entry_from_marker(project_root, marker_data, paths)
    if not project_requires_upgrade(marker_data):
        return None
    project_id = marker_data.get("project_id", "") or str(uuid.uuid4())
    backup = create_backup(
        f"upgrade-project-{reason}",
        paths=paths,
        target_project_root=project_root,
        include_global_state=False,
    )
    status = apply_project_binding(project_root, project_id, paths)
    return {
        "project_root": str(project_root),
        "project_id": project_id,
        "backup_id": backup["backup_id"],
        "status": status,
        "upgraded": True,
        "from_version": project_adapter_metadata(marker_data)["version"],
        "to_version": ADAPTER_VERSION,
    }


def enable_project_mode(project_root: str | Path, confirm: str = "", paths: AdapterPaths | None = None) -> dict[str, Any]:
    paths = ensure_layout(paths)
    root = normalize_project_root(project_root)
    plan = build_project_plan(root, "enable", paths)
    state = plan["state"]
    if state["bound"] and state["healthy"]:
        marker_data = read_json(project_marker_path(root), {})
        refresh = refresh_bound_project(root, paths, reason="enable")
        project_id = marker_data.get("project_id", "")
        return {
            "ok": True,
            "already_bound": True,
            "auto_upgraded": bool(refresh),
            "upgrade_result": refresh,
            "project_root": str(root),
            "project_id": project_id,
            "status": project_state(root, paths),
        }

    expected = plan["confirmation_text"]
    if confirm.strip() != expected:
        return {
            "ok": False,
            "requires_confirmation": True,
            "confirmation_text": expected,
            "preview": plan,
        }

    backup = create_backup("bind-project", paths=paths, target_project_root=root, include_global_state=False)
    result = apply_project_binding(root, plan["project_id"], paths)
    payload = {
        "ok": True,
        "action": "enable",
        "backup_id": backup["backup_id"],
        "project_root": str(root),
        "project_id": plan["project_id"],
        "status": result,
    }
    write_json(paths.start_report, payload)
    return payload


def disable_project_mode(project_root: str | Path, confirm: str = "", paths: AdapterPaths | None = None) -> dict[str, Any]:
    paths = ensure_layout(paths)
    root = normalize_project_root(project_root)
    state = project_state(root, paths)
    expected = confirm_text(root, "disable")
    if not state["bound"]:
        return {
            "ok": True,
            "already_disabled": True,
            "project_root": str(root),
            "status": state,
        }
    if confirm.strip() != expected:
        return {
            "ok": False,
            "requires_confirmation": True,
            "confirmation_text": expected,
            "preview": build_project_plan(root, "disable", paths),
        }
    backup = create_backup("unbind-project", paths=paths, target_project_root=root, include_global_state=False)
    result = remove_project_binding(root, paths)
    payload = {
        "ok": True,
        "action": "disable",
        "backup_id": backup["backup_id"],
        "project_root": str(root),
        "status": result,
    }
    write_json(paths.start_report, payload)
    return payload


def project_mode_status(project_root: str | Path, paths: AdapterPaths | None = None) -> dict[str, Any]:
    paths = ensure_layout(paths)
    root = normalize_project_root(project_root)
    marker_data = read_json(project_marker_path(root), {})
    auto_upgrade = refresh_bound_project(root, paths, reason="status") if marker_data else None
    return {
        "ok": True,
        "project_root": str(root),
        "auto_upgraded": bool(auto_upgrade),
        "upgrade_result": auto_upgrade,
        "status": project_state(root, paths),
    }


def repair_project_mode(project_root: str | Path, confirm: str = "", paths: AdapterPaths | None = None) -> dict[str, Any]:
    paths = ensure_layout(paths)
    root = normalize_project_root(project_root)
    marker_data = read_json(project_marker_path(root), {})
    project_id = marker_data.get("project_id", "") or str(uuid.uuid4())
    expected = confirm_text(root, "enable")
    plan = build_project_plan(root, "repair", paths)
    if confirm.strip() != expected:
        return {
            "ok": False,
            "requires_confirmation": True,
            "confirmation_text": expected,
            "preview": plan,
        }
    backup = create_backup("repair-project", paths=paths, target_project_root=root, include_global_state=False)
    result = apply_project_binding(root, project_id, paths)
    payload = {
        "ok": True,
        "action": "repair",
        "backup_id": backup["backup_id"],
        "project_root": str(root),
        "project_id": project_id,
        "status": result,
    }
    write_json(paths.start_report, payload)
    return payload


def discover_registered_project_upgrades(paths: AdapterPaths | None = None) -> list[dict[str, Any]]:
    paths = ensure_layout(paths)
    registry = load_registry(paths)
    candidates: list[dict[str, Any]] = []
    for project in sorted(registry.get("projects", {}).values(), key=lambda item: item.get("project_root", "")):
        project_root = Path(project.get("project_root", ""))
        item = {
            "project_id": project.get("project_id", ""),
            "project_root": str(project_root),
        }
        if not project_root.exists():
            item["result"] = "offline_missing"
            candidates.append(item)
            continue
        marker_data = read_json(project_marker_path(project_root), {})
        if not marker_data:
            item["result"] = "marker_missing"
            candidates.append(item)
            continue
        adapter = project_adapter_metadata(marker_data)
        item["current_adapter_version"] = adapter["version"]
        item["current_adapter_schema"] = adapter["schema"]
        item["result"] = "upgrade_needed" if project_requires_upgrade(marker_data) else "already_current"
        candidates.append(item)
    return candidates


def upgrade_registered_projects(global_backup_id: str = "", paths: AdapterPaths | None = None) -> dict[str, Any]:
    paths = ensure_layout(paths)
    results: list[dict[str, Any]] = []
    for item in discover_registered_project_upgrades(paths):
        result = dict(item)
        project_root = Path(item["project_root"])
        if item["result"] != "upgrade_needed":
            results.append(result)
            continue
        try:
            marker_data = read_json(project_marker_path(project_root), {})
            project_id = marker_data.get("project_id", "") or item["project_id"] or str(uuid.uuid4())
            backup = create_backup("upgrade-project", paths=paths, target_project_root=project_root, include_global_state=False)
            state = apply_project_binding(project_root, project_id, paths)
            result.update(
                {
                    "result": "upgraded",
                    "backup_id": backup["backup_id"],
                    "from_version": project_adapter_metadata(marker_data)["version"],
                    "to_version": ADAPTER_VERSION,
                    "status": state,
                }
            )
        except Exception as exc:
            result.update(
                {
                    "result": "upgrade_failed",
                    "error": str(exc),
                }
            )
        results.append(result)
    batch = write_upgrade_batch_manifest(results, global_backup_id=global_backup_id, paths=paths)
    return {
        "batch_id": batch["batch_id"],
        "summary": batch["summary"],
        "projects": results,
    }


def install_or_repair_global_config(
    replace_related: bool = False,
    confirm_project_upgrades: bool = False,
    paths: AdapterPaths | None = None,
) -> dict[str, Any]:
    paths = ensure_layout(paths)
    uv_path = detect_uv()
    python_path = detect_python()
    status = current_global_status(paths)
    if not python_path:
        payload = {
            "schema": 1,
            "generated_at": utc_now_iso(),
            "overall": "FAIL",
            "error": "python not found",
        }
        write_json(paths.install_report, payload)
        return payload
    if not uv_path:
        payload = {
            "schema": 1,
            "generated_at": utc_now_iso(),
            "overall": "FAIL",
            "error": "uv not found",
        }
        write_json(paths.install_report, payload)
        return payload

    related = [
        section
        for section in status["related_mcp_sections"]
        if section["name"] != SERVER_NAME
    ]
    if related and not replace_related:
        payload = {
            "schema": 1,
            "adapter_schema": ADAPTER_SCHEMA,
            "adapter_version": ADAPTER_VERSION,
            "generated_at": utc_now_iso(),
            "overall": "NEEDS_CONFIRMATION",
            "confirmation_kind": "replace_related",
            "message": "Found old related Codex MCP entries that match this repo by command/path evidence.",
            "related_entries": related,
            "desired_server": status["desired_server"],
        }
        write_json(paths.install_report, payload)
        return payload

    project_upgrade_scan = discover_registered_project_upgrades(paths)
    pending_project_upgrades = [item for item in project_upgrade_scan if item.get("result") == "upgrade_needed"]
    if pending_project_upgrades and not confirm_project_upgrades:
        payload = {
            "schema": 1,
            "adapter_schema": ADAPTER_SCHEMA,
            "adapter_version": ADAPTER_VERSION,
            "generated_at": utc_now_iso(),
            "overall": "NEEDS_CONFIRMATION",
            "confirmation_kind": "project_upgrades",
            "message": "Registered public-version projects need adapter upgrades before they are reopened.",
            "close_sessions_required": True,
            "project_upgrade_summary": {
                "upgrade_needed": len(pending_project_upgrades),
                "offline_missing": sum(1 for item in project_upgrade_scan if item.get("result") == "offline_missing"),
                "marker_missing": sum(1 for item in project_upgrade_scan if item.get("result") == "marker_missing"),
                "already_current": sum(1 for item in project_upgrade_scan if item.get("result") == "already_current"),
            },
            "project_upgrade_candidates": pending_project_upgrades,
        }
        write_json(paths.install_report, payload)
        return payload

    sync_result = subprocess.run(
        [uv_path, "sync", "--project", str(upstream_project_dir(paths))],
        cwd=str(paths.repo_root),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if sync_result.returncode != 0:
        payload = {
            "schema": 1,
            "adapter_schema": ADAPTER_SCHEMA,
            "adapter_version": ADAPTER_VERSION,
            "generated_at": utc_now_iso(),
            "overall": "FAIL",
            "error": "uv sync failed",
            "stdout": sync_result.stdout[-4000:],
            "stderr": sync_result.stderr[-4000:],
        }
        write_json(paths.install_report, payload)
        return payload

    backup = create_backup("install-global-config", paths=paths, extra_files=[paths.workspace_codex_config])
    config_text = read_text(paths.global_codex_config)
    if replace_related:
        for section in related:
            config_text = remove_mcp_server_sections(config_text, section["name"])
    updated_text = ensure_global_server_and_instructions(config_text, paths, uv_path)
    write_text(paths.global_codex_config, updated_text)
    upgrade_batch = upgrade_registered_projects(global_backup_id=backup["backup_id"], paths=paths) if project_upgrade_scan else None

    runtime_state = {
        "schema": 1,
        "adapter_schema": ADAPTER_SCHEMA,
        "adapter_version": ADAPTER_VERSION,
        "updated_at": utc_now_iso(),
        "repo_root": str(paths.repo_root),
        "server_name": SERVER_NAME,
        "workspace_codex_config_preserved": True,
        "backup_id": backup["backup_id"],
        "project_upgrade_batch_id": upgrade_batch["batch_id"] if upgrade_batch else "",
    }
    write_json(paths.runtime_state_file, runtime_state)
    write_json(
        paths.local_manifest,
        {
            "schema": 1,
            "adapter_schema": ADAPTER_SCHEMA,
            "adapter_version": ADAPTER_VERSION,
            "updated_at": utc_now_iso(),
            "managed_root_bats": [
                "LAUNCHER.bat",
                "CODEX.bat",
            ],
            "local_runtime_dir": LOCAL_RUNTIME_DIR,
            "server_name": SERVER_NAME,
            "backup_id": backup["backup_id"],
            "project_upgrade_batch_id": upgrade_batch["batch_id"] if upgrade_batch else "",
        },
    )
    payload = {
        "schema": 1,
        "adapter_schema": ADAPTER_SCHEMA,
        "adapter_version": ADAPTER_VERSION,
        "generated_at": utc_now_iso(),
        "overall": "PASS",
        "backup_id": backup["backup_id"],
        "uv_sync_project": str(upstream_project_dir(paths)),
        "global_config": str(paths.global_codex_config),
        "workspace_codex_config_exists": paths.workspace_codex_config.exists(),
        "server_name": SERVER_NAME,
        "related_entries_replaced": related,
        "project_upgrade_batch": upgrade_batch,
    }
    write_json(paths.install_report, payload)
    return payload


def uninstall_global_config(paths: AdapterPaths | None = None) -> dict[str, Any]:
    paths = ensure_layout(paths)
    backup = create_backup("remove-global-config", paths=paths)
    config_text = read_text(paths.global_codex_config)
    updated_text = remove_global_server_and_instructions(config_text)
    write_text(paths.global_codex_config, updated_text)
    payload = {
        "schema": 1,
        "generated_at": utc_now_iso(),
        "overall": "PASS",
        "backup_id": backup["backup_id"],
        "global_config": str(paths.global_codex_config),
    }
    write_json(paths.install_report, payload)
    return payload


def codex_status_summary(paths: AdapterPaths | None = None) -> dict[str, Any]:
    paths = ensure_layout(paths)
    registry = load_registry(paths)
    global_status = current_global_status(paths)
    wrapper_exists = wrapper_script_path().exists()
    manager_exists = manager_script_path().exists()
    global_install_ready = bool(
        global_status["config_exists"] and global_status["developer_block_present"] and global_status["server_block_present"]
    )
    return {
        "schema": 1,
        "adapter_schema": ADAPTER_SCHEMA,
        "adapter_version": ADAPTER_VERSION,
        "generated_at": utc_now_iso(),
        "repo_root": str(paths.repo_root),
        "local_runtime_dir": str(paths.local_root),
        "global_codex_config": str(paths.global_codex_config),
        "workspace_codex_config_exists": paths.workspace_codex_config.exists(),
        "server_name": SERVER_NAME,
        "global_install_ready": global_install_ready,
        "developer_block_present": global_status["developer_block_present"],
        "server_block_present": global_status["server_block_present"],
        "wrapper_exists": wrapper_exists,
        "manager_exists": manager_exists,
        "related_mcp_sections": global_status["related_mcp_sections"],
        "replaceable_related_mcp_sections": [
            section for section in global_status["related_mcp_sections"] if section.get("name") != SERVER_NAME
        ],
        "bound_project_count": len(registry["projects"]),
        "bound_projects": sorted(registry["projects"].values(), key=lambda item: item.get("project_root", "")),
        "available_backups": [item.get("backup_id", "") for item in list_backups(paths)[:10]],
        "available_upgrade_batches": [item.get("batch_id", "") for item in list_upgrade_batches(paths)[:10]],
    }


def write_report(path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    write_json(path, payload)
    return payload


def file_uri_to_path(uri: str) -> Path:
    parsed = urlparse(uri)
    if parsed.scheme and parsed.scheme != "file":
        raise ValueError(f"unsupported root uri: {uri}")
    if parsed.scheme == "file":
        return Path(url2pathname(unquote(parsed.path))).resolve()
    return Path(uri).expanduser().resolve()


def select_project_root(explicit: str = "", roots: list[str] | None = None) -> Path:
    if explicit:
        return normalize_project_root(explicit)
    if roots:
        for root in roots:
            try:
                candidate = file_uri_to_path(root)
            except Exception:
                continue
            if candidate.exists() and candidate.is_dir():
                return candidate
    cwd = Path.cwd().resolve()
    return cwd


def wrapper_environment(project_root: Path | None = None, paths: AdapterPaths | None = None) -> dict[str, str]:
    paths = paths or adapter_paths()
    target_root = project_root or paths.repo_root
    env = os.environ.copy()
    env["REVERSELAB_LAB_ROOT"] = str(paths.repo_root)
    env["REVERSELAB_DATA_ROOT"] = str(target_root)
    env["REVERSELAB_OUTPUT_NAMESPACE"] = OUTPUT_NAMESPACE
    env["PYTHONIOENCODING"] = "utf-8"
    return env


def invoke_upstream_tool(tool_name: str, arguments: dict[str, Any], project_root: Path | None = None, paths: AdapterPaths | None = None) -> dict[str, Any]:
    paths = paths or adapter_paths()
    script = wrapper_script_path()
    payload = json.dumps(arguments, ensure_ascii=False)
    command = [
        sys.executable,
        str(script),
        "--invoke-upstream",
        tool_name,
        "--arguments-json",
        payload,
    ]
    if project_root:
        command.extend(["--project-root", str(project_root)])
    result = subprocess.run(
        command,
        cwd=str(paths.repo_root),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        # The MCP wrapper itself runs over stdio. If the child process inherits the
        # parent's stdin pipe, upstream tool calls can hang indefinitely while the
        # client waits for a response. Detach stdin for the helper subprocess.
        stdin=subprocess.DEVNULL,
        env=wrapper_environment(project_root, paths),
    )
    if result.returncode != 0:
        return {
            "error": "upstream tool invocation failed",
            "tool": tool_name,
            "exit_code": result.returncode,
            "stdout": result.stdout[-4000:],
            "stderr": result.stderr[-4000:],
        }
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return {
            "error": "invalid upstream tool output",
            "tool": tool_name,
            "stdout": result.stdout[-4000:],
            "stderr": result.stderr[-4000:],
        }


def discover_upstream_tool_names(paths: AdapterPaths | None = None) -> list[str]:
    paths = paths or adapter_paths()
    env = wrapper_environment(paths.repo_root, paths)
    uv_path = detect_uv()
    if uv_path:
        command = [
            uv_path,
            "run",
            "--project",
            str(upstream_project_dir(paths)),
            "python",
            str(wrapper_script_path()),
            "--list-upstream-tools",
        ]
    else:
        command = [
            sys.executable,
            str(wrapper_script_path()),
            "--list-upstream-tools",
        ]
    result = subprocess.run(
        command,
        cwd=str(paths.repo_root),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "failed to list upstream tools")
    payload = json.loads(result.stdout)
    return payload["tools"]


def doctor(paths: AdapterPaths | None = None) -> dict[str, Any]:
    paths = ensure_layout(paths)
    payload = {
        "schema": 1,
        "generated_at": utc_now_iso(),
        "repo_root": str(paths.repo_root),
        "wrapper_script": str(wrapper_script_path()),
        "manager_script": str(manager_script_path()),
        "global_status": current_global_status(paths),
        "upstream_tool_count": len(discover_upstream_tool_names(paths)),
    }
    write_json(paths.verify_report, payload)
    return payload
