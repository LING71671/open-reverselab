from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace


MODULE_PATH = Path(__file__).resolve().parents[2] / "scripts" / "codex" / "python" / "open_reverselab_codex_support.py"
SPEC = importlib.util.spec_from_file_location("open_reverselab_codex_support", MODULE_PATH)
support = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = support
SPEC.loader.exec_module(support)


def make_paths(tmp_path: Path) -> support.AdapterPaths:
    repo_root = tmp_path / "repo"
    local_root = repo_root / support.LOCAL_RUNTIME_DIR
    global_codex_root = tmp_path / "home" / ".codex"
    return support.AdapterPaths(
        repo_root=repo_root,
        local_root=local_root,
        python_root=repo_root / "scripts" / "codex" / "python",
        state_root=local_root / "state",
        backups_root=local_root / "backups",
        batch_root=local_root / "upgrade-batches",
        reports_root=local_root / "reports",
        docs_root=repo_root / "docs" / "codex",
        global_codex_root=global_codex_root,
        global_codex_config=global_codex_root / "config.toml",
        workspace_codex_config=repo_root / ".codex" / "config.toml",
        registry_file=local_root / "state" / "project_registry.json",
        runtime_state_file=local_root / "state" / "adapter_state.json",
        install_report=local_root / "reports" / "codex-install-report.json",
        verify_report=local_root / "reports" / "codex-verify-report.json",
        backup_report=local_root / "reports" / "codex-backup-report.json",
        restore_report=local_root / "reports" / "codex-restore-report.json",
        start_report=local_root / "reports" / "codex-start-report.json",
        menu_report=local_root / "reports" / "codex-menu-report.json",
        local_manifest=local_root / "state" / "manifest.json",
    )


def test_upsert_and_remove_global_instructions_and_server(tmp_path: Path) -> None:
    paths = make_paths(tmp_path)
    support.ensure_layout(paths)
    original = """model = "gpt-5.4"
service_tier = "fast"

[mcp_servers]

[projects.'e:\\demo']
trust_level = "trusted"
"""

    updated = support.ensure_global_server_and_instructions(original, paths, uv_path="C:\\Tools\\uv.exe")
    assert "developer_instructions" in updated
    assert support.GLOBAL_BLOCK_BEGIN in updated
    assert f"[mcp_servers.{support.SERVER_NAME}]" in updated
    assert "uv.exe" in updated

    restored = support.remove_global_server_and_instructions(updated)
    assert support.GLOBAL_BLOCK_BEGIN not in restored
    assert f"[mcp_servers.{support.SERVER_NAME}]" not in restored
    assert "model = \"gpt-5.4\"" in restored


def test_bind_and_unbind_project_updates_marker_agents_and_registry(tmp_path: Path) -> None:
    paths = make_paths(tmp_path)
    support.ensure_layout(paths)
    project_root = tmp_path / "target-project"
    project_root.mkdir(parents=True)
    (project_root / ".git").mkdir()

    preview = support.enable_project_mode(project_root, confirm="", paths=paths)
    assert preview["requires_confirmation"] is True
    confirmation = preview["confirmation_text"]

    bound = support.enable_project_mode(project_root, confirm=confirmation, paths=paths)
    assert bound["ok"] is True
    marker_path = project_root / support.PROJECT_MARKER_DIR / support.PROJECT_MARKER_FILE
    assert marker_path.exists()
    assert (project_root / "notes" / support.OUTPUT_NAMESPACE).exists()
    assert (project_root / "reports" / support.OUTPUT_NAMESPACE).exists()
    assert (project_root / "exports" / support.OUTPUT_NAMESPACE).exists()
    assert (project_root / ".codex" / "config.toml").exists()
    assert (project_root / ".codex" / support.PROJECT_CODEX_MANIFEST).exists()
    assert (project_root / ".codex" / support.PROJECT_CODEX_CTF_CONFIG).exists()
    assert (project_root / ".codex" / support.PROJECT_CODEX_PROMPT).exists()
    codex_config_text = (project_root / ".codex" / "config.toml").read_text(encoding="utf-8")
    assert support.PROJECT_CODEX_BLOCK_BEGIN in codex_config_text
    assert support.PROJECT_BLOCK_BEGIN in (project_root / "AGENTS.md").read_text(encoding="utf-8")
    assert support.MANAGED_IGNORE_HEADER in (project_root / ".gitignore").read_text(encoding="utf-8")

    registry = json.loads(paths.registry_file.read_text(encoding="utf-8"))
    marker_payload = json.loads(marker_path.read_text(encoding="utf-8"))
    project_id = marker_payload["project_id"]
    assert project_id in registry["projects"]
    assert marker_payload["adapter_version"] == support.ADAPTER_VERSION
    assert registry["projects"][project_id]["adapter_version"] == support.ADAPTER_VERSION

    disable_preview = support.disable_project_mode(project_root, confirm="", paths=paths)
    assert disable_preview["requires_confirmation"] is True
    disabled = support.disable_project_mode(project_root, confirm=disable_preview["confirmation_text"], paths=paths)
    assert disabled["ok"] is True
    assert not (project_root / support.PROJECT_MARKER_DIR).exists()
    agents_text = (project_root / "AGENTS.md").read_text(encoding="utf-8")
    assert support.PROJECT_BLOCK_BEGIN not in agents_text
    codex_config_text = (project_root / ".codex" / "config.toml").read_text(encoding="utf-8")
    assert support.PROJECT_CODEX_BLOCK_BEGIN not in codex_config_text
    assert (project_root / ".codex" / support.PROJECT_CODEX_MANIFEST).exists()
    gitignore = project_root / ".gitignore"
    if gitignore.exists():
        gitignore_text = gitignore.read_text(encoding="utf-8")
        assert support.MANAGED_IGNORE_HEADER not in gitignore_text


def test_restore_backup_restores_only_integration_state(tmp_path: Path) -> None:
    paths = make_paths(tmp_path)
    support.ensure_layout(paths)
    paths.global_codex_root.mkdir(parents=True, exist_ok=True)
    paths.global_codex_config.write_text('model = "gpt-5.5"\n', encoding="utf-8")
    project_root = tmp_path / "restore-project"
    project_root.mkdir(parents=True)
    (project_root / ".git").mkdir()

    preview = support.enable_project_mode(project_root, confirm="", paths=paths)
    bound = support.enable_project_mode(project_root, confirm=preview["confirmation_text"], paths=paths)
    backup_id = bound["backup_id"]

    marker_root = project_root / support.PROJECT_MARKER_DIR
    marker_root.rename(project_root / ".open-reverselab-codex-missing")
    codex_config = project_root / ".codex" / "config.toml"
    codex_config.write_text("# broken\n", encoding="utf-8")
    artifacts_root = project_root / "reports" / support.OUTPUT_NAMESPACE
    artifact = artifacts_root / "result.txt"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text("keep me", encoding="utf-8")
    paths.global_codex_config.write_text('model = "gpt-5.6"\n', encoding="utf-8")

    restored = support.restore_backup(backup_id, paths=paths)
    assert restored["backup_id"] == backup_id
    assert not marker_root.exists()
    assert artifact.exists()
    assert artifact.read_text(encoding="utf-8") == "keep me"
    assert not codex_config.exists()
    assert paths.global_codex_config.read_text(encoding="utf-8") == 'model = "gpt-5.6"\n'


def test_existing_project_codex_values_are_restored_on_disable(tmp_path: Path) -> None:
    paths = make_paths(tmp_path)
    support.ensure_layout(paths)
    project_root = tmp_path / "existing-config-project"
    project_root.mkdir(parents=True)
    (project_root / ".git").mkdir()
    codex_root = project_root / ".codex"
    codex_root.mkdir()
    original_text = (
        'model = "gpt-5.5"\n'
        'approval_policy = "on-request"\n'
        'sandbox_mode = "workspace-write"\n'
        'model_instructions_file = "custom.md"\n'
    )
    (codex_root / "config.toml").write_text(original_text, encoding="utf-8")

    preview = support.enable_project_mode(project_root, confirm="", paths=paths)
    bound = support.enable_project_mode(project_root, confirm=preview["confirmation_text"], paths=paths)
    assert bound["ok"] is True
    enabled_text = (codex_root / "config.toml").read_text(encoding="utf-8")
    assert support.PROJECT_CODEX_BLOCK_BEGIN in enabled_text
    assert 'approval_policy = "on-request"' not in enabled_text

    disable_preview = support.disable_project_mode(project_root, confirm="", paths=paths)
    disabled = support.disable_project_mode(project_root, confirm=disable_preview["confirmation_text"], paths=paths)
    assert disabled["ok"] is True
    restored_text = (codex_root / "config.toml").read_text(encoding="utf-8")
    assert support.PROJECT_CODEX_BLOCK_BEGIN not in restored_text
    assert 'approval_policy = "on-request"' in restored_text
    assert 'sandbox_mode = "workspace-write"' in restored_text
    assert 'model_instructions_file = "custom.md"' in restored_text


def test_project_status_rebuilds_registry_and_upgrades_outdated_marker(tmp_path: Path) -> None:
    paths = make_paths(tmp_path)
    support.ensure_layout(paths)
    project_root = tmp_path / "status-project"
    project_root.mkdir(parents=True)
    (project_root / ".git").mkdir()

    preview = support.enable_project_mode(project_root, confirm="", paths=paths)
    bound = support.enable_project_mode(project_root, confirm=preview["confirmation_text"], paths=paths)
    assert bound["ok"] is True

    marker_path = project_root / support.PROJECT_MARKER_DIR / support.PROJECT_MARKER_FILE
    marker_payload = json.loads(marker_path.read_text(encoding="utf-8"))
    marker_payload["adapter_version"] = "0.9.0"
    marker_payload["adapter"]["version"] = "0.9.0"
    marker_path.write_text(json.dumps(marker_payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    paths.registry_file.unlink()

    status = support.project_mode_status(project_root, paths=paths)
    assert status["ok"] is True
    assert status["auto_upgraded"] is True
    assert status["status"]["adapter_version"] == support.ADAPTER_VERSION
    registry = json.loads(paths.registry_file.read_text(encoding="utf-8"))
    assert marker_payload["project_id"] in registry["projects"]


def test_install_preserves_workspace_codex_config(tmp_path: Path, monkeypatch) -> None:
    paths = make_paths(tmp_path)
    support.ensure_layout(paths)
    paths.global_codex_root.mkdir(parents=True, exist_ok=True)
    paths.workspace_codex_config.parent.mkdir(parents=True, exist_ok=True)
    paths.workspace_codex_config.write_text('approval_policy = "on-request"\n', encoding="utf-8")

    monkeypatch.setattr(support, "detect_python", lambda: "python")
    monkeypatch.setattr(support, "detect_uv", lambda: "uv")
    monkeypatch.setattr(
        support.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout="", stderr=""),
    )

    payload = support.install_or_repair_global_config(paths=paths)
    assert payload["overall"] == "PASS"
    assert paths.workspace_codex_config.exists()
    assert payload["workspace_codex_config_exists"] is True


def test_invoke_upstream_tool_detaches_stdin(tmp_path: Path, monkeypatch) -> None:
    paths = make_paths(tmp_path)
    support.ensure_layout(paths)
    project_root = tmp_path / "target-project"
    project_root.mkdir(parents=True)

    calls: list[dict[str, object]] = []

    def fake_run(*args, **kwargs):
        calls.append({"args": args, "kwargs": kwargs})
        return SimpleNamespace(returncode=0, stdout='{"ok": true}', stderr="")

    monkeypatch.setattr(support.subprocess, "run", fake_run)

    payload = support.invoke_upstream_tool("project_skills_status", {}, project_root=project_root, paths=paths)

    assert payload == {"ok": True}
    assert len(calls) == 1
    assert calls[0]["kwargs"]["stdin"] is subprocess.DEVNULL
