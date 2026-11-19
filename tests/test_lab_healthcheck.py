from __future__ import annotations

from conftest import load_script_module

health = load_script_module("scripts/misc/lab_healthcheck.py", "lab_healthcheck_test")


def test_healthcheck_excludes_nested_dependency_venvs_and_node_modules(tmp_path):
    root = tmp_path / "repo"
    source = root / "tools" / "example.py"
    nested_venv = root / "tools" / "package" / ".venv" / "lib" / "dependency.py"
    nested_node = root / "tools" / "web" / "node_modules" / "package" / "index.py"
    for path in (source, nested_venv, nested_node):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("pass\n", encoding="utf-8")

    assert health.should_compile_source(source, root)
    assert not health.should_compile_source(nested_venv, root)
    assert not health.should_compile_source(nested_node, root)


def test_healthcheck_skips_only_root_workspace_directories(tmp_path):
    root = tmp_path / "repo"
    root_case = root / "cases" / "sample.py"
    nested_source = root / "tools" / "fixture" / "cases" / "sample.py"
    for path in (root_case, nested_source):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("pass\n", encoding="utf-8")

    assert not health.should_compile_source(root_case, root)
    assert health.should_compile_source(nested_source, root)
