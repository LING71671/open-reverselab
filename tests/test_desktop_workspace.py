"""Workspace isolation, import integrity, and persistence tests with synthetic data."""
import importlib.util
import json
from pathlib import Path

import pytest

MODULE = Path(__file__).resolve().parents[1] / 'scripts/misc/desktop_workspace.py'
spec = importlib.util.spec_from_file_location('desktop_workspace', MODULE)
workspace = importlib.util.module_from_spec(spec)
spec.loader.exec_module(workspace)

@pytest.fixture
def roots(tmp_path, monkeypatch):
    monkeypatch.setenv('REVERSELAB_DATA_DIR', str(tmp_path / 'data'))
    a = workspace.dispatch({'action': 'create', 'root': str(tmp_path / 'one')})
    b = workspace.dispatch({'action': 'create', 'root': str(tmp_path / 'two')})
    return a, b

def test_default_is_stable_and_open_does_not_initialize_arbitrary_folders(tmp_path, monkeypatch):
    monkeypatch.setenv('REVERSELAB_DATA_DIR', str(tmp_path / 'data'))
    a = workspace.dispatch({'action': 'default'})
    b = workspace.dispatch({'action': 'default'})
    assert a['id'] == b['id']
    with pytest.raises(FileNotFoundError):
        workspace.dispatch({'action': 'open', 'root': str(tmp_path / 'unknown')})
    assert not (tmp_path / 'unknown').exists()

def test_goal_and_report_storage_stays_with_its_workspace(roots):
    a, b = roots
    snapshot = {'sessions': [{'id': 'goal-a', 'track': 'red'}], 'records': {'goal-a': {'messages': []}}}
    workspace.dispatch({'action': 'save', 'root': a['root'], 'snapshot': snapshot})
    assert workspace.dispatch({'action': 'load', 'root': a['root']}) == snapshot
    assert workspace.dispatch({'action': 'load', 'root': b['root']}) is None
    for root in (a['root'], b['root']):
        result = workspace.dispatch({'action': 'report', 'root': root, 'report': {'goalId': 'goal-a:red', 'summary': root, 'track': 'red', 'script': 'print(1)', 'goalVerification': {'status': 'in_progress'}}})
        assert Path(result['report_path']).is_relative_to(Path(root))
        assert 'in_progress' in Path(result['report_path']).read_text()

def test_import_keeps_original_and_working_copy_independent(roots, tmp_path):
    source = tmp_path / 'fixture.txt'
    source.write_text('synthetic specimen')
    record = workspace.dispatch({'action': 'import', 'root': roots[0]['root'], 'source': str(source)})
    target = Path(record['target'])
    assert target.read_text() == source.read_text()
    original = target.parent.parent / 'original' / source.name
    target.write_text('analysis changes')
    assert original.read_text() == source.read_text() == 'synthetic specimen'
    assert len(record['sha256']) == 64
    assert workspace.dispatch({'action': 'samples', 'root': roots[1]['root']}) == []

def test_directory_import_and_no_self_import(roots, tmp_path):
    source = tmp_path / 'source'
    source.mkdir()
    (source / 'a.txt').write_text('a')
    (source / 'b.txt').write_text('b')
    record = workspace.dispatch({'action': 'import', 'root': roots[0]['root'], 'source': str(source)})
    assert Path(record['target']).is_dir()
    assert len(record['files']) == 2
    with pytest.raises(ValueError, match='itself'):
        workspace.dispatch({'action': 'import', 'root': roots[0]['root'], 'source': roots[0]['root']})

def test_report_identifier_cannot_escape_workspace(roots):
    with pytest.raises(ValueError):
        workspace.dispatch({'action': 'report', 'root': roots[0]['root'], 'report': {'goalId': '../outside'}})

def test_open_rejects_invalid_manifest(roots):
    root = Path(roots[0]['root'])
    (root / '.reverselab/workspace.json').write_text(json.dumps({'version': 999, 'id': 'bogus'}))
    with pytest.raises(ValueError, match='format'):
        workspace.dispatch({'action': 'open', 'root': str(root)})
