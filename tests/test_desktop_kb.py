from __future__ import annotations

import json
from pathlib import Path

import pytest

from conftest import ROOT, load_script_module


desktop_kb = load_script_module("scripts/misc/desktop_kb.py", "desktop_kb_test")


@pytest.fixture(scope="module")
def catalog():
    return desktop_kb.build_catalog()


def test_catalog_includes_nested_jwt_and_unique_canonical_paths(catalog):
    paths = {item["path"] for item in catalog}
    assert "kb/red/ctf-website/techniques/02-auth/jwt/00-overview.md" in paths
    assert "kb/blue/ctf-website/techniques/02-auth/jwt/09-toolchain-operations-defense.md" in paths
    assert len(paths) == len(catalog) == len({item["id"] for item in catalog})
    for item in catalog:
        assert ".." not in item["path"].split("/")
        assert (ROOT / item["path"]).is_file()
        assert set(item["related_paths"]) <= paths
        assert item["path"] not in item["related_paths"]
    for board in desktop_kb.router.BOARDS:
        for path in (p for folder in desktop_kb.router.layout.technique_dirs(board, ROOT) for p in folder.rglob("*.md")):
            if path.name != "README.md":
                assert path.relative_to(ROOT).as_posix() in paths


def test_catalog_uses_index_tracks_and_filters_shared_articles(catalog, monkeypatch):
    monkeypatch.setenv("REVERSELAB_MODE", "blue")
    assert desktop_kb.build_catalog() == catalog
    for track in ("red", "blue"):
        filtered = desktop_kb.build_catalog(track)
        assert filtered
        assert {item["path"] for item in filtered} == {
            item["path"] for item in catalog if item["track"] in (track, "both")
        }
    by_path = {item["path"]: item for item in catalog}
    jwt = by_path["kb/red/ctf-website/techniques/02-auth/jwt/00-overview.md"]
    assert jwt["track"] == "red"
    assert jwt["title"] == "JWT 攻击全景"
    assert jwt["category"] == "02-auth"
    assert "authorization header" in jwt["signals"]
    assert "kb_router" in jwt["mcp_tools"]
    defense_path = "kb/blue/ctf-website/techniques/02-auth/jwt/00-overview-defense.md"
    assert jwt["related_paths"] == [defense_path]
    assert by_path[defense_path]["track"] == "blue"
    assert by_path[defense_path]["related_paths"] == [jwt["path"]]


def _write_board(root: Path, board: str, entries: list[dict], docs: dict[str, str]):
    tech_dir = root / "kb" / board / "techniques"
    tech_dir.mkdir(parents=True, exist_ok=True)
    (tech_dir / "kb-index.json").write_text(json.dumps({"entries": entries}), encoding="utf-8")
    for name, content in docs.items():
        path = tech_dir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


def test_cross_board_references_and_unclassified_docs(tmp_path):
    _write_board(tmp_path, "general", [
        {"id": "sample", "track": "red", "files": ["nested/sample.md"], "signals": ["owned signal"], "defended_by": "guard"},
        {"id": "guard", "track": "blue", "files": ["nested/guard.md"]},
    ], {"nested/sample.md": "# Sample", "nested/guard.md": "# Guard", "new-defense.md": "# Newly added"})
    _write_board(tmp_path, "ctf-website", [
        {"id": "alias", "track": "both", "files": ["../../general/techniques/nested/sample.md"], "signals": ["alias"]},
    ], {})
    items = {item["path"]: item for item in desktop_kb.build_catalog(repo_root=tmp_path)}
    sample = items["kb/general/techniques/nested/sample.md"]
    assert sample["board"] == "general"
    assert sample["track"] == "red"
    assert sample["signals"] == ["owned signal"]
    assert sample["related_paths"] == ["kb/general/techniques/nested/guard.md"]
    assert items["kb/general/techniques/new-defense.md"]["track"] == "both"
    assert len(items) == 3


@pytest.mark.parametrize("path", [
    "AGENTS.md", "../AGENTS.md", "kb/../AGENTS.md", "/kb/shared/general/README.md",
    "kb\\general\\README.md", "kb//general/README.md", "kb/./general/README.md",
    "kb/catalog/general.json", "kb/shared/general/README.md:stream", "kb/\x00.md",
])
def test_document_reader_rejects_noncanonical_or_non_markdown_paths(path):
    with pytest.raises((ValueError, OSError)):
        desktop_kb.read_document(path)


def test_document_reader_reads_existing_unicode_content():
    content = desktop_kb.read_document("kb/red/ctf-website/techniques/02-auth/jwt/00-overview.md")
    assert "JWT 攻击全景" in content


def test_document_reader_rejects_symlink_escape(tmp_path):
    kb = tmp_path / "kb"
    kb.mkdir()
    outside = tmp_path / "outside.md"
    outside.write_text("private", encoding="utf-8")
    try:
        (kb / "linked.md").symlink_to(outside)
    except (OSError, NotImplementedError) as error:
        pytest.skip(f"Symbolic links are unavailable: {error}")
    with pytest.raises(ValueError, match="inside kb/"):
        desktop_kb.read_document("kb/linked.md", repo_root=tmp_path)


def test_catalog_rejects_unknown_track():
    with pytest.raises(ValueError, match="red, blue, or both"):
        desktop_kb.build_catalog("invalid")


def test_migration_keeps_legacy_reads_and_track_directories(catalog):
    aliases = desktop_kb.router.layout.aliases(ROOT)
    assert aliases
    for old, new in aliases.items():
        assert (ROOT / new).is_file(), (old, new)
        assert desktop_kb.read_document(old) == desktop_kb.read_document(new)
    for item in catalog:
        layer = "shared" if item["track"] == "both" else item["track"]
        assert item["path"].startswith(f"kb/{layer}/{item['board']}/techniques/")


@pytest.mark.parametrize("board", desktop_kb.router.BOARDS)
def test_network_maps_pair_across_tracks(board, catalog):
    items = {item["path"]: item for item in catalog}
    red = f"kb/red/{board}/techniques/attack-network.md"
    blue = f"kb/blue/{board}/techniques/defense-network.md"
    assert items[red]["track"] == "red"
    assert items[blue]["track"] == "blue"
    assert blue in items[red]["related_paths"]
    assert red in items[blue]["related_paths"]


@pytest.mark.parametrize("board,technique", [
    ("general", "ai-security/01-indirect-prompt-injection"),
    ("general", "ai-security/02-mcp-trust-boundary"),
    ("general", "ai-security/03-rag-authorization-poisoning"),
    ("ctf-website", "02-auth/webauthn-passkey"),
    ("ctf-website", "10-cloud/presigned-object-storage"),
    ("ctf-website", "11-supply-chain/artifact-provenance-verification"),
])
def test_expanded_techniques_have_exact_bidirectional_pairs(board, technique, catalog):
    items = {item["path"]: item for item in catalog}
    red = f"kb/red/{board}/techniques/{technique}.md"
    blue = f"kb/blue/{board}/techniques/{technique}-defense.md"
    assert items[red]["related_paths"] == [blue]
    assert items[blue]["related_paths"] == [red]
