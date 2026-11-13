from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MCP_ROOT = ROOT / "tools" / "skills" / "mcp" / "ReverseLabToolsMCP"
sys.path.insert(0, str(MCP_ROOT))

from reverselab_mcp.errors import ToolError  # noqa: E402
from reverselab_mcp.tools import analysis_notes, kb, web_ctf  # noqa: E402


def test_apk_jni_route_references_existing_technique():
    result = web_ctf.kb_router("JNI_OnLoad RegisterNatives native method", board="apk-reverse")

    assert result["total"] >= 1
    native = next(item for item in result["top"] if item["id"] == "native")
    assert any(path.endswith("02-native/06-jni-register-natives-tracing.md") for path in native["files"])


def test_apk_index_files_stay_under_board_technique_roots():
    technique_roots = kb.layout.technique_dirs("apk-reverse", ROOT)
    data = json.loads(kb.layout.index_path("apk-reverse", ROOT).read_text(encoding="utf-8"))

    for entry in data["entries"]:
        for relative_path in entry["files"] + entry.get("defense_files", []):
            resolved = (ROOT / relative_path).resolve()
            assert any(resolved.is_relative_to(root.resolve()) for root in technique_roots)
            assert resolved.is_file()


def test_kb_read_file_rejects_traversal():
    try:
        web_ctf.kb_read_file("../../README.md", board="apk-reverse")
    except ToolError as exc:
        assert "outside allowed roots" in str(exc)
    else:
        raise AssertionError("path traversal must fail")


@pytest.mark.parametrize("layer,relative", [
    ("red", "ai-security/01-indirect-prompt-injection.md"),
    ("blue", "ai-security/01-indirect-prompt-injection-defense.md"),
    ("shared", "crypto/01-algorithm-identification.md"),
])
def test_kb_read_file_accepts_canonical_legacy_and_technique_paths(layer, relative):
    canonical = f"kb/{layer}/general/techniques/{relative}"
    legacy = f"kb/general/techniques/{relative}"
    expected_track = "both" if layer == "shared" else layer
    for path, board in [
        (canonical, ""), (canonical, "general"),
        (legacy, ""), (legacy, "general"),
        (relative, ""), (relative, "general"),
        (canonical.replace("/", "\\"), ""), (str(ROOT / canonical), ""),
    ]:
        result = web_ctf.kb_read_file(path, board=board)
        assert "error" not in result, (path, board, result)
        assert result["board"] == "general"
        assert result["path"] == canonical
        assert result["track"] == expected_track
        assert result["content"]


@pytest.mark.parametrize("path,board", [
    ("../../README.md", ""),
    ("kb/blue/general/techniques/../../../README.md", "general"),
    ("kb/general/techniques/../../../AGENTS.md", "general"),
    ("kb/catalog/general.json", "general"),
    ("kb/blue/general/techniques/ai-security/01-indirect-prompt-injection-defense.md", "apk-reverse"),
    (str(ROOT / "AGENTS.md"), ""),
])
def test_kb_read_file_rejects_non_technique_and_cross_board_paths(path, board):
    with pytest.raises(ToolError, match="outside allowed roots"):
        web_ctf.kb_read_file(path, board=board)


def test_kb_router_returns_existing_layer_paths_and_both_pairs():
    for track in ("red", "blue", "both"):
        result = web_ctf.kb_router("prompt injection", board="general", track=track)
        assert result["total"] > 0
        for item in result["top"]:
            assert track == "both" or item["track"] in (track, "both")
            for path in item["files"] + item.get("paired_files", []):
                assert Path(path).is_file()
                relative = Path(path).relative_to(ROOT).as_posix()
                assert kb.layout.document_parts(relative)[0] == "general"
        if track == "both":
            assert result["paired_links"]
            assert any(item.get("paired_entries") for item in result["top"])


def test_kb_catalog_uses_technique_categories_instead_of_layout_layers():
    for track in ("red", "blue", "both"):
        board = web_ctf.kb_catalog(board="general", track=track)["boards"]["general"]
        assert board["index_path"] == "kb/catalog/general.json"
        assert "ai-security" in board["categories"]
        assert not {"kb", "red", "blue", "shared"} & board["categories"].keys()
        assert {
            f"kb/{layer}/general/techniques" for layer in ("red", "blue", "shared")
        } <= set(board["techniques_dirs"])
        assert all((ROOT / path).is_dir() for path in board["techniques_dirs"])


def test_kb_read_file_rejects_alias_escape(tmp_path, monkeypatch):
    legacy = tmp_path / "kb/general/techniques"
    blue = tmp_path / "kb/blue/general/techniques"
    blue.mkdir(parents=True)
    (tmp_path / "outside.md").write_text("must not read", encoding="utf-8")
    (tmp_path / "kb/path-aliases.json").write_text(json.dumps({
        "kb/general/techniques/alias.md": "outside.md",
    }), encoding="utf-8")
    monkeypatch.setattr(kb, "REVERSE_ROOT", tmp_path)
    monkeypatch.setitem(kb.KB_ROOTS, "general", legacy)
    with pytest.raises(ToolError, match="outside allowed roots"):
        web_ctf.kb_read_file("alias.md", board="general")


def test_kb_read_file_rejects_symlink_escape(tmp_path, monkeypatch):
    blue = tmp_path / "kb/blue/general/techniques"
    blue.mkdir(parents=True)
    outside = tmp_path / "outside.md"
    outside.write_text("must not read", encoding="utf-8")
    try:
        (blue / "escape.md").symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"Symlinks unavailable: {exc}")
    monkeypatch.setattr(kb, "REVERSE_ROOT", tmp_path)
    monkeypatch.setitem(kb.KB_ROOTS, "general", tmp_path / "kb/general/techniques")
    with pytest.raises(ToolError, match="outside allowed roots"):
        web_ctf.kb_read_file("kb/blue/general/techniques/escape.md")


def test_function_map_schema_separates_confidence_and_review_status():
    header = "| Address | Current Name | Proposed Name | Purpose / Evidence | Confidence | Review Status |"
    row = "| `0x401000` | `FUN_00401000` | `candidate_fun_00401000` | `signature` | `Low` | `Needs review` |"

    assert header.count("|") == row.count("|")
    assert "`Low`" in row
    assert "`Needs review`" in row


def test_symbol_evidence_cue_and_candidate_name_are_conservative():
    function = {
        "name": "FUN_00401000",
        "signature": "int FUN_00401000(int)",
        "import_refs": [{"name": "CreateFileW"}],
        "string_refs": [{"value": "config"}],
        "callers": [{"name": "entry"}],
        "callees": [{"name": "FUN_00402000"}],
        "decompile": {"status": "ok"},
    }

    assert analysis_notes._proposed_function_name(function) == "candidate_fun_00401000"
    cue = analysis_notes._function_evidence_cue(function)
    assert "signature" in cue
    assert "imports:1" in cue
    assert "strings:1" in cue
    assert "callers:1" in cue
    assert "callees:1" in cue
    assert "decompile" in cue
