from __future__ import annotations

import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MCP_ROOT = ROOT / "tools" / "skills" / "mcp" / "ReverseLabToolsMCP"
sys.path.insert(0, str(MCP_ROOT))

from reverselab_mcp.errors import ToolError  # noqa: E402
from reverselab_mcp.tools import analysis_notes, web_ctf  # noqa: E402


def test_apk_jni_route_references_existing_technique():
    result = web_ctf.kb_router("JNI_OnLoad RegisterNatives native method", board="apk-reverse")

    assert result["total"] >= 1
    native = next(item for item in result["top"] if item["id"] == "native")
    assert any(path.endswith("02-native/06-jni-register-natives-tracing.md") for path in native["files"])


def test_apk_index_files_stay_under_techniques_root():
    techniques_root = web_ctf.KB_ROOTS["apk-reverse"].resolve()
    data = json.loads((techniques_root / "kb-index.json").read_text(encoding="utf-8"))

    for entry in data["entries"]:
        for relative_path in entry["files"]:
            resolved = (techniques_root / relative_path).resolve()
            assert resolved.is_relative_to(techniques_root)
            assert resolved.is_file()


def test_kb_read_file_rejects_traversal():
    try:
        web_ctf.kb_read_file("../../README.md", board="apk-reverse")
    except ToolError as exc:
        assert "outside allowed roots" in str(exc)
    else:
        raise AssertionError("path traversal must fail")


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
