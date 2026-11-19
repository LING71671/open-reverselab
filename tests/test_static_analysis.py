from __future__ import annotations

import json
import os
import subprocess
import sys
from types import SimpleNamespace
from pathlib import Path

import pytest
from conftest import load_script_module

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/skills/mcp/ReverseLabToolsMCP"))
from reverselab_mcp import paths, static_config
from reverselab_mcp.errors import ToolError
from reverselab_mcp.tools import ghidra_headless, ghidra_summary, ida_headless, static_analysis, workflow


@pytest.fixture
def lab(tmp_path, monkeypatch):
    ida = tmp_path / "ida"; ida.mkdir()
    ghidra = tmp_path / "ghidra"; ghidra.mkdir()
    sample = tmp_path / "sample.exe"; sample.write_bytes(b"synthetic test fixture")
    monkeypatch.setattr(paths, "ALLOWED_ROOTS", [tmp_path])
    monkeypatch.setattr(paths, "GHIDRA_EXPORTS_DIR", ghidra)
    monkeypatch.setattr(paths, "IDA_EXPORTS_DIR", ida)
    monkeypatch.setattr(ghidra_summary, "GHIDRA_EXPORTS_DIR", ghidra)
    monkeypatch.delenv("REVERSELAB_STATIC_BACKEND", raising=False)
    return tmp_path, sample, ida, ghidra


def summary_result(folder, backend="ida", **changes):
    data = {"backend": backend, "program": {"name": "sample.exe"}, "functions": [], "imports": [], "strings": []}
    path = folder / f"sample-{backend}-summary.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return {"returncode": 0, "summary_path": str(path), "summary": data, **changes}


def test_auto_prefers_ida(lab, monkeypatch):
    _, sample, ida, _ = lab
    monkeypatch.setattr(ida_headless, "ida_headless_analyze", lambda *a: summary_result(ida))
    monkeypatch.setattr(ghidra_headless, "ghidra_headless_analyze", lambda *a: pytest.fail("Ghidra must not run"))
    result = static_analysis.static_headless_analyze(str(sample))
    assert result["backend"] == "ida" and not result["fallback_used"]


@pytest.mark.parametrize("failure", ["missing", "timeout", "returncode", "empty", "malformed", "status"])
def test_auto_falls_back_for_ida_failures(lab, monkeypatch, failure):
    _, sample, ida, ghidra = lab
    def fail(*args):
        if failure == "missing": raise FileNotFoundError("not installed")
        if failure == "timeout": raise subprocess.TimeoutExpired("idat", 1)
        if failure == "empty": return {"returncode": 0, "summary": None}
        result = summary_result(ida)
        if failure == "returncode": result["returncode"] = 1
        if failure == "status": result["status"] = "error"
        if failure == "malformed": Path(result["summary_path"]).write_text("{}")
        return result
    monkeypatch.setattr(ida_headless, "ida_headless_analyze", fail)
    monkeypatch.setattr(ghidra_headless, "ghidra_headless_analyze", lambda *a: summary_result(ghidra, "ghidra"))
    result = static_analysis.static_headless_analyze(str(sample))
    assert result["status"] == "ok" and result["backend"] == "ghidra" and result["fallback_used"]
    assert [a["backend"] for a in result["attempts"]] == ["ida", "ghidra"]
    assert result["attempts"][0]["error"]


def test_explicit_ida_never_silently_switches(lab, monkeypatch):
    _, sample, _, _ = lab
    monkeypatch.setattr(ida_headless, "ida_headless_analyze", lambda *a: {"returncode": 1})
    monkeypatch.setattr(ghidra_headless, "ghidra_headless_analyze", lambda *a: pytest.fail("unexpected fallback"))
    result = static_analysis.static_headless_analyze(str(sample), "ida")
    assert result["status"] == "error" and len(result["attempts"]) == 1


def test_environment_default_and_explicit_override(lab, monkeypatch):
    _, sample, ida, ghidra = lab
    monkeypatch.setenv("REVERSELAB_STATIC_BACKEND", "ghidra")
    monkeypatch.setattr(ida_headless, "ida_headless_analyze", lambda *a: summary_result(ida))
    monkeypatch.setattr(ghidra_headless, "ghidra_headless_analyze", lambda *a: summary_result(ghidra, "ghidra"))
    assert static_analysis.static_headless_analyze(str(sample))["backend"] == "ghidra"
    assert static_analysis.static_headless_analyze(str(sample), "auto")["backend"] == "ida"


def test_both_fail_without_success_or_summary(lab, monkeypatch):
    _, sample, _, _ = lab
    for module, name in [(ida_headless, "ida_headless_analyze"), (ghidra_headless, "ghidra_headless_analyze")]:
        monkeypatch.setattr(module, name, lambda *a: {"returncode": 9, "stderr": "failed"})
    result = static_analysis.static_headless_analyze(str(sample))
    assert result["status"] == "error" and result["summary"] is None and not result["summary_path"]
    assert len(result["attempts"]) == 2


def test_invalid_input_never_launches(lab, monkeypatch):
    _, sample, _, _ = lab
    monkeypatch.setattr(ida_headless, "ida_headless_analyze", lambda *a: pytest.fail("must not launch"))
    with pytest.raises(ToolError): static_analysis.static_headless_analyze(str(sample), "bad-backend")
    with pytest.raises((ToolError, FileNotFoundError)): static_analysis.static_headless_analyze(str(sample) + ".missing")


def test_explicit_ida_path_is_not_silently_replaced(tmp_path, monkeypatch):
    bad = tmp_path / "missing-idat.exe"
    monkeypatch.setenv("REVERSELAB_IDA_EXE", str(bad))
    assert static_config.find_ida_executable() == bad


def test_summary_readers_accept_both_roots_and_reject_escape(lab):
    root, _, ida, ghidra = lab
    a = summary_result(ida); g = summary_result(ghidra, "ghidra")
    assert ghidra_summary.ghidra_summary_overview(a["summary_path"])["backend"] == "ida"
    assert paths.resolve_summary(g["summary_path"]).is_file()
    assert ghidra_summary.ghidra_summary_list(include_ida=True)["summaries_total"] == 2
    assert ghidra_summary.ghidra_summary_list()["summaries_total"] == 1
    os.utime(g["summary_path"], (100, 100))
    assert ghidra_summary.ghidra_summary_overview()["backend"] == "ghidra"
    assert paths.resolve_summary(include_ida=True) == Path(a["summary_path"])
    outside = root / "outside.json"; outside.write_text("{}")
    with pytest.raises(ToolError): paths.resolve_summary(str(outside))


def test_legacy_function_detail_reads_ida_contract(lab):
    _, _, ida, _ = lab
    result = summary_result(ida)
    result["summary"]["functions"] = [{"entry": "0x401000", "name": "main", "decompile": {"status": "ok", "preview": "return 0;"}, "callers": [], "callees": [], "import_refs": [], "string_refs": []}]
    Path(result["summary_path"]).write_text(json.dumps(result["summary"]))
    detail = ghidra_summary.ghidra_summary_function_detail(result["summary_path"], name="main")
    assert detail["function"]["decompile"]["preview"] == "return 0;"


@pytest.mark.parametrize("input_name", ["sample.exe", "analysis.i64", "export-options.json"])
def test_ida_uses_fresh_database_and_preserves_input(lab, monkeypatch, input_name):
    root, sample, ida, _ = lab
    sample = root / input_name
    sample.write_bytes(b"synthetic test fixture")
    exe = root / "idat.exe"; exe.write_bytes(b"mock")
    script = root / "export.py"; script.write_text("# mock")
    monkeypatch.setattr(ida_headless, "find_ida_executable", lambda: exe)
    monkeypatch.setattr(ida_headless, "IDA_SCRIPT", script)
    monkeypatch.setattr(ida_headless, "IDA_EXPORTS_DIR", ida)
    monkeypatch.setattr(ida_headless, "IDA_PROJECTS_DIR", root / "projects")
    calls = []
    def run(args, timeout):
        calls.append(args)
        project = Path(next(a[2:] for a in args if a.startswith("-o"))).parent
        options = json.loads((project / "export-options.json").read_text())
        data = {"run_id": options["run_id"], "program": {}, "functions": [], "imports": [], "strings": []}
        Path(options["output"]).write_text(json.dumps(data))
        return 0, "", ""
    monkeypatch.setattr(ida_headless, "run", run)
    before = sample.read_bytes()
    a = ida_headless.ida_headless_analyze(str(sample), overwrite=False)
    b = ida_headless.ida_headless_analyze(str(sample), overwrite=True)
    assert a["status"] == b["status"] == "ok" and a["project_location"] != b["project_location"]
    assert sample.read_bytes() == before and Path(calls[0][-1]) != sample
    assert "-A" in calls[0] and "-c" in calls[0]


def test_failed_export_is_not_published_as_successful_summary(tmp_path, monkeypatch):
    exporter = load_script_module("scripts/_shared/ida/export_summary.py", "ida_exporter_test")
    output = tmp_path / "sample-ida-summary.json"
    options = tmp_path / "options.json"
    options.write_text(json.dumps({"output": str(output)}))
    exits = []
    monkeypatch.setitem(sys.modules, "ida_pro", SimpleNamespace(qexit=exits.append))
    monkeypatch.setitem(sys.modules, "idc", SimpleNamespace(ARGV=["export.py", str(options)]))
    def fail(*a): raise RuntimeError("synthetic export failure")
    monkeypatch.setattr(exporter, "export", fail)
    exporter.main()
    assert exits == [1] and not output.exists()
    assert "synthetic export failure" in output.with_suffix(".error.json").read_text()


def test_ghidra_does_not_return_old_summary(lab, monkeypatch):
    root, sample, _, ghidra = lab
    summary_result(ghidra, "ghidra")
    exe = root / "analyzeHeadless"; exe.write_text("mock")
    script = root / "ReverseLabExportSummary.java"; script.write_text("mock")
    monkeypatch.setattr(ghidra_headless, "GHIDRA_EXPORTS_DIR", ghidra)
    monkeypatch.setattr(ghidra_headless, "GHIDRA_PROJECTS_DIR", root / "gprojects")
    monkeypatch.setattr(ghidra_headless, "GHIDRA_SCRIPT_DIR", root)
    monkeypatch.setattr(ghidra_headless, "GHIDRA_HEADLESS_BAT", exe)
    monkeypatch.setattr(ghidra_headless, "run", lambda *a, **k: (0, "", ""))
    result = ghidra_headless.ghidra_headless_analyze(str(sample))
    assert result["status"] == "error" and result["summary"] is None


def test_autopilot_uses_ida_first_and_preserves_backend_preference():
    actions = workflow._build_action_queue({"sample_path": "synthetic.exe", "summary_path": "", "static_backend": "ida"}, 1)
    assert actions[0]["params"]["run_static"] is True
    assert actions[0]["params"]["static_backend"] == "ida"
    assert not actions[0]["params"].get("run_ghidra", False)


@pytest.mark.parametrize("kwargs,expected", [({}, "auto"), ({"run_ghidra": True}, "ghidra"), ({"static_backend": "ida"}, "ida"), ({"run_static": False}, None), ({"summary_path": "existing.json"}, None)])
def test_workflow_default_legacy_and_skip_modes(lab, monkeypatch, kwargs, expected):
    root, sample, _, _ = lab
    monkeypatch.setattr(workflow, "REPORTS_DIR", root)
    def report(*a, **k):
        p = root / "report.md"; p.write_text("test"); return p
    monkeypatch.setattr(workflow, "_write_battleplan_report", report)
    selected = []
    def safe_step(name, func, *args, **kw):
        if name in ["static_analysis", "ghidra_headless"]:
            selected.append(args[1])
            return {"status": "ok", "summary_path": "new.json", "backend": args[1]}
        return {"status": "ok"}
    monkeypatch.setattr(workflow, "_safe_step", safe_step)
    result = workflow.sample_full_workup(str(sample), **kwargs)
    assert selected == ([] if expected is None else [expected])
    manifest = json.loads(Path(result["manifest_path"]).read_text())
    assert manifest["static_backend"] == result["static_backend"]
