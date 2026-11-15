"""Runtime distribution and shared KB adapters exercise real installed packages."""
from __future__ import annotations

import io
import json
from pathlib import Path
import subprocess
import sys
import zipfile

from conftest import ROOT, load_script_module

sys.path.insert(0, str(ROOT / "scripts" / "misc"))
from desktop_kb import build_catalog, read_document
from extension_protocol import PROTOCOL, json_bytes, pack
from extension_store import ExtensionStore
import kb_router


def fixture_pack(folder: Path) -> Path:
    folder.mkdir()
    (folder / "a.md").write_text("# Optical signals\n\n[Verify](b.md)\n", encoding="utf-8")
    (folder / "b.md").write_text("# Verify optical signal\n", encoding="utf-8")
    docs = [{"id": f"example.optical/docs/{name}", "path": f"{name}.md", "title": title,
             "track": track, "domain": "optical-systems"} for name, title, track in (("a", "Optical signals", "red"), ("b", "Verify optical signal", "blue"))]
    methods = [{"id": f"example.optical/{name}", "document": f"example.optical/docs/{name}", "title": title,
                "domain": "optical-systems", "track": track, "signals": ["optical"], "requiresEvidence": [], "produces": [], "toolRequirements": []}
               for name, title, track in (("a", "Inspect", "red"), ("b", "Verify", "blue"))]
    knowledge = {"domains": ["optical-systems"], "documents": docs, "methods": methods, "bindings": [],
                 "networks": [{"id": "example.optical/network", "title": "Optical network", "track": "shared",
                               "entrypoints": ["example.optical/a"], "nodes": ["example.optical/a", "example.optical/b"],
                               "relations": [{"from": "example.optical/b", "to": "example.optical/a", "type": "verifies"}]}]}
    (folder / "knowledge.json").write_bytes(json_bytes(knowledge))
    (folder / "reverselab.extension.json").write_bytes(json_bytes({"protocol": PROTOCOL, "id": "example.optical",
        "version": "1.0.0", "kind": "knowledge", "title": "Optical methods", "description": "Synthetic extension integration fixture.",
        "license": "Apache-2.0", "knowledge": "knowledge.json", "files": ["knowledge.json", "a.md", "b.md"], "requires": []}))
    return folder


def test_new_domain_install_search_read_disable_and_retained_reference(tmp_path, monkeypatch):
    monkeypatch.setenv("REVERSELAB_EXTENSIONS_DIR", str(tmp_path / "store"))
    store = ExtensionStore()
    source = fixture_pack(tmp_path / "source")
    archive = tmp_path / "pack.zip"
    pack(source, archive)
    inspection = store.inspect(str(archive))
    installed = store.install(inspection["inspectionId"], inspection["entries"][0]["id"])
    # A packaged runtime has no source kb directory.
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    catalog = build_catalog("both", runtime)
    assert len(catalog) == 2
    assert {doc["board"] for doc in catalog} == {"optical-systems"}
    red = next(doc for doc in catalog if doc["track"] == "red")
    blue = next(doc for doc in catalog if doc["track"] == "blue")
    assert blue["path"] in red["related_paths"]
    assert store.resolve_link(red["path"], "b.md") == blue["path"]
    assert "Optical signals" in read_document(red["path"], runtime)
    monkeypatch.setattr(kb_router, "ROOT", runtime)
    hits = kb_router.search("optical", kb_router.load_index("optical-systems"), "both")
    assert len(hits) == 2 and hits[0]["files"][0].startswith("reverselab://")
    pins = store.pin()
    store.enable(installed["installationId"], False)
    assert build_catalog("both", runtime) == []
    assert len(store.catalog("both", pins)) == 2
    assert read_document(red["path"], runtime).startswith("# Optical")
    exported = tmp_path / "exported.zip"
    store.export(installed["installationId"], str(exported))
    other = ExtensionStore(tmp_path / "other-store")
    preview = other.inspect(str(exported))
    reinstalled = other.install(preview["inspectionId"], preview["entries"][0]["id"])
    assert reinstalled["digest"] == installed["digest"]
    assert len(other.graph()["networks"]) == 1


def test_installer_and_portable_share_runtime_without_knowledge_or_tool_sources(tmp_path):
    release = load_script_module("scripts/misc/package_desktop_release.py", "extension_release_test")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name in release.RUNTIME_FILES:
            archive.write(ROOT / name, name)
        archive.writestr("kb/red/example.md", "knowledge payload")
        archive.writestr("tools/skills/example.md", "tool payload")
        archive.writestr("README.md", "source overview")
    with zipfile.ZipFile(io.BytesIO(buffer.getvalue())) as archive:
        entries = dict(release.runtime_entries(archive))
    assert not any(path.startswith(("kb/", "tools/")) for path in entries)
    runtime = tmp_path / "runtime"
    for path, raw in entries.items():
        destination = runtime / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw)
    env = __import__("os").environ.copy()
    env["REVERSELAB_EXTENSIONS_DIR"] = str(tmp_path / "clean-store")
    env["REVERSELAB_DATA_DIR"] = str(tmp_path / "data")
    result = subprocess.run([sys.executable, str(runtime / "scripts/misc/desktop_kb.py"), "list"], env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == []
    for command in ("desktop_extensions.py", "desktop_mcp.py"):
        result = subprocess.run([sys.executable, str(runtime / "scripts/misc" / command)], input='{"operation":"list"}', env=env, capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout)["ok"] is True
    result = subprocess.run([sys.executable, str(runtime / "scripts/misc/desktop_extensions.py")], input='{"operation":"sources/list"}', env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    sources = json.loads(result.stdout)["sources"]
    assert len(sources) == 1
    assert sources[0]["source"] == "https://github.com/LING71671/open-reverselab-knowledge"
    assert not (runtime / "kb").exists()
