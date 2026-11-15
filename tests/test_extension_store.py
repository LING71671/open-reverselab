from __future__ import annotations

import base64
import io
import json
from pathlib import Path
import stat
import subprocess
import sys
import zipfile

import pytest

from conftest import ROOT, load_script_module

store_module = load_script_module("scripts/misc/extension_store.py", "extension_store")
protocol = store_module.protocol
ExtensionStore = store_module.ExtensionStore
cli = load_script_module("scripts/misc/desktop_extensions.py", "desktop_extensions")


def make_package(root: Path, pack_id: str = "example.integrity", version: str = "1.0.0", **extra) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    manifest = {"protocol": protocol.PROTOCOL, "kind": "knowledge", "id": pack_id, "version": version, "title": "Integrity", "description": "Synthetic checks", "license": "MIT", "files": ["knowledge.json", "docs/read.md", "docs/check.md"], "requires": [], "knowledge": "knowledge.json", "extensions": {"futureOptional": {"preserve": True}}, **extra}
    document = lambda name: {"id": f"{pack_id}/docs/{name}", "title": name.title(), "path": f"docs/{name}.md", "track": "shared", "domain": "new-domain", "aliases": [f"legacy/{name}.md"]}
    method = lambda name: {"id": f"{pack_id}/{name}", "title": name.title(), "document": f"{pack_id}/docs/{name}", "track": "shared", "domain": "new-domain", "signals": ["integrity"], "requiresEvidence": [], "produces": [name], "toolRequirements": []}
    knowledge = {"domains": ["new-domain"], "documents": [document("read"), document("check")], "methods": [method("read"), method("check")], "networks": [{"id": f"{pack_id}/network", "title": "Integrity network", "track": "shared", "nodes": [f"{pack_id}/read", f"{pack_id}/check"], "entrypoints": [f"{pack_id}/read"], "relations": [{"from": f"{pack_id}/check", "to": f"{pack_id}/read", "type": "depends_on"}]}]}
    (root / protocol.MANIFEST).write_bytes(protocol.json_bytes(manifest))
    (root / "knowledge.json").write_bytes(protocol.json_bytes(knowledge))
    (root / "docs").mkdir(exist_ok=True)
    (root / "docs/read.md").write_text("# Read\n\n[Check](check.md)\n", encoding="utf-8")
    (root / "docs/check.md").write_text("# Check\n", encoding="utf-8")
    return root


def install(store, source):
    inspection = store.inspect(str(source))
    return store.install(inspection["inspectionId"], inspection["entries"][0]["id"])


def test_install_export_and_pinned_history(tmp_path):
    source = make_package(tmp_path / "source")
    store = ExtensionStore(tmp_path / "store")
    entry = install(store, source)
    pins = store.pin()
    documents = store.catalog()
    assert documents[0]["board"] == "new-domain"
    assert store.read_document(documents[0]["path"]).startswith("# Read")
    assert store.resolve_link(documents[0]["path"], "check.md") == documents[1]["path"]
    assert store.neighbors("example.integrity/read")["relations"]
    assert documents[0]["related_paths"] == [documents[1]["path"]]
    exported = store.export(entry["installationId"], tmp_path / "pack.zip")
    payload, archive = protocol.load(Path(exported["path"]))
    assert protocol.validate(payload, archive)["extensions"]["futureOptional"]["preserve"] is True
    removed = store.remove(entry["installationId"])
    assert removed["retained"] and store.catalog() == []
    assert store.catalog(pinned=pins)[0]["path"] == documents[0]["path"]
    assert store.read_document(documents[0]["path"]).startswith("# Read")


def test_inspection_is_immutable_and_same_version_cannot_change(tmp_path):
    source = make_package(tmp_path / "source")
    store = ExtensionStore(tmp_path / "store")
    inspection = store.inspect(str(source))
    (source / "docs/read.md").write_text("Changed after inspection", encoding="utf-8")
    entry = store.install(inspection["inspectionId"], "example.integrity")
    assert store.read_document(store.catalog()[0]["path"]).startswith("# Read")
    changed = store.inspect(str(source))
    with pytest.raises(ValueError, match="different content"):
        store.install(changed["inspectionId"], "example.integrity")
    assert store.list()[0]["installationId"] == entry["installationId"]
    assert store.list()[0]["enabled"]


def test_update_keeps_old_pin_and_sources_do_not_collide(tmp_path):
    source = make_package(tmp_path / "source")
    store = ExtensionStore(tmp_path / "store")
    first = install(store, source)
    pins = store.pin()
    make_package(source, version="1.1.0")
    second = install(store, source)
    other = install(store, make_package(tmp_path / "other"))
    assert len({first["installationId"], second["installationId"], other["installationId"]}) == 3
    assert store.get(first["installationId"])["enabled"] is False
    assert store.catalog(pinned=pins)[0]["version"] == "1.0.0"
    with pytest.raises(ValueError, match="ambiguous"):
        store.resolve("example.integrity/read")
    graph = store.graph()
    assert len(graph["networks"]) == 2
    assert len({network["id"] for network in graph["networks"]}) == 2
    for network in graph["networks"]:
        prefix = "reverselab://" + network["installationId"] + "/"
        assert all(node.startswith(prefix) for node in network["nodes"])
        assert all(edge[end].startswith(prefix) for edge in network["relations"] for end in ("from", "to"))


def test_missing_dependencies_and_unknown_features_never_activate(tmp_path):
    source = make_package(tmp_path / "source", requires=[{"id": "example.base", "version": "1.0.0", "source": "https://github.com/example/base", "optional": False}])
    store = ExtensionStore(tmp_path / "store")
    inspected = store.inspect(str(source))
    with pytest.raises(ValueError, match="Required dependency unavailable"):
        store.install(inspected["inspectionId"], "example.integrity")
    assert store.list() == []
    make_package(source, requiredFeatures=["future/unknown"])
    inspected = store.inspect(str(source))
    with pytest.raises(ValueError, match="Unsupported requiredFeatures"):
        store.install(inspected["inspectionId"], "example.integrity")
    assert store.list() == []


def test_external_references_and_dependency_history(tmp_path):
    source = make_package(tmp_path / "base", pack_id="example.base")
    store = ExtensionStore(tmp_path / "store")
    base = install(store, source)
    dependent = make_package(tmp_path / "dependent", requires=[{"id": "example.base", "version": "1.0.0", "source": base["source"]["identity"], "optional": False}])
    data = json.loads((dependent / "knowledge.json").read_text())
    data["methods"][0]["document"] = "example.base/docs/read"
    data["networks"][0]["nodes"].append("example.base/read")
    data["networks"][0]["relations"].append({"from": "example.integrity/check", "to": "example.base/read", "type": "verifies"})
    (dependent / "knowledge.json").write_bytes(protocol.json_bytes(data))
    item = install(store, dependent)
    with pytest.raises(ValueError, match="Required by enabled"):
        store.enable(base["installationId"], False)
    make_package(source, pack_id="example.base", version="2.0.0")
    install(store, source)
    assert base["installationId"] in {pin["installationId"] for pin in store.pin()}
    graph = store.graph()
    dependency_method = next(method for method in graph["methods"] if method["installationId"] == item["installationId"] and method["entityId"].endswith("/read"))
    assert dependency_method["document"] in {document["id"] for document in graph["documents"]}
    network = next(network for network in graph["networks"] if network["installationId"] == item["installationId"])
    assert {"from": store.uri(item["installationId"], "example.integrity/check"),
            "to": store.uri(base["installationId"], "example.base/read"), "type": "verifies"} in network["relations"]
    result = store.remove(base["installationId"])
    assert item["installationId"] in result["disabledDependents"]


def test_bad_external_reference_rejected(tmp_path):
    store = ExtensionStore(tmp_path / "store")
    base = install(store, make_package(tmp_path / "base", pack_id="example.base"))
    source = make_package(tmp_path / "dependent", requires=[{"id": "example.base", "version": "1.0.0", "source": base["source"]["identity"], "optional": False}])
    data = json.loads((source / "knowledge.json").read_text())
    data["methods"][0]["document"] = "example.base/does-not-exist"
    (source / "knowledge.json").write_bytes(protocol.json_bytes(data))
    with pytest.raises(ValueError, match="Unresolved external"):
        install(store, source)
    assert len(store.list()) == 1


@pytest.mark.parametrize("name", ["../escape", "/absolute", "docs/../escape", "docs\\escape", "CON.txt", "file:stream"])
def test_archive_path_rejection(tmp_path, name):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(name, b"bad")
    store = ExtensionStore(tmp_path / "store")
    with pytest.raises(ValueError):
        store.inspect(archive_base64=base64.b64encode(buffer.getvalue()).decode())
    assert store.list() == []


def test_archive_link_case_collision_and_hash_rejection(tmp_path):
    source = make_package(tmp_path / "source")
    payload, _ = protocol.load(source)
    good = protocol.zip_bytes(payload)
    store = ExtensionStore(tmp_path / "store")
    for mode in ("link", "collision", "hash"):
        buffer = io.BytesIO(good)
        with zipfile.ZipFile(buffer, "a") as archive:
            if mode == "link":
                info = zipfile.ZipInfo("symlink")
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
                archive.writestr(info, "docs/read.md")
            elif mode == "collision":
                archive.writestr("DOCS/read.md", "collision")
            else:
                archive.writestr("docs/read.md", "changed")
        with pytest.raises(ValueError):
            store.inspect(archive_base64=base64.b64encode(buffer.getvalue()).decode())
    files = store_module._archive_files(good)
    files["docs/read.md"] = b"tampered"
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, raw in files.items():
            archive.writestr(name, raw)
    with pytest.raises(ValueError, match="digest mismatch"):
        store.inspect(archive_base64=base64.b64encode(buffer.getvalue()).decode())


def test_archive_requires_lock_and_explicit_draft_migration(tmp_path):
    source = make_package(tmp_path / "source")
    payload, _ = protocol.load(source)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, raw in payload.items():
            archive.writestr(name, raw)
    store = ExtensionStore(tmp_path / "store")
    with pytest.raises(ValueError, match="missing reverselab.lock"):
        store.inspect(archive_base64=base64.b64encode(buffer.getvalue()).decode())
    manifest = json.loads((source / protocol.MANIFEST).read_text())
    manifest["protocol"] = "open-reverselab.extension/v1-draft"
    (source / protocol.MANIFEST).write_bytes(protocol.json_bytes(manifest))
    with pytest.raises(ValueError, match="explicit migration"):
        store.inspect(str(source))
    inspected = store.inspect(str(source), migrate_draft=True)
    assert store.install(inspected["inspectionId"], "example.integrity")["enabled"]


def test_three_valued_conditions():
    observed = {"evidence": "digest", "state": "observed"}
    assert protocol.evaluate_condition(observed, {}) is None
    assert protocol.evaluate_condition({"not": observed}, {}) is None
    assert protocol.evaluate_condition({"all": []}, {}) is True
    assert protocol.evaluate_condition({"any": []}, {}) is False
    assert protocol.evaluate_condition({"all": [observed, {"any": []}]}, {}) is False
    assert protocol.evaluate_condition({"any": [observed, {"all": []}]}, {}) is True
    assert protocol.evaluate_condition(observed, {"digest": {"state": "observed"}}) is True
    assert protocol.evaluate_condition(observed, {"digest": "absent"}) is False


def test_github_catalog_is_metadata_only_and_pins_slash_ref(tmp_path, monkeypatch):
    source = make_package(tmp_path / "source")
    payload, _ = protocol.load(source)
    commit = "a" * 40
    registry = {"protocol": protocol.REGISTRY_PROTOCOL, "id": "example.catalog", "title": "Catalog", "entries": [{"id": "example.integrity", "kind": "knowledge", "title": "Integrity", "version": "1.0.0", "path": "packs/integrity"}]}
    calls = []

    def fetch(url, *, optional=False, github_recursive=False):
        protocol.validate_https(url)
        calls.append(url)
        if url == "https://api.github.com/repos/example/extensions":
            return protocol.json_bytes({"default_branch": "main"})
        if "/commits/feature%2Ftopic%2Fcatalog" in url:
            return None
        if "/commits/feature%2Ftopic" in url:
            return protocol.json_bytes({"sha": commit})
        if url.endswith("/git/trees/" + commit):
            return protocol.json_bytes({"tree": [{"path": "catalog/packs/integrity/" + name, "type": "blob", "mode": "100644"} for name in payload]})
        prefix = f"https://raw.githubusercontent.com/example/extensions/{commit}/catalog/"
        if url == prefix + protocol.REGISTRY:
            return protocol.json_bytes(registry)
        if url.startswith(prefix + "packs/integrity/"):
            name = url.removeprefix(prefix + "packs/integrity/")
            return payload.get(name)
        raise AssertionError(url)

    monkeypatch.setattr(store_module, "_read_url", fetch)
    store = ExtensionStore(tmp_path / "store")
    inspected = store.inspect("https://github.com/example/extensions/tree/feature/topic/catalog")
    assert inspected["source"]["commit"] == commit
    assert inspected["source"]["ref"] == "feature/topic"
    assert not any("knowledge.json" in url for url in calls)
    item = store.install(inspected["inspectionId"], "example.integrity")
    assert item["source"]["path"] == "catalog/packs/integrity"
    assert any(commit + "/catalog/packs/integrity/knowledge.json" in url for url in calls)


def test_local_catalog_and_sources_refresh_preserve_install(tmp_path):
    source = tmp_path / "catalog"
    make_package(source / "packs/integrity")
    registry = {"protocol": protocol.REGISTRY_PROTOCOL, "id": "example.catalog", "title": "Catalog", "entries": [{"id": "example.integrity", "kind": "knowledge", "title": "Integrity", "version": "1.0.0", "path": "packs/integrity"}]}
    (source / protocol.REGISTRY).write_bytes(protocol.json_bytes(registry))
    store = ExtensionStore(tmp_path / "store")
    item = install(store, source)
    saved = store.sources_add(str(source))
    refreshed = store.sources_refresh(saved["sourceId"])
    assert refreshed["entries"][0]["id"] == "example.integrity"
    store.sources_remove(saved["sourceId"])
    assert [entry["source"] for entry in store.sources_list()] == [store_module.OFFICIAL_KNOWLEDGE_URL]
    assert store.get(item["installationId"])["enabled"]


def test_official_source_available_offline_without_installing_or_writing(tmp_path, monkeypatch):
    def offline(*args, **kwargs):
        pytest.fail("Listing sources must not access the network")
    monkeypatch.setattr(store_module, "_read_url", offline)
    store = ExtensionStore(tmp_path / "store")
    assert store.sources_list() == [store_module.OFFICIAL_KNOWLEDGE_SOURCE]
    assert store.list() == [] and store.catalog() == []
    assert not store.root.exists()


@pytest.mark.parametrize("already_added", [False, True])
def test_official_source_merges_existing_profiles_without_duplicates(tmp_path, already_added):
    store = ExtensionStore(tmp_path / "store")
    custom = {"sourceId": "custom", "source": "https://github.com/example/knowledge", "title": "My catalog"}
    existing = {"sourceId": "legacy", "source": store_module.OFFICIAL_KNOWLEDGE_URL + ".git/", "inspectionId": "retained"}
    state = {"sources": [custom, existing] if already_added else [custom]}
    store_module._atomic_json(store.root / "sources.json", state)
    sources = store.sources_list()
    assert custom in sources and len(sources) == 2
    official = next(item for item in sources if item != custom)
    assert official["title"] == store_module.OFFICIAL_KNOWLEDGE_SOURCE["title"]
    assert store.sources_add(store_module.OFFICIAL_KNOWLEDGE_URL) == official
    assert store.sources_add(store_module.OFFICIAL_KNOWLEDGE_URL.lower() + "/") == official
    assert len(ExtensionStore(store.root).sources_list()) == 2
    if already_added:
        assert official["sourceId"] == "legacy" and official["inspectionId"] == "retained"


def test_removed_official_source_stays_removed_and_can_be_added_again(tmp_path, monkeypatch):
    store = ExtensionStore(tmp_path / "store")
    official = store.sources_list()[0]
    store.sources_remove(official["sourceId"])
    store = ExtensionStore(store.root)
    assert store.sources_list() == []
    custom = store.sources_add("https://github.com/example/knowledge")
    monkeypatch.setattr(store, "inspect", lambda source: {"inspectionId": "inspected", "entries": [], "source": {"identity": source}})
    store.sources_refresh(custom["sourceId"])
    assert len(ExtensionStore(store.root).sources_list()) == 1
    store.sources_remove(custom["sourceId"])
    assert ExtensionStore(store.root).sources_list() == []
    assert store.sources_add(store_module.OFFICIAL_KNOWLEDGE_URL + "/") == official
    assert ExtensionStore(store.root).sources_list() == [official]


@pytest.mark.parametrize("catalog_source", ["github", "folder", "zip"])
def test_catalog_repository_uses_destination_identity_and_pinned_commit(tmp_path, monkeypatch, catalog_source):
    payload, _ = protocol.load(make_package(tmp_path / "pack"))
    commit = "c" * 40
    registry = {"protocol": protocol.REGISTRY_PROTOCOL, "id": "example.catalog", "title": "Catalog",
                "entries": [{"id": "example.integrity", "kind": "knowledge", "title": "Integrity", "version": "1.0.0",
                             "repository": "https://github.com/example/knowledge"}]}
    calls = []

    def fetch(url, *, optional=False, github_recursive=False):
        protocol.validate_https(url)
        calls.append(url)
        if url in {"https://api.github.com/repos/example/app", "https://api.github.com/repos/example/knowledge"}:
            return protocol.json_bytes({"default_branch": "main"})
        if url.endswith("/commits/main"):
            return protocol.json_bytes({"sha": commit})
        if url == f"https://raw.githubusercontent.com/example/app/{commit}/{protocol.REGISTRY}":
            return protocol.json_bytes(registry)
        if url == f"https://api.github.com/repos/example/knowledge/git/trees/{commit}":
            if github_recursive:
                return protocol.json_bytes({"truncated": True, "tree": []})
            return protocol.json_bytes({"tree": [{"path": name, "type": "blob", "mode": "100644"} for name in payload if "/" not in name]
                + [{"path": "docs", "type": "tree", "sha": "d" * 40}]})
        if url == "https://api.github.com/repos/example/knowledge/git/trees/" + "d" * 40:
            return protocol.json_bytes({"tree": [{"path": name[5:], "type": "blob", "mode": "100644"} for name in payload if name.startswith("docs/")]})
        prefix = f"https://raw.githubusercontent.com/example/knowledge/{commit}/"
        if url.startswith(prefix):
            return payload.get(url.removeprefix(prefix))
        raise AssertionError(url)

    monkeypatch.setattr(store_module, "_read_url", fetch)
    store = ExtensionStore(tmp_path / "store")
    if catalog_source == "github":
        inspected = store.inspect("https://github.com/example/app")
    else:
        folder = tmp_path / "catalog"
        folder.mkdir()
        (folder / protocol.REGISTRY).write_bytes(protocol.json_bytes(registry))
        if catalog_source == "zip":
            archive = tmp_path / "catalog.zip"
            with zipfile.ZipFile(archive, "w") as output:
                output.writestr("catalog/" + protocol.REGISTRY, protocol.json_bytes(registry))
            inspected = store.inspect(str(archive))
        else:
            inspected = store.inspect(str(folder))
    entry = inspected["entries"][0]
    assert entry["source"]["identity"] == "https://github.com/example/knowledge"
    assert entry["source"]["commit"] == commit
    assert not any(url.endswith("knowledge.json") for url in calls)
    calls.clear()
    installed = store.install(inspected["inspectionId"], entry["id"])
    assert not any("/commits/" in url for url in calls)  # Do not re-resolve a moving branch.
    direct = install(store, "https://github.com/example/knowledge")
    assert direct["installationId"] == installed["installationId"]
    assert len(store.list()) == 1


@pytest.mark.parametrize("location", [
    {"repository": "https://example.com/knowledge"},
    {"repository": "https://github.com/example/knowledge?ref=main"},
    {"repository": "https://github.com/example/knowledge", "path": "kb"},
    {"repository": "https://github.com/example/knowledge", "artifact": "https://example.com/kb.zip", "sha256": "a" * 64},
])
def test_catalog_rejects_ambiguous_or_invalid_repository_locations(location):
    registry = {"protocol": protocol.REGISTRY_PROTOCOL, "id": "example.catalog", "title": "Catalog",
                "entries": [{"id": "example.integrity", "kind": "knowledge", "title": "Integrity", "version": "1.0.0", **location}]}
    with pytest.raises(ValueError):
        protocol.validate_registry(registry)


def test_recursive_github_tree_query_is_added_only_by_transport(monkeypatch):
    tree_url = "https://api.github.com/repos/example/knowledge/git/trees/" + "a" * 40
    requests = []

    class Response:
        url = tree_url + "?recursive=1"
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
        def read(self):
            return b'{"tree": []}'

    class Opener:
        def open(self, request, timeout):
            requests.append(request.full_url)
            return Response()

    monkeypatch.setattr(store_module, "build_opener", lambda *args: Opener())
    assert store_module._read_url(tree_url, github_recursive=True) == b'{"tree": []}'
    assert requests == [tree_url + "?recursive=1"]
    with pytest.raises(ValueError):
        store_module._read_url(tree_url + "?recursive=1")
    with pytest.raises(ValueError):
        store_module._read_url("https://example.com/tree", github_recursive=True)


def test_mcp_install_is_descriptor_only_and_export_contains_no_local_inputs(tmp_path):
    source = tmp_path / "mcp"
    source.mkdir()
    descriptor = {"transport": "stdio", "command": "never-execute-this", "args": ["${inputs.endpoint}"], "inputs": [{"name": "endpoint", "type": "url", "required": True}]}
    manifest = {"protocol": protocol.PROTOCOL, "kind": "mcp", "id": "example.mcp", "version": "1.0.0", "title": "MCP", "description": "Synthetic descriptor", "license": "MIT", "files": ["connection.json"], "mcp": "connection.json"}
    (source / protocol.MANIFEST).write_bytes(protocol.json_bytes(manifest))
    (source / "connection.json").write_bytes(protocol.json_bytes(descriptor))
    store = ExtensionStore(tmp_path / "store")
    item = install(store, source)
    assert item["descriptor"] == descriptor
    assert store.catalog() == []
    (store.root / "mcp-connections.json").write_text('{"secret":"never-export"}')
    exported = store.export(item["installationId"])
    files = store_module._archive_files(base64.b64decode(exported["archiveBase64"]))
    assert not any(b"never-export" in raw for raw in files.values())
    descriptor["inputs"][0]["value"] = "secret"
    with pytest.raises(ValueError, match="locally"):
        protocol.validate_mcp(descriptor)


def test_json_cli_contract_and_process(tmp_path, monkeypatch):
    store = ExtensionStore(tmp_path / "store")
    inspected = cli.dispatch({"operation": "inspect", "source": str(make_package(tmp_path / "source"))}, store)
    cli.dispatch({"operation": "install", "inspectionId": inspected["inspectionId"], "entryId": "example.integrity"}, store)
    assert cli.dispatch({"operation": "pin"}, store)["pins"]
    catalog = cli.dispatch({"operation": "catalog"}, store)
    assert catalog["entries"] == catalog["documents"]
    monkeypatch.setenv("REVERSELAB_EXTENSIONS_DIR", str(store.root))
    result = subprocess.run([sys.executable, str(ROOT / "scripts/misc/desktop_extensions.py")], input='{"operation":"list"}', text=True, capture_output=True, check=True)
    assert json.loads(result.stdout)["ok"] is True
    assert not result.stderr


def test_enclosing_source_archive_computes_lock_without_importing_extra_files(tmp_path):
    payload, _ = protocol.load(make_package(tmp_path / "source"))
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, raw in payload.items():
            archive.writestr("repository-main/" + name, raw)
        archive.writestr("repository-main/README.md", "Repository notes")
    store = ExtensionStore(tmp_path / "store")
    inspection = store.inspect(archive_base64=base64.b64encode(buffer.getvalue()).decode(), filename="repository-main.zip")
    assert inspection["warnings"]
    installed = store.install(inspection["inspectionId"], "example.integrity")
    assert not (Path(installed["root"]) / "README.md").exists()
    lock = json.loads((Path(installed["root"]) / protocol.LOCK).read_text())
    assert lock["provenance"]["computedOnImport"]


def test_source_archive_respects_root_catalog_and_ignores_undeclared_examples(tmp_path):
    source = tmp_path / "repo"
    make_package(source / "packs/declared", pack_id="example.declared")
    make_package(source / "examples/extra", pack_id="example.extra")
    registry = {"protocol": protocol.REGISTRY_PROTOCOL, "id": "example.catalog", "title": "Catalog", "entries": [
        {"id": "example.declared", "kind": "knowledge", "version": "1.0.0", "title": "Declared", "path": "packs/declared"}
    ]}
    (source / protocol.REGISTRY).write_bytes(protocol.json_bytes(registry))
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as output:
        for path in source.rglob("*"):
            if path.is_file():
                output.writestr("repository-main/" + path.relative_to(source).as_posix(), path.read_bytes())
    store = ExtensionStore(tmp_path / "store")
    inspection = store.inspect(archive_base64=base64.b64encode(archive.getvalue()).decode())
    assert [entry["id"] for entry in inspection["entries"]] == ["example.declared"]
    store.install(inspection["inspectionId"], "example.declared")
    assert len(store.catalog()) == 2


def test_github_payload_rejects_symlinks(tmp_path, monkeypatch):
    monkeypatch.setattr(store_module, "_read_url", lambda url, **kwargs: protocol.json_bytes({"tree": [
        {"path": "docs/read.md", "type": "blob", "mode": "120000"}
    ]}))
    with pytest.raises(ValueError, match="regular Git file"):
        store_module._github_regular_files({"owner": "example", "repo": "pack", "commit": "a" * 40}, ["docs/read.md"])


def test_selected_network_export_closes_dependencies_and_changes_identity(tmp_path):
    source = make_package(tmp_path / "source")
    data = json.loads((source / "knowledge.json").read_text())
    data["networks"].append({"id": "example.integrity/selected", "title": "Selection", "track": "shared", "nodes": ["example.integrity/check"], "entrypoints": ["example.integrity/check"], "relations": []})
    (source / "knowledge.json").write_bytes(protocol.json_bytes(data))
    store = ExtensionStore(tmp_path / "store")
    entry = install(store, source)
    exported = store.export(entry["installationId"], network_ids=[store.uri(entry["installationId"], "example.integrity/selected")])
    files = store_module._archive_files(base64.b64decode(exported["archiveBase64"]))
    manifest = protocol.validate(files, archive=True)
    assert manifest["id"] != entry["id"]
    assert manifest["id"] == exported["derivedPackId"]
    assert manifest["origin"]["digest"] == entry["digest"]
    subset = json.loads(files["knowledge.json"])
    assert len(subset["methods"]) == 2
    assert len(subset["documents"]) == 2
    assert any(network["id"].endswith("/dependency-closure") for network in subset["networks"])
    imported = store.inspect(archive_base64=exported["archiveBase64"])
    store.install(imported["inspectionId"], exported["derivedPackId"])
    assert all(method["origin"]["id"].startswith("example.integrity/") for method in subset["methods"])


def test_tampered_dependency_lock_rejected(tmp_path):
    store = ExtensionStore(tmp_path / "store")
    base = install(store, make_package(tmp_path / "base", pack_id="example.base"))
    source = make_package(tmp_path / "dependent", requires=[{"id": "example.base", "version": "1.0.0", "source": base["source"]["identity"], "optional": False}])
    dependent = install(store, source)
    raw = base64.b64decode(store.export(dependent["installationId"])["archiveBase64"])
    payload = store_module._archive_files(raw)
    lock = json.loads(payload[protocol.LOCK])
    lock["dependencies"][0]["digest"] = "0" * 64
    payload[protocol.LOCK] = protocol.json_bytes(lock)
    inspection = store.inspect(archive_base64=base64.b64encode(protocol.zip_bytes(payload)).decode())
    with pytest.raises(ValueError, match="exported lock"):
        store.install(inspection["inspectionId"], "example.integrity")


def test_failed_atomic_activation_leaves_previous_registry(tmp_path, monkeypatch):
    source = make_package(tmp_path / "source")
    store = ExtensionStore(tmp_path / "store")
    first = install(store, source)
    make_package(source, version="2.0.0")
    inspection = store.inspect(str(source))
    original = store_module._atomic_json

    def fail(path, value):
        if path == store.registry_path:
            raise OSError("Synthetic failed registry write")
        original(path, value)

    monkeypatch.setattr(store_module, "_atomic_json", fail)
    with pytest.raises(OSError, match="Synthetic"):
        store.install(inspection["inspectionId"], "example.integrity")
    assert store.list()[0]["installationId"] == first["installationId"]
    assert store.list()[0]["enabled"]


def test_concurrent_process_installs_do_not_drop_records(tmp_path, monkeypatch):
    store = ExtensionStore(tmp_path / "store")
    first = store.inspect(str(make_package(tmp_path / "a", pack_id="example.first")))
    second = store.inspect(str(make_package(tmp_path / "b", pack_id="example.second")))
    monkeypatch.setenv("REVERSELAB_EXTENSIONS_DIR", str(store.root))
    processes = []
    for inspection in (first, second):
        process = subprocess.Popen([sys.executable, str(ROOT / "scripts/misc/desktop_extensions.py")], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        request = {"operation": "install", "inspectionId": inspection["inspectionId"], "entryId": inspection["entries"][0]["id"]}
        process.stdin.write(json.dumps(request))
        process.stdin.close()
        processes.append(process)
    for process in processes:
        process.wait(timeout=15)
        assert process.returncode == 0, process.stderr.read()
        assert json.loads(process.stdout.read())["ok"]
    assert {item["id"] for item in store.list()} == {"example.first", "example.second"}
