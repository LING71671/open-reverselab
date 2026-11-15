from __future__ import annotations

from urllib.error import HTTPError
from urllib.parse import unquote

import pytest

from test_extension_store import ExtensionStore, install, make_package, protocol, store_module, cli


@pytest.mark.parametrize("left,right,expected", [
    ("1.10.0", "1.9.0", 1), ("2.0.0", "1.99.99", 1), ("1.0.0", "1.0.0", 0),
    ("1.0.0+build2", "1.0.0+build1", 0), ("1.0.0", "1.0.0-rc.1", 1),
    ("1.0.0-alpha.2", "1.0.0-alpha.10", -1), ("1.0.0-beta", "1.0.0-alpha", 1),
    ("1.0.0-alpha", "1.0.0-alpha.1", -1), ("1.0.0-1", "1.0.0-alpha", -1),
])
def test_content_version_precedence(left, right, expected):
    assert store_module.compare_versions(left, right) == expected


def test_github_update_pins_discovered_commit_and_keeps_goal_history(tmp_path, monkeypatch):
    commits = {"a" * 40: "1.0.0", "b" * 40: "1.1.0", "c" * 40: "2.0.0"}
    payloads = {}
    for commit, version in commits.items():
        folder = make_package(tmp_path / version, version=version)
        (folder / "docs/read.md").write_text("# Read " + version, encoding="utf-8")
        payloads[commit], _ = protocol.load(folder)
    latest = "a" * 40
    calls = []
    prefix = "packs/integrity/"

    def fetch(url, *, optional=False, github_recursive=False):
        protocol.validate_https(url)
        calls.append(url)
        if url == "https://api.github.com/repos/example/knowledge":
            return protocol.json_bytes({"default_branch": "main"})
        if "/commits/" in url:
            ref = unquote(url.split("/commits/", 1)[1])
            if ref == "main":
                return protocol.json_bytes({"sha": latest})
            return protocol.json_bytes({"sha": ref}) if ref in payloads else None
        if "/git/trees/" in url:
            commit = url.rsplit("/", 1)[-1]
            return protocol.json_bytes({"tree": [{"path": prefix + name, "type": "blob", "mode": "100644"} for name in payloads[commit]]})
        raw = "https://raw.githubusercontent.com/example/knowledge/"
        if url.startswith(raw):
            commit, path = url.removeprefix(raw).split("/", 1)
            return payloads[commit].get(path.removeprefix(prefix))
        raise AssertionError(url)

    monkeypatch.setattr(store_module, "_read_url", fetch)
    store = ExtensionStore(tmp_path / "store")
    first = install(store, "https://github.com/example/knowledge/tree/" + latest + "/packs/integrity")
    pins = store.pin()
    old_document = next(doc for doc in store.catalog() if doc["entityId"].endswith("docs/read"))
    latest = "b" * 40
    calls.clear()
    checked = cli.dispatch({"operation": "updates/check", "installationId": first["installationId"]}, store)
    assert checked["available"] and checked["latestVersion"] == "1.1.0"
    assert checked["entry"]["source"]["commit"] == latest
    assert not any(url.endswith("knowledge.json") for url in calls)
    assert store.get(first["installationId"])["enabled"]
    latest = "c" * 40  # Branch advances between check and install.
    second = cli.dispatch({"operation": "updates/install", "installationId": first["installationId"], "inspectionId": checked["inspectionId"]}, store)["entry"]
    assert second["version"] == "1.1.0" and second["source"]["commit"] == "b" * 40
    assert not store.get(first["installationId"])["enabled"] and second["enabled"]
    assert store.read_document(old_document["path"]) == "# Read 1.0.0"
    assert {doc["version"] for doc in store.catalog(pinned=pins)} == {"1.0.0"}
    assert store.check_update(first["installationId"])["status"] == "superseded"
    latest = "b" * 40
    assert store.check_update(second["installationId"])["status"] == "current"


def test_update_retains_disabled_state_and_rejects_foreign_source(tmp_path):
    source = make_package(tmp_path / "source")
    store = ExtensionStore(tmp_path / "store")
    first = install(store, source)
    store.enable(first["installationId"], False)
    foreign = store.inspect(str(make_package(tmp_path / "foreign", version="1.1.0")))
    with pytest.raises(ValueError, match="source differs"):
        store.update(first["installationId"], foreign["inspectionId"])
    make_package(source, version="1.1.0")
    checked = store.inspect(str(source))
    second = store.update(first["installationId"], checked["inspectionId"])
    assert second["version"] == "1.1.0" and not second["enabled"]
    assert store.catalog() == []
    assert store.check_update(second["installationId"])["status"] == "manual"


def test_stale_or_failed_update_does_not_replace_installed_knowledge(tmp_path):
    source = make_package(tmp_path / "source")
    store = ExtensionStore(tmp_path / "store")
    first = install(store, source)
    make_package(source, version="1.1.0")
    checked = store.inspect(str(source))
    metadata, stage = store._inspection(checked["inspectionId"])
    payload = stage / "payloads" / metadata["entries"][0]["payload"]
    (payload / "docs/read.md").write_text("Tampered staging", encoding="utf-8")
    with pytest.raises(ValueError):
        store.update(first["installationId"], checked["inspectionId"])
    assert store.get(first["installationId"])["enabled"]
    fresh = store.inspect(str(source))
    make_package(source, version="2.0.0")
    newest = install(store, source)
    with pytest.raises(ValueError, match="newer version is already installed"):
        store.update(first["installationId"], fresh["inspectionId"])
    assert store.get(newest["installationId"])["enabled"]
    downgrade = store.inspect(str(make_package(source, version="1.0.0")))
    with pytest.raises(ValueError, match="newer content version"):
        store.update(newest["installationId"], downgrade["inspectionId"])


def test_github_rate_limit_has_actionable_error(monkeypatch):
    class Limited:
        def open(self, request, timeout):
            raise HTTPError(request.full_url, 403, "Forbidden", {"X-RateLimit-Remaining": "0"}, None)

    monkeypatch.setattr(store_module, "build_opener", lambda *args: Limited())
    with pytest.raises(ValueError, match="GitHub 请求已限流"):
        store_module._read_url("https://api.github.com/repos/example/knowledge")
