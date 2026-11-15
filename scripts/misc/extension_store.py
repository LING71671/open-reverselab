#!/usr/bin/env python3
"""Persistent extension manager shared by desktop, CLI and knowledge adapters."""

from __future__ import annotations

import base64
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
import copy
import hashlib
import io
import json
import os
import posixpath
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile
import time
from urllib.error import HTTPError
from urllib.parse import quote, unquote, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
import uuid
import zipfile

try:
    import extension_protocol as protocol
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import extension_protocol as protocol


def _hash(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


OFFICIAL_KNOWLEDGE_URL = "https://github.com/LING71671/open-reverselab-knowledge"
OFFICIAL_KNOWLEDGE_SOURCE = {
    "sourceId": _hash(OFFICIAL_KNOWLEDGE_URL.encode())[:24],
    "source": OFFICIAL_KNOWLEDGE_URL,
    "identity": OFFICIAL_KNOWLEDGE_URL.lower(),
    "title": "Open ReverseLab 官方知识库",
}


def _is_official_knowledge_source(source: str) -> bool:
    return source.rstrip("/").lower().removesuffix(".git") == OFFICIAL_KNOWLEDGE_URL.lower()


def compare_versions(left: str, right: str) -> int:
    """SemVer precedence; build metadata does not create an upgrade."""
    def parts(version: str):
        protocol.require(bool(re.fullmatch(protocol.SEMVER, version)), "Invalid content version")
        core, separator, prerelease = version.split("+", 1)[0].partition("-")
        return tuple(map(int, core.split("."))), prerelease.split(".") if separator else []

    left_core, left_pre = parts(left)
    right_core, right_pre = parts(right)
    if left_core != right_core:
        return 1 if left_core > right_core else -1
    if not left_pre or not right_pre:
        return (not left_pre) - (not right_pre)
    for first, second in zip(left_pre, right_pre):
        if first == second:
            continue
        if first.isdigit() and second.isdigit():
            if int(first) != int(second):
                return 1 if int(first) > int(second) else -1
            continue
        if first.isdigit() != second.isdigit():
            return -1 if first.isdigit() else 1
        return 1 if first > second else -1
    return (len(left_pre) > len(right_pre)) - (len(left_pre) < len(right_pre))


def _atomic_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    try:
        with temporary.open("xb") as handle:
            handle.write(protocol.json_bytes(value))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _load_json(path: Path, default: dict | None = None) -> dict:
    if not path.exists() and default is not None:
        return copy.deepcopy(default)
    return protocol.object_json(path.read_bytes(), path.name)


@contextmanager
def _file_lock(path: Path):
    """Kernel locks release automatically if an installer exits or is cancelled."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as handle:
        handle.seek(0, os.SEEK_END)
        if not handle.tell():
            handle.write(b"\0")
            handle.flush()
        deadline = time.monotonic() + 30
        while True:
            try:
                handle.seek(0)
                if os.name == "nt":
                    import msvcrt
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise TimeoutError("Another extension operation is holding the store lock")
                time.sleep(0.05)
        try:
            yield
        finally:
            handle.seek(0)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _url_identity(url: str) -> str:
    protocol.validate_https(url)
    parsed = urlsplit(url)
    if parsed.hostname == "github.com":
        parts = parsed.path.strip("/").split("/")
        protocol.require(len(parts) >= 2, "GitHub URL must identify a repository")
        return "https://github.com/" + "/".join(parts[:2]).removesuffix(".git").lower()
    return url.rstrip("/")


class _SourceRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        protocol.require(urlsplit(newurl).scheme == "https", "HTTPS redirect downgrade rejected")
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected is not None and urlsplit(req.full_url).hostname != urlsplit(newurl).hostname:
            redirected.remove_header("Authorization")
        return redirected


def _read_url(url: str, *, optional: bool = False, github_recursive: bool = False) -> bytes | None:
    protocol.validate_https(url)
    if github_recursive:
        parsed = urlsplit(url)
        protocol.require(parsed.hostname == "api.github.com" and bool(re.fullmatch(r"/repos/[^/]+/[^/]+/git/trees/[0-9a-fA-F]{40}", parsed.path)), "Recursive tree query requires a GitHub tree endpoint")
        # Transport-generated query; user source URLs still disallow queries.
        url += "?recursive=1"
    headers = {"User-Agent": "Open-ReverseLab-Extensions/1", "Accept": "application/vnd.github+json"}
    # Credentials are consulted locally and never persisted in provenance or exports.
    if urlsplit(url).hostname in {"api.github.com", "raw.githubusercontent.com"}:
        github_authorization = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        if github_authorization:
            headers["Authorization"] = "Bearer " + github_authorization
    try:
        with build_opener(_SourceRedirects()).open(Request(url, headers=headers), timeout=30) as response:
            protocol.require(urlsplit(response.url).scheme == "https", "HTTPS redirect downgrade rejected")
            return response.read()
    except HTTPError as error:
        if optional and (error.code == 404 or (error.code == 422 and "/commits/" in url)):
            return None
        if error.code == 429 or (error.code == 403 and error.headers.get("X-RateLimit-Remaining") == "0"):
            raise ValueError("GitHub 请求已限流，请稍后重试；已安装的知识库仍可使用") from None
        raise ValueError(f"Source request failed (HTTP {error.code})") from None


def resolve_github(url: str) -> dict:
    """Resolve slash-containing refs using GitHub commit metadata, never guesses."""
    protocol.validate_https(url)
    parsed = urlsplit(url)
    protocol.require(parsed.hostname == "github.com", "Expected GitHub repository URL")
    parts = [unquote(part) for part in parsed.path.strip("/").split("/")]
    protocol.require(len(parts) >= 2, "GitHub URL must include owner/repository")
    owner, repo = parts[:2]
    repo = repo.removesuffix(".git")
    protocol.require(bool(re.fullmatch(r"[A-Za-z0-9_.-]+", owner)) and bool(re.fullmatch(r"[A-Za-z0-9_.-]+", repo)), "Invalid GitHub repository")
    api = f"https://api.github.com/repos/{owner}/{repo}"
    path = ""
    if len(parts) == 2:
        metadata = protocol.object_json(_read_url(api), "GitHub repository")
        ref = metadata["default_branch"]
        commit = protocol.object_json(_read_url(api + "/commits/" + quote(ref, safe="")), "GitHub commit")["sha"]
    else:
        protocol.require(parts[2] in {"tree", "blob"}, "Use a repository, tree, blob or release ZIP URL")
        remainder = parts[3:]
        protocol.require(bool(remainder), "Missing GitHub ref")
        commit = None
        # Longest valid ref avoids incorrectly splitting feature/topic at '/'.
        for count in range(len(remainder), 0, -1):
            ref = "/".join(remainder[:count])
            raw = _read_url(api + "/commits/" + quote(ref, safe=""), optional=True)
            if raw is not None:
                commit = protocol.object_json(raw, "GitHub commit")["sha"]
                path = "/".join(remainder[count:])
                break
        protocol.require(commit is not None, "GitHub ref could not be resolved")
    protocol.require(isinstance(commit, str) and bool(re.fullmatch(r"[0-9a-fA-F]{40}", commit)), "GitHub returned an invalid commit")
    if path:
        protocol.safe_path(path)
    if path.endswith((protocol.MANIFEST, protocol.REGISTRY)):
        path = path.rpartition("/")[0]
    return {"identity": _url_identity(url), "url": _url_identity(url), "commit": commit, "path": path, "ref": ref, "owner": owner, "repo": repo}


def _github_raw(source: dict, path: str, *, optional: bool = False) -> bytes | None:
    protocol.safe_path(path)
    return _read_url(f"https://raw.githubusercontent.com/{source['owner']}/{source['repo']}/{source['commit']}/" + quote(path, safe="/"), optional=optional)


def _github_regular_files(source: dict, paths: list[str], optional: list[str] = ()) -> None:
    """Check Git modes before fetching a payload; raw URLs hide symlink modes."""
    api = f"https://api.github.com/repos/{source['owner']}/{source['repo']}/git/trees/"
    wanted = set(paths) | set(optional)
    tree = protocol.object_json(_read_url(api + source["commit"], github_recursive=True), "GitHub tree")
    entries = {item["path"]: item for item in tree.get("tree", [])}
    pending = [(source["commit"], "")] if tree.get("truncated") else []
    if pending:
        entries = {}
    while pending:
        sha, prefix = pending.pop()
        branch = protocol.object_json(_read_url(api + sha), "GitHub directory tree")
        protocol.require(not branch.get("truncated"), "GitHub returned an incomplete directory tree")
        for item in branch.get("tree", []):
            path = prefix + item["path"]
            entries[path] = item
            if item.get("type") == "tree" and any(name.startswith(path + "/") for name in wanted):
                pending.append((item["sha"], path + "/"))
    for path in wanted:
        item = entries.get(path)
        if item is None and path in optional:
            continue
        protocol.require(item is not None and item.get("type") == "blob" and item.get("mode") in {"100644", "100755"},
                         "Package source must be a regular Git file: " + path)


def _archive_files(raw: bytes) -> dict[str, bytes]:
    """Validate every member before reading. Do not extract filesystem entries."""
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        entries = archive.infolist()
        seen = set()
        file_names = []
        for entry in entries:
            name = entry.filename.rstrip("/")
            protocol.safe_path(name)
            protocol.require(name.casefold() not in seen, "Duplicate/case-colliding archive entry")
            seen.add(name.casefold())
            mode = stat.S_IFMT(entry.external_attr >> 16)
            protocol.require(mode in {0, stat.S_IFREG, stat.S_IFDIR}, "Archive links/special files are not supported")
            protocol.require(not entry.flag_bits & 1, "Encrypted archives are not supported")
            if not entry.is_dir():
                file_names.append(name)
        protocol.unique_paths(file_names)
        file_set = {name.casefold() for name in file_names}
        for name in seen:
            protocol.require(not any(parent.as_posix() in file_set for parent in Path(name).parents if str(parent) != "."), "File/directory archive collision")
        return {entry.filename: archive.read(entry) for entry in entries if not entry.is_dir()}


class ExtensionStore:
    def __init__(self, root: str | Path | None = None, data_dir: str | Path | None = None):
        base = data_dir or os.environ.get("REVERSELAB_DATA_DIR")
        self.root = Path(root or os.environ.get("REVERSELAB_EXTENSIONS_DIR") or (Path(base) / "extensions" if base else Path.home() / ".open-reverselab" / "extensions")).resolve()
        self.registry_path = self.root / "installed.json"
        self.lock_path = self.root / ".store.lock"

    def _registry(self) -> dict:
        return _load_json(self.registry_path, {"protocol": "open-reverselab.installed/v1", "installations": []})

    def _record(self, item: dict) -> dict:
        result = copy.deepcopy(item)
        package_root = self.root / "packages" / item["installationId"]
        result["root"] = str(package_root)
        if item["kind"] == "mcp":
            payload, _ = protocol.load(package_root)
            manifest = protocol.validate(payload)
            result["descriptor"] = protocol.object_json(payload[manifest["mcp"]], manifest["mcp"])
        return result

    def list(self) -> list[dict]:
        return [self._record(item) for item in self._registry()["installations"] if not item.get("removed")]

    def get(self, installation_id: str) -> dict:
        for item in self._registry()["installations"]:
            if item["installationId"] == installation_id:
                return self._record(item)
        raise ValueError("Unknown installationId")

    def _stage_payload(self, stage: Path, payload: dict[str, bytes], source: dict, *, require_lock: bool, migrate: bool) -> dict:
        manifest = protocol.object_json(payload[protocol.MANIFEST], protocol.MANIFEST)
        if migrate and manifest.get("protocol") == "open-reverselab.extension/v1-draft":
            payload = protocol.migrate_draft(payload)
        manifest = protocol.validate(payload, archive=require_lock, check_features=False)
        generated = protocol.LOCK not in payload
        if generated:
            payload = dict(payload)
            lock = protocol.make_lock(manifest, payload)
            lock["provenance"] = {**source, "computedOnImport": True}
            payload[protocol.LOCK] = protocol.json_bytes(lock)
        digest = protocol.package_digest(payload)
        folder = stage / "payloads" / digest
        folder.mkdir(parents=True, exist_ok=True)
        for name, raw in payload.items():
            target = folder.joinpath(*name.split("/"))
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
        return {**self._summary(manifest), "digest": digest, "payload": digest, "source": source, "computedLock": generated}

    @staticmethod
    def _summary(manifest: dict) -> dict:
        return {key: copy.deepcopy(manifest[key]) for key in ("id", "kind", "title", "version", "description", "license", "requires", "requiredFeatures") if key in manifest}

    @staticmethod
    def _remote_catalog_entry(entry: dict, source: dict) -> dict:
        if "repository" in entry:
            source = resolve_github(entry["repository"])
            locator = {"github": source, "path": source["path"]}
        else:
            locator = {"artifact": entry["artifact"], "sha256": entry["sha256"]}
        return {**entry, "source": source, "locator": locator}

    def _inspect_local(self, path: Path, stage: Path, migrate: bool) -> tuple[list, dict, list]:
        path = path.resolve(strict=True)
        if path.is_file() and path.name in {protocol.MANIFEST, protocol.REGISTRY}:
            path = path.parent
        source = {"identity": "local:sha256:" + _hash(path.as_uri().encode()), "label": path.name}
        entries = []
        if path.is_dir():
            registry_path = path / protocol.REGISTRY
            if registry_path.exists():
                registry = protocol.validate_registry(protocol.object_json(protocol.read_local(path, protocol.REGISTRY), protocol.REGISTRY))
                for entry in registry["entries"]:
                    if "artifact" in entry or "repository" in entry:
                        entries.append(self._remote_catalog_entry(entry, source))
                    else:
                        relative = entry["path"]
                        folder = path if relative == "." else path.joinpath(*relative.split("/"))
                        protocol.require(folder.resolve().is_relative_to(path), "Catalog path leaves source")
                        payload, _ = protocol.load(folder)
                        candidate = self._stage_payload(stage, payload, source, require_lock=False, migrate=migrate)
                        self._match(entry, candidate)
                        entries.append(candidate)
            elif (path / protocol.MANIFEST).is_file():
                payload, _ = protocol.load(path)
                entries.append(self._stage_payload(stage, payload, source, require_lock=False, migrate=migrate))
            else:
                for manifest in sorted(path.rglob(protocol.MANIFEST)):
                    protocol.require(not any(parent.is_symlink() or getattr(parent, "is_junction", lambda: False)() for parent in [manifest.parent, *manifest.parent.parents] if parent.is_relative_to(path)), "Links in source directory")
                    payload, _ = protocol.load(manifest.parent)
                    entries.append(self._stage_payload(stage, payload, source, require_lock=False, migrate=migrate))
        else:
            raw = path.read_bytes()
            source["archiveSha256"] = _hash(raw)
            entries = self._inspect_archive(raw, stage, source, migrate=migrate)
        protocol.require(bool(entries), "No extension manifests found; select a package folder or create a document collection")
        return entries, source, []

    @staticmethod
    def _match(expected: dict, actual: dict) -> None:
        protocol.require(all(expected.get(key) == actual.get(key) for key in ("id", "kind", "version")), "Catalog entry identity/version differs from package manifest")

    def _inspect_archive(self, raw: bytes, stage: Path, source: dict, *, migrate: bool = False, source_archive: bool | None = None) -> list[dict]:
        files = _archive_files(raw)
        manifests = [name for name in files if name.split("/")[-1] == protocol.MANIFEST]
        roots = {name.split("/", 1)[0] for name in files}
        enclosed = len(roots) == 1 and all("/" in name for name in files)
        archive_prefix = next(iter(roots)) + "/" if enclosed else ""
        registry_name = archive_prefix + protocol.REGISTRY
        if source_archive is None:
            has_lock = any(name.split("/")[-1] == protocol.LOCK for name in files)
            # GitHub source downloads are an enclosing source directory, not a
            # package artifact. Their explicit manifest files get computed locks.
            source_archive = registry_name in files or (enclosed and not has_lock)
        if source_archive:
            source = {**source, "archiveRoot": archive_prefix.rstrip("/"), "computedOnImport": True}
        entries = []
        expected = {}
        if source_archive and registry_name in files:
            registry = protocol.validate_registry(protocol.object_json(files[registry_name], protocol.REGISTRY))
            manifests = []
            for entry in registry["entries"]:
                if "artifact" in entry or "repository" in entry:
                    entries.append(self._remote_catalog_entry(entry, source))
                else:
                    relative = entry["path"]
                    filename = archive_prefix + (relative + "/" if relative != "." else "") + protocol.MANIFEST
                    protocol.require(filename in files, "Catalog manifest missing from archive: " + filename)
                    manifests.append(filename)
                    expected[filename] = entry
        protocol.require(bool(manifests or entries), "Archive contains no declared extensions")
        for filename in manifests:
            prefix = filename.removesuffix(protocol.MANIFEST)
            manifest = protocol.object_json(files[filename], filename)
            names = manifest.get("files")
            protocol.require(protocol.strings(names), "Manifest files must be an array")
            protocol.unique_paths([protocol.MANIFEST, protocol.LOCK, *names])
            payload = {}
            for name in [protocol.MANIFEST, *names]:
                protocol.require(prefix + name in files, "Missing archive payload: " + name)
                payload[name] = files[prefix + name]
            if prefix + protocol.LOCK in files:
                payload[protocol.LOCK] = files[prefix + protocol.LOCK]
            if not source_archive:
                protocol.require(len(manifests) == 1 and (not prefix or prefix.count("/") == 1), "Package ZIP requires one root or one enclosing directory")
                protocol.require(set(files) == {prefix + name for name in payload}, "Unexpected files in package ZIP; use a repository source archive import")
            candidate = self._stage_payload(stage, payload, source, require_lock=not source_archive, migrate=migrate)
            if filename in expected:
                self._match(expected[filename], candidate)
            entries.append(candidate)
        return entries

    def _inspect_github(self, url: str, stage: Path) -> tuple[list, dict, list]:
        source = resolve_github(url)
        prefix = source["path"] + "/" if source["path"] else ""
        raw_registry = _github_raw(source, prefix + protocol.REGISTRY, optional=True)
        if raw_registry is not None:
            registry = protocol.validate_registry(protocol.object_json(raw_registry, protocol.REGISTRY))
            entries = []
            for entry in registry["entries"]:
                if "path" in entry:
                    locator = {"github": source, "path": prefix + (entry["path"] if entry["path"] != "." else "")}
                    entries.append({**entry, "source": source, "locator": locator})
                else:
                    entries.append(self._remote_catalog_entry(entry, source))
            return entries, source, []
        raw_manifest = _github_raw(source, prefix + protocol.MANIFEST, optional=True)
        candidates = [prefix + protocol.MANIFEST] if raw_manifest is not None else []
        if not candidates:
            tree = protocol.object_json(_read_url(f"https://api.github.com/repos/{source['owner']}/{source['repo']}/git/trees/{source['commit']}"), "GitHub tree")
            # Traverse tree metadata instead of a recursive API response which can truncate.
            pending = [(tree, "")]
            while pending:
                current, parent = pending.pop()
                for item in current.get("tree", []):
                    item_path = parent + item["path"]
                    if item.get("type") == "tree" and (item_path.startswith(prefix.rstrip("/")) or prefix.startswith(item_path + "/")):
                        child = protocol.object_json(_read_url(item["url"]), "GitHub tree")
                        pending.append((child, item_path + "/"))
                    elif item.get("type") == "blob" and item_path.startswith(prefix) and item_path.split("/")[-1] == protocol.MANIFEST:
                        candidates.append(item_path)
        entries = []
        for path in candidates:
            raw = raw_manifest if path == prefix + protocol.MANIFEST and raw_manifest is not None else _github_raw(source, path)
            manifest = protocol.object_json(raw, path)
            protocol.require(manifest.get("protocol") == protocol.PROTOCOL, "Unsupported extension protocol; migrate draft explicitly")
            entries.append({**self._summary(manifest), "source": source, "locator": {"github": source, "path": path.rpartition("/")[0], "manifestSha256": _hash(raw)}})
        protocol.require(bool(entries), "No extension manifest/catalog found in selected GitHub path")
        return entries, source, []

    def inspect(self, source: str = "", *, migrate_draft: bool = False, archive_base64: str | None = None, filename: str = "package.zip") -> dict:
        inspection_id = uuid.uuid4().hex
        stage = self.root / "inspections" / inspection_id
        stage.mkdir(parents=True)
        try:
            if archive_base64 is not None:
                raw = base64.b64decode(archive_base64, validate=True)
                provenance = {"identity": "archive:sha256:" + _hash(raw), "label": Path(filename).name, "archiveSha256": _hash(raw)}
                entries = self._inspect_archive(raw, stage, provenance, migrate=migrate_draft)
                warnings = []
            elif source.startswith("https://"):
                protocol.validate_https(source)
                parsed = urlsplit(source)
                if parsed.hostname == "github.com" and "/releases/download/" not in parsed.path and not parsed.path.endswith(".zip"):
                    entries, provenance, warnings = self._inspect_github(source, stage)
                else:
                    raw = _read_url(source)
                    provenance = {"identity": _url_identity(source), "url": source, "archiveSha256": _hash(raw)}
                    is_source = parsed.hostname in {"github.com", "codeload.github.com"} and ("/archive/" in parsed.path or parsed.hostname == "codeload.github.com")
                    entries = self._inspect_archive(raw, stage, provenance, migrate=migrate_draft, source_archive=is_source)
                    warnings = ["Computed import locks from GitHub source archive"] if is_source else []
            else:
                entries, provenance, warnings = self._inspect_local(Path(source), stage, migrate_draft)
            ids = [entry["id"] for entry in entries]
            protocol.require(len(ids) == len(set(ids)), "Source contains duplicate package IDs; select a specific package path")
            if any(entry.get("computedLock") and entry.get("source", {}).get("archiveRoot") for entry in entries):
                warnings.append("Computed locks for an enclosing source archive; hashes identify content, not publisher ownership")
            inspection = {"inspectionId": inspection_id, "entries": entries, "source": provenance, "warnings": warnings, "migrateDraft": migrate_draft}
            _atomic_json(stage / "inspection.json", inspection)
            return {**inspection, "entries": [{key: value for key, value in item.items() if key not in {"payload", "locator"}} for item in entries]}
        except BaseException:
            # This is a freshly allocated directory under our own store only.
            if stage.resolve().is_relative_to((self.root / "inspections").resolve()):
                shutil.rmtree(stage, ignore_errors=True)
            raise

    def _inspection(self, inspection_id: str) -> tuple[dict, Path]:
        protocol.require(bool(re.fullmatch(r"[0-9a-f]{32}", inspection_id)), "Invalid inspectionId")
        stage = self.root / "inspections" / inspection_id
        return _load_json(stage / "inspection.json"), stage

    def _materialize(self, entry: dict, stage: Path, migrate: bool) -> dict:
        if "payload" in entry:
            return entry
        locator = entry["locator"]
        if "artifact" in locator:
            raw = _read_url(locator["artifact"])
            protocol.require(_hash(raw) == locator["sha256"], "Catalog artifact SHA256 mismatch")
            candidates = self._inspect_archive(raw, stage, entry["source"], migrate=migrate)
            protocol.require(len(candidates) == 1, "Artifact must contain one package")
            actual = candidates[0]
        else:
            source = locator["github"]
            prefix = locator["path"].strip("/")
            prefix = prefix + "/" if prefix else ""
            raw = _github_raw(source, prefix + protocol.MANIFEST)
            if "manifestSha256" in locator:
                protocol.require(_hash(raw) == locator["manifestSha256"], "Pinned manifest changed")
            manifest = protocol.object_json(raw, protocol.MANIFEST)
            protocol.require(protocol.strings(manifest.get("files")), "Manifest files must be an array")
            protocol.unique_paths([protocol.MANIFEST, protocol.LOCK, *manifest["files"]])
            _github_regular_files(source, [prefix + name for name in [protocol.MANIFEST, *manifest["files"]]], [prefix + protocol.LOCK])
            payload = {protocol.MANIFEST: raw}
            def fetch_file(name: str) -> tuple[str, bytes]:
                return name, _github_raw(source, prefix + name)

            with ThreadPoolExecutor(max_workers=8, thread_name_prefix="extension-download") as downloads:
                payload.update(downloads.map(fetch_file, manifest["files"]))
            locked = _github_raw(source, prefix + protocol.LOCK, optional=True)
            if locked is not None:
                payload[protocol.LOCK] = locked
            actual = self._stage_payload(stage, payload, {**source, "path": prefix.rstrip("/")}, require_lock=False, migrate=migrate)
        self._match(entry, actual)
        return actual

    @staticmethod
    def _dependencies(manifest: dict, installations: list[dict]) -> tuple[list[dict], list[str]]:
        resolved, warnings = [], []
        for dependency in manifest.get("requires", []):
            identity = dependency["source"].rstrip("/")
            if identity.startswith("https://"):
                identity = _url_identity(identity)
            matches = [item for item in installations if item["id"] == dependency["id"] and item["version"] == dependency["version"] and item["source"]["identity"] == identity and item.get("enabled") and not item.get("removed")]
            if not matches:
                if dependency["optional"]:
                    warnings.append("Optional dependency unavailable: " + dependency["id"])
                    continue
                raise ValueError("Required dependency unavailable: " + dependency["id"] + "@" + dependency["version"] + " from " + identity)
            item = matches[0]
            resolved.append({"id": item["id"], "version": item["version"], "source": identity, "digest": item["digest"], "installationId": item["installationId"], "optional": dependency["optional"]})
        return resolved, warnings

    def _validate_external(self, manifest: dict, payload: dict, dependencies: list[dict]) -> None:
        locked = protocol.object_json(payload[protocol.LOCK], protocol.LOCK).get("dependencies", []) if protocol.LOCK in payload else []
        for dependency in locked:
            actual = next((item for item in dependencies if item["id"] == dependency["id"]), None)
            if actual is not None:
                protocol.require(actual["digest"] == dependency["digest"], "Installed dependency differs from exported lock: " + dependency["id"])
        if manifest["kind"] != "knowledge":
            return
        data = protocol.object_json(payload[manifest["knowledge"]], manifest["knowledge"])
        groups = {group: {item["id"] for item in data[group]} for group in ("documents", "methods", "networks")}
        optional_missing = {dep["id"] for dep in manifest.get("requires", []) if dep["optional"]} - {dep["id"] for dep in dependencies}
        for dependency in dependencies:
            other, _ = protocol.load(self.root / "packages" / dependency["installationId"])
            dep_manifest = protocol.validate(other)
            protocol.require(protocol.package_digest(other) == dependency["digest"], "Dependency content changed")
            if dep_manifest["kind"] == "knowledge":
                contents = protocol.object_json(other[dep_manifest["knowledge"]], dep_manifest["knowledge"])
                for group in groups:
                    groups[group].update(item["id"] for item in contents[group])
        refs = [(method["document"], "documents") for method in data["methods"]]
        refs += [(node, "methods") for network in data["networks"] for node in network["nodes"]]
        refs += [(binding["method"], "methods") for binding in data.get("bindings", [])]
        for reference, group in refs:
            protocol.require(reference in groups[group] or reference.split("/", 1)[0] in optional_missing, "Unresolved external " + group + " reference: " + reference)

    def install(self, inspection_id: str, entry_id: str, *, updating: str | None = None) -> dict:
        inspection, stage = self._inspection(inspection_id)
        entry = next((item for item in inspection["entries"] if item["id"] == entry_id), None)
        protocol.require(entry is not None, "Unknown inspection entryId")
        # Network I/O does not hold the registry lock; activation rechecks dependencies.
        entry = self._materialize(entry, stage, inspection.get("migrateDraft", False))
        payload, _ = protocol.load(stage / "payloads" / entry["payload"])
        manifest = protocol.validate(payload, archive=True)
        protocol.require(protocol.package_digest(payload) == entry["digest"], "Inspection staging changed")
        identity = entry["source"]["identity"]
        installation_id = _hash((identity + "\n" + manifest["id"] + "\n" + manifest["version"] + "\n" + entry["digest"]).encode())[:32]
        with _file_lock(self.lock_path):
            registry = self._registry()
            previous = registry["installations"]
            enabled = True
            if updating is not None:
                current = next((item for item in previous if item["installationId"] == updating and not item.get("removed")), None)
                protocol.require(current is not None, "Knowledge installation was removed; refresh the list")
                self._validate_update(current, entry)
                protocol.require(not any(item["source"]["identity"] == identity and item["id"] == entry["id"] and not item.get("removed")
                                         and compare_versions(item["version"], current["version"]) > 0 for item in previous),
                                 "A newer version is already installed; refresh the list")
                enabled = current["enabled"]
            for item in previous:
                if item["source"]["identity"] == identity and item["id"] == manifest["id"] and item["version"] == manifest["version"]:
                    protocol.require(item["digest"] == entry["digest"], "Same source/id/version has different content; publish a new version")
            dependencies, warnings = self._dependencies(manifest, previous)
            self._validate_external(manifest, payload, dependencies)
            destination = self.root / "packages" / installation_id
            if not destination.exists():
                destination.parent.mkdir(parents=True, exist_ok=True)
                temporary = destination.with_name(".install-" + uuid.uuid4().hex)
                shutil.copytree(stage / "payloads" / entry["payload"], temporary)
                os.replace(temporary, destination)
            else:
                existing, _ = protocol.load(destination)
                protocol.validate(existing, archive=True)
                protocol.require(protocol.package_digest(existing) == entry["digest"], "Retained installation content changed")
            for item in previous:
                if item["source"]["identity"] == identity and item["id"] == manifest["id"]:
                    item["enabled"] = False
            record = {**self._summary(manifest), "installationId": installation_id, "source": entry["source"], "digest": entry["digest"], "enabled": enabled, "removed": False, "dependencies": dependencies, "warnings": warnings}
            registry["installations"] = [item for item in previous if item["installationId"] != installation_id] + [record]
            _atomic_json(self.registry_path, registry)
        return self._record(record)

    @staticmethod
    def _validate_update(current: dict, candidate: dict) -> None:
        protocol.require(current["kind"] == candidate["kind"] == "knowledge" and current["id"] == candidate["id"], "Update must match the installed knowledge package")
        protocol.require(current["source"]["identity"] == candidate["source"]["identity"], "Update source differs from the installed knowledge package")
        protocol.require(compare_versions(candidate["version"], current["version"]) > 0, "Update requires a newer content version")

    def check_update(self, installation_id: str) -> dict:
        current = self.get(installation_id)
        protocol.require(current["kind"] == "knowledge" and not current.get("removed"), "Select an installed knowledge package")
        result = {"installationId": installation_id, "currentVersion": current["version"], "available": False}
        identity = current["source"]["identity"]
        if not identity.startswith("https://github.com/"):
            return {**result, "status": "manual", "message": "此知识包来自本地文件，请通过原来源导入新版本"}
        for item in self.list():
            if item["id"] == current["id"] and item["source"]["identity"] == identity and compare_versions(item["version"], current["version"]) > 0:
                return {**result, "status": "superseded", "message": "已安装更新版本，请在该版本上检查更新"}
        # Installation commits stay pinned; discovery follows the source's
        # default branch, including packages reached through pinned catalogs.
        source = resolve_github(identity)
        path = current["source"].get("path", "")
        url = identity + "/tree/" + source["commit"] + ("/" + quote(path, safe="/") if path else "")
        inspection = self.inspect(url)
        candidate = next((entry for entry in inspection["entries"] if entry["id"] == current["id"] and entry["kind"] == "knowledge"
                          and entry["source"]["identity"] == identity), None)
        protocol.require(candidate is not None, "The source no longer lists this knowledge package")
        if compare_versions(candidate["version"], current["version"]) <= 0:
            return {**result, "status": "current", "message": "没有更高版本", "latestVersion": candidate["version"]}
        return {**result, "status": "available", "available": True, "latestVersion": candidate["version"],
                "inspectionId": inspection["inspectionId"], "entry": candidate}

    def update(self, installation_id: str, inspection_id: str) -> dict:
        current = self.get(installation_id)
        inspection, _ = self._inspection(inspection_id)
        candidate = next((entry for entry in inspection["entries"] if entry["id"] == current["id"]), None)
        protocol.require(candidate is not None, "Update inspection does not contain this package")
        self._validate_update(current, candidate)
        return self.install(inspection_id, current["id"], updating=installation_id)

    def enable(self, installation_id: str, enabled: bool = True) -> dict:
        protocol.require(isinstance(enabled, bool), "enabled must be boolean")
        with _file_lock(self.lock_path):
            registry = self._registry()
            record = next((item for item in registry["installations"] if item["installationId"] == installation_id), None)
            protocol.require(record is not None and not record.get("removed"), "Unknown installationId")
            if enabled:
                payload, _ = protocol.load(self.root / "packages" / installation_id)
                manifest = protocol.validate(payload, archive=True)
                protocol.require(protocol.package_digest(payload) == record["digest"], "Installed package changed")
                dependencies, warnings = self._dependencies(manifest, registry["installations"])
                self._validate_external(manifest, payload, dependencies)
                record.update(dependencies=dependencies, warnings=warnings)
                for other in registry["installations"]:
                    if other["source"]["identity"] == record["source"]["identity"] and other["id"] == record["id"]:
                        other["enabled"] = False
            else:
                dependents = [item["id"] for item in registry["installations"] if item.get("enabled") and any(dep["installationId"] == installation_id and not dep["optional"] for dep in item.get("dependencies", []))]
                protocol.require(not dependents, "Required by enabled packages: " + ", ".join(dependents))
            record["enabled"] = enabled
            _atomic_json(self.registry_path, registry)
        return self._record(record)

    def remove(self, installation_id: str) -> dict:
        with _file_lock(self.lock_path):
            registry = self._registry()
            record = next((item for item in registry["installations"] if item["installationId"] == installation_id), None)
            protocol.require(record is not None, "Unknown installationId")
            affected = {installation_id}
            changed = True
            while changed:
                changed = False
                for item in registry["installations"]:
                    if item.get("enabled") and item["installationId"] not in affected and any(dep["installationId"] in affected and not dep["optional"] for dep in item.get("dependencies", [])):
                        affected.add(item["installationId"])
                        changed = True
            for item in registry["installations"]:
                if item["installationId"] in affected:
                    item["enabled"] = False
            record["removed"] = True
            _atomic_json(self.registry_path, registry)
        return {"entry": self._record(record), "disabledDependents": sorted(affected - {installation_id}), "retained": True}

    def _subgraph(self, record: dict, payload: dict[str, bytes], network_ids: list[str]) -> tuple[dict[str, bytes], str]:
        protocol.require(isinstance(network_ids, list) and protocol.strings(network_ids) and bool(network_ids), "Select at least one network for a subgraph export")
        manifest = protocol.object_json(payload[protocol.MANIFEST], protocol.MANIFEST)
        protocol.require(manifest["kind"] == "knowledge", "Only knowledge packages have networks")
        data = protocol.object_json(payload[manifest["knowledge"]], manifest["knowledge"])
        requested = {name.removeprefix("reverselab://" + record["installationId"] + "/") for name in network_ids}
        networks = [network for network in data["networks"] if network["id"] in requested]
        protocol.require(len(networks) == len(requested), "Unknown selected network ID")
        method_ids = {node for network in networks for node in network["nodes"]}
        dependencies = [edge for network in data["networks"] for edge in network["relations"] if edge["type"] == "depends_on"]
        changed = True
        while changed:
            before = len(method_ids)
            method_ids.update(edge["to"] for edge in dependencies if edge["from"] in method_ids)
            changed = len(method_ids) != before
        methods = [method for method in data["methods"] if method["id"] in method_ids]
        document_ids = {method["document"] for method in methods}
        documents = [document for document in data["documents"] if document["id"] in document_ids]
        by_path = {document["path"]: document for document in data["documents"]}
        paths = {document["path"] for document in documents}
        # Keep declared Markdown links and their own links so exported prose remains usable.
        pending = list(paths)
        while pending:
            path = pending.pop()
            text = payload[path].decode("utf-8")
            for href in re.findall(r"\]\(([^\s)]+)(?:\s+[^)]*)?\)", text):
                link = urlsplit(href.strip("<>"))
                if link.scheme or link.netloc or not link.path:
                    continue
                linked = posixpath.normpath(posixpath.join(posixpath.dirname(path), unquote(link.path)))
                if linked in manifest["files"] and linked not in paths:
                    paths.add(linked)
                    if linked.endswith(".md"):
                        pending.append(linked)
                        if linked in by_path and by_path[linked]["id"] not in document_ids:
                            documents.append(by_path[linked])
                            document_ids.add(by_path[linked]["id"])
        selection_hash = _hash(protocol.json_bytes({"digest": record["digest"], "networks": sorted(requested)}))[:12]
        derived_id = manifest["id"] + ".subset-" + selection_hash
        origin = {"packId": manifest["id"], "version": manifest["version"], "digest": record["digest"], "source": record["source"]["identity"]}

        def remap(entity_id: str) -> str:
            return derived_id + entity_id[len(manifest["id"]):] if entity_id.startswith(manifest["id"] + "/") else entity_id

        def entity(item: dict) -> dict:
            return {**copy.deepcopy(item), "id": remap(item["id"]), "origin": {**origin, "id": item["id"]}}

        new_documents = [entity(item) for item in documents]
        new_methods = [{**entity(item), "document": remap(item["document"])} for item in methods]
        new_networks = [{**entity(item), "nodes": [remap(node) for node in item["nodes"]], "entrypoints": [remap(node) for node in item["entrypoints"]], "relations": [{**edge, "from": remap(edge["from"]), "to": remap(edge["to"])} for edge in item["relations"]]} for item in networks]
        existing_edges = {(edge["from"], edge["to"], edge["type"]) for network in networks for edge in network["relations"]}
        closure_edges = [edge for edge in dependencies if edge["from"] in method_ids and edge["to"] in method_ids and (edge["from"], edge["to"], edge["type"]) not in existing_edges]
        if closure_edges:
            new_networks.append({"id": derived_id + "/dependency-closure", "title": "Required method dependencies", "track": "shared", "nodes": sorted({remap(edge[key]) for edge in closure_edges for key in ("from", "to")}), "entrypoints": [], "relations": [{**edge, "from": remap(edge["from"]), "to": remap(edge["to"])} for edge in closure_edges], "origin": origin})
        new_data = {**data, "documents": new_documents, "methods": new_methods, "networks": new_networks, "bindings": [{**binding, "method": remap(binding["method"])} for binding in data.get("bindings", []) if binding["method"] in method_ids]}
        # Non-Markdown authored assets may support selected prose/scripts. Keep them;
        # task/workspace files were never part of this explicit package payload.
        keep = paths | {name for name in manifest["files"] if not name.endswith(".md")}
        new_manifest = {**manifest, "id": derived_id, "title": manifest["title"] + " (selected networks)", "files": sorted(keep), "origin": {**origin, "networkIds": sorted(requested)}}
        result = {name: raw for name, raw in payload.items() if name in keep}
        result[protocol.MANIFEST] = protocol.json_bytes(new_manifest)
        result[manifest["knowledge"]] = protocol.json_bytes(new_data)
        lock = protocol.make_lock(new_manifest, result)
        lock["provenance"] = origin
        declared_sources = {dependency["id"]: dependency["source"] for dependency in manifest.get("requires", [])}
        lock["dependencies"] = [{**{key: dependency[key] for key in ("id", "version", "digest")}, "source": declared_sources[dependency["id"]]} for dependency in record.get("dependencies", [])]
        result[protocol.LOCK] = protocol.json_bytes(lock)
        protocol.validate(result, archive=True)
        return result, derived_id

    def export(self, installation_id: str, output_path: str | Path | None = None, network_ids: list[str] | None = None) -> dict:
        item = self.get(installation_id)
        payload, _ = protocol.load(Path(item["root"]))
        protocol.validate(payload, archive=True)
        protocol.require(protocol.package_digest(payload) == item["digest"], "Installed package changed")
        extra = {}
        export_id = item["id"]
        if network_ids is not None:
            payload, export_id = self._subgraph(item, payload, network_ids)
            extra["derivedPackId"] = export_id
        else:
            # An export includes exact dependency locks, not local installation IDs.
            lock = protocol.object_json(payload[protocol.LOCK], protocol.LOCK)
            manifest = protocol.object_json(payload[protocol.MANIFEST], protocol.MANIFEST)
            declared_sources = {dependency["id"]: dependency["source"] for dependency in manifest.get("requires", [])}
            lock["dependencies"] = [{**{key: dependency[key] for key in ("id", "version", "digest")}, "source": declared_sources[dependency["id"]]} for dependency in item.get("dependencies", [])]
            payload[protocol.LOCK] = protocol.json_bytes(lock)
        raw = protocol.zip_bytes(payload)
        filename = export_id + "-" + item["version"] + (".kbpack.zip" if item["kind"] == "knowledge" else ".mcp.zip")
        if output_path is None:
            return {"filename": filename, "archiveBase64": base64.b64encode(raw).decode(), "sha256": _hash(raw), **extra}
        path = Path(output_path).resolve()
        protocol.require(not path.is_relative_to(self.root), "Export outside the extension store")
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as handle:
            handle.write(raw)
        return {"path": str(path), "filename": path.name, "sha256": _hash(raw), **extra}

    def _sources_state(self) -> dict:
        # A source address is available offline; no content is downloaded until
        # the user browses it. Existing profiles receive the same default.
        state = _load_json(self.root / "sources.json", {"sources": []})
        existing = next((item for item in state["sources"] if _is_official_knowledge_source(item.get("source", ""))), None)
        if existing is not None:
            existing.setdefault("title", OFFICIAL_KNOWLEDGE_SOURCE["title"])
        elif OFFICIAL_KNOWLEDGE_SOURCE["sourceId"] not in state.get("removedDefaults", []):
            state["sources"].insert(0, copy.deepcopy(OFFICIAL_KNOWLEDGE_SOURCE))
        return state

    def sources_list(self) -> list[dict]:
        return self._sources_state()["sources"]

    def sources_add(self, source: str) -> dict:
        if source.startswith("https://"):
            protocol.validate_https(source)
            identity = _url_identity(source)
        else:
            identity = "local:sha256:" + _hash(Path(source).resolve(strict=True).as_uri().encode())
        record = {"sourceId": _hash(source.encode())[:24], "source": source, "identity": identity}
        official = _is_official_knowledge_source(source)
        if official:
            record = copy.deepcopy(OFFICIAL_KNOWLEDGE_SOURCE)
        with _file_lock(self.lock_path):
            state = self._sources_state()
            sources = state["sources"]
            previous = next((item for item in sources if item["sourceId"] == record["sourceId"] or (official and _is_official_knowledge_source(item.get("source", "")))), None)
            if previous:
                return previous
            if official:
                state["removedDefaults"] = [item for item in state.get("removedDefaults", []) if item != record["sourceId"]]
            _atomic_json(self.root / "sources.json", {**state, "sources": [*sources, record]})
        return record

    def sources_remove(self, source_id: str) -> dict:
        with _file_lock(self.lock_path):
            state = self._sources_state()
            sources = state["sources"]
            removed = next((item for item in sources if item["sourceId"] == source_id), None)
            protocol.require(removed is not None, "Unknown sourceId")
            if _is_official_knowledge_source(removed.get("source", "")):
                state["removedDefaults"] = list(dict.fromkeys([*state.get("removedDefaults", []), OFFICIAL_KNOWLEDGE_SOURCE["sourceId"]]))
            _atomic_json(self.root / "sources.json", {**state, "sources": [item for item in sources if item["sourceId"] != source_id]})
        return {"removed": source_id}

    def sources_refresh(self, source_id: str) -> dict:
        source = next((item for item in self.sources_list() if item["sourceId"] == source_id), None)
        protocol.require(source is not None, "Unknown sourceId")
        inspection = self.inspect(source["source"])
        with _file_lock(self.lock_path):
            state = self._sources_state()
            sources = state["sources"]
            source = next((item for item in sources if item["sourceId"] == source_id), None)
            protocol.require(source is not None, "Source removed during refresh")
            source.update(inspectionId=inspection["inspectionId"], entries=inspection["entries"], resolved=inspection["source"])
            _atomic_json(self.root / "sources.json", {**state, "sources": sources})
        return {**inspection, "source": source}

    def pin(self) -> list[dict]:
        return [{"installationId": item["installationId"], "id": item["id"], "version": item["version"], "digest": item["digest"], "source": item["source"]["identity"]} for item in self._selected()]

    def _selected(self, pinned: list | None = None) -> list[dict]:
        records = self._registry()["installations"]
        if pinned is None:
            selected = [item for item in records if item.get("enabled") and not item.get("removed")]
        else:
            selected = []
            for pin in pinned:
                protocol.require(isinstance(pin, dict), "Pin entries must contain installationId and digest")
                match = next((item for item in records if item["installationId"] == pin.get("installationId")), None)
                protocol.require(match is not None and match["digest"] == pin.get("digest"), "Pinned package is unavailable or digest differs")
                selected.append(match)
        seen = {item["installationId"] for item in selected}
        for record in selected:
            for dependency in record.get("dependencies", []):
                if dependency["installationId"] in seen:
                    continue
                match = next((item for item in records if item["installationId"] == dependency["installationId"]), None)
                protocol.require(match is not None and match["digest"] == dependency["digest"], "Pinned dependency is unavailable")
                seen.add(match["installationId"])
                selected.append(match)
        return selected

    @staticmethod
    def uri(installation_id: str, entity_id: str) -> str:
        return "reverselab://" + installation_id + "/" + entity_id

    def graph(self, track: str = "both", pinned: list | None = None) -> dict:
        protocol.require(track in {"red", "blue", "both", "shared"}, "Invalid track")
        records = self._selected(pinned)
        result = {"documents": [], "methods": [], "networks": [], "bindings": [], "packs": []}
        for record in records:
            if record["kind"] != "knowledge":
                continue
            payload, _ = protocol.load(self.root / "packages" / record["installationId"])
            manifest = protocol.validate(payload, archive=True)
            protocol.require(protocol.package_digest(payload) == record["digest"], "Installed knowledge content changed")
            data = protocol.object_json(payload[manifest["knowledge"]], manifest["knowledge"])
            result["packs"].append({"installationId": record["installationId"], "id": record["id"], "version": record["version"], "digest": record["digest"], "source": record["source"], "domains": data["domains"]})
            dependencies = {dep["id"]: dep for dep in record.get("dependencies", [])}

            def resolve(entity_id: str) -> str:
                namespace = entity_id.split("/", 1)[0]
                owner = record["installationId"] if namespace == record["id"] else dependencies.get(namespace, {}).get("installationId")
                return self.uri(owner, entity_id) if owner else "unavailable:" + entity_id

            for group in ("documents", "methods", "networks"):
                for item in data[group]:
                    if track not in {"both", "shared"} and item["track"] not in {track, "shared"}:
                        continue
                    copied = {**copy.deepcopy(item), "entityId": item["id"], "id": resolve(item["id"]), "installationId": record["installationId"], "packId": record["id"], "version": record["version"], "digest": record["digest"], "source": record["source"]}
                    if group == "documents":
                        copied["packagePath"] = item["path"]
                        copied["sourcePath"] = item["path"]
                        copied["path"] = copied["id"]
                    elif group == "methods":
                        copied["document"] = resolve(item["document"])
                        copied["available"] = not copied["document"].startswith("unavailable:")
                    else:
                        copied["nodes"] = [resolve(node) for node in item["nodes"]]
                        copied["entrypoints"] = [resolve(node) for node in item["entrypoints"]]
                        copied["relations"] = [{**edge, "from": resolve(edge["from"]), "to": resolve(edge["to"])} for edge in item["relations"]]
                    result[group].append(copied)
            result["bindings"].extend({**copy.deepcopy(binding), "method": resolve(binding["method"]), "installationId": record["installationId"]} for binding in data.get("bindings", []))
        return result

    def catalog(self, track: str = "both", pinned: list | None = None) -> list[dict]:
        graph = self.graph(track, pinned)
        result = []
        methods_by_document = {}
        document_by_method = {}
        network_ids_by_method = {}
        related_by_document = {}
        for method in graph["methods"]:
            methods_by_document.setdefault(method["document"], []).append(method)
            document_by_method[method["id"]] = method["document"]
        for network in graph["networks"]:
            for method_id in network["nodes"]:
                network_ids_by_method.setdefault(method_id, []).append(network["id"])
            for relation in network["relations"]:
                start, end = document_by_method.get(relation["from"]), document_by_method.get(relation["to"])
                if start and end and start != end:
                    related_by_document.setdefault(start, []).append(end)
                    related_by_document.setdefault(end, []).append(start)
        for document in graph["documents"]:
            methods = methods_by_document.get(document["id"], [])
            method_ids = [method["id"] for method in methods]
            result.append({**document, "aliases": document.get("aliases", []), "board": document["domain"], "category": document.get("category", "general"), "signals": list(dict.fromkeys(signal for method in methods for signal in method["signals"])), "mcp_tools": document.get("mcp_tools", list(dict.fromkeys(capability for method in methods for capability in method["toolRequirements"]))), "related": document.get("related", []), "related_paths": list(dict.fromkeys(related_by_document.get(document["id"], []))), "methodIds": method_ids, "networkIds": list(dict.fromkeys(network_id for method_id in method_ids for network_id in network_ids_by_method.get(method_id, [])))})
        return result

    def read_document(self, uri: str) -> str:
        parsed = urlsplit(uri)
        protocol.require(parsed.scheme == "reverselab" and bool(re.fullmatch(r"[0-9a-f]{32}", parsed.netloc)) and not parsed.query and not parsed.fragment, "Expected versioned reverselab document URI")
        record = self.get(parsed.netloc)
        protocol.require(record["kind"] == "knowledge", "Installation has no knowledge documents")
        payload, _ = protocol.load(Path(record["root"]))
        manifest = protocol.validate(payload, archive=True)
        protocol.require(protocol.package_digest(payload) == record["digest"], "Installed document content changed")
        data = protocol.object_json(payload[manifest["knowledge"]], manifest["knowledge"])
        entity_id = parsed.path.removeprefix("/")
        document = next((item for item in data["documents"] if item["id"] == entity_id), None)
        protocol.require(document is not None, "Unknown document ID")
        return payload[document["path"]].decode("utf-8")

    def resolve(self, entity_id: str, pinned: list | None = None) -> dict:
        graph = self.graph(pinned=pinned)
        matches = [item for group in ("documents", "methods", "networks") for item in graph[group] if item["id"] == entity_id or item["entityId"] == entity_id or entity_id in item.get("aliases", [])]
        protocol.require(len(matches) == 1, "Entity is unavailable or ambiguous; use its source-qualified URI")
        return matches[0]

    def resolve_link(self, uri: str, href: str) -> str:
        parsed = urlsplit(uri)
        record = self.get(parsed.netloc)
        payload, _ = protocol.load(Path(record["root"]))
        manifest = protocol.validate(payload, archive=True)
        protocol.require(record["kind"] == "knowledge" and protocol.package_digest(payload) == record["digest"], "Knowledge package content changed")
        data = protocol.object_json(payload[manifest["knowledge"]], manifest["knowledge"])
        current = next((item for item in data["documents"] if item["id"] == parsed.path.removeprefix("/")), None)
        protocol.require(current is not None, "Unknown document URI")
        link = urlsplit(href)
        protocol.require(not link.scheme and not link.netloc and not link.query, "Expected a relative package document link")
        if not link.path:
            return uri
        path = posixpath.normpath(posixpath.join(posixpath.dirname(current["path"]), unquote(link.path)))
        protocol.safe_path(path)
        target = next((item for item in data["documents"] if item["path"] == path), None)
        protocol.require(target is not None, "Link is not a declared package document")
        return self.uri(record["installationId"], target["id"])

    def neighbors(self, entity_id: str, pinned: list | None = None) -> dict:
        entity = self.resolve(entity_id, pinned)
        graph = self.graph(pinned=pinned)
        relations = [relation for network in graph["networks"] for relation in network["relations"] if entity["id"] in {relation["from"], relation["to"]}]
        return {"entity": entity, "relations": relations}


Store = ExtensionStore
