#!/usr/bin/env python3
"""Canonical, standard-library-only Open ReverseLab extension v1 validator.

The JSON schemas describe wire shapes; this module additionally validates paths,
references, portable archives, declared features and content hashes. No package
code, installation command or hook is ever executed by this module.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import zipfile
from urllib.parse import urlsplit

MANIFEST = "reverselab.extension.json"
LOCK = "reverselab.lock.json"
PROTOCOL = "open-reverselab.extension/v1"
REGISTRY_PROTOCOL = "open-reverselab.registry/v1"
LOCK_PROTOCOL = "open-reverselab.lock/v1"
REGISTRY = "reverselab.registry.json"
SUPPORTED_FEATURES = frozenset({"knowledge", "mcp", "conditions/v1", "typed-relations/v1", "source-qualified-ids/v1"})
TRACKS = {"red", "blue", "shared"}
RELATIONS = {"depends_on", "enables", "composes_with", "defends", "detects", "verifies", "conflicts"}
NAMESPACE = r"[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)+"
LOCAL_ID = r"[a-z0-9][a-z0-9._-]*(?:/[a-z0-9][a-z0-9._-]*)*"
SEMVER = r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
INPUT_REF = re.compile(r"\$\{inputs\.([A-Za-z][A-Za-z0-9_]*)\}")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def string(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def strings(value: object) -> bool:
    return isinstance(value, list) and all(string(item) for item in value)


def object_json(raw: bytes, name: str) -> dict:
    def unique(pairs: list) -> dict:
        result = {}
        for key, value in pairs:
            require(key not in result, f"Duplicate JSON key in {name}: {key}")
            result[key] = value
        return result

    value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique)
    require(isinstance(value, dict), f"Expected JSON object: {name}")
    return value


def safe_path(name: str) -> str:
    require(isinstance(name, str) and name, "Empty or non-string path")
    parts = name.split("/")
    require(not any(p in {"", ".", ".."} for p in parts), f"Non-relative path: {name}")
    require(not any(c in name for c in '\\:<>"|?*') and not any(ord(c) < 32 for c in name), f"Invalid path: {name}")
    for part in parts:
        require(not part.endswith((".", " ")), f"Nonportable path: {name}")
        require(not re.fullmatch(r"(?i)(CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])(?:\..*)?", part), f"Reserved path: {name}")
    return name


def unique_paths(names: list[str]) -> None:
    lowered = set()
    for name in names:
        safe_path(name)
        require(name.casefold() not in lowered, f"Duplicate/case-colliding path: {name}")
        lowered.add(name.casefold())
    for name in lowered:
        require(not any(str(parent) in lowered for parent in PurePosixPath(name).parents if str(parent) != "."), f"File/directory collision: {name}")


def read_local(root: Path, name: str) -> bytes:
    safe_path(name)
    require(not root.is_symlink() and not getattr(root, "is_junction", lambda: False)(), "Package root must not be a link")
    candidate = root.joinpath(*name.split("/"))
    require(candidate.resolve().is_relative_to(root.resolve()), f"Path leaves package: {name}")
    current = candidate
    while current != root:
        require(not current.is_symlink() and not getattr(current, "is_junction", lambda: False)(), f"Link in package: {name}")
        current = current.parent
    require(candidate.is_file(), f"Missing file: {name}")
    return candidate.read_bytes()


def load(source: Path) -> tuple[dict[str, bytes], bool]:
    if source.is_dir():
        root = source.absolute()
        raw = read_local(root, MANIFEST)
        manifest = object_json(raw, MANIFEST)
        names = manifest.get("files")
        require(strings(names), "files must be an array of paths")
        unique_paths([MANIFEST, LOCK, *names])
        payload = {MANIFEST: raw, **{name: read_local(root, name) for name in names}}
        if (root / LOCK).exists():
            payload[LOCK] = read_local(root, LOCK)
        return payload, False

    with zipfile.ZipFile(source) as archive:
        entries = archive.infolist()
        paths = [entry.filename.rstrip("/") for entry in entries]
        require(len({p.casefold() for p in paths}) == len(paths), "Duplicate archive entries")
        for entry, name in zip(entries, paths):
            safe_path(name)
            mode = entry.external_attr >> 16
            require(stat.S_IFMT(mode) in {0, stat.S_IFREG, stat.S_IFDIR}, f"Unsupported archive entry: {name}")
        members = [entry for entry in entries if not entry.is_dir()]
        roots = [e.filename.removesuffix(MANIFEST) for e in members if PurePosixPath(e.filename).name == MANIFEST]
        require(len(roots) == 1, "Archive must contain exactly one extension manifest")
        prefix = roots[0]
        require(not prefix or prefix.count("/") == 1, "Only one enclosing archive directory is supported")
        require(all(e.filename.startswith(prefix) for e in members), "Files outside package root")
        result = {e.filename[len(prefix):]: archive.read(e) for e in members}
        unique_paths(list(result))
        return result, True


def validate(payload: dict[str, bytes], archive: bool = False, *, check_features: bool = True) -> dict:
    manifest = object_json(payload[MANIFEST], MANIFEST)
    require(manifest.get("protocol") == PROTOCOL, "Unsupported extension protocol; v1-draft requires explicit migration")
    require(manifest.get("kind") in {"knowledge", "mcp"}, "kind must be knowledge or mcp")
    for field in ("id", "version", "title", "description", "license"):
        require(string(manifest.get(field)), f"Missing manifest field: {field}")
    require(re.fullmatch(NAMESPACE, manifest["id"]) is not None, "Invalid pack namespace")
    require(re.fullmatch(SEMVER, manifest["version"]) is not None, "Invalid content version")
    pre = manifest["version"].split("+", 1)[0].partition("-")[2]
    require(all(not (p.isdigit() and len(p) > 1 and p.startswith("0")) for p in pre.split(".")), "Leading zero in prerelease version")
    names = manifest.get("files")
    require(strings(names), "files must be an array of paths")
    unique_paths([MANIFEST, LOCK, *names])
    expected = {MANIFEST, *names}
    require(set(payload) == expected | ({LOCK} if LOCK in payload else set()), "Package file set differs from manifest")
    require(not archive or LOCK in payload, "Package ZIP is missing reverselab.lock.json")
    dependencies = manifest.get("requires", [])
    require(isinstance(dependencies, list), "requires must be an array")
    dependency_ids = set()
    for dep in dependencies:
        require(isinstance(dep, dict), "Invalid dependency")
        for field in ("id", "version", "source"):
            require(string(dep.get(field)), f"Missing dependency {field}")
        require(re.fullmatch(NAMESPACE, dep["id"]) is not None, "Invalid dependency namespace")
        require(re.fullmatch(SEMVER, dep["version"]) is not None, "Dependencies require exact SemVer versions")
        require(isinstance(dep.get("optional"), bool), "Dependency optional must be boolean")
        require(dep["id"] not in dependency_ids | {manifest["id"]}, "Duplicate/self dependency")
        dependency_ids.add(dep["id"])
    if "requiredFeatures" in manifest:
        require(strings(manifest["requiredFeatures"]), "requiredFeatures must be strings")
        if check_features:
            require(set(manifest["requiredFeatures"]).issubset(SUPPORTED_FEATURES), "Unsupported requiredFeatures: " + ", ".join(sorted(set(manifest["requiredFeatures"]) - SUPPORTED_FEATURES)))
    require(not any(key in manifest for key in ("install", "postinstall", "hooks")), "Installation hooks are not supported")
    content_path = manifest.get(manifest["kind"])
    require(isinstance(content_path, str) and content_path in names, "Missing listed knowledge/mcp file")
    content = object_json(payload[content_path], content_path)
    if manifest["kind"] == "knowledge":
        validate_knowledge(manifest, content, payload, dependency_ids)
    else:
        validate_mcp(content)
    if LOCK in payload:
        locked = object_json(payload[LOCK], LOCK)
        expected_lock = make_lock(manifest, {name: payload[name] for name in expected})
        require(all(locked.get(key) == value for key, value in expected_lock.items()), "Archive lock or content digest mismatch")
        lock_dependencies = locked.get("dependencies", [])
        require(isinstance(lock_dependencies, list), "Lock dependencies must be an array")
        seen_dependencies = set()
        declared = {item["id"]: item for item in dependencies}
        for item in lock_dependencies:
            require(isinstance(item, dict) and item.get("id") in declared, "Lock contains an undeclared dependency")
            require(item["id"] not in seen_dependencies, "Duplicate locked dependency")
            seen_dependencies.add(item["id"])
            require(item.get("version") == declared[item["id"]]["version"] and item.get("source") == declared[item["id"]]["source"], "Lock dependency differs from manifest")
            require(isinstance(item.get("digest"), str) and re.fullmatch(r"[0-9a-f]{64}", item["digest"]) is not None, "Invalid dependency digest")
    return manifest


def validate_knowledge(manifest: dict, data: dict, payload: dict, dependencies: set) -> None:
    require(strings(data.get("domains")) and data["domains"], "Knowledge domains are required")
    domains = set(data["domains"])
    groups = {}
    all_ids = set()
    for group in ("documents", "methods", "networks"):
        records = data.get(group)
        require(isinstance(records, list), f"{group} must be an array")
        groups[group] = {}
        for item in records:
            require(isinstance(item, dict), f"Invalid {group} record")
            item_id = item.get("id")
            require(string(item_id) and re.fullmatch(re.escape(manifest["id"]) + "/" + LOCAL_ID, item_id) is not None, "Invalid local entity ID")
            require(item_id not in all_ids, f"Duplicate entity ID: {item_id}")
            all_ids.add(item_id)
            require(string(item.get("title")) and item.get("track") in TRACKS, f"Invalid title/track: {item_id}")
            if group != "networks":
                require(item.get("domain") in domains, f"Unknown domain: {item_id}")
            for optional_list in ("aliases", "mcp_tools"):
                if optional_list in item:
                    require(strings(item[optional_list]), f"{optional_list} must be strings")
            groups[group][item_id] = item

    def reference(ref: object, group: str) -> None:
        require(string(ref), "Empty entity reference")
        namespace, separator, local = ref.partition("/")
        require(bool(separator) and re.fullmatch(LOCAL_ID, local) is not None, f"Invalid reference: {ref}")
        require(ref in groups[group] or namespace in dependencies, f"Missing {group} reference: {ref}")

    for item in groups["documents"].values():
        path = item.get("path")
        require(isinstance(path, str) and path in manifest["files"] and path.endswith(".md"), "Document must reference listed Markdown")
        payload[path].decode("utf-8")
    for item in groups["methods"].values():
        reference(item.get("document"), "documents")
        for field in ("signals", "requiresEvidence", "produces", "toolRequirements"):
            require(strings(item.get(field)), f"Method {field} must be strings")
        if "when" in item:
            validate_condition(item["when"])
    for network in groups["networks"].values():
        require(strings(network.get("nodes")) and strings(network.get("entrypoints")), "Network nodes and entrypoints must be arrays")
        require(len(set(network["nodes"])) == len(network["nodes"]), "Duplicate network node")
        require(set(network["entrypoints"]).issubset(network["nodes"]), "Entrypoint is not a network node")
        for node in network["nodes"]:
            reference(node, "methods")
        require(isinstance(network.get("relations"), list), "Network relations must be an array")
        for relation in network["relations"]:
            require(isinstance(relation, dict) and relation.get("type") in RELATIONS, "Unknown relation type")
            require(relation.get("from") in network["nodes"] and relation.get("to") in network["nodes"], "Relation endpoint is not a network node")
            if "when" in relation:
                validate_condition(relation["when"])
    bindings = data.get("bindings", [])
    require(isinstance(bindings, list), "bindings must be an array")
    for binding in bindings:
        require(isinstance(binding, dict), "Invalid tool binding")
        reference(binding.get("method"), "methods")
        require(all(string(binding.get(f)) for f in ("capability", "server", "tool")), "Incomplete tool binding")
        require(isinstance(binding.get("inputMapping"), dict), "Binding inputMapping must be an object")
        require("outputMapping" not in binding or isinstance(binding["outputMapping"], dict), "Binding outputMapping must be an object")


def validate_mcp(data: dict) -> None:
    require(data.get("transport") in {"stdio", "streamable-http"}, "Unsupported MCP transport")
    require(isinstance(data.get("inputs"), list), "MCP inputs must be an array")
    names = set()
    for item in data["inputs"]:
        require(isinstance(item, dict), "Invalid MCP input")
        name = item.get("name")
        require(string(name) and re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", name) is not None and name not in names, "Invalid/duplicate MCP input name")
        require(item.get("type") in {"string", "url", "path", "secret"} and isinstance(item.get("required"), bool), "Invalid MCP input type/required")
        require("value" not in item and "default" not in item, "Store configured input values locally")
        names.add(name)
    values = []
    if data["transport"] == "stdio":
        require(string(data.get("command")) and strings(data.get("args")), "stdio requires command and argument array")
        values.extend([data["command"], *data["args"]])
        require("url" not in data and "headers" not in data, "HTTP fields on stdio connection")
    else:
        url = data.get("url")
        require(string(url) and (url.startswith("https://") or url.startswith("http://") or INPUT_REF.fullmatch(url)), "HTTP connection requires URL or input reference")
        require("command" not in data and "args" not in data and "env" not in data, "stdio fields on HTTP connection")
        values.append(url)
        if not INPUT_REF.fullmatch(url):
            parsed = urlsplit(url)
            require(bool(parsed.hostname) and parsed.username is None and parsed.password is None, "MCP URL must not contain credentials")
            require(not parsed.query and not parsed.fragment, "MCP URL query/fragment must be supplied through a local input")
    for field in ("env", "headers"):
        mapping = data.get(field, {})
        require(isinstance(mapping, dict), f"{field} must be an object")
        for key, value in mapping.items():
            require(string(key) and isinstance(value, str) and INPUT_REF.fullmatch(value), f"{field} values must be input references")
            values.append(value)
    for value in values:
        for name in INPUT_REF.findall(value):
            require(name in names, f"Undeclared MCP input: {name}")
        require("${" not in INPUT_REF.sub("", value), "Unsupported input expression")


def make_lock(manifest: dict, payload: dict[str, bytes]) -> dict:
    return {"protocol": LOCK_PROTOCOL, "id": manifest["id"], "version": manifest["version"],
            "files": {name: hashlib.sha256(raw).hexdigest() for name, raw in sorted(payload.items()) if name != LOCK}}


def json_bytes(value: dict) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def package_digest(payload: dict[str, bytes]) -> str:
    """Content identity excludes lock provenance, includes names and exact bytes."""
    hashes = {name: hashlib.sha256(raw).hexdigest() for name, raw in sorted(payload.items()) if name != LOCK}
    return hashlib.sha256(json_bytes(hashes)).hexdigest()


def validate_condition(value: object) -> None:
    require(isinstance(value, dict), "Condition must be an object")
    if set(value) in ({"all"}, {"any"}):
        children = next(iter(value.values()))
        require(isinstance(children, list), "Condition children must be an array")
        for child in children:
            validate_condition(child)
    elif set(value) == {"not"}:
        validate_condition(value["not"])
    else:
        require(set(value) == {"evidence", "state"} and string(value.get("evidence")) and value.get("state") in {"observed", "absent", "unobservable"}, "Invalid evidence condition")


def evaluate_condition(condition: dict, evidence: dict) -> bool | None:
    """Kleene three-valued logic: an unrecorded key is unknown (None)."""
    validate_condition(condition)
    if "evidence" in condition:
        state = evidence.get(condition["evidence"])
        if isinstance(state, dict):
            state = state.get("state", state.get("status"))
        return None if state is None or state == "unknown" else state == condition["state"]
    if "not" in condition:
        value = evaluate_condition(condition["not"], evidence)
        return None if value is None else not value
    operation = "all" if "all" in condition else "any"
    values = [evaluate_condition(item, evidence) for item in condition[operation]]
    decisive = False if operation == "all" else True
    if decisive in values:
        return decisive
    return None if None in values else operation == "all"


def validate_registry(data: dict) -> dict:
    require(data.get("protocol") == REGISTRY_PROTOCOL, "Unsupported registry protocol")
    require(string(data.get("id")) and string(data.get("title")), "Registry requires id and title")
    require(isinstance(data.get("entries"), list), "Registry entries must be an array")
    ids = set()
    for item in data["entries"]:
        require(isinstance(item, dict), "Invalid registry entry")
        require(string(item.get("id")) and re.fullmatch(NAMESPACE, item["id"]) is not None, "Invalid registry entry ID")
        require(item["id"] not in ids, "Duplicate registry entry ID")
        ids.add(item["id"])
        require(item.get("kind") in {"knowledge", "mcp"} and string(item.get("title")), "Invalid registry kind/title")
        require(string(item.get("version")) and re.fullmatch(SEMVER, item["version"]) is not None, "Invalid registry version")
        require(sum(key in item for key in ("path", "artifact", "repository")) == 1, "Registry entry needs exactly one path, artifact or repository")
        if "path" in item:
            if item["path"] != ".":
                safe_path(item["path"])
        elif "repository" in item:
            validate_https(item["repository"])
            require(urlsplit(item["repository"]).hostname == "github.com", "Repository entries require a GitHub URL")
        else:
            validate_https(item["artifact"])
            require(isinstance(item.get("sha256"), str) and re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) is not None, "Artifact requires SHA256")
    return data


def validate_https(url: str) -> str:
    require(string(url), "Expected HTTPS URL")
    parsed = urlsplit(url)
    require(parsed.scheme == "https" and bool(parsed.hostname), "Remote source must use HTTPS")
    require(parsed.username is None and parsed.password is None and not parsed.query and not parsed.fragment, "Source URLs must not contain credentials, query strings or fragments")
    return url


def migrate_draft(payload: dict[str, bytes]) -> dict[str, bytes]:
    """Explicit offline migration. Existing hashes are checked before conversion."""
    manifest = object_json(payload[MANIFEST], MANIFEST)
    require(manifest.get("protocol") == "open-reverselab.extension/v1-draft", "Only v1-draft can be migrated")
    if LOCK in payload:
        lock = object_json(payload[LOCK], LOCK)
        expected = make_lock(manifest, payload)
        expected["protocol"] = "open-reverselab.lock/v1-draft"
        require(all(lock.get(key) == value for key, value in expected.items()), "Draft lock mismatch")
    result = dict(payload)
    manifest["protocol"] = PROTOCOL
    manifest.setdefault("extensions", {})["migratedFrom"] = "open-reverselab.extension/v1-draft"
    result[MANIFEST] = json_bytes(manifest)
    result.pop(LOCK, None)
    validate(result)
    result[LOCK] = json_bytes(make_lock(manifest, result))
    return result


def zip_bytes(payload: dict[str, bytes]) -> bytes:
    manifest = validate(payload)
    payload = dict(payload)
    payload.setdefault(LOCK, json_bytes(make_lock(manifest, payload)))
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as output:
        for name, raw in sorted(payload.items()):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            output.writestr(info, raw)
    return buffer.getvalue()


def pack(source: str | Path, output: str | Path) -> dict:
    source, output = Path(source), Path(output)
    require(not output.resolve().is_relative_to(source.resolve()), "Write output outside the package source")
    payload, archive = load(source)
    manifest = validate(payload, archive)
    raw = zip_bytes(payload)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("xb") as handle:
        handle.write(raw)
    return {"path": str(output), "sha256": hashlib.sha256(raw).hexdigest(), "id": manifest["id"], "version": manifest["version"]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("check", "build", "migrate"))
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path, nargs="?")
    args = parser.parse_args()
    try:
        payload, archive = load(args.source)
        if args.operation == "migrate":
            payload = migrate_draft(payload)
        manifest = validate(payload, archive)
        if args.operation in {"build", "migrate"}:
            require(args.output is not None, "Build requires an output ZIP path")
            require(not args.output.resolve().is_relative_to(args.source.resolve()), "Write output outside the package source")
            output = zip_bytes(payload)
            with args.output.open("xb") as destination:
                destination.write(output)
            print(f"ZIP SHA256: {hashlib.sha256(output).hexdigest()}")
        else:
            require(args.output is None, "check takes no output path")
        print(f"Extension v1 checks passed: {manifest['id']}@{manifest['version']} ({manifest['kind']})")
        return 0
    except (ValueError, OSError, KeyError, TypeError, zipfile.BadZipFile, RuntimeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
