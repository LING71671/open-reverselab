"""Local desktop workspaces. JSON request on stdin, JSON response on stdout."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
import time
import uuid
from contextlib import contextmanager


def data_root() -> Path:
    return Path(os.environ.get("REVERSELAB_DATA_DIR", str(Path.home() / ".open-reverselab"))).resolve()


def atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".write-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


@contextmanager
def lock(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as stream:
        stream.seek(0, 2)
        if stream.tell() == 0:
            stream.write(b"0")
            stream.flush()
        deadline = time.monotonic() + 10
        while True:
            stream.seek(0)
            try:
                if os.name == "nt":
                    import msvcrt
                    msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise TimeoutError("Workspace is busy")
                time.sleep(.025)
        try:
            yield
        finally:
            stream.seek(0)
            if os.name == "nt":
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream, fcntl.LOCK_UN)


def managed_path(root: Path, *parts: str) -> Path:
    managed = root / ".reverselab"
    if managed.is_symlink() or (managed.exists() and managed.resolve() != managed):
        raise ValueError("Workspace metadata cannot be a link")
    path = managed.joinpath(*parts)
    if not path.resolve().is_relative_to(managed):
        raise ValueError("Workspace path escapes managed directory")
    return path


def metadata(root: Path) -> dict:
    value = json.loads(managed_path(root, "workspace.json").read_text(encoding="utf-8"))
    if value.get("version") != 1 or not re.fullmatch(r"[a-f0-9]{32}", value.get("id", "")):
        raise ValueError("Unsupported workspace format")
    return {**value, "root": str(root)}


def register(workspace: dict) -> None:
    registry = data_root() / "workspaces.json"
    with lock(data_root() / "workspaces.lock"):
        items = json.loads(registry.read_text(encoding="utf-8")) if registry.exists() else []
        atomic_json(registry, [workspace, *[item for item in items if item["root"] != workspace["root"]]][:30])


def open_workspace(root_value: str, create: bool = False, name: str = "") -> dict:
    root = Path(root_value).expanduser().resolve()
    marker = managed_path(root, "workspace.json")
    if create:
        root.mkdir(parents=True, exist_ok=True)
        with lock(managed_path(root, "workspace.lock")):
            if not marker.exists():
                atomic_json(marker, {"version": 1, "id": uuid.uuid4().hex, "name": name.strip() or root.name, "createdAt": int(time.time() * 1000)})
            for folder in ("samples", "goals", "reports", "exports"):
                managed_path(root, folder).mkdir(exist_ok=True)
    workspace = metadata(root)
    register(workspace)
    return workspace


def identifier(value: str) -> str:
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9:_-]{0,180}", value):
        raise ValueError("Invalid record identifier")
    return value.replace(":", "_")


def import_sample(root: Path, source_value: str) -> dict:
    source = Path(source_value).expanduser().absolute()
    if source.is_symlink() or not source.exists():
        raise ValueError("Sample must be an existing regular file or directory")
    source = source.resolve()
    managed = managed_path(root)
    if source.is_relative_to(managed) or managed.is_relative_to(source):
        raise ValueError("Cannot import a workspace into itself")
    files = [source] if source.is_file() else sorted(source.rglob("*"))
    total = 0
    for path in files:
        if path.is_symlink() or not path.resolve().is_relative_to(source if source.is_dir() else source.parent):
            raise ValueError("Linked sample entries are not supported")
        if not path.is_file() and not path.is_dir():
            raise ValueError("Sample contains an unsupported entry")
        if path.is_file():
            total += path.stat().st_size
        if total > 2 * 1024**3 or len(files) > 10000:
            raise ValueError("Sample import exceeds 2 GiB or 10,000 entries")
    sample_id = uuid.uuid4().hex
    samples = managed_path(root, "samples")
    staging = Path(tempfile.mkdtemp(prefix=".import-", dir=samples))
    try:
        original = staging / "original"
        if source.is_dir():
            shutil.copytree(source, original)
        else:
            original.mkdir()
            shutil.copy2(source, original / source.name)
        copied = sorted(p for p in original.rglob("*") if p.is_file())
        manifest = []
        for path in copied:
            with path.open("rb") as stream:
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
            manifest.append({"path": path.relative_to(original).as_posix(), "sha256": digest, "sizeBytes": path.stat().st_size})
        identity = manifest[0]["sha256"] if source.is_file() else hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest()
        destination = samples / sample_id
        shutil.copytree(original, staging / "working")
        target = destination / "working" if source.is_dir() else destination / "working" / source.name
        record = {"id": sample_id, "name": source.name, "kind": "directory" if source.is_dir() else "file", "sha256": identity, "sizeBytes": total, "target": str(target), "importedAt": int(time.time() * 1000), "files": manifest}
        atomic_json(staging / "sample.json", record)
        os.replace(staging, destination)
        return record
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def dispatch(request: dict) -> object:
    action = request.get("action")
    if action == "list":
        registry = data_root() / "workspaces.json"
        items = json.loads(registry.read_text(encoding="utf-8")) if registry.exists() else []
        return items
    if action == "default":
        root = os.environ.get("REVERSELAB_WORKSPACE_DIR", str(data_root() / "workspaces" / "Default"))
        return open_workspace(root, create=True, name="默认工作区")
    if action in ("open", "create"):
        return open_workspace(request["root"], create=action == "create", name=request.get("name", ""))
    root = Path(request["root"]).resolve()
    metadata(root)
    if action == "samples":
        return [json.loads(path.read_text(encoding="utf-8")) for path in managed_path(root, "samples").glob("*/sample.json") if not path.parent.name.startswith(".")]
    if action == "import":
        return import_sample(root, request["source"])
    if action == "load":
        snapshot = managed_path(root, "goals.json")
        return json.loads(snapshot.read_text(encoding="utf-8")) if snapshot.exists() else None
    if action == "save":
        snapshot = request["snapshot"]
        if not isinstance(snapshot, dict) or not isinstance(snapshot.get("sessions"), list) or not isinstance(snapshot.get("records"), dict):
            raise ValueError("Invalid goal snapshot")
        with lock(managed_path(root, "goals.lock")):
            atomic_json(managed_path(root, "goals.json"), snapshot)
        return {"status": "saved"}
    if action == "report":
        report = request["report"]
        scope = identifier(report["goalId"])
        route = identifier(f'{report.get("track", "blue")}-{int(report.get("attempt", 1))}')
        reports = managed_path(root, "reports", scope, route)
        exports = managed_path(root, "exports", scope, route)
        reports.mkdir(parents=True, exist_ok=True)
        exports.mkdir(parents=True, exist_ok=True)
        report_path = reports / "analysis.md"
        script_path = exports / "observation.py"
        text = "# Goal Report\n\n" + str(report.get("summary", ""))
        text += "\n\n## Target\n\n" + str(report.get("target", ""))
        text += "\n\n## Execution\n\n```json\n" + json.dumps(report.get("executionOutput"), ensure_ascii=False, indent=2) + "\n```\n"
        text += "\n\n## Verification\n\n```json\n" + json.dumps(report.get("goalVerification"), ensure_ascii=False, indent=2) + "\n```\n"
        report_path.write_text(text, encoding="utf-8")
        script_path.write_text(report.get("script", ""), encoding="utf-8")
        return {"status": "saved", "report_path": str(report_path), "script_path": str(script_path)}
    raise ValueError("Unknown workspace operation")


if __name__ == "__main__":
    try:
        print(json.dumps(dispatch(json.load(sys.stdin)), ensure_ascii=True))
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(json.dumps({"error": str(error)}, ensure_ascii=True))
        sys.exit(1)
