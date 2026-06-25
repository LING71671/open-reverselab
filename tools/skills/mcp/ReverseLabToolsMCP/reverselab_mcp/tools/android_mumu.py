from __future__ import annotations

import base64
import json
import re
import socket
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from ..audit import append_audit, audit_log_path
from ..config import ADB_EXE, ANDROID_EXPORTS_DIR, HOST_PYTHON_EXE, MUMU_CLI_EXE, MUMU_DEFAULT_SERIAL, REVERSE_ROOT
from ..errors import ToolError
from ..paths import check_tool, ensure_under, resolve_file
from ..runner import run
from ..utils import contains, slug


def _mumu_info() -> dict[str, Any]:
    try:
        _, stdout, _ = _mumu_cli(["info", "--vmindex", _mumu_vmindex()], timeout=20, check=True)
        value = json.loads(stdout)
        if isinstance(value, dict):
            return value
    except Exception:
        pass
    return {}


def _candidate_serials(serial: str = "") -> list[str]:
    candidates: list[str] = []
    if serial.strip():
        candidates.append(serial.strip())
    info = _mumu_info()
    adb_port = info.get("adb_port")
    if isinstance(adb_port, int) and adb_port > 0:
        candidates.append(f"127.0.0.1:{adb_port}")
    candidates.extend([MUMU_DEFAULT_SERIAL, "127.0.0.1:5555"])
    deduped: list[str] = []
    seen: set[str] = set()
    for item in candidates:
        if item and item not in seen:
            seen.add(item)
            deduped.append(item)
    return deduped


def _tcp_open(serial: str, timeout_seconds: float = 0.5) -> bool:
    if ":" not in serial:
        return False
    host, port_text = serial.rsplit(":", 1)
    try:
        port = int(port_text)
    except ValueError:
        return False
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout_seconds)
    try:
        sock.connect((host, port))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def _serial(serial: str = "") -> str:
    for candidate in _candidate_serials(serial):
        if _tcp_open(candidate):
            return candidate
    return _candidate_serials(serial)[0]


def _is_default_mumu_serial(serial: str) -> bool:
    candidate = serial.strip() or _serial("")
    return candidate.startswith("127.0.0.1:")


def _mumu_vmindex() -> str:
    return "0"


def _mumu_cli(args: list[str], timeout: int = 60, check: bool = True) -> tuple[int, str, str]:
    check_tool(MUMU_CLI_EXE, "mumu-cli")
    cmd = [str(MUMU_CLI_EXE), *args]
    code, stdout, stderr = run(cmd, timeout=max(5, timeout))
    if check and code != 0:
        raise ToolError(f"mumu-cli command failed: returncode={code}; stderr={stderr or stdout}")
    return code, stdout, stderr


def _adb(args: list[str], serial: str = "", timeout: int = 60, check: bool = True) -> tuple[int, str, str]:
    check_tool(ADB_EXE, "adb")
    cmd = [str(ADB_EXE)]
    if serial.strip():
        cmd.extend(["-s", _serial(serial)])
    cmd.extend(args)
    code, stdout, stderr = run(cmd, timeout=max(5, timeout))
    if check and code != 0:
        raise ToolError(f"adb command failed: returncode={code}; stderr={stderr or stdout}")
    return code, stdout, stderr


def _shell(command: str, serial: str = "", as_root: bool = False, timeout: int = 30) -> dict[str, Any]:
    code = 0
    stdout = ""
    stderr = ""
    try:
        args = ["shell"]
        if as_root:
            escaped = command.replace('"', '\\"')
            args.append(f'su -c "{escaped}"')
        else:
            args.append(command)
        code, stdout, stderr = _adb(args, serial=serial, timeout=timeout, check=True)
    except Exception:
        if not _is_default_mumu_serial(serial):
            raise
        wrapped = command if as_root else f"su -c \"{command.replace('\"', '\\\"')}\""
        code, stdout, stderr = _mumu_cli(["sh", "--vmindex", _mumu_vmindex(), "--cmd", wrapped], timeout=timeout, check=True)
    return {
        "command": command,
        "as_root": as_root,
        "returncode": code,
        "stdout": stdout,
        "stderr": stderr,
    }


def _android_output_path(output_path: str, prefix: str, suffix: str) -> Path:
    if output_path.strip():
        destination = Path(output_path).expanduser().resolve()
        ensure_under(destination, [ANDROID_EXPORTS_DIR], "android output path")
    else:
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        destination = ANDROID_EXPORTS_DIR / f"{prefix}-{stamp}{suffix}"
    destination.parent.mkdir(parents=True, exist_ok=True)
    return destination


def _find_existing_app_output_dir(package_name: str) -> Path | None:
    normalized = package_name.strip()
    if not normalized or not ANDROID_EXPORTS_DIR.exists():
        return None
    for child in ANDROID_EXPORTS_DIR.iterdir():
        if not child.is_dir() or child.name == "packages":
            continue
        if (child / "packages" / normalized).exists():
            return child
        for category in ["artifacts", "logs", "screenshots", "package-info", "frida"]:
            category_dir = child / category
            if category_dir.exists() and any(category_dir.glob(f"*{normalized}*")):
                return child
    return None


def _app_output_dir(package_name: str) -> Path:
    normalized = package_name.strip()
    if not normalized:
        return ANDROID_EXPORTS_DIR
    destination = _find_existing_app_output_dir(normalized)
    if destination is None:
        destination = ANDROID_EXPORTS_DIR / normalized
    destination.mkdir(parents=True, exist_ok=True)
    return destination


def _app_output_path(package_name: str, category: str, prefix: str, suffix: str, output_path: str = "") -> Path:
    if output_path.strip():
        destination = Path(output_path).expanduser().resolve()
        ensure_under(destination, [ANDROID_EXPORTS_DIR], "android app output path")
    else:
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        destination = _app_output_dir(package_name) / category / f"{prefix}-{stamp}{suffix}"
    destination.parent.mkdir(parents=True, exist_ok=True)
    return destination


def _package_output_dir(package_name: str) -> Path:
    destination = _app_output_dir(package_name) / "packages" / package_name.strip()
    destination.mkdir(parents=True, exist_ok=True)
    return destination


def _pull_via_mumu_shell(remote_path: str, destination: Path, timeout: int = 300) -> None:
    escaped = remote_path.replace('"', '\\"')
    code, stdout, stderr = _mumu_cli(
        ["sh", "--vmindex", _mumu_vmindex(), "--cmd", f'su -c "base64 {escaped}"'],
        timeout=timeout,
        check=True,
    )
    if code != 0:
        raise ToolError(f"mumu shell pull failed: {stderr or stdout}")
    compact = "".join(stdout.split())
    try:
        data = base64.b64decode(compact, validate=False)
    except Exception as exc:
        raise ToolError("failed to decode base64 data from MuMu shell") from exc
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(data)


def _push_via_mumu_shell(source: Path, remote_path: str, timeout: int = 300) -> None:
    data = base64.b64encode(source.read_bytes()).decode("ascii")
    remote_b64 = f"{remote_path}.reverselab.b64"
    setup = f"""su -c "mkdir -p \\"$(dirname '{remote_path}')\\" && : > '{remote_b64}'" """
    _mumu_cli(["sh", "--vmindex", _mumu_vmindex(), "--cmd", setup.strip()], timeout=timeout, check=True)
    chunk_size = 2048
    for index in range(0, len(data), chunk_size):
        chunk = data[index:index + chunk_size]
        append = f"""su -c "printf '%s' '{chunk}' >> '{remote_b64}'" """
        _mumu_cli(["sh", "--vmindex", _mumu_vmindex(), "--cmd", append.strip()], timeout=timeout, check=True)
    finalize = f"""su -c "base64 -d '{remote_b64}' > '{remote_path}' && rm -f '{remote_b64}'" """
    _mumu_cli(["sh", "--vmindex", _mumu_vmindex(), "--cmd", finalize.strip()], timeout=timeout, check=True)


def _shell_stdout(command: str, serial: str = "", as_root: bool = False, timeout: int = 30) -> str:
    return _shell(command, serial=serial, as_root=as_root, timeout=timeout).get("stdout", "")


def _remote_path_exists(path: str, serial: str = "", as_root: bool = True) -> bool:
    code = _shell(f'test -e "{path}"', serial=serial, as_root=as_root, timeout=20).get("returncode", 1)
    return code == 0


def _remote_dir_exists(path: str, serial: str = "", as_root: bool = True) -> bool:
    code = _shell(f'test -d "{path}"', serial=serial, as_root=as_root, timeout=20).get("returncode", 1)
    return code == 0


def _package_private_dirs(package_name: str, serial: str = "") -> list[str]:
    output = _shell_stdout(
        f"dumpsys package {package_name} | grep -E 'dataDir=|credentialProtectedDataDir=|deviceProtectedDataDir='",
        serial=serial,
        timeout=60,
    )
    found: list[str] = []
    for line in output.splitlines():
        line = line.strip()
        if "=" not in line:
            continue
        _, value = line.split("=", 1)
        value = value.strip()
        if value and value not in found:
            found.append(value)
    for candidate in [
        f"/data/user/0/{package_name}",
        f"/data/user_de/0/{package_name}",
        f"/data/data/{package_name}",
    ]:
        if candidate not in found and _remote_dir_exists(candidate, serial=serial, as_root=True):
            found.append(candidate)
    return found


def _list_remote_tree(path: str, serial: str = "", max_depth: int = 2, max_entries: int = 200) -> list[str]:
    depth = max(1, int(max_depth))
    entries = max(1, int(max_entries))
    command = f'find "{path}" -maxdepth {depth} \\( -type d -o -type f \\) | head -n {entries}'
    stdout = _shell_stdout(command, serial=serial, as_root=True, timeout=60)
    return [line.strip() for line in stdout.splitlines() if line.strip()]


def _archive_remote_dir(remote_dir: str, local_destination: Path, serial: str = "", timeout: int = 600) -> dict[str, Any]:
    archive_name = f"reverselab-{slug(Path(remote_dir).name or 'dir')}.tgz"
    remote_archive = f"/sdcard/Download/{archive_name}"
    parent = str(Path(remote_dir).parent).replace("\\", "/")
    leaf = Path(remote_dir).name
    _shell(f'rm -f "{remote_archive}"', serial=serial, as_root=True, timeout=30)
    _shell(
        f'tar -czf "{remote_archive}" -C "{parent}" "{leaf}"',
        serial=serial,
        as_root=True,
        timeout=timeout,
    )
    local_destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        _adb(["pull", remote_archive, str(local_destination)], serial=_serial(serial), timeout=timeout, check=True)
    except Exception:
        if not _is_default_mumu_serial(serial):
            raise
        _pull_via_mumu_shell(remote_archive, local_destination, timeout=timeout)
    finally:
        _shell(f'rm -f "{remote_archive}"', serial=serial, as_root=True, timeout=30)
    return {
        "remote_dir": remote_dir,
        "remote_archive": remote_archive,
        "local_archive": str(local_destination),
        "size_bytes": local_destination.stat().st_size if local_destination.exists() else 0,
    }


def _snapshot_package_subdirs(
    package_name: str,
    serial: str = "",
    subdirs: list[str] | None = None,
    max_depth: int = 2,
    max_entries: int = 200,
) -> dict[str, Any]:
    normalized_subdirs = [item.strip() for item in (subdirs or ["shared_prefs", "databases", "files"]) if item.strip()]
    roots = []
    for root_dir in _package_private_dirs(package_name, serial):
        root_item: dict[str, Any] = {
            "path": root_dir,
            "exists": _remote_dir_exists(root_dir, serial=serial, as_root=True),
            "selected_subdirs": [],
        }
        if root_item["exists"]:
            for subdir_name in normalized_subdirs:
                candidate = f"{root_dir.rstrip('/')}/{subdir_name}"
                listing = _list_remote_tree(candidate, serial=serial, max_depth=max_depth, max_entries=max_entries) if _remote_dir_exists(candidate, serial=serial, as_root=True) else []
                root_item["selected_subdirs"].append(
                    {
                        "path": candidate,
                        "name": subdir_name,
                        "exists": bool(listing) or _remote_dir_exists(candidate, serial=serial, as_root=True),
                        "listing": listing,
                    }
                )
        roots.append(root_item)
    return {
        "package_name": package_name,
        "subdirs": normalized_subdirs,
        "roots": roots,
    }


def _build_runtime_diff(before_snapshot: dict[str, Any], after_snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    before_map: dict[str, set[str]] = {}
    after_map: dict[str, set[str]] = {}
    for root in before_snapshot.get("roots", []):
        for item in root.get("selected_subdirs", []):
            before_map[item["path"]] = set(item.get("listing", []))
    for root in after_snapshot.get("roots", []):
        for item in root.get("selected_subdirs", []):
            after_map[item["path"]] = set(item.get("listing", []))
    all_paths = sorted(set(before_map) | set(after_map))
    diffs = []
    for path in all_paths:
        before_entries = before_map.get(path, set())
        after_entries = after_map.get(path, set())
        added = sorted(after_entries - before_entries)
        removed = sorted(before_entries - after_entries)
        diffs.append(
            {
                "path": path,
                "before_count": len(before_entries),
                "after_count": len(after_entries),
                "added_count": len(added),
                "removed_count": len(removed),
                "added": added[:100],
                "removed": removed[:100],
            }
        )
    return diffs


def _activity_pid_candidates(activity_lines: list[str], package_name: str) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    pattern = re.compile(r"([A-Za-z0-9._$]+)/([A-Za-z0-9._$/]+).*?pid=(\d+)")
    for line in activity_lines:
        match = pattern.search(line)
        if not match:
            continue
        if match.group(1) != package_name:
            continue
        results.append(
            {
                "package_name": match.group(1),
                "activity_name": match.group(2),
                "pid": int(match.group(3)),
                "source": "activity_top",
                "line": line,
            }
        )
    return results


def _select_frida_target_process(
    package_name: str,
    processes: list[dict[str, Any]],
    explicit_target: str = "",
    activity_pid_candidates: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    requested = explicit_target.strip()
    if requested:
        for item in processes:
            if item.get("name") == requested or str(item.get("pid")) == requested:
                return {
                    "selected": requested,
                    "reason": "explicit_target_matched",
                    "selected_process": item,
                }
        return {
            "selected": requested,
            "reason": "explicit_target_passthrough",
            "selected_process": None,
        }

    for item in activity_pid_candidates or []:
        if item.get("pid"):
            return {
                "selected": str(item["pid"]),
                "reason": "activity_pid",
                "selected_process": item,
            }

    main_process = next((item for item in processes if item.get("name") == package_name), None)
    if main_process:
        return {
            "selected": main_process["name"],
            "reason": "exact_package_process",
            "selected_process": main_process,
        }

    service_process = next((item for item in processes if str(item.get("name", "")).startswith(package_name + ":")), None)
    if service_process:
        return {
            "selected": service_process["name"],
            "reason": "package_service_process",
            "selected_process": service_process,
        }

    first = processes[0] if processes else None
    return {
        "selected": first.get("name", "") if first else "",
        "reason": "first_candidate" if first else "no_process_candidates",
        "selected_process": first,
    }


def _frida_message_event_summary(messages: list[dict[str, Any]]) -> dict[str, Any]:
    event_counts: dict[str, int] = {}
    errors: list[dict[str, Any]] = []
    previews: list[dict[str, Any]] = []
    for message in messages:
        if message.get("type") == "send":
            payload = message.get("payload")
            if isinstance(payload, dict):
                event_name = str(payload.get("event") or payload.get("type") or "send")
                event_counts[event_name] = event_counts.get(event_name, 0) + 1
                if "error" in payload:
                    errors.append(payload)
                if len(previews) < 20:
                    previews.append(payload)
            else:
                event_counts["send"] = event_counts.get("send", 0) + 1
                if len(previews) < 20:
                    previews.append({"payload": payload})
        else:
            event_counts[message.get("type", "unknown")] = event_counts.get(message.get("type", "unknown"), 0) + 1
            if len(previews) < 20:
                previews.append(message)
    return {
        "event_counts": event_counts,
        "errors": errors[:20],
        "preview_messages": previews,
    }


def _focused_logcat_lines(log_path: Path, package_name: str, limit: int = 200) -> dict[str, Any]:
    keywords = [
        package_name.lower(),
        "okhttp",
        "retrofit",
        "webview",
        "chromium",
        "ssl",
        "tls",
        "http",
        "https",
        "alipay",
        "wechat",
        "pay",
        "payment",
    ]
    lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
    matched = []
    for line in lines:
        lowered = line.lower()
        if any(keyword in lowered for keyword in keywords):
            matched.append(line)
            if len(matched) >= max(1, limit):
                break
    return {
        "keywords": keywords,
        "matched_lines": matched,
        "matched_count": len(matched),
        "log_path": str(log_path),
    }


def android_mumu_instance_info(serial: str = "") -> dict[str, Any]:
    info = _mumu_info()
    candidates = _candidate_serials(serial)
    candidate_status = [{"serial": item, "tcp_open": _tcp_open(item)} for item in candidates]
    adb_devices = android_adb_devices()
    return {
        "vmindex": _mumu_vmindex(),
        "resolved_serial": _serial(serial),
        "candidate_serials": candidate_status,
        "mumu_info": info,
        "adb_devices": adb_devices,
    }


def android_adb_connect(serial: str = "") -> dict[str, Any]:
    attempts = []
    last_stdout = ""
    last_stderr = ""
    resolved = _serial(serial)
    for candidate in _candidate_serials(serial):
        tcp_open = _tcp_open(candidate)
        attempt: dict[str, Any] = {"serial": candidate, "tcp_open": tcp_open}
        if not tcp_open:
            attempt["skipped"] = True
            attempt["reason"] = "tcp port closed"
            attempts.append(attempt)
            continue
        code, stdout, stderr = _adb(["connect", candidate], timeout=20, check=False)
        attempt.update({"returncode": code, "stdout": stdout, "stderr": stderr})
        attempts.append(attempt)
        last_stdout = stdout
        last_stderr = stderr
        if code == 0 and ("connected" in stdout.lower() or "already connected" in stdout.lower()):
            return {
                "serial": candidate,
                "resolved_serial": resolved,
                "connected": True,
                "returncode": code,
                "stdout": stdout,
                "stderr": stderr,
                "attempts": attempts,
                "mumu_info": _mumu_info(),
            }
    return {
        "serial": resolved,
        "resolved_serial": resolved,
        "connected": False,
        "returncode": 1,
        "stdout": last_stdout,
        "stderr": last_stderr,
        "attempts": attempts,
        "mumu_info": _mumu_info(),
        "warning": "No reachable MuMu adb endpoint was found; CLI-based shell/app controls may still work.",
    }


def android_adb_devices() -> dict[str, Any]:
    code, stdout, stderr = _adb(["devices", "-l"], timeout=20, check=True)
    devices = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("List of devices attached"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        item = {
            "serial": parts[0],
            "state": parts[1],
        }
        for token in parts[2:]:
            if ":" in token:
                key, value = token.split(":", 1)
                item[key] = value
        devices.append(item)
    candidates = _candidate_serials("")
    return {
        "returncode": code,
        "stderr": stderr,
        "devices": devices,
        "device_count": len(devices),
        "resolved_serial": _serial(""),
        "candidate_serials": [{"serial": item, "tcp_open": _tcp_open(item)} for item in candidates],
        "mumu_info": _mumu_info(),
    }


def android_device_info(serial: str = "") -> dict[str, Any]:
    target = _serial(serial)
    props = {
        "ro.product.model": "",
        "ro.product.manufacturer": "",
        "ro.product.device": "",
        "ro.build.version.release": "",
        "ro.build.version.sdk": "",
        "ro.product.cpu.abi": "",
        "ro.product.cpu.abilist": "",
        "ro.build.fingerprint": "",
        "ro.build.hv.platform": "",
    }
    for key in list(props):
        props[key] = _shell(f"getprop {key}", serial=target, timeout=20)["stdout"].strip()
    shell_id = _shell("id", serial=target, timeout=20)
    root_id = _shell("id", serial=target, as_root=True, timeout=20)
    return {
        "serial": target,
        "properties": props,
        "shell_id": shell_id.get("stdout", "").strip(),
        "root_id": root_id.get("stdout", "").strip(),
        "root_available": "uid=0(root)" in root_id.get("stdout", ""),
    }


def android_list_packages(serial: str = "", query: str = "", limit: int = 200) -> dict[str, Any]:
    target = _serial(serial)
    output = _shell("pm list packages", serial=target, timeout=30)
    packages = []
    for line in output["stdout"].splitlines():
        line = line.strip()
        if not line.startswith("package:"):
            continue
        package_name = line.split(":", 1)[1]
        if contains(package_name, query):
            packages.append(package_name)
        if len(packages) >= max(0, limit):
            break
    return {
        "serial": target,
        "query": query,
        "packages": packages,
        "packages_returned": len(packages),
    }


def android_install_apk(apk_path: str, serial: str = "", reinstall: bool = True, grant_permissions: bool = False) -> dict[str, Any]:
    source = resolve_file(apk_path)
    target = _serial(serial)
    try:
        args = ["install"]
        if reinstall:
            args.append("-r")
        if grant_permissions:
            args.append("-g")
        args.append(str(source))
        code, stdout, stderr = _adb(args, serial=target, timeout=300, check=True)
    except Exception:
        if not _is_default_mumu_serial(serial):
            raise
        code, stdout, stderr = _mumu_cli(["control", "--vmindex", _mumu_vmindex(), "app", "install", "--path", str(source)], timeout=300, check=True)
    audit_record = append_audit(
        {
            "action": "android_install_apk",
            "status": "ok",
            "serial": target,
            "apk_path": str(source),
            "reinstall": reinstall,
            "grant_permissions": grant_permissions,
        }
    )
    return {
        "operation_id": audit_record["operation_id"],
        "serial": target,
        "apk_path": str(source),
        "reinstall": reinstall,
        "grant_permissions": grant_permissions,
        "returncode": code,
        "stdout": stdout,
        "stderr": stderr,
        "audit_log": str(audit_log_path()),
    }


def android_uninstall_package(package_name: str, serial: str = "", keep_data: bool = False) -> dict[str, Any]:
    if not package_name.strip():
        raise ToolError("package_name is required")
    target = _serial(serial)
    try:
        args = ["uninstall"]
        if keep_data:
            args.append("-k")
        args.append(package_name.strip())
        code, stdout, stderr = _adb(args, serial=target, timeout=120, check=True)
    except Exception:
        if not _is_default_mumu_serial(serial):
            raise
        code, stdout, stderr = _mumu_cli(["control", "--vmindex", _mumu_vmindex(), "app", "uninstall", "--package", package_name.strip()], timeout=120, check=True)
    audit_record = append_audit(
        {
            "action": "android_uninstall_package",
            "status": "ok",
            "serial": target,
            "package_name": package_name.strip(),
            "keep_data": keep_data,
        }
    )
    return {
        "operation_id": audit_record["operation_id"],
        "serial": target,
        "package_name": package_name.strip(),
        "keep_data": keep_data,
        "returncode": code,
        "stdout": stdout,
        "stderr": stderr,
        "audit_log": str(audit_log_path()),
    }


def android_start_package(package_name: str, activity: str = "", serial: str = "") -> dict[str, Any]:
    if not package_name.strip():
        raise ToolError("package_name is required")
    target = _serial(serial)
    try:
        if activity.strip():
            output = _shell(f"am start -n {package_name.strip()}/{activity.strip()}", serial=target, timeout=60)
        else:
            output = _shell(f"monkey -p {package_name.strip()} -c android.intent.category.LAUNCHER 1", serial=target, timeout=60)
    except Exception:
        if activity.strip() or not _is_default_mumu_serial(serial):
            raise
        code, stdout, stderr = _mumu_cli(["control", "--vmindex", _mumu_vmindex(), "app", "launch", "--package", package_name.strip()], timeout=60, check=True)
        output = {"command": f"launch {package_name.strip()}", "as_root": True, "returncode": code, "stdout": stdout, "stderr": stderr}
    audit_record = append_audit(
        {
            "action": "android_start_package",
            "status": "ok",
            "serial": target,
            "package_name": package_name.strip(),
            "activity": activity.strip(),
        }
    )
    return {
        "operation_id": audit_record["operation_id"],
        "serial": target,
        "package_name": package_name.strip(),
        "activity": activity.strip(),
        **output,
        "audit_log": str(audit_log_path()),
    }


def android_force_stop(package_name: str, serial: str = "") -> dict[str, Any]:
    if not package_name.strip():
        raise ToolError("package_name is required")
    target = _serial(serial)
    try:
        output = _shell(f"am force-stop {package_name.strip()}", serial=target, timeout=30)
    except Exception:
        if not _is_default_mumu_serial(serial):
            raise
        code, stdout, stderr = _mumu_cli(["control", "--vmindex", _mumu_vmindex(), "app", "close", "--package", package_name.strip()], timeout=30, check=True)
        output = {"command": f"close {package_name.strip()}", "as_root": True, "returncode": code, "stdout": stdout, "stderr": stderr}
    audit_record = append_audit(
        {
            "action": "android_force_stop",
            "status": "ok",
            "serial": target,
            "package_name": package_name.strip(),
        }
    )
    return {
        "operation_id": audit_record["operation_id"],
        "serial": target,
        "package_name": package_name.strip(),
        **output,
        "audit_log": str(audit_log_path()),
    }


def android_logcat_dump(
    serial: str = "",
    output_path: str = "",
    clear_before: bool = False,
    max_lines: int = 2000,
) -> dict[str, Any]:
    target = _serial(serial)
    if clear_before:
        try:
            _adb(["logcat", "-c"], serial=target, timeout=30, check=True)
        except Exception:
            if not _is_default_mumu_serial(serial):
                raise
            _shell("logcat -c", serial=target, as_root=True, timeout=30)

    try:
        code, stdout, stderr = _adb(["logcat", "-d"], serial=target, timeout=60, check=True)
    except Exception:
        if not _is_default_mumu_serial(serial):
            raise
        shell_result = _shell("logcat -d", serial=target, as_root=True, timeout=60)
        code = shell_result["returncode"]
        stdout = shell_result["stdout"]
        stderr = shell_result["stderr"]
    lines = stdout.splitlines()
    selected = lines[-max(0, max_lines):] if max_lines > 0 else lines
    destination = _android_output_path(output_path, "mumu-logcat", ".txt")
    destination.write_text("\n".join(selected), encoding="utf-8", errors="replace")
    return {
        "serial": target,
        "output_path": str(destination),
        "returncode": code,
        "stderr": stderr,
        "lines_written": len(selected),
        "lines_total": len(lines),
    }


def android_clear_logcat(serial: str = "") -> dict[str, Any]:
    target = _serial(serial)
    try:
        code, stdout, stderr = _adb(["logcat", "-c"], serial=target, timeout=30, check=True)
    except Exception:
        if not _is_default_mumu_serial(serial):
            raise
        shell_result = _shell("logcat -c", serial=target, as_root=True, timeout=30)
        code = shell_result["returncode"]
        stdout = shell_result["stdout"]
        stderr = shell_result["stderr"]
    return {
        "serial": target,
        "returncode": code,
        "stdout": stdout,
        "stderr": stderr,
        "cleared": True,
    }


def android_push_file(local_path: str, remote_path: str, serial: str = "") -> dict[str, Any]:
    source = resolve_file(local_path)
    if not remote_path.strip():
        raise ToolError("remote_path is required")
    target = _serial(serial)
    try:
        code, stdout, stderr = _adb(["push", str(source), remote_path.strip()], serial=target, timeout=300, check=True)
    except Exception:
        if not _is_default_mumu_serial(serial):
            raise
        _push_via_mumu_shell(source, remote_path.strip(), timeout=300)
        code, stdout, stderr = 0, "", ""
    audit_record = append_audit(
        {
            "action": "android_push_file",
            "status": "ok",
            "serial": target,
            "source_path": str(source),
            "remote_path": remote_path.strip(),
        }
    )
    return {
        "operation_id": audit_record["operation_id"],
        "serial": target,
        "source_path": str(source),
        "remote_path": remote_path.strip(),
        "returncode": code,
        "stdout": stdout,
        "stderr": stderr,
        "audit_log": str(audit_log_path()),
    }


def android_pull_file(remote_path: str, serial: str = "", output_path: str = "") -> dict[str, Any]:
    if not remote_path.strip():
        raise ToolError("remote_path is required")
    target = _serial(serial)
    if output_path.strip():
        destination = Path(output_path).expanduser().resolve()
        ensure_under(destination, [ANDROID_EXPORTS_DIR], "android pull output")
    else:
        destination = _android_output_path("", f"pull-{slug(Path(remote_path).name or 'artifact')}", Path(remote_path).suffix or ".bin")
    try:
        code, stdout, stderr = _adb(["pull", remote_path.strip(), str(destination)], serial=target, timeout=300, check=True)
    except Exception:
        if not _is_default_mumu_serial(serial):
            raise
        _pull_via_mumu_shell(remote_path.strip(), destination, timeout=300)
        code, stdout, stderr = 0, "", ""
    audit_record = append_audit(
        {
            "action": "android_pull_file",
            "status": "ok",
            "serial": target,
            "remote_path": remote_path.strip(),
            "destination_path": str(destination),
        }
    )
    return {
        "operation_id": audit_record["operation_id"],
        "serial": target,
        "remote_path": remote_path.strip(),
        "destination_path": str(destination),
        "returncode": code,
        "stdout": stdout,
        "stderr": stderr,
        "audit_log": str(audit_log_path()),
    }


def android_current_activity(serial: str = "") -> dict[str, Any]:
    target = _serial(serial)
    output = _shell("dumpsys activity top | grep -E 'ACTIVITY|ResumedActivity|mResumedActivity|topResumedActivity'", serial=target, timeout=60)
    lines = [line.strip() for line in output["stdout"].splitlines() if line.strip()]
    package_name = ""
    activity_name = ""
    pattern = re.compile(r"([A-Za-z0-9._$]+)/([A-Za-z0-9._$/]+)")
    for line in lines:
        match = pattern.search(line)
        if match:
            package_name = match.group(1)
            activity_name = match.group(2)
            break
    return {
        "serial": target,
        "package_name": package_name,
        "activity_name": activity_name,
        "matched": bool(package_name),
        "lines": lines[:10],
    }


def android_package_paths(package_name: str, serial: str = "") -> dict[str, Any]:
    if not package_name.strip():
        raise ToolError("package_name is required")
    target = _serial(serial)
    output = _shell(f"pm path {package_name.strip()}", serial=target, timeout=30)
    paths = []
    for line in output["stdout"].splitlines():
        line = line.strip()
        if line.startswith("package:"):
            paths.append(line.split(":", 1)[1])
    return {
        "serial": target,
        "package_name": package_name.strip(),
        "paths": paths,
        "paths_returned": len(paths),
    }


def android_pull_package_apk(package_name: str, serial: str = "") -> dict[str, Any]:
    paths_result = android_package_paths(package_name, serial)
    target = _serial(serial)
    pulled = []
    output_dir = _package_output_dir(package_name.strip())
    for index, remote_path in enumerate(paths_result["paths"]):
        suffix = Path(remote_path).name or f"split_{index}.apk"
        destination = output_dir / suffix
        try:
            code, stdout, stderr = _adb(["pull", remote_path, str(destination)], serial=target, timeout=300, check=True)
        except Exception:
            if not _is_default_mumu_serial(serial):
                raise
            _pull_via_mumu_shell(remote_path, destination, timeout=600)
            code, stdout, stderr = 0, "", ""
        pulled.append(
            {
                "remote_path": remote_path,
                "destination_path": str(destination),
                "returncode": code,
                "stdout": stdout,
                "stderr": stderr,
            }
        )
    audit_record = append_audit(
        {
            "action": "android_pull_package_apk",
            "status": "ok",
            "serial": target,
            "package_name": package_name.strip(),
            "pulled_count": len(pulled),
        }
    )
    return {
        "operation_id": audit_record["operation_id"],
        "serial": target,
        "package_name": package_name.strip(),
        "output_dir": str(output_dir),
        "pulled": pulled,
        "pulled_count": len(pulled),
        "audit_log": str(audit_log_path()),
    }


def android_capture_screenshot(serial: str = "", output_path: str = "") -> dict[str, Any]:
    target = _serial(serial)
    remote_path = "/sdcard/Download/reverselab-screenshot.png"
    _shell(f"screencap -p {remote_path}", serial=target, timeout=60)
    if output_path.strip():
        destination = Path(output_path).expanduser().resolve()
        ensure_under(destination, [ANDROID_EXPORTS_DIR], "android screenshot output")
    else:
        destination = _android_output_path("", "mumu-screenshot", ".png")
    try:
        code, stdout, stderr = _adb(["pull", remote_path, str(destination)], serial=target, timeout=120, check=True)
    except Exception:
        if not _is_default_mumu_serial(serial):
            raise
        _pull_via_mumu_shell(remote_path, destination, timeout=180)
        code, stdout, stderr = 0, "", ""
    return {
        "serial": target,
        "remote_path": remote_path,
        "output_path": str(destination),
        "returncode": code,
        "stdout": stdout,
        "stderr": stderr,
    }


def android_package_info(package_name: str, serial: str = "", output_path: str = "") -> dict[str, Any]:
    if not package_name.strip():
        raise ToolError("package_name is required")
    target = _serial(serial)
    output = _shell(f"dumpsys package {package_name.strip()}", serial=target, timeout=90)
    destination = _android_output_path(output_path, f"package-info-{slug(package_name)}", ".txt")
    destination.write_text(output["stdout"], encoding="utf-8", errors="replace")
    return {
        "serial": target,
        "package_name": package_name.strip(),
        "output_path": str(destination),
        "chars_written": len(output["stdout"]),
    }


def android_frida_ensure_server(serial: str = "", version: str = "17.9.8", arch: str = "android-x86_64") -> dict[str, Any]:
    script = (REVERSE_ROOT / "scripts" / "android" / "install_frida_server.ps1").resolve()
    if not script.exists():
        raise ToolError(f"frida install script not found: {script}")
    target = _serial(serial)
    args = [
        "powershell",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(script),
        "-AdbPath",
        str(ADB_EXE),
        "-Serial",
        target,
        "-Version",
        version,
        "-Arch",
        arch,
    ]
    code, stdout, stderr = run(args, timeout=900)
    if code != 0:
        raise ToolError(f"frida-server install failed: returncode={code}; stderr={stderr or stdout}")
    audit_record = append_audit(
        {
            "action": "android_frida_ensure_server",
            "status": "ok",
            "serial": target,
            "version": version,
            "arch": arch,
        }
    )
    return {
        "operation_id": audit_record["operation_id"],
        "serial": target,
        "version": version,
        "arch": arch,
        "stdout": stdout,
        "stderr": stderr,
        "audit_log": str(audit_log_path()),
    }


def _host_frida_json(source: str) -> dict[str, Any]:
    if not HOST_PYTHON_EXE.exists():
        raise ToolError(f"host python not found: {HOST_PYTHON_EXE}")
    code, stdout, stderr = run([str(HOST_PYTHON_EXE), "-c", source], timeout=180)
    if code != 0:
        raise ToolError(f"host frida helper failed: returncode={code}; stderr={stderr or stdout}")
    try:
        value = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise ToolError(f"host frida helper returned non-JSON output: {stdout}") from exc
    if not isinstance(value, dict):
        raise ToolError(f"host frida helper returned unexpected payload: {type(value).__name__}")
    return value


def android_frida_status(serial: str = "") -> dict[str, Any]:
    target = _serial(serial)
    ps_result = _shell("ps -A | grep frida-server", serial=target, as_root=True, timeout=20)
    script = f"""
import frida, json
serial = {json.dumps(target, ensure_ascii=False)}
mgr = frida.get_device_manager()
devices = [{{"id": d.id, "name": d.name, "type": d.type}} for d in mgr.enumerate_devices()]
matched = next((item for item in devices if item["id"] == serial), None)
print(json.dumps({{"devices": devices, "matched_device": matched}}, ensure_ascii=False))
"""
    try:
        host = _host_frida_json(script)
    except Exception as exc:
        host = {"devices": [], "matched_device": None, "host_error": str(exc)}
    return {
        "serial": target,
        "server_process": ps_result.get("stdout", "").strip(),
        "frida_server_running": bool(ps_result.get("stdout", "").strip()),
        **host,
    }


def android_frida_processes(serial: str = "", query: str = "", limit: int = 50) -> dict[str, Any]:
    target = _serial(serial)
    script = f"""
import frida, json
serial = {json.dumps(target, ensure_ascii=False)}
query = {json.dumps(query, ensure_ascii=False)}.lower()
limit = {int(limit)}
mgr = frida.get_device_manager()
dev = next((d for d in mgr.enumerate_devices() if d.id == serial), None)
if dev is None:
    print(json.dumps({{"error": f"device not found: {{serial}}"}}))
    raise SystemExit(0)
items = []
for proc in dev.enumerate_processes():
    if query and query not in proc.name.lower():
        continue
    items.append({{"pid": proc.pid, "name": proc.name}})
    if len(items) >= max(0, limit):
        break
print(json.dumps({{"device": {{"id": dev.id, "name": dev.name, "type": dev.type}}, "processes": items, "processes_returned": len(items)}}, ensure_ascii=False))
"""
    result = _host_frida_json(script)
    if "error" in result:
        raise ToolError(str(result["error"]))
    result["serial"] = target
    result["query"] = query
    return result


def android_frida_run_script(
    target: str,
    script_source: str,
    serial: str = "",
    mode: str = "attach",
    duration_seconds: int = 10,
    output_path: str = "",
) -> dict[str, Any]:
    if not target.strip():
        raise ToolError("target is required")
    if not script_source.strip():
        raise ToolError("script_source is required")
    normalized_mode = mode.strip().lower() or "attach"
    if normalized_mode not in {"attach", "spawn"}:
        raise ToolError("mode must be one of: attach, spawn")
    target_serial = _serial(serial)
    duration = max(1, min(int(duration_seconds), 120))
    destination = _android_output_path(output_path, f"frida-run-{slug(target)}", ".json")
    script = f"""
import frida, json, time
serial = {json.dumps(target_serial, ensure_ascii=False)}
target = {json.dumps(target, ensure_ascii=False)}
source = {json.dumps(script_source, ensure_ascii=False)}
mode = {json.dumps(normalized_mode, ensure_ascii=False)}
duration = {duration}
mgr = frida.get_device_manager()
dev = next((d for d in mgr.enumerate_devices() if d.id == serial), None)
if dev is None:
    print(json.dumps({{"error": f"device not found: {{serial}}"}}))
    raise SystemExit(0)
spawned_pid = None
resolved_pid = None
if mode == "spawn":
    spawned_pid = dev.spawn([target])
    session = dev.attach(spawned_pid)
    resolved_pid = spawned_pid
else:
    try:
        resolved_pid = int(target)
        session = dev.attach(resolved_pid)
    except ValueError:
        proc = next((p for p in dev.enumerate_processes() if p.name == target), None)
        if proc is None:
            proc = next((p for p in dev.enumerate_processes() if target.lower() in p.name.lower()), None)
        if proc is None:
            print(json.dumps({{"error": f"process not found: {{target}}"}}))
            raise SystemExit(0)
        resolved_pid = proc.pid
        session = dev.attach(resolved_pid)
messages = []
def on_message(message, data):
    item = dict(message)
    if data is not None:
        item["data_hex"] = data.hex()
        item["data_size"] = len(data)
    messages.append(item)
script_obj = session.create_script(source)
script_obj.on("message", on_message)
script_obj.load()
if spawned_pid is not None:
    dev.resume(spawned_pid)
time.sleep(duration)
try:
    script_obj.unload()
except Exception:
    pass
try:
    session.detach()
except Exception:
    pass
print(json.dumps({{"device": {{"id": dev.id, "name": dev.name, "type": dev.type}}, "target": target, "mode": mode, "resolved_pid": resolved_pid, "spawned_pid": spawned_pid, "messages": messages, "message_count": len(messages)}}, ensure_ascii=False))
"""
    result = _host_frida_json(script)
    if "error" in result:
        raise ToolError(str(result["error"]))
    destination.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    audit_record = append_audit(
        {
            "action": "android_frida_run_script",
            "status": "ok",
            "serial": target_serial,
            "target": target,
            "mode": normalized_mode,
            "duration_seconds": duration,
            "output_path": str(destination),
            "message_count": result.get("message_count", 0),
        }
    )
    return {
        "operation_id": audit_record["operation_id"],
        "serial": target_serial,
        "target": target,
        "mode": normalized_mode,
        "duration_seconds": duration,
        "output_path": str(destination),
        "message_count": result.get("message_count", 0),
        "result": result,
        "audit_log": str(audit_log_path()),
    }


FRIDA_TEMPLATE_LIBRARY: dict[str, dict[str, Any]] = {
    "java_runtime_exec": {
        "title": "Hook Runtime.exec",
        "description": "记录 Java 层 Runtime.exec 调用参数。",
        "placeholders": [],
        "script": """if (typeof Java === 'undefined' || !Java.available) {
  send({event: 'Runtime.exec', error: 'Java unavailable'});
} else { Java.perform(function () {
  var Runtime = Java.use('java.lang.Runtime');
  Runtime.exec.overloads.forEach(function (overload) {
    overload.implementation = function () {
      var args = [];
      for (var i = 0; i < arguments.length; i++) {
        try {
          args.push(String(arguments[i]));
        } catch (e) {
          args.push('<unprintable>');
        }
      }
      send({event: 'Runtime.exec', overload: overload.toString(), args: args});
      return overload.apply(this, arguments);
    };
  });
}); }""",
    },
    "java_system_loadlibrary": {
        "title": "Hook System.loadLibrary",
        "description": "记录 Java 层 System.loadLibrary / System.load。",
        "placeholders": [],
        "script": """if (typeof Java === 'undefined' || !Java.available) {
  send({event: 'System.loadLibrary', error: 'Java unavailable'});
} else { Java.perform(function () {
  var System = Java.use('java.lang.System');
  var loadLibrary = System.loadLibrary.overload('java.lang.String');
  loadLibrary.implementation = function (name) {
    send({event: 'System.loadLibrary', name: String(name)});
    return loadLibrary.call(this, name);
  };
  var load = System.load.overload('java.lang.String');
  load.implementation = function (path) {
    send({event: 'System.load', path: String(path)});
    return load.call(this, path);
  };
}); }""",
    },
    "java_system_loadlibrary_verbose": {
        "title": "Hook Runtime.loadLibrary0/load0",
        "description": "更深一层记录 Runtime.loadLibrary0 / Runtime.load0 调用和调用者。", 
        "placeholders": [],
        "script": """if (typeof Java === 'undefined' || !Java.available) {
  send({event: 'Runtime.loadLibrary0', error: 'Java unavailable'});
} else { Java.perform(function () {
  var Runtime = Java.use('java.lang.Runtime');
  var Throwable = Java.use('java.lang.Throwable');
  function stackTrace() {
    try {
      return Throwable.$new().getStackTrace().toString();
    } catch (e) {
      return '<stack unavailable>';
    }
  }
  if (Runtime.loadLibrary0) {
    Runtime.loadLibrary0.overloads.forEach(function (overload) {
      overload.implementation = function () {
        var args = [];
        for (var i = 0; i < arguments.length; i++) {
          try {
            args.push(String(arguments[i]));
          } catch (e) {
            args.push('<unprintable>');
          }
        }
        send({event: 'Runtime.loadLibrary0', overload: overload.toString(), args: args, stack: stackTrace()});
        return overload.apply(this, arguments);
      };
    });
  }
  if (Runtime.load0) {
    Runtime.load0.overloads.forEach(function (overload) {
      overload.implementation = function () {
        var args = [];
        for (var i = 0; i < arguments.length; i++) {
          try {
            args.push(String(arguments[i]));
          } catch (e) {
            args.push('<unprintable>');
          }
        }
        send({event: 'Runtime.load0', overload: overload.toString(), args: args, stack: stackTrace()});
        return overload.apply(this, arguments);
      };
    });
  }
}); }""",
    },
    "crypto_cipher": {
        "title": "Hook Cipher.doFinal",
        "description": "记录 javax.crypto.Cipher.doFinal 算法、输入和输出 buffer。",
        "placeholders": [],
        "script": """if (typeof Java === 'undefined' || !Java.available) {
  send({event: 'Cipher.doFinal', error: 'Java unavailable'});
} else { Java.perform(function () {
  var Cipher = Java.use('javax.crypto.Cipher');
  function safeAlgorithm(obj) {
    try { return String(obj.getAlgorithm()); } catch (e) { return ''; }
  }
  function firstByteArray(args) {
    for (var i = 0; i < args.length; i++) {
      try {
        if (args[i] && args[i].length !== undefined) return args[i];
      } catch (e) {}
    }
    return null;
  }
  function byteArrayData(bytes, maxLen, offset, requestedLen) {
    try {
      if (!bytes) return null;
      var start = Math.max(0, offset || 0);
      var available = Math.max(0, bytes.length - start);
      var wanted = requestedLen === undefined || requestedLen === null ? available : Math.max(0, requestedLen);
      var n = Math.min(available, wanted, maxLen);
      var p = Memory.alloc(n);
      for (var i = 0; i < n; i++) p.add(i).writeS8(bytes[start + i]);
      return p.readByteArray(n);
    } catch (e) {
      send({event: 'byteArrayData.error', error: String(e)});
      return null;
    }
  }
  function inputWindow(args) {
    var bytes = firstByteArray(args);
    var offset = 0;
    var length = bytes ? bytes.length : 0;
    try {
      if (bytes && args.length >= 3 && args[0] === bytes && typeof args[1] === 'number' && typeof args[2] === 'number') {
        offset = args[1];
        length = args[2];
      }
    } catch (e) {}
    return {bytes: bytes, offset: offset, length: length};
  }
  Cipher.doFinal.overloads.forEach(function (overload) {
    overload.implementation = function () {
      var input = inputWindow(arguments);
      var inputDump = byteArrayData(input.bytes, 4096, input.offset, input.length);
      if (input.bytes && inputDump) {
        send({
          event: 'Cipher.doFinal.input',
          cipher_algorithm: safeAlgorithm(this),
          overload: overload.toString(),
          buffer_role: 'crypto_input',
          size: input.length,
          offset: input.offset,
          dumped: Math.min(input.length, 4096)
        }, inputDump);
      }
      var out = overload.apply(this, arguments);
      send({
        event: 'Cipher.doFinal',
        cipher_algorithm: safeAlgorithm(this),
        overload: overload.toString(),
        input_arg_count: arguments.length,
        output_length: out && out.length !== undefined ? out.length : out
      });
      if (out && out.length !== undefined) {
        var outDump = byteArrayData(out, 4096, 0, out.length);
        send({
          event: 'Cipher.doFinal.output',
          cipher_algorithm: safeAlgorithm(this),
          overload: overload.toString(),
          buffer_role: 'crypto_output',
          size: out.length,
          dumped: Math.min(out.length, 4096)
        }, outDump);
      }
      return out;
    };
  });
}); }""",
    },
    "crypto_key_iv": {
        "title": "Hook SecretKeySpec / IvParameterSpec",
        "description": "记录 Java crypto key、algorithm、IV 构造证据，适合还原 AES/DES/RC4 参数。",
        "placeholders": [],
        "script": """if (typeof Java === 'undefined' || !Java.available) {
  send({event: 'crypto_key_iv', error: 'Java unavailable'});
} else { Java.perform(function () {
  function hexPreview(bytes, maxLen) {
    try {
      if (!bytes) return '';
      var out = [];
      var n = Math.min(bytes.length, maxLen);
      for (var i = 0; i < n; i++) {
        var b = bytes[i];
        if (b < 0) b += 256;
        out.push(('0' + b.toString(16)).slice(-2));
      }
      return out.join('');
    } catch (e) {
      return '<hex unavailable>';
    }
  }
  function byteArrayData(bytes, maxLen, offset, requestedLen) {
    try {
      if (!bytes) return null;
      var start = Math.max(0, offset || 0);
      var available = Math.max(0, bytes.length - start);
      var wanted = requestedLen === undefined || requestedLen === null ? available : Math.max(0, requestedLen);
      var n = Math.min(available, wanted, maxLen);
      var p = Memory.alloc(n);
      for (var i = 0; i < n; i++) p.add(i).writeS8(bytes[start + i]);
      return p.readByteArray(n);
    } catch (e) {
      send({event: 'byteArrayData.error', error: String(e)});
      return null;
    }
  }
  var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
  SecretKeySpec.$init.overloads.forEach(function (overload) {
    overload.implementation = function () {
      var alg = arguments.length > 1 ? String(arguments[arguments.length - 1]) : '';
      var key = arguments.length > 0 ? arguments[0] : null;
      var offset = arguments.length >= 4 && typeof arguments[1] === 'number' && typeof arguments[2] === 'number' ? arguments[1] : 0;
      var keyLen = arguments.length >= 4 && typeof arguments[1] === 'number' && typeof arguments[2] === 'number' ? arguments[2] : (key ? key.length : 0);
      var keyDump = byteArrayData(key, 4096, offset, keyLen);
      send({event: 'SecretKeySpec.init', overload: overload.toString(), algorithm: alg, key_len: keyLen, key_offset: offset, key_hex_preview: hexPreview(key, 64)});
      if (key && keyDump) {
        send({event: 'SecretKeySpec.key', algorithm: alg, buffer_role: 'crypto_key', size: keyLen, offset: offset, dumped: Math.min(keyLen, 4096)}, keyDump);
      }
      return overload.apply(this, arguments);
    };
  });
  var IvParameterSpec = Java.use('javax.crypto.spec.IvParameterSpec');
  IvParameterSpec.$init.overloads.forEach(function (overload) {
    overload.implementation = function () {
      var iv = arguments.length > 0 ? arguments[0] : null;
      var offset = arguments.length >= 3 && typeof arguments[1] === 'number' && typeof arguments[2] === 'number' ? arguments[1] : 0;
      var ivLen = arguments.length >= 3 && typeof arguments[1] === 'number' && typeof arguments[2] === 'number' ? arguments[2] : (iv ? iv.length : 0);
      var ivDump = byteArrayData(iv, 4096, offset, ivLen);
      send({event: 'IvParameterSpec.init', overload: overload.toString(), iv_len: ivLen, iv_offset: offset, iv_hex_preview: hexPreview(iv, 64)});
      if (iv && ivDump) {
        send({event: 'IvParameterSpec.iv', buffer_role: 'crypto_iv', size: ivLen, offset: offset, dumped: Math.min(ivLen, 4096)}, ivDump);
      }
      return overload.apply(this, arguments);
    };
  });
}); }""",
    },
    "crypto_digest_mac": {
        "title": "Hook MessageDigest / Mac",
        "description": "记录 hash/HMAC update/digest/doFinal 长度和算法。",
        "placeholders": [],
        "script": """if (typeof Java === 'undefined' || !Java.available) {
  send({event: 'crypto_digest_mac', error: 'Java unavailable'});
} else { Java.perform(function () {
  function safeAlg(obj) {
    try { return String(obj.getAlgorithm()); } catch (e) { return ''; }
  }
  function byteArrayData(bytes, maxLen, offset, requestedLen) {
    try {
      if (!bytes) return null;
      var start = Math.max(0, offset || 0);
      var available = Math.max(0, bytes.length - start);
      var wanted = requestedLen === undefined || requestedLen === null ? available : Math.max(0, requestedLen);
      var n = Math.min(available, wanted, maxLen);
      var p = Memory.alloc(n);
      for (var i = 0; i < n; i++) p.add(i).writeS8(bytes[start + i]);
      return p.readByteArray(n);
    } catch (e) {
      send({event: 'byteArrayData.error', error: String(e)});
      return null;
    }
  }
  function byteArgWindow(args) {
    var bytes = null;
    for (var i = 0; i < args.length; i++) {
      try {
        if (args[i] && args[i].length !== undefined) {
          bytes = args[i];
          break;
        }
      } catch (e) {}
    }
    var offset = 0;
    var length = bytes ? bytes.length : 0;
    try {
      if (bytes && args.length >= 3 && args[0] === bytes && typeof args[1] === 'number' && typeof args[2] === 'number') {
        offset = args[1];
        length = args[2];
      }
    } catch (e) {}
    return {bytes: bytes, offset: offset, length: length};
  }
  var MessageDigest = Java.use('java.security.MessageDigest');
  MessageDigest.update.overloads.forEach(function (overload) {
    overload.implementation = function () {
      send({event: 'MessageDigest.update', algorithm: safeAlg(this), overload: overload.toString(), arg_count: arguments.length});
      var input = byteArgWindow(arguments);
      var inputDump = byteArrayData(input.bytes, 4096, input.offset, input.length);
      if (input.bytes && inputDump) {
        send({event: 'MessageDigest.update.input', algorithm: safeAlg(this), buffer_role: 'digest_input', size: input.length, offset: input.offset, dumped: Math.min(input.length, 4096)}, inputDump);
      }
      return overload.apply(this, arguments);
    };
  });
  MessageDigest.digest.overloads.forEach(function (overload) {
    overload.implementation = function () {
      var out = overload.apply(this, arguments);
      send({event: 'MessageDigest.digest', algorithm: safeAlg(this), overload: overload.toString(), output_len: out ? out.length : 0});
      if (out) {
        send({event: 'MessageDigest.digest.output', algorithm: safeAlg(this), buffer_role: 'digest_output', size: out.length, dumped: Math.min(out.length, 4096)}, byteArrayData(out, 4096, 0, out.length));
      }
      return out;
    };
  });
  var Mac = Java.use('javax.crypto.Mac');
  Mac.init.overloads.forEach(function (overload) {
    overload.implementation = function () {
      send({event: 'Mac.init', algorithm: safeAlg(this), overload: overload.toString(), arg_count: arguments.length});
      return overload.apply(this, arguments);
    };
  });
  Mac.doFinal.overloads.forEach(function (overload) {
    overload.implementation = function () {
      var input = byteArgWindow(arguments);
      var inputDump = byteArrayData(input.bytes, 4096, input.offset, input.length);
      if (input.bytes && inputDump) {
        send({event: 'Mac.doFinal.input', algorithm: safeAlg(this), overload: overload.toString(), buffer_role: 'mac_input', size: input.length, offset: input.offset, dumped: Math.min(input.length, 4096)}, inputDump);
      }
      var out = overload.apply(this, arguments);
      send({event: 'Mac.doFinal', algorithm: safeAlg(this), overload: overload.toString(), output_len: out ? out.length : 0});
      if (out) {
        send({event: 'Mac.doFinal.output', algorithm: safeAlg(this), overload: overload.toString(), buffer_role: 'mac_output', size: out.length, dumped: Math.min(out.length, 4096)}, byteArrayData(out, 4096, 0, out.length));
      }
      return out;
    };
  });
}); }""",
    },
    "java_classloader_dex": {
        "title": "Hook DexClassLoader / PathClassLoader",
        "description": "记录动态 dex/apk/jar 加载路径，适合 Android 壳和插件化定位。",
        "placeholders": [],
        "script": """if (typeof Java === 'undefined' || !Java.available) {
  send({event: 'ClassLoader.dex', error: 'Java unavailable'});
} else { Java.perform(function () {
  function hookInit(className) {
    try {
      var Cls = Java.use(className);
      Cls.$init.overloads.forEach(function (overload) {
        overload.implementation = function () {
          var args = [];
          for (var i = 0; i < arguments.length; i++) {
            try { args.push(String(arguments[i])); } catch (e) { args.push('<unprintable>'); }
          }
          send({event: className + '.$init', overload: overload.toString(), args: args});
          return overload.apply(this, arguments);
        };
      });
    } catch (e) {
      send({event: className + '.$init', error: String(e)});
    }
  }
  hookInit('dalvik.system.DexClassLoader');
  hookInit('dalvik.system.PathClassLoader');
  hookInit('dalvik.system.InMemoryDexClassLoader');
}); }""",
    },
    "webview_navigation": {
        "title": "Hook WebView 导航与 JS 执行",
        "description": "记录 WebView.loadUrl / postUrl / loadData / evaluateJavascript。",
        "placeholders": [],
        "script": """if (typeof Java === 'undefined' || !Java.available) {
  send({event: 'WebView.loadUrl', error: 'Java unavailable'});
} else { Java.perform(function () {
  var WebView = Java.use('android.webkit.WebView');
  function safeString(value) {
    try {
      return String(value);
    } catch (e) {
      return '<unprintable>';
    }
  }
  WebView.loadUrl.overloads.forEach(function (overload) {
    overload.implementation = function () {
      var args = [];
      for (var i = 0; i < arguments.length; i++) {
        args.push(safeString(arguments[i]));
      }
      send({event: 'WebView.loadUrl', overload: overload.toString(), args: args});
      return overload.apply(this, arguments);
    };
  });
  if (WebView.postUrl) {
    var postUrl = WebView.postUrl.overload('java.lang.String', '[B');
    postUrl.implementation = function (url, data) {
      send({event: 'WebView.postUrl', url: safeString(url), post_length: data ? data.length : 0});
      return postUrl.call(this, url, data);
    };
  }
  if (WebView.loadData) {
    var loadData = WebView.loadData.overload('java.lang.String', 'java.lang.String', 'java.lang.String');
    loadData.implementation = function (data, mimeType, encoding) {
      send({event: 'WebView.loadData', mime_type: safeString(mimeType), encoding: safeString(encoding), data_preview: safeString(data).slice(0, 200)});
      return loadData.call(this, data, mimeType, encoding);
    };
  }
  if (WebView.loadDataWithBaseURL) {
    var loadDataWithBaseURL = WebView.loadDataWithBaseURL.overload('java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.String');
    loadDataWithBaseURL.implementation = function (baseUrl, data, mimeType, encoding, historyUrl) {
      send({event: 'WebView.loadDataWithBaseURL', base_url: safeString(baseUrl), mime_type: safeString(mimeType), encoding: safeString(encoding), history_url: safeString(historyUrl), data_preview: safeString(data).slice(0, 200)});
      return loadDataWithBaseURL.call(this, baseUrl, data, mimeType, encoding, historyUrl);
    };
  }
  if (WebView.evaluateJavascript) {
    var evaluateJavascript = WebView.evaluateJavascript.overload('java.lang.String', 'android.webkit.ValueCallback');
    evaluateJavascript.implementation = function (script, callback) {
      send({event: 'WebView.evaluateJavascript', script_preview: safeString(script).slice(0, 200)});
      return evaluateJavascript.call(this, script, callback);
    };
  }
}); }""",
    },
    "webview_js_bridge": {
        "title": "Hook addJavascriptInterface",
        "description": "记录 WebView 暴露给 JS 的 bridge 对象和名称。",
        "placeholders": [],
        "script": """if (typeof Java === 'undefined' || !Java.available) {
  send({event: 'WebView.addJavascriptInterface', error: 'Java unavailable'});
} else { Java.perform(function () {
  var WebView = Java.use('android.webkit.WebView');
  var addJavascriptInterface = WebView.addJavascriptInterface.overload('java.lang.Object', 'java.lang.String');
  addJavascriptInterface.implementation = function (obj, name) {
    var className = '<unknown>';
    try {
      className = obj.getClass().getName().toString();
    } catch (e) {}
    send({event: 'WebView.addJavascriptInterface', name: String(name), class_name: className});
    return addJavascriptInterface.call(this, obj, name);
  };
}); }""",
    },
    "okhttp_newcall": {
        "title": "Hook OkHttpClient.newCall",
        "description": "记录 OkHttp 请求方法、URL 和头部。",
        "placeholders": [],
        "script": """if (typeof Java === 'undefined' || !Java.available) {
  send({event: 'OkHttpClient.newCall', error: 'Java unavailable'});
} else { Java.perform(function () {
  var OkHttpClient = Java.use('okhttp3.OkHttpClient');
  var newCall = OkHttpClient.newCall.overload('okhttp3.Request');
  newCall.implementation = function (request) {
    var headers = {};
    try {
      var names = request.headers().names().toArray();
      for (var i = 0; i < names.length; i++) {
        var key = String(names[i]);
        headers[key] = String(request.header(key));
      }
    } catch (e) {}
    send({
      event: 'OkHttpClient.newCall',
      method: String(request.method()),
      url: String(request.url().toString()),
      headers: headers
    });
    return newCall.call(this, request);
  };
}); }""",
    },
    "okhttp_response": {
        "title": "Hook OkHttp 响应",
        "description": "记录 OkHttp RealCall.execute / enqueue 的响应码与 URL。",
        "placeholders": [],
        "script": """if (typeof Java === 'undefined' || !Java.available) {
  send({event: 'OkHttp.execute', error: 'Java unavailable'});
} else { Java.perform(function () {
  var RealCall = Java.use('okhttp3.internal.connection.RealCall');
  if (RealCall.execute) {
    var execute = RealCall.execute.overload();
    execute.implementation = function () {
      var response = execute.call(this);
      try {
        send({
          event: 'OkHttp.execute',
          code: response.code(),
          message: String(response.message()),
          url: String(response.request().url().toString())
        });
      } catch (e) {
        send({event: 'OkHttp.execute', error: String(e)});
      }
      return response;
    };
  }
  if (RealCall.enqueue) {
    var enqueue = RealCall.enqueue.overload('okhttp3.Callback');
    enqueue.implementation = function (callback) {
      try {
        send({event: 'OkHttp.enqueue', url: String(this.request().url().toString())});
      } catch (e) {
        send({event: 'OkHttp.enqueue', error: String(e)});
      }
      return enqueue.call(this, callback);
    };
  }
}); }""",
    },
    "sharedpreferences_editor": {
        "title": "Hook SharedPreferences 写入",
        "description": "记录 SharedPreferences.Editor 的 put/apply/commit 行为。",
        "placeholders": [],
        "script": """if (typeof Java === 'undefined' || !Java.available) {
  send({event: 'SharedPreferences.Editor', error: 'Java unavailable'});
} else { Java.perform(function () {
  var EditorImpl = Java.use('android.app.SharedPreferencesImpl$EditorImpl');
  function wrap(name) {
    if (!EditorImpl[name]) {
      return;
    }
    EditorImpl[name].overloads.forEach(function (overload) {
      overload.implementation = function () {
        var args = [];
        for (var i = 0; i < arguments.length; i++) {
          try {
            args.push(String(arguments[i]));
          } catch (e) {
            args.push('<unprintable>');
          }
        }
        send({event: 'SharedPreferences.' + name, overload: overload.toString(), args: args});
        return overload.apply(this, arguments);
      };
    });
  }
  ['putString', 'putBoolean', 'putInt', 'putLong', 'putFloat', 'putStringSet', 'remove', 'clear', 'apply', 'commit'].forEach(wrap);
}); }""",
    },
    "sharedpreferences_reads": {
        "title": "Hook SharedPreferences 读取",
        "description": "记录 SharedPreferencesImpl.getString/getBoolean/getInt/getLong 调用。",
        "placeholders": [],
        "script": """if (typeof Java === 'undefined' || !Java.available) {
  send({event: 'SharedPreferences.read', error: 'Java unavailable'});
} else { Java.perform(function () {
  var Prefs = Java.use('android.app.SharedPreferencesImpl');
  ['getString', 'getBoolean', 'getInt', 'getLong', 'contains'].forEach(function (name) {
    if (!Prefs[name]) {
      return;
    }
    Prefs[name].overloads.forEach(function (overload) {
      overload.implementation = function () {
        var result = overload.apply(this, arguments);
        var args = [];
        for (var i = 0; i < arguments.length; i++) {
          try {
            args.push(String(arguments[i]));
          } catch (e) {
            args.push('<unprintable>');
          }
        }
        send({event: 'SharedPreferences.' + name, overload: overload.toString(), args: args, result: String(result)});
        return result;
      };
    });
  });
}); }""",
    },
    "native_dlopen": {
        "title": "Hook android_dlopen_ext",
        "description": "记录 so 加载行为。",
        "placeholders": [],
        "script": """var addr = Module.findExportByName(null, 'android_dlopen_ext') || Module.findExportByName(null, 'dlopen');
if (addr) {
  Interceptor.attach(addr, {
    onEnter: function (args) {
      this.path = args[0].isNull() ? '' : Memory.readUtf8String(args[0]);
    },
    onLeave: function (retval) {
      send({event: 'dlopen', path: this.path, retval: retval.toString()});
    }
  });
} else {
  send({event: 'dlopen', error: 'export not found'});
}""",
    },
    "native_memory_map": {
        "title": "Hook mmap/mprotect",
        "description": "记录 native 内存映射和权限变化，适合定位 unpack 后可执行内存。",
        "placeholders": [],
        "script": """function hookExport(name) {
  var addr = Module.findExportByName(null, name);
  if (!addr) {
    send({event: name, error: 'export not found'});
    return;
  }
  Interceptor.attach(addr, {
    onEnter: function (args) {
      this.args0 = args[0]; this.args1 = args[1]; this.args2 = args[2];
      send({event: name + '.enter', a0: String(args[0]), a1: String(args[1]), a2: String(args[2]), a3: String(args[3])});
    },
    onLeave: function (retval) {
      send({event: name + '.leave', retval: String(retval), a0: String(this.args0), a1: String(this.args1), a2: String(this.args2)});
    }
  });
}
['mmap', 'mmap64', 'mprotect', 'munmap'].forEach(hookExport);""",
    },
    "native_register_natives": {
        "title": "Hook RegisterNatives",
        "description": "记录 JNI native 方法注册，适合壳 stub 交接和 native 算法入口定位。",
        "placeholders": [],
        "script": """function findRegisterNatives() {
  var candidates = [];
  Process.enumerateModules().forEach(function (m) {
    if (m.name.indexOf('libart') < 0) return;
    try {
      m.enumerateSymbols().forEach(function (s) {
        if (s.name.indexOf('RegisterNatives') >= 0 && s.name.indexOf('CheckJNI') < 0) {
          candidates.push(s.address);
        }
      });
    } catch (e) {}
  });
  return candidates.length ? candidates[0] : null;
}
var rn = findRegisterNatives();
if (rn) {
  Interceptor.attach(rn, {
    onEnter: function (args) {
      send({event: 'RegisterNatives.enter', env: String(args[0]), clazz: String(args[1]), methods: String(args[2]), count: args[3].toInt32()});
    },
    onLeave: function (retval) {
      send({event: 'RegisterNatives.leave', retval: String(retval)});
    }
  });
  send({event: 'RegisterNatives.hooked', address: String(rn)});
} else {
  send({event: 'RegisterNatives', error: 'symbol not found'});
}""",
    },
    "native_export_log": {
        "title": "Hook 指定 native export",
        "description": "Hook 指定 so 导出函数，适合先验证是否被调用。",
        "placeholders": ["library_name", "export_name"],
        "script": """var libraryName = "{library_name}";
var exportName = "{export_name}";
var addr = Module.findExportByName(libraryName, exportName);
if (addr) {
  Interceptor.attach(addr, {
    onEnter: function (args) {
      send({event: 'native_export_enter', library: libraryName, export: exportName, address: addr.toString()});
    },
    onLeave: function (retval) {
      send({event: 'native_export_leave', library: libraryName, export: exportName, retval: retval.toString()});
    }
  });
} else {
  send({event: 'native_export', error: 'export not found', library: libraryName, export: exportName});
}""",
    },
}


def android_frida_template_library() -> dict[str, Any]:
    templates = []
    for template_id, item in sorted(FRIDA_TEMPLATE_LIBRARY.items()):
        templates.append(
            {
                "template_id": template_id,
                "title": item["title"],
                "description": item["description"],
                "placeholders": list(item["placeholders"]),
            }
        )
    return {
        "templates": templates,
        "template_count": len(templates),
    }


def android_frida_render_template(template_id: str, substitutions_json: str = "") -> dict[str, Any]:
    normalized = template_id.strip()
    if normalized not in FRIDA_TEMPLATE_LIBRARY:
        known = ", ".join(sorted(FRIDA_TEMPLATE_LIBRARY))
        raise ToolError(f"unknown template_id: {template_id}; known template ids: {known}")
    template = FRIDA_TEMPLATE_LIBRARY[normalized]
    substitutions: dict[str, str] = {}
    if substitutions_json.strip():
        try:
            parsed = json.loads(substitutions_json)
        except json.JSONDecodeError as exc:
            raise ToolError("substitutions_json must be valid JSON object") from exc
        if not isinstance(parsed, dict):
            raise ToolError("substitutions_json must decode to an object")
        substitutions = {str(key): str(value) for key, value in parsed.items()}
    missing = [key for key in template["placeholders"] if key not in substitutions]
    if missing:
        raise ToolError(f"missing placeholders for template {normalized}: {', '.join(missing)}")
    script = str(template["script"])
    for key, value in substitutions.items():
        script = script.replace("{" + key + "}", value)
    return {
        "template_id": normalized,
        "title": template["title"],
        "description": template["description"],
        "placeholders": list(template["placeholders"]),
        "script_source": script,
    }


def android_app_baseline(
    package_name: str = "",
    apk_path: str = "",
    serial: str = "",
    reinstall: bool = False,
    grant_permissions: bool = False,
    launch: bool = True,
    clear_logcat_first: bool = True,
    logcat_lines: int = 400,
    output_path: str = "",
) -> dict[str, Any]:
    target = _serial(serial)
    if not package_name.strip() and not apk_path.strip():
        raise ToolError("package_name or apk_path is required")

    installed_package = package_name.strip()
    install_result: dict[str, Any] | None = None
    if apk_path.strip():
        install_result = android_install_apk(apk_path, target, reinstall=reinstall, grant_permissions=grant_permissions)
        if not installed_package:
            dump = _shell("pm list packages -3", serial=target, timeout=60)
            user_packages = [line.split(":", 1)[1].strip() for line in dump["stdout"].splitlines() if line.startswith("package:")]
            if not user_packages:
                raise ToolError("apk installed but package_name could not be inferred; please provide package_name explicitly")
            installed_package = user_packages[-1]

    if clear_logcat_first:
        android_clear_logcat(target)

    start_result: dict[str, Any] | None = None
    if launch and installed_package:
        start_result = android_start_package(installed_package, "", target)
        time.sleep(2)

    current_activity = android_current_activity(target)
    package_paths = android_package_paths(installed_package, target) if installed_package else {"paths": [], "paths_returned": 0}
    package_info = (
        android_package_info(
            installed_package,
            target,
            str(_app_output_path(installed_package, "package-info", f"package-info-{slug(installed_package)}", ".txt")),
        )
        if installed_package
        else {"output_path": ""}
    )
    logcat_result = android_logcat_dump(
        target,
        str(_app_output_path(installed_package or "android", "logs", "mumu-logcat", ".txt")),
        clear_before=False,
        max_lines=logcat_lines,
    )
    frida_processes: dict[str, Any]
    if installed_package:
        try:
            frida_processes = android_frida_processes(target, installed_package, 20)
        except Exception as exc:
            frida_processes = {
                "query": installed_package,
                "processes": [],
                "processes_returned": 0,
                "error": str(exc),
            }
    else:
        frida_processes = {"processes": [], "processes_returned": 0}

    summary = {
        "serial": target,
        "package_name": installed_package,
        "apk_path": apk_path.strip(),
        "install_result": install_result,
        "start_result": start_result,
        "current_activity": current_activity,
        "package_paths": package_paths,
        "package_info": package_info,
        "logcat_dump": logcat_result,
        "frida_processes": frida_processes,
    }
    destination = _app_output_path(
        installed_package or Path(apk_path).stem or "android",
        "artifacts",
        f"app-baseline-{slug(installed_package or Path(apk_path).stem)}",
        ".json",
        output_path,
    )
    destination.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    audit_record = append_audit(
        {
            "action": "android_app_baseline",
            "status": "ok",
            "serial": target,
            "package_name": installed_package,
            "apk_path": apk_path.strip(),
            "output_path": str(destination),
            "launched": bool(start_result),
        }
    )
    return {
        "operation_id": audit_record["operation_id"],
        "serial": target,
        "package_name": installed_package,
        "apk_path": apk_path.strip(),
        "output_path": str(destination),
        "summary": summary,
        "audit_log": str(audit_log_path()),
    }


def android_pull_artifact_recipe(
    package_name: str,
    serial: str = "",
    include_apk: bool = True,
    include_screenshot: bool = True,
    include_package_info: bool = True,
    include_logcat: bool = True,
    max_logcat_lines: int = 400,
    output_path: str = "",
) -> dict[str, Any]:
    if not package_name.strip():
        raise ToolError("package_name is required")
    target = _serial(serial)
    artifacts: dict[str, Any] = {"serial": target, "package_name": package_name.strip()}
    if include_screenshot:
        try:
            artifacts["screenshot"] = android_capture_screenshot(
                target,
                str(_app_output_path(package_name.strip(), "screenshots", "mumu-screenshot", ".png")),
            )
        except Exception as exc:
            artifacts["screenshot"] = {"error": str(exc)}
    if include_package_info:
        try:
            artifacts["package_info"] = android_package_info(
                package_name.strip(),
                target,
                str(_app_output_path(package_name.strip(), "package-info", f"package-info-{slug(package_name)}", ".txt")),
            )
        except Exception as exc:
            artifacts["package_info"] = {"error": str(exc)}
    if include_apk:
        try:
            artifacts["apk_pull"] = android_pull_package_apk(package_name.strip(), target)
        except Exception as exc:
            artifacts["apk_pull"] = {"error": str(exc)}
    if include_logcat:
        try:
            artifacts["logcat"] = android_logcat_dump(
                target,
                str(_app_output_path(package_name.strip(), "logs", "mumu-logcat", ".txt")),
                clear_before=False,
                max_lines=max_logcat_lines,
            )
        except Exception as exc:
            artifacts["logcat"] = {"error": str(exc)}
    destination = _app_output_path(package_name.strip(), "artifacts", f"artifact-recipe-{slug(package_name)}", ".json", output_path)
    destination.write_text(json.dumps(artifacts, ensure_ascii=False, indent=2), encoding="utf-8")
    audit_record = append_audit(
        {
            "action": "android_pull_artifact_recipe",
            "status": "ok",
            "serial": target,
            "package_name": package_name.strip(),
            "output_path": str(destination),
        }
    )
    return {
        "operation_id": audit_record["operation_id"],
        "serial": target,
        "package_name": package_name.strip(),
        "output_path": str(destination),
        "artifacts": artifacts,
        "audit_log": str(audit_log_path()),
    }


def android_package_fs_recipe(
    package_name: str,
    serial: str = "",
    include_archives: bool = True,
    subdirs_csv: str = "shared_prefs,databases,files",
    max_depth: int = 2,
    max_entries: int = 200,
    output_path: str = "",
) -> dict[str, Any]:
    if not package_name.strip():
        raise ToolError("package_name is required")
    target = _serial(serial)
    package_root = _package_output_dir(package_name.strip()) / f"fs-recipe-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    package_root.mkdir(parents=True, exist_ok=True)
    subdirs = [item.strip() for item in subdirs_csv.split(",") if item.strip()]
    private_dirs = _package_private_dirs(package_name.strip(), target)
    results: dict[str, Any] = {
        "serial": target,
        "package_name": package_name.strip(),
        "private_dirs": private_dirs,
        "subdirs_requested": subdirs,
        "roots": [],
        "archives": [],
    }

    for root_dir in private_dirs:
        root_item: dict[str, Any] = {
            "path": root_dir,
            "exists": _remote_dir_exists(root_dir, serial=target, as_root=True),
            "top_listing": [],
            "selected_subdirs": [],
        }
        if root_item["exists"]:
            root_item["top_listing"] = _list_remote_tree(root_dir, serial=target, max_depth=max_depth, max_entries=max_entries)
            for subdir_name in subdirs:
                candidate = f"{root_dir.rstrip('/')}/{subdir_name}"
                selected = {
                    "path": candidate,
                    "exists": _remote_dir_exists(candidate, serial=target, as_root=True),
                    "listing": [],
                }
                if selected["exists"]:
                    selected["listing"] = _list_remote_tree(candidate, serial=target, max_depth=max_depth, max_entries=max_entries)
                    if include_archives:
                        archive_label = slug(root_dir.replace("/", "_").strip("_"))
                        archive_path = package_root / f"{archive_label}-{slug(subdir_name)}.tgz"
                        try:
                            archive_result = _archive_remote_dir(candidate, archive_path, serial=target, timeout=600)
                            results["archives"].append(archive_result)
                        except Exception as exc:
                            results["archives"].append({"remote_dir": candidate, "error": str(exc)})
                root_item["selected_subdirs"].append(selected)
        results["roots"].append(root_item)

    manifest_path = package_root / "manifest.json"
    manifest_path.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
    final_output = _app_output_path(package_name.strip(), "artifacts", f"package-fs-{slug(package_name)}", ".json", output_path)
    final_output.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
    audit_record = append_audit(
        {
            "action": "android_package_fs_recipe",
            "status": "ok",
            "serial": target,
            "package_name": package_name.strip(),
            "output_path": str(final_output),
            "archives_count": len(results["archives"]),
        }
    )
    return {
        "operation_id": audit_record["operation_id"],
        "serial": target,
        "package_name": package_name.strip(),
        "output_path": str(final_output),
        "package_output_dir": str(package_root),
        "manifest_path": str(manifest_path),
        "results": results,
        "audit_log": str(audit_log_path()),
    }


def android_runtime_file_watch_recipe(
    package_name: str,
    serial: str = "",
    launch: bool = True,
    observe_seconds: int = 3,
    subdirs_csv: str = "shared_prefs,databases,files",
    max_depth: int = 2,
    max_entries: int = 200,
    output_path: str = "",
) -> dict[str, Any]:
    if not package_name.strip():
        raise ToolError("package_name is required")
    target = _serial(serial)
    subdirs = [item.strip() for item in subdirs_csv.split(",") if item.strip()]
    before_snapshot = _snapshot_package_subdirs(package_name.strip(), target, subdirs, max_depth, max_entries)
    start_result: dict[str, Any] | None = None
    if launch:
        start_result = android_start_package(package_name.strip(), "", target)
    wait_seconds = max(0, min(int(observe_seconds), 60))
    if wait_seconds:
        time.sleep(wait_seconds)
    after_snapshot = _snapshot_package_subdirs(package_name.strip(), target, subdirs, max_depth, max_entries)
    diffs = _build_runtime_diff(before_snapshot, after_snapshot)
    summary = {
        "serial": target,
        "package_name": package_name.strip(),
        "launch": launch,
        "observe_seconds": wait_seconds,
        "start_result": start_result,
        "current_activity": android_current_activity(target),
        "before_snapshot": before_snapshot,
        "after_snapshot": after_snapshot,
        "diffs": diffs,
    }
    destination = _app_output_path(package_name.strip(), "artifacts", f"runtime-file-watch-{slug(package_name)}", ".json", output_path)
    destination.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    audit_record = append_audit(
        {
            "action": "android_runtime_file_watch_recipe",
            "status": "ok",
            "serial": target,
            "package_name": package_name.strip(),
            "launch": launch,
            "observe_seconds": wait_seconds,
            "output_path": str(destination),
        }
    )
    return {
        "operation_id": audit_record["operation_id"],
        "serial": target,
        "package_name": package_name.strip(),
        "output_path": str(destination),
        "summary": summary,
        "audit_log": str(audit_log_path()),
    }


def android_http_observation_recipe(
    package_name: str,
    serial: str = "",
    target_process: str = "",
    launch: bool = False,
    observe_seconds: int = 8,
    clear_logcat_first: bool = False,
    logcat_lines: int = 800,
    template_ids_csv: str = "webview_navigation,webview_js_bridge,okhttp_newcall,okhttp_response",
    output_path: str = "",
) -> dict[str, Any]:
    if not package_name.strip():
        raise ToolError("package_name is required")
    target = _serial(serial)
    normalized_templates = [item.strip() for item in template_ids_csv.split(",") if item.strip()]
    if not normalized_templates:
        raise ToolError("template_ids_csv must contain at least one template id")

    if clear_logcat_first:
        android_clear_logcat(target)

    start_result: dict[str, Any] | None = None
    if launch:
        start_result = android_start_package(package_name.strip(), "", target)
        time.sleep(2)

    current_activity_before = android_current_activity(target)
    frida_status_before = android_frida_status(target)
    frida_ensure: dict[str, Any] | None = None
    frida_status_after = frida_status_before
    if not (frida_status_before.get("frida_server_running") and frida_status_before.get("matched_device")):
        try:
            frida_ensure = android_frida_ensure_server(target)
            frida_status_after = android_frida_status(target)
        except Exception as exc:
            frida_status_after = {**frida_status_before, "ensure_error": str(exc)}

    frida_processes: dict[str, Any]
    try:
        frida_processes = android_frida_processes(target, package_name.strip(), 50)
    except Exception as exc:
        frida_processes = {
            "serial": target,
            "query": package_name.strip(),
            "processes": [],
            "processes_returned": 0,
            "error": str(exc),
        }
    activity_candidates = _activity_pid_candidates(current_activity_before.get("lines", []), package_name.strip())
    selection = _select_frida_target_process(
        package_name.strip(),
        frida_processes.get("processes", []),
        target_process,
        activity_candidates,
    )

    rendered_templates = []
    combined_scripts: list[str] = []
    for template_id in normalized_templates:
        rendered = android_frida_render_template(template_id, "")
        rendered_templates.append(
            {
                "template_id": template_id,
                "title": rendered.get("title", ""),
                "description": rendered.get("description", ""),
            }
        )
        combined_scripts.append(f"// template: {template_id}\n{rendered['script_source']}")

    frida_run: dict[str, Any]
    can_run_frida = bool(frida_status_after.get("frida_server_running") and frida_status_after.get("matched_device") and selection.get("selected"))
    frida_output_path = _app_output_path(package_name.strip(), "frida", f"http-observation-{slug(package_name)}", ".json")
    if can_run_frida:
        try:
            frida_run = android_frida_run_script(
                str(selection["selected"]),
                "\n\n".join(combined_scripts),
                target,
                "attach",
                observe_seconds,
                str(frida_output_path),
            )
        except Exception as exc:
            frida_run = {
                "target": selection.get("selected", ""),
                "output_path": str(frida_output_path),
                "error": str(exc),
            }
    else:
        wait_seconds = max(1, min(int(observe_seconds), 60))
        time.sleep(wait_seconds)
        frida_run = {
            "skipped": True,
            "reason": "Frida bridge, frida-server, or target process unavailable",
            "target": selection.get("selected", ""),
            "output_path": str(frida_output_path),
        }

    current_activity_after = android_current_activity(target)
    logcat_output_path = _app_output_path(package_name.strip(), "logs", f"http-observation-logcat-{slug(package_name)}", ".txt")
    logcat_result = android_logcat_dump(target, str(logcat_output_path), clear_before=False, max_lines=logcat_lines)
    logcat_focus = _focused_logcat_lines(Path(logcat_result["output_path"]), package_name.strip(), 200)
    frida_result = frida_run.get("result", {}) if isinstance(frida_run, dict) else {}
    frida_message_summary = _frida_message_event_summary(frida_result.get("messages", [])) if isinstance(frida_result, dict) else {"event_counts": {}, "errors": [], "preview_messages": []}

    summary = {
        "serial": target,
        "package_name": package_name.strip(),
        "target_process": target_process.strip(),
        "launch": launch,
        "observe_seconds": max(1, min(int(observe_seconds), 60)),
        "templates_requested": normalized_templates,
        "templates_rendered": rendered_templates,
        "current_activity_before": current_activity_before,
        "current_activity_after": current_activity_after,
        "start_result": start_result,
        "frida_status_before": frida_status_before,
        "frida_ensure": frida_ensure,
        "frida_status_after": frida_status_after,
        "frida_processes": frida_processes,
        "activity_pid_candidates": activity_candidates,
        "selected_target": selection,
        "frida_run": frida_run,
        "frida_message_summary": frida_message_summary,
        "logcat_dump": logcat_result,
        "logcat_focus": logcat_focus,
    }
    destination = _app_output_path(package_name.strip(), "artifacts", f"http-observation-{slug(package_name)}", ".json", output_path)
    destination.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    audit_record = append_audit(
        {
            "action": "android_http_observation_recipe",
            "status": "ok",
            "serial": target,
            "package_name": package_name.strip(),
            "target_process": selection.get("selected", ""),
            "launch": launch,
            "observe_seconds": max(1, min(int(observe_seconds), 60)),
            "output_path": str(destination),
        }
    )
    return {
        "operation_id": audit_record["operation_id"],
        "serial": target,
        "package_name": package_name.strip(),
        "selected_target": selection.get("selected", ""),
        "output_path": str(destination),
        "summary": summary,
        "audit_log": str(audit_log_path()),
    }


ANDROID_CRYPTO_UNPACK_TEMPLATES = (
    "crypto_cipher,"
    "crypto_key_iv,"
    "crypto_digest_mac,"
    "java_classloader_dex,"
    "java_system_loadlibrary,"
    "java_system_loadlibrary_verbose,"
    "native_dlopen,"
    "native_memory_map,"
    "native_register_natives"
)


def android_crypto_unpack_recipe(
    package_name: str,
    serial: str = "",
    target_process: str = "",
    launch: bool = False,
    observe_seconds: int = 10,
    clear_logcat_first: bool = False,
    logcat_lines: int = 1000,
    template_ids_csv: str = ANDROID_CRYPTO_UNPACK_TEMPLATES,
    output_path: str = "",
) -> dict[str, Any]:
    """Run Android decrypt/unpack runtime probes with Frida and logcat evidence."""
    result = android_http_observation_recipe(
        package_name=package_name,
        serial=serial,
        target_process=target_process,
        launch=launch,
        observe_seconds=observe_seconds,
        clear_logcat_first=clear_logcat_first,
        logcat_lines=logcat_lines,
        template_ids_csv=template_ids_csv,
        output_path=output_path,
    )
    result["recipe"] = "android_crypto_unpack_recipe"
    result["focus"] = [
        "Cipher.doFinal plus SecretKeySpec/IvParameterSpec reconstruct Java crypto parameters.",
        "MessageDigest/Mac probes identify hash/HMAC gates and signature checks.",
        "DexClassLoader/InMemoryDexClassLoader locate dynamically loaded dex/apk/jar payloads.",
        "dlopen/mmap/mprotect/RegisterNatives locate native unpacking and JNI algorithm entry points.",
    ]
    return result
