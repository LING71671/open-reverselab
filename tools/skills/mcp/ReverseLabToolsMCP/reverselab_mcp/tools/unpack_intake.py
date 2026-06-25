from __future__ import annotations

import json
import re
import shutil
import struct
from datetime import datetime
from pathlib import Path
from typing import Any

from ..config import EXPORTS_ROOT, SAMPLES_DIR, SCRIPTS_DIR
from ..paths import ensure_under, resolve_file
from ..utils import slug
from . import triage


UNPACK_EXPORTS_DIR = EXPORTS_ROOT / "unpack"
UNPACKED_SAMPLES_DIR = SAMPLES_DIR / "unpacked"


def _stamp() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S-%f")


def _read_source(path: str) -> tuple[Path, bytes]:
    source = resolve_file(path)
    return source, source.read_bytes()


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    total = len(data)
    value = 0.0
    for count in counts:
        if count:
            p = count / total
            value -= p * __import__("math").log2(p)
    return round(value, 4)


def _pe_candidate_size(data: bytes, offset: int) -> tuple[int, dict[str, Any]] | None:
    if offset + 0x40 > len(data) or data[offset:offset + 2] != b"MZ":
        return None
    try:
        e_lfanew = struct.unpack_from("<I", data, offset + 0x3C)[0]
        nt = offset + e_lfanew
        if nt + 0x108 > len(data) or data[nt:nt + 4] != b"PE\x00\x00":
            return None
        machine, section_count, _timestamp, _ptrsym, _numsym, opt_size, characteristics = struct.unpack_from("<HHIIIHH", data, nt + 4)
        optional_offset = nt + 24
        magic = struct.unpack_from("<H", data, optional_offset)[0]
        if magic not in (0x10B, 0x20B):
            return None
        size_of_image = struct.unpack_from("<I", data, optional_offset + 56)[0]
        size_of_headers = struct.unpack_from("<I", data, optional_offset + 60)[0]
        section_table = optional_offset + opt_size
        max_raw_end = size_of_headers
        sections: list[dict[str, Any]] = []
        for index in range(section_count):
            base = section_table + index * 40
            if base + 40 > len(data):
                break
            raw_name = data[base:base + 8].split(b"\x00", 1)[0]
            name = raw_name.decode("ascii", errors="replace")
            virtual_size, virtual_address, raw_size, raw_ptr = struct.unpack_from("<IIII", data, base + 8)
            if raw_ptr and raw_size:
                max_raw_end = max(max_raw_end, raw_ptr + raw_size)
            sections.append(
                {
                    "name": name,
                    "virtual_size": virtual_size,
                    "virtual_address": virtual_address,
                    "raw_size": raw_size,
                    "raw_ptr": raw_ptr,
                }
            )
        expected_size = max(max_raw_end, size_of_headers, 0x200)
        available_size = len(data) - offset
        candidate_size = min(available_size, expected_size)
        return candidate_size, {
            "type": "pe",
            "machine": f"0x{machine:04x}",
            "characteristics": f"0x{characteristics:04x}",
            "bits": 64 if magic == 0x20B else 32,
            "section_count": section_count,
            "size_of_image": size_of_image,
            "size_of_headers": size_of_headers,
            "expected_file_size": expected_size,
            "available_size": available_size,
            "truncated": available_size < expected_size,
            "e_lfanew": e_lfanew,
            "sections": sections[:16],
        }
    except Exception:
        return None


def _dex_candidate_size(data: bytes, offset: int) -> tuple[int, dict[str, Any]] | None:
    if offset + 0x70 > len(data) or data[offset:offset + 4] != b"dex\n":
        return None
    version = data[offset + 4:offset + 7].decode("ascii", errors="replace")
    try:
        file_size = struct.unpack_from("<I", data, offset + 0x20)[0]
        header_size = struct.unpack_from("<I", data, offset + 0x24)[0]
        if file_size <= 0 or file_size > len(data) - offset or header_size not in (0x70, 0x78):
            return None
        return file_size, {"type": "dex", "version": version, "file_size": file_size, "header_size": header_size}
    except Exception:
        return None


def _candidate_offsets(data: bytes) -> list[tuple[int, str]]:
    offsets: list[tuple[int, str]] = []
    for magic, kind in [(b"MZ", "pe"), (b"dex\n", "dex")]:
        start = 0
        while True:
            found = data.find(magic, start)
            if found < 0:
                break
            offsets.append((found, kind))
            start = found + 1
    return sorted(offsets)


def _output_path(source: Path, kind: str, offset: int, suffix: str, output_subdir: str = "") -> Path:
    safe_subdir = slug(output_subdir) if output_subdir.strip() else slug(source.stem)
    out_dir = UNPACK_EXPORTS_DIR / "carved" / safe_subdir
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir / f"{slug(source.stem)}-{kind}-off{offset:x}-{_stamp()}{suffix}"


def _sample_path(source: Path, kind: str, offset: int, suffix: str, output_subdir: str = "") -> Path:
    safe_subdir = slug(output_subdir) if output_subdir.strip() else slug(source.stem)
    out_dir = UNPACKED_SAMPLES_DIR / safe_subdir
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir / f"{slug(source.stem)}-{kind}-off{offset:x}{suffix}"


def carve_payloads_from_dump(
    source_path: str,
    output_subdir: str = "",
    import_to_samples: bool = True,
    max_candidates: int = 20,
    min_size: int = 256,
    run_triage: bool = True,
) -> dict[str, Any]:
    """Carve PE/DEX payloads from a dump or decrypted buffer and prepare them for the next analysis round."""
    source, data = _read_source(source_path)
    candidates: list[dict[str, Any]] = []
    for offset, kind in _candidate_offsets(data):
        if len(candidates) >= max(0, max_candidates):
            break
        parsed = _pe_candidate_size(data, offset) if kind == "pe" else _dex_candidate_size(data, offset)
        if not parsed:
            continue
        size, meta = parsed
        if size < max(0, min_size):
            continue
        suffix = ".exe" if kind == "pe" else ".dex"
        blob = data[offset:offset + size]
        carved_path = _output_path(source, kind, offset, suffix, output_subdir)
        carved_path.write_bytes(blob)
        sample_path = ""
        if import_to_samples:
            sample_dest = _sample_path(source, kind, offset, suffix, output_subdir)
            shutil.copy2(carved_path, sample_dest)
            sample_path = str(sample_dest)
        item = {
            "kind": kind,
            "offset": offset,
            "offset_hex": f"0x{offset:x}",
            "size": size,
            "sha256": triage.hashes(carved_path)["sha256"],
            "entropy": _entropy(blob),
            "carved_path": str(carved_path),
            "sample_path": sample_path,
            "metadata": meta,
        }
        if run_triage and kind == "pe" and not bool(meta.get("truncated")):
            try:
                item["triage"] = triage.triage_pe(str(carved_path), True)
            except Exception as exc:
                item["triage_error"] = str(exc)
        elif kind == "pe" and bool(meta.get("truncated")):
            item["triage_skipped"] = "truncated PE candidate; dump a larger region before full reanalysis"
        candidates.append(item)

    manifest = {
        "source_path": str(source),
        "source_size": len(data),
        "candidate_count": len(candidates),
        "candidates": candidates,
        "next_actions": [
            "Run sample_full_workup on carved PE sample_path entries.",
            "Open carved DEX files with jadx/apktool or feed them into Android reverse workflow.",
            "Compare carved payload hashes across runs to determine whether unpacking is stable.",
        ],
    }
    manifest_path = UNPACK_EXPORTS_DIR / f"{slug(source.stem)}-payload-carve-{_stamp()}.json"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    manifest["manifest_path"] = str(manifest_path)
    return manifest


def _load_json(path: str) -> tuple[Path, dict[str, Any]]:
    source = resolve_file(path)
    data = json.loads(source.read_text(encoding="utf-8", errors="replace"))
    if not isinstance(data, dict):
        raise ValueError(f"JSON root is not an object: {source}")
    return source, data


def _messages_from_result(data: dict[str, Any]) -> list[dict[str, Any]]:
    if isinstance(data.get("messages"), list):
        return [m for m in data["messages"] if isinstance(m, dict)]
    result = data.get("result")
    if isinstance(result, dict) and isinstance(result.get("messages"), list):
        return [m for m in result["messages"] if isinstance(m, dict)]
    summary = data.get("summary")
    if isinstance(summary, dict):
        frida_run = summary.get("frida_run")
        if isinstance(frida_run, dict):
            nested = frida_run.get("result")
            if isinstance(nested, dict) and isinstance(nested.get("messages"), list):
                return [m for m in nested["messages"] if isinstance(m, dict)]
    return []


def extract_frida_buffers(
    result_json_path: str,
    output_subdir: str = "",
    carve: bool = True,
    import_to_samples: bool = True,
    max_buffers: int = 50,
) -> dict[str, Any]:
    """Materialize Frida binary message payloads and optionally carve PE/DEX payloads from them."""
    source, data = _load_json(result_json_path)
    messages = _messages_from_result(data)
    safe_subdir = slug(output_subdir) if output_subdir.strip() else slug(source.stem)
    out_dir = UNPACK_EXPORTS_DIR / "frida-buffers" / safe_subdir
    out_dir.mkdir(parents=True, exist_ok=True)
    buffers: list[dict[str, Any]] = []
    for index, message in enumerate(messages):
        if len(buffers) >= max(0, max_buffers):
            break
        data_hex = str(message.get("data_hex", "")).strip()
        if not data_hex:
            continue
        try:
            blob = bytes.fromhex(data_hex)
        except ValueError:
            continue
        payload = message.get("payload") if isinstance(message.get("payload"), dict) else {}
        role = slug(str(payload.get("buffer_role", "buffer"))) if isinstance(payload, dict) else "buffer"
        path = out_dir / f"{slug(source.stem)}-{index:03d}-{role}-{_stamp()}.bin"
        path.write_bytes(blob)
        item: dict[str, Any] = {
            "index": index,
            "path": str(path),
            "size": len(blob),
            "sha256": triage.hashes(path)["sha256"],
            "entropy": _entropy(blob),
            "payload": payload,
        }
        if carve:
            item["carve"] = carve_payloads_from_dump(
                str(path),
                output_subdir=safe_subdir,
                import_to_samples=import_to_samples,
                max_candidates=10,
                min_size=128,
                run_triage=True,
            )
        buffers.append(item)

    manifest = {
        "source_path": str(source),
        "buffer_count": len(buffers),
        "buffers": buffers,
        "next_actions": [
            "Run sample_full_workup on carved PE sample_path entries.",
            "Use buffer payload metadata to correlate dump source API and caller.",
            "For Android dex buffers, open carved .dex with jadx or Android reverse workflow.",
        ],
    }
    destination = UNPACK_EXPORTS_DIR / f"{slug(source.stem)}-frida-buffer-extract-{_stamp()}.json"
    destination.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    manifest["manifest_path"] = str(destination)
    return manifest


def _payloads(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for message in messages:
        payload = message.get("payload")
        if isinstance(payload, dict):
            items.append(payload)
    return items


def _event_matches(payload: dict[str, Any], terms: list[str]) -> bool:
    event = str(payload.get("event", "")).lower()
    return any(term in event for term in terms)


def _dedupe(items: list[dict[str, Any]], keys: list[str]) -> list[dict[str, Any]]:
    seen: set[tuple[str, ...]] = set()
    out: list[dict[str, Any]] = []
    for item in items:
        key = tuple(str(item.get(k, "")) for k in keys)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def parse_android_crypto_unpack_result(result_json_path: str, output_path: str = "") -> dict[str, Any]:
    """Extract Android crypto/unpack evidence from android_crypto_unpack_recipe or android_frida_run_script JSON."""
    source, data = _load_json(result_json_path)
    payloads = _payloads(_messages_from_result(data))
    key_iv: list[dict[str, Any]] = []
    crypto_ops: list[dict[str, Any]] = []
    dex_loaders: list[dict[str, Any]] = []
    native_loaders: list[dict[str, Any]] = []
    memory_maps: list[dict[str, Any]] = []
    jni_registers: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []

    for payload in payloads:
        if "error" in payload:
            errors.append(payload)
        if _event_matches(payload, ["secretkeyspec", "ivparameterspec"]):
            key_iv.append(payload)
        if _event_matches(payload, ["cipher", "messagedigest", "mac."]):
            crypto_ops.append(payload)
        if _event_matches(payload, ["dexclassloader", "pathclassloader", "inmemorydexclassloader"]):
            dex_loaders.append(payload)
        if _event_matches(payload, ["dlopen", "system.load", "runtime.load"]):
            native_loaders.append(payload)
        if _event_matches(payload, ["mmap", "mprotect", "munmap"]):
            memory_maps.append(payload)
        if _event_matches(payload, ["registernatives"]):
            jni_registers.append(payload)

    dex_paths: list[str] = []
    native_paths: list[str] = []
    for payload in dex_loaders:
        for value in payload.values():
            if isinstance(value, list):
                for entry in value:
                    text = str(entry)
                    if re.search(r"\.(dex|apk|jar|zip)(?:$|[^\w])", text, re.I):
                        dex_paths.append(text)
            else:
                text = str(value)
                if re.search(r"\.(dex|apk|jar|zip)(?:$|[^\w])", text, re.I):
                    dex_paths.append(text)
    for payload in native_loaders:
        text = " ".join(str(value) for value in payload.values())
        for match in re.findall(r"[/A-Za-z0-9_.:-]+\.so", text):
            native_paths.append(match)

    parsed = {
        "source_path": str(source),
        "message_payload_count": len(payloads),
        "key_iv": _dedupe(key_iv, ["event", "algorithm", "key_hex_preview", "iv_hex_preview"])[:200],
        "crypto_ops": crypto_ops[:300],
        "dex_loaders": dex_loaders[:200],
        "native_loaders": native_loaders[:200],
        "memory_maps": memory_maps[:300],
        "jni_registers": jni_registers[:200],
        "dex_paths": sorted(set(dex_paths)),
        "native_paths": sorted(set(native_paths)),
        "errors": errors[:50],
        "next_actions": [
            "Use key_hex_preview/iv_hex_preview plus Cipher.doFinal sizes to reconstruct decrypt routines.",
            "Pull dex_paths/native_paths from the device when present and run Android/static workup on them.",
            "For RegisterNatives entries, attach a focused native_export_log hook or inspect the corresponding lib in Ghidra.",
            "For mmap/mprotect executable transitions, dump the mapped region from Frida or debugger and run carve_payloads_from_dump.",
        ],
    }
    destination = Path(output_path).expanduser().resolve() if output_path.strip() else UNPACK_EXPORTS_DIR / f"{slug(source.stem)}-android-crypto-unpack-parse-{_stamp()}.json"
    ensure_under(destination, [UNPACK_EXPORTS_DIR], "android crypto/unpack parse output")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(parsed, ensure_ascii=False, indent=2), encoding="utf-8")
    parsed["output_path"] = str(destination)
    return parsed


def _hex_from_payload(payload: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = str(payload.get(key, "")).strip()
        if value and re.fullmatch(r"[0-9a-fA-F]+", value) and len(value) % 2 == 0:
            return value.lower()
    return ""


def _crypto_evidence_from_messages(messages: list[dict[str, Any]]) -> dict[str, Any]:
    keys: list[dict[str, Any]] = []
    ivs: list[dict[str, Any]] = []
    inputs: list[dict[str, Any]] = []
    outputs: list[dict[str, Any]] = []
    algorithms: list[str] = []
    events: list[dict[str, Any]] = []

    for index, message in enumerate(messages):
        payload = message.get("payload") if isinstance(message.get("payload"), dict) else {}
        if not payload:
            continue
        events.append(payload)
        for field in ["cipher_algorithm", "algorithm"]:
            value = str(payload.get(field, "")).strip()
            if value and value not in algorithms:
                algorithms.append(value)
        role = str(payload.get("buffer_role", "")).lower()
        data_hex = str(message.get("data_hex", "")).strip().lower()
        item = {
            "message_index": index,
            "event": payload.get("event", ""),
            "api": payload.get("api", ""),
            "algorithm": payload.get("cipher_algorithm") or payload.get("algorithm") or "",
            "role": role,
            "size": payload.get("size") or payload.get("output_length") or payload.get("output_len") or message.get("data_size") or 0,
            "hex": data_hex,
            "payload": payload,
        }
        if role in {"crypto_key", "crypto_key_blob"}:
            keys.append(item)
        elif role == "crypto_iv":
            ivs.append(item)
        elif role in {"crypto_input", "mac_input", "digest_input"}:
            inputs.append(item)
        elif role in {"crypto_output", "mac_output", "digest_output"}:
            outputs.append(item)

        key_hex = _hex_from_payload(payload, "key_hex_preview")
        if key_hex:
            keys.append({**item, "role": "crypto_key_preview", "hex": key_hex})
        iv_hex = _hex_from_payload(payload, "iv_hex_preview")
        if iv_hex:
            ivs.append({**item, "role": "crypto_iv_preview", "hex": iv_hex})

    return {
        "algorithms": algorithms,
        "keys": _dedupe(keys, ["role", "hex", "algorithm"])[:20],
        "ivs": _dedupe(ivs, ["role", "hex"])[:20],
        "inputs": _dedupe(inputs, ["role", "hex", "event"])[:20],
        "outputs": _dedupe(outputs, ["role", "hex", "event"])[:20],
        "events_preview": events[:50],
    }


def _python_literal_bytes(items: list[dict[str, Any]], name: str) -> str:
    lines = [f"{name} = ["]
    for item in items:
        value = str(item.get("hex", ""))
        if value:
            lines.append(f"    bytes.fromhex({value!r}),  # {item.get('event', '')} {item.get('algorithm', '')} {item.get('role', '')}")
    lines.append("]")
    return "\n".join(lines)


def _bytes_items(items: list[dict[str, Any]]) -> list[tuple[dict[str, Any], bytes]]:
    out: list[tuple[dict[str, Any], bytes]] = []
    for item in items:
        value = str(item.get("hex", "")).strip()
        if not value:
            continue
        try:
            out.append((item, bytes.fromhex(value)))
        except ValueError:
            continue
    return out


def _unpad_pkcs7(data: bytes, block_size: int = 16) -> bytes:
    if not data:
        return data
    pad = data[-1]
    if 0 < pad <= block_size and data.endswith(bytes([pad]) * pad):
        return data[:-pad]
    return data


def _crypto_transform_candidates(keys: list[bytes], ivs: list[bytes], inputs: list[bytes]) -> tuple[list[dict[str, Any]], list[str]]:
    candidates: list[dict[str, Any]] = []
    errors: list[str] = []

    def add(label: str, direction: str, data: bytes, key: bytes = b"", iv: bytes = b"") -> None:
        candidates.append(
            {
                "label": label,
                "direction": direction,
                "key_len": len(key),
                "iv_len": len(iv),
                "size": len(data),
                "hex": data.hex(),
            }
        )

    try:
        from Crypto.Cipher import AES, ARC4, DES, DES3
    except Exception as exc:
        errors.append(f"pycryptodome unavailable for block/stream cipher solving: {exc}")
        AES = ARC4 = DES = DES3 = None  # type: ignore[assignment]

    for key in keys:
        for data in inputs:
            if AES and len(key) in (16, 24, 32) and data:
                cipher_specs: list[tuple[str, Any, int, bytes]] = [("AES-ECB", lambda: AES.new(key, AES.MODE_ECB), 16, b"")]
                for iv in ivs:
                    if len(iv) == 16:
                        cipher_specs.extend(
                            [
                                ("AES-CBC", lambda iv=iv: AES.new(key, AES.MODE_CBC, iv), 16, iv),
                                ("AES-CFB", lambda iv=iv: AES.new(key, AES.MODE_CFB, iv), 16, iv),
                                ("AES-OFB", lambda iv=iv: AES.new(key, AES.MODE_OFB, iv), 16, iv),
                            ]
                        )
                for label, maker, block_size, used_iv in cipher_specs:
                    for direction in ["decrypt", "encrypt"]:
                        try:
                            if direction in {"decrypt", "encrypt"} and ("ECB" in label or "CBC" in label) and len(data) % block_size != 0:
                                continue
                            out = getattr(maker(), direction)(data)
                            add(label, direction, out, key, used_iv)
                            unpadded = _unpad_pkcs7(out, block_size)
                            if unpadded != out:
                                add(f"{label}-pkcs7", f"{direction}-unpad", unpadded, key, used_iv)
                        except Exception as exc:
                            errors.append(f"{label} {direction} failed: {exc}")
            if ARC4 and len(key) in (5, 8, 16, 24, 32, 64, 128, 256) and data:
                try:
                    add("ARC4", "apply", ARC4.new(key).decrypt(data), key, b"")
                except Exception as exc:
                    errors.append(f"ARC4 failed: {exc}")
            if DES and len(key) in (8, 24) and data:
                klass = DES if len(key) == 8 else DES3
                cipher_specs = [("DES-ECB" if len(key) == 8 else "3DES-ECB", lambda klass=klass: klass.new(key, klass.MODE_ECB), 8, b"")]
                for iv in ivs:
                    if len(iv) == 8:
                        cipher_specs.append(("DES-CBC" if len(key) == 8 else "3DES-CBC", lambda klass=klass, iv=iv: klass.new(key, klass.MODE_CBC, iv), 8, iv))
                for label, maker, block_size, used_iv in cipher_specs:
                    for direction in ["decrypt", "encrypt"]:
                        try:
                            if len(data) % block_size != 0:
                                continue
                            out = getattr(maker(), direction)(data)
                            add(label, direction, out, key, used_iv)
                            unpadded = _unpad_pkcs7(out, block_size)
                            if unpadded != out:
                                add(f"{label}-pkcs7", f"{direction}-unpad", unpadded, key, used_iv)
                        except Exception as exc:
                            errors.append(f"{label} {direction} failed: {exc}")
    return _dedupe(candidates, ["label", "direction", "hex"])[:500], errors[:100]


def _hash_candidates(keys: list[bytes], inputs: list[bytes]) -> list[dict[str, Any]]:
    import hashlib
    import hmac

    candidates: list[dict[str, Any]] = []
    for data in inputs:
        for name, maker in [
            ("md5", hashlib.md5),
            ("sha1", hashlib.sha1),
            ("sha256", hashlib.sha256),
            ("sha512", hashlib.sha512),
        ]:
            digest = maker(data).digest()
            candidates.append({"label": name, "direction": "digest", "key_len": 0, "iv_len": 0, "size": len(digest), "hex": digest.hex()})
    for key in keys:
        for data in inputs:
            for name, digestmod in [
                ("hmac-md5", hashlib.md5),
                ("hmac-sha1", hashlib.sha1),
                ("hmac-sha256", hashlib.sha256),
                ("hmac-sha512", hashlib.sha512),
            ]:
                digest = hmac.new(key, data, digestmod).digest()
                candidates.append({"label": name, "direction": "digest", "key_len": len(key), "iv_len": 0, "size": len(digest), "hex": digest.hex()})
    return _dedupe(candidates, ["label", "direction", "hex"])[:500]


def _candidate_output_path(source: Path, index: int, label: str, direction: str, output_subdir: str = "") -> Path:
    safe_subdir = slug(output_subdir) if output_subdir.strip() else slug(source.stem)
    out_dir = UNPACK_EXPORTS_DIR / "crypto-solve" / safe_subdir
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir / f"{slug(source.stem)}-{index:03d}-{slug(label)}-{slug(direction)}-{_stamp()}.bin"


def solve_crypto_from_evidence(
    result_json_path: str,
    output_subdir: str = "",
    algorithm_hint: str = "",
    carve_matches: bool = True,
) -> dict[str, Any]:
    """Automatically try common crypto/hash transforms from Frida key/IV/input/output evidence."""
    source, data = _load_json(result_json_path)
    messages = _messages_from_result(data)
    evidence = _crypto_evidence_from_messages(messages)
    key_items = _bytes_items(evidence.get("keys", []))
    iv_items = _bytes_items(evidence.get("ivs", []))
    input_items = _bytes_items(evidence.get("inputs", []))
    output_items = _bytes_items(evidence.get("outputs", []))

    keys = [blob for _item, blob in key_items]
    ivs = [blob for _item, blob in iv_items]
    inputs = [blob for _item, blob in input_items]
    expected_outputs = [blob for _item, blob in output_items]

    cipher_candidates, cipher_errors = _crypto_transform_candidates(keys, ivs, inputs)
    hash_candidates = _hash_candidates(keys, inputs)
    all_candidates = cipher_candidates + hash_candidates

    matches: list[dict[str, Any]] = []
    expected_hex = {blob.hex(): index for index, blob in enumerate(expected_outputs)}
    for candidate in all_candidates:
        value = str(candidate.get("hex", ""))
        if value in expected_hex:
            matches.append({**candidate, "expected_output_index": expected_hex[value]})

    materialized: list[dict[str, Any]] = []
    for index, item in enumerate(matches or [{"label": "captured-output", "direction": "captured", "hex": blob.hex(), "size": len(blob)} for blob in expected_outputs]):
        value = str(item.get("hex", ""))
        if not value:
            continue
        try:
            blob = bytes.fromhex(value)
        except ValueError:
            continue
        path = _candidate_output_path(source, index, str(item.get("label", "candidate")), str(item.get("direction", "output")), output_subdir)
        path.write_bytes(blob)
        entry: dict[str, Any] = {
            "path": str(path),
            "size": len(blob),
            "sha256": triage.hashes(path)["sha256"],
            "entropy": _entropy(blob),
            "candidate": item,
        }
        if carve_matches:
            entry["carve"] = carve_payloads_from_dump(
                str(path),
                output_subdir=slug(output_subdir) if output_subdir.strip() else slug(source.stem),
                import_to_samples=True,
                max_candidates=10,
                min_size=128,
                run_triage=True,
            )
        materialized.append(entry)

    manifest = {
        "source_path": str(source),
        "algorithm_hint": algorithm_hint,
        "evidence_counts": {
            "keys": len(keys),
            "ivs": len(ivs),
            "inputs": len(inputs),
            "outputs": len(expected_outputs),
        },
        "candidate_count": len(all_candidates),
        "match_count": len(matches),
        "matches": matches[:100],
        "materialized_outputs": materialized,
        "solver_errors": cipher_errors,
        "evidence_preview": {
            "algorithms": evidence.get("algorithms", []),
            "events": evidence.get("events_preview", [])[:20],
        },
        "next_actions": [
            "If match_count > 0, inspect materialized outputs and carve results; run sample_full_workup on carved payloads.",
            "If match_count == 0 but outputs exist, inspect captured-output materialized buffers; many decrypt APIs already return plaintext directly.",
            "If no useful output appears, collect a longer Frida run or add algorithm-specific mode/padding from the captured API events.",
        ],
    }
    manifest_path = UNPACK_EXPORTS_DIR / f"{slug(source.stem)}-crypto-solve-{_stamp()}.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    manifest["manifest_path"] = str(manifest_path)
    return manifest


def postprocess_frida_crypto_result(
    result_json_path: str,
    output_subdir: str = "",
    algorithm_hint: str = "",
    include_replay: bool = True,
    extract_buffers: bool = True,
    carve: bool = True,
) -> dict[str, Any]:
    """Run the full Frida crypto/unpack intake chain: parse, solve, replay scaffold, buffer extract/carve."""
    source, data = _load_json(result_json_path)
    messages = _messages_from_result(data)
    evidence = _crypto_evidence_from_messages(messages)
    safe_subdir = slug(output_subdir) if output_subdir.strip() else slug(source.stem)

    steps: list[dict[str, Any]] = []

    def run_step(name: str, func: Any, *args: Any) -> dict[str, Any]:
        try:
            result = func(*args)
            step = {"name": name, "status": "ok", "result": result}
        except Exception as exc:
            step = {"name": name, "status": "error", "error": str(exc)}
        steps.append(step)
        return step

    parse_step = run_step("parse_android_crypto_unpack_result", parse_android_crypto_unpack_result, str(source), "")
    solve_step = run_step("solve_crypto_from_evidence", solve_crypto_from_evidence, str(source), safe_subdir, algorithm_hint, carve)
    replay_step: dict[str, Any] | None = None
    if include_replay:
        replay_step = run_step("make_crypto_replay_scaffold", make_crypto_replay_scaffold, str(source), "", algorithm_hint)
    extract_step: dict[str, Any] | None = None
    if extract_buffers:
        extract_step = run_step("extract_frida_buffers", extract_frida_buffers, str(source), safe_subdir, carve, True, 50)

    solved = solve_step.get("result") if isinstance(solve_step.get("result"), dict) else {}
    parsed = parse_step.get("result") if isinstance(parse_step.get("result"), dict) else {}
    extracted = extract_step.get("result") if extract_step and isinstance(extract_step.get("result"), dict) else {}
    replay = replay_step.get("result") if replay_step and isinstance(replay_step.get("result"), dict) else {}

    carved_payloads: list[dict[str, Any]] = []
    for source_item in list(solved.get("materialized_outputs", [])) + list(extracted.get("buffers", [])):
        if not isinstance(source_item, dict):
            continue
        carve_result = source_item.get("carve")
        if not isinstance(carve_result, dict):
            continue
        for candidate in carve_result.get("candidates", []) if isinstance(carve_result.get("candidates"), list) else []:
            if isinstance(candidate, dict):
                carved_payloads.append(candidate)

    manifest = {
        "source_path": str(source),
        "message_count": len(messages),
        "output_subdir": safe_subdir,
        "evidence_counts": {
            "algorithms": len(evidence.get("algorithms", [])),
            "keys": len(evidence.get("keys", [])),
            "ivs": len(evidence.get("ivs", [])),
            "inputs": len(evidence.get("inputs", [])),
            "outputs": len(evidence.get("outputs", [])),
        },
        "android_parse_output": parsed.get("output_path", ""),
        "crypto_solve_manifest": solved.get("manifest_path", ""),
        "crypto_solve_match_count": solved.get("match_count", 0),
        "crypto_replay_script": replay.get("script_path", ""),
        "frida_buffer_manifest": extracted.get("manifest_path", ""),
        "carved_payload_count": len(carved_payloads),
        "carved_payloads": carved_payloads[:50],
        "steps": steps,
        "next_actions": [
            "Run sample_full_workup on carved_payloads[].sample_path when present.",
            "If crypto_solve_match_count is zero, inspect crypto_replay_script and captured-output materialized buffers.",
            "For Android, use android_parse_output dex/native paths to pull additional artifacts from the device.",
        ],
    }
    manifest_path = UNPACK_EXPORTS_DIR / f"{slug(source.stem)}-frida-crypto-postprocess-{_stamp()}.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    manifest["manifest_path"] = str(manifest_path)
    return manifest


def _replay_script_text(evidence: dict[str, Any], source_path: str, algorithm_hint: str) -> str:
    algorithms = evidence.get("algorithms", [])
    hint = algorithm_hint.strip() or (str(algorithms[0]) if algorithms else "")
    source_doc = source_path.replace("\\", "\\\\")
    return f'''#!/usr/bin/env python3
"""
ReverseLab crypto replay scaffold.

Source evidence: {source_doc}
Algorithm hint: {hint}

This script is intentionally a scaffold: it tries common modes when enough
key/iv/input/output evidence exists, and prints candidates for the AI/operator
to compare against captured output.
"""

from __future__ import annotations

import base64
import hashlib
import hmac


ALGORITHM_HINT = {hint!r}
{_python_literal_bytes(evidence.get("keys", []), "KEYS")}
{_python_literal_bytes(evidence.get("ivs", []), "IVS")}
{_python_literal_bytes(evidence.get("inputs", []), "INPUTS")}
{_python_literal_bytes(evidence.get("outputs", []), "EXPECTED_OUTPUTS")}


def unpad_pkcs7(data: bytes) -> bytes:
    if not data:
        return data
    pad = data[-1]
    if 0 < pad <= 16 and data.endswith(bytes([pad]) * pad):
        return data[:-pad]
    return data


def show(label: str, data: bytes) -> None:
    preview = data[:96]
    marker = " MATCH" if any(data == expected for expected in EXPECTED_OUTPUTS) else ""
    print(f"{{label}}{{marker}} len={{len(data)}} hex={{preview.hex()}} ascii={{preview!r}}")


def try_block_ciphers() -> None:
    try:
        from Crypto.Cipher import AES, DES, DES3, ARC4
    except Exception as exc:
        print("pycryptodome is not installed; install it or port constants into your preferred crypto library:", exc)
        return

    for key in KEYS:
        for data in INPUTS:
            if len(key) in (16, 24, 32):
                ciphers = [("AES-ECB", lambda: AES.new(key, AES.MODE_ECB))]
                for iv in IVS:
                    if len(iv) == 16:
                        ciphers.extend([
                            ("AES-CBC", lambda iv=iv: AES.new(key, AES.MODE_CBC, iv)),
                            ("AES-CFB", lambda iv=iv: AES.new(key, AES.MODE_CFB, iv)),
                            ("AES-OFB", lambda iv=iv: AES.new(key, AES.MODE_OFB, iv)),
                        ])
                for name, maker in ciphers:
                    try:
                        out = maker().decrypt(data)
                        show(name, out)
                        show(name + "-unpad", unpad_pkcs7(out))
                    except Exception as exc:
                        print(name, "failed", exc)
            if len(key) in (5, 16, 32, 64, 128, 256):
                try:
                    out = ARC4.new(key).decrypt(data)
                    show("ARC4", out)
                except Exception as exc:
                    print("ARC4 failed", exc)
            if len(key) in (8, 24):
                klass = DES if len(key) == 8 else DES3
                for name, mode in [("DES/3DES-ECB", klass.MODE_ECB)]:
                    try:
                        out = klass.new(key, mode).decrypt(data)
                        show(name, out)
                    except Exception as exc:
                        print(name, "failed", exc)


def try_hashes() -> None:
    for data in INPUTS:
        show("md5", hashlib.md5(data).digest())
        show("sha1", hashlib.sha1(data).digest())
        show("sha256", hashlib.sha256(data).digest())
    for key in KEYS:
        for data in INPUTS:
            show("hmac-sha1", hmac.new(key, data, hashlib.sha1).digest())
            show("hmac-sha256", hmac.new(key, data, hashlib.sha256).digest())


def compare_expected() -> None:
    if not EXPECTED_OUTPUTS:
        return
    print("Expected captured outputs:")
    for out in EXPECTED_OUTPUTS:
        show("expected", out)


def main() -> None:
    print("algorithm hint:", ALGORITHM_HINT)
    print("keys:", [len(x) for x in KEYS], "ivs:", [len(x) for x in IVS], "inputs:", [len(x) for x in INPUTS], "outputs:", [len(x) for x in EXPECTED_OUTPUTS])
    compare_expected()
    try_block_ciphers()
    try_hashes()


if __name__ == "__main__":
    main()
'''


def make_crypto_replay_scaffold(
    result_json_path: str,
    output_path: str = "",
    algorithm_hint: str = "",
) -> dict[str, Any]:
    """Generate a runnable Python crypto replay scaffold from Frida crypto evidence."""
    source, data = _load_json(result_json_path)
    messages = _messages_from_result(data)
    evidence = _crypto_evidence_from_messages(messages)
    out_dir = SCRIPTS_DIR / "crypto_replay"
    out_dir.mkdir(parents=True, exist_ok=True)
    destination = Path(output_path).expanduser().resolve() if output_path.strip() else out_dir / f"{slug(source.stem)}-crypto-replay-{_stamp()}.py"
    ensure_under(destination, [out_dir], "crypto replay output")
    script = _replay_script_text(evidence, str(source), algorithm_hint)
    destination.write_text(script, encoding="utf-8")
    manifest = {
        "source_path": str(source),
        "script_path": str(destination),
        "algorithm_hint": algorithm_hint,
        "evidence": evidence,
        "next_actions": [
            "Run the replay script and compare candidate plaintext with captured crypto_output.",
            "If no mode matches, inspect Cipher.getAlgorithm/API events and add the exact mode/padding.",
            "Feed recovered plaintext/payload into carve_payloads_from_dump.",
        ],
    }
    manifest_path = UNPACK_EXPORTS_DIR / f"{slug(source.stem)}-crypto-replay-{_stamp()}.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    manifest["manifest_path"] = str(manifest_path)
    return manifest
