from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from ..config import DEBUG_SCRIPTS_DIR, EXPORTS_ROOT, SCRIPTS_DIR
from ..paths import ensure_under, resolve_file
from ..utils import slug
from . import ghidra_summary, triage


CRYPTO_APIS = [
    "CryptAcquireContextA",
    "CryptAcquireContextW",
    "CryptCreateHash",
    "CryptHashData",
    "CryptDeriveKey",
    "CryptImportKey",
    "CryptGenKey",
    "CryptEncrypt",
    "CryptDecrypt",
    "CryptDestroyKey",
    "BCryptOpenAlgorithmProvider",
    "BCryptSetProperty",
    "BCryptGenerateSymmetricKey",
    "BCryptImportKey",
    "BCryptEncrypt",
    "BCryptDecrypt",
    "BCryptCreateHash",
    "BCryptHashData",
    "BCryptFinishHash",
    "NCryptDecrypt",
    "NCryptEncrypt",
]

UNPACK_APIS = [
    "VirtualAlloc",
    "VirtualAllocEx",
    "VirtualProtect",
    "VirtualProtectEx",
    "MapViewOfFile",
    "CreateFileMappingW",
    "CreateFileMappingA",
    "WriteProcessMemory",
    "ReadProcessMemory",
    "CreateRemoteThread",
    "NtCreateThreadEx",
    "NtUnmapViewOfSection",
    "LoadLibraryA",
    "LoadLibraryW",
    "GetProcAddress",
]

CRT_CRYPTO_HINTS = [
    "memcpy",
    "memmove",
    "memcmp",
    "RtlMoveMemory",
    "RtlCopyMemory",
]

CRYPTO_STRING_HINTS = [
    "aes",
    "des",
    "rc4",
    "rsa",
    "xor",
    "base64",
    "sha1",
    "sha256",
    "md5",
    "key",
    "iv",
    "salt",
    "decrypt",
    "encrypt",
]


def _stamp() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S-%f")


def _load_import_names(sample_path: str, summary_path: str) -> tuple[set[str], list[dict[str, Any]], str]:
    names: set[str] = set()
    imports: list[dict[str, Any]] = []
    sources: list[str] = []
    if summary_path.strip():
        path, data = ghidra_summary.load_summary(summary_path)
        for item in data.get("imports", []) if isinstance(data.get("imports"), list) else []:
            if isinstance(item, dict) and item.get("name"):
                names.add(str(item.get("name", "")).lower())
                imports.append(item)
        sources.append(str(path))
    if sample_path.strip():
        result = triage.rizin_imports(sample_path, limit=5000)
        stdout = result.get("stdout", {})
        for item in stdout.get("imports", []) if isinstance(stdout, dict) and isinstance(stdout.get("imports"), list) else []:
            if isinstance(item, dict) and item.get("name"):
                names.add(str(item.get("name", "")).lower())
                imports.append(item)
        sources.append("rizin_imports")
    return names, imports, ", ".join(sources)


def _load_summary_strings(summary_path: str) -> list[dict[str, Any]]:
    if not summary_path.strip():
        return []
    _path, data = ghidra_summary.load_summary(summary_path)
    strings = data.get("strings", [])
    return [item for item in strings if isinstance(item, dict)] if isinstance(strings, list) else []


def _matching(items: list[str], imported_names: set[str]) -> list[str]:
    return [item for item in items if item.lower() in imported_names]


def _summary_focus(summary_path: str, mode: str, limit: int) -> list[dict[str, Any]]:
    if not summary_path.strip():
        return []
    query = ""
    behavior = ""
    if mode == "crypto":
        query = "\n".join(CRYPTO_APIS + CRYPTO_STRING_HINTS)
    elif mode == "unpack":
        query = "\n".join(UNPACK_APIS)
        behavior = "process"
    else:
        query = "\n".join(CRYPTO_APIS + UNPACK_APIS + CRYPTO_STRING_HINTS)
    result = ghidra_summary.ghidra_summary_call_focus(summary_path, query, behavior, 16, limit)
    return [item for item in result.get("suggested_functions", []) if isinstance(item, dict)]


def _x64dbg_script(sample_name: str, mode: str, apis: list[str], focus_functions: list[dict[str, Any]]) -> Path:
    DEBUG_SCRIPTS_DIR.mkdir(parents=True, exist_ok=True)
    path = DEBUG_SCRIPTS_DIR / f"{slug(sample_name)}-{mode}-crypto-unpack-{_stamp()}.txt"
    lines = [
        "// ReverseLab crypto/unpack x64dbg probe",
        f"// Generated: {datetime.now().isoformat(timespec='seconds')}",
        f"// Mode: {mode}",
        "// Load the sample in x64dbg, run this script, then exercise the target path.",
        "// API breakpoints catch decrypt/unpack boundaries; function breakpoints come from Ghidra semantic focus.",
        "",
        "// API breakpoints",
    ]
    for api in apis:
        lines.append(f"bp {api}")
    if focus_functions:
        lines.extend(["", "// Focus function breakpoints (module-relative RVA)"])
        image_base = None
        for item in focus_functions:
            entry = str(item.get("entry", "")).replace("0x", "")
            if len(entry) >= 8:
                try:
                    value = int(entry, 16)
                    if image_base is None:
                        image_base = value & 0xFFFFFFFFFFFF0000
                    rva = value - image_base
                    lines.append(f"bp mod.main()+0x{rva:X} // {item.get('name', '')} score={item.get('score', '')}")
                except ValueError:
                    continue
    lines.extend(
        [
            "",
            "// Manual dump checkpoints:",
            "// - On VirtualProtect/VirtualProtectEx changing pages to executable, inspect base/size and dump the region.",
            "// - On GetProcAddress/LoadLibrary*, watch dynamically resolved APIs.",
            "// - On BCryptDecrypt/CryptDecrypt return, inspect output buffer and caller.",
            "// - After unpacking, search for MZ/PE headers or high-entropy-to-code transitions in memory map.",
        ]
    )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _frida_script(sample_name: str, mode: str, apis: list[str]) -> Path:
    out_dir = SCRIPTS_DIR / "frida" / "windows"
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{slug(sample_name)}-{mode}-crypto-unpack-{_stamp()}.js"
    api_json = json.dumps(apis)
    script = f"""// ReverseLab Windows crypto/unpack Frida probe
// Attach with: frida -f <sample.exe> -l {path.name} --no-pause
const apis = {api_json};
function readUtf16(ptr) {{
  try {{ return ptr.isNull() ? "" : Memory.readUtf16String(ptr); }} catch (e) {{ return "<utf16?>"; }}
}}
function readUtf8(ptr) {{
  try {{ return ptr.isNull() ? "" : Memory.readUtf8String(ptr); }} catch (e) {{ return "<utf8?>"; }}
}}
function hookAny(api) {{
  const modules = ["kernel32.dll", "kernelbase.dll", "advapi32.dll", "bcrypt.dll", "ncrypt.dll", "ntdll.dll"];
  let addr = null;
  let moduleName = "";
  for (const m of modules) {{
    addr = Module.findExportByName(m, api);
    if (addr) {{ moduleName = m; break; }}
  }}
  if (!addr) return;
  Interceptor.attach(addr, {{
    onEnter(args) {{
      this.api = api;
      this.args = [];
      for (let i = 0; i < 10; i++) this.args.push(args[i]);
      const event = {{event: "api_enter", api, module: moduleName, a0: String(args[0]), a1: String(args[1]), a2: String(args[2]), a3: String(args[3])}};
      if (api.indexOf("LoadLibraryW") >= 0) event.path = readUtf16(args[0]);
      if (api.indexOf("LoadLibraryA") >= 0) event.path = readUtf8(args[0]);
      if (api.indexOf("GetProcAddress") >= 0) event.proc = readUtf8(args[1]);
      if (api === "BCryptOpenAlgorithmProvider") event.algorithm = readUtf16(args[1]);
      send(event);
      try {{
        if ((api === "CryptDecrypt" || api === "CryptEncrypt") && args[4] && !args[4].isNull()) {{
          const lenPtr = args[5];
          const inLen = lenPtr.isNull() ? 0 : lenPtr.readU32();
          const dumpLen = Math.min(inLen, 4096);
          if (dumpLen > 0) send({{event: "api_buffer", api, buffer_role: "crypto_input", buffer: String(args[4]), size: inLen, dumped: dumpLen}}, args[4].readByteArray(dumpLen));
        }}
        if ((api === "BCryptDecrypt" || api === "BCryptEncrypt") && args[1] && !args[1].isNull()) {{
          const inLen = args[2].toInt32 ? args[2].toInt32() : 0;
          const dumpLen = Math.min(inLen, 4096);
          if (dumpLen > 0) send({{event: "api_buffer", api, buffer_role: "crypto_input", buffer: String(args[1]), size: inLen, dumped: dumpLen}}, args[1].readByteArray(dumpLen));
        }}
        if ((api === "BCryptDecrypt" || api === "BCryptEncrypt") && args[4] && !args[4].isNull()) {{
          const ivLen = args[5].toInt32 ? args[5].toInt32() : 0;
          const dumpLen = Math.min(ivLen, 4096);
          if (dumpLen > 0) send({{event: "api_buffer", api, buffer_role: "crypto_iv", buffer: String(args[4]), size: ivLen, dumped: dumpLen}}, args[4].readByteArray(dumpLen));
        }}
        if ((api === "NCryptDecrypt" || api === "NCryptEncrypt") && args[1] && !args[1].isNull()) {{
          const inLen = args[2].toInt32 ? args[2].toInt32() : 0;
          const dumpLen = Math.min(inLen, 4096);
          if (dumpLen > 0) send({{event: "api_buffer", api, buffer_role: "crypto_input", buffer: String(args[1]), size: inLen, dumped: dumpLen}}, args[1].readByteArray(dumpLen));
        }}
        if (api === "CryptImportKey" && args[1] && !args[1].isNull()) {{
          const keyLen = args[2].toInt32 ? args[2].toInt32() : 0;
          const dumpLen = Math.min(keyLen, 4096);
          if (dumpLen > 0) send({{event: "api_buffer", api, buffer_role: "crypto_key_blob", buffer: String(args[1]), size: keyLen, dumped: dumpLen}}, args[1].readByteArray(dumpLen));
        }}
        if (api === "BCryptImportKey" && args[5] && !args[5].isNull()) {{
          const blobLen = args[6].toInt32 ? args[6].toInt32() : 0;
          const dumpLen = Math.min(blobLen, 4096);
          if (dumpLen > 0) send({{event: "api_buffer", api, buffer_role: "crypto_key_blob", buffer: String(args[5]), size: blobLen, dumped: dumpLen}}, args[5].readByteArray(dumpLen));
        }}
        if (api === "BCryptGenerateSymmetricKey" && args[4] && !args[4].isNull()) {{
          const keyLen = args[5].toInt32 ? args[5].toInt32() : 0;
          const dumpLen = Math.min(keyLen, 4096);
          if (dumpLen > 0) send({{event: "api_buffer", api, buffer_role: "crypto_key", buffer: String(args[4]), size: keyLen, dumped: dumpLen}}, args[4].readByteArray(dumpLen));
        }}
      }} catch (e) {{
        send({{event: "api_buffer_error", api, error: String(e)}});
      }}
    }},
    onLeave(retval) {{
      const leaveEvent = {{event: "api_leave", api: this.api, retval: String(retval)}};
      if ((api === "CryptDecrypt" || api === "CryptEncrypt") && this.args[4] && !this.args[4].isNull()) {{
        try {{
          const lenPtr = this.args[5];
          const outLen = lenPtr.isNull() ? 0 : lenPtr.readU32();
          const dumpLen = Math.min(outLen, 4096);
          if (dumpLen > 0) {{
            const bytes = this.args[4].readByteArray(dumpLen);
            send(Object.assign(leaveEvent, {{buffer_role: "crypto_output", buffer: String(this.args[4]), size: outLen, dumped: dumpLen}}), bytes);
            return;
          }}
        }} catch (e) {{ leaveEvent.dump_error = String(e); }}
      }}
      if ((api === "BCryptDecrypt" || api === "BCryptEncrypt") && this.args[6] && !this.args[6].isNull()) {{
        try {{
          const outLen = this.args[8] && !this.args[8].isNull() ? this.args[8].readU32() : (this.args[7].toInt32 ? this.args[7].toInt32() : 0);
          const dumpLen = Math.min(outLen, 4096);
          if (dumpLen > 0) {{
            const bytes = this.args[6].readByteArray(dumpLen);
            send(Object.assign(leaveEvent, {{buffer_role: "crypto_output", buffer: String(this.args[6]), size: outLen, dumped: dumpLen}}), bytes);
            return;
          }}
        }} catch (e) {{ leaveEvent.dump_error = String(e); }}
      }}
      if ((api === "NCryptDecrypt" || api === "NCryptEncrypt") && this.args[4] && !this.args[4].isNull()) {{
        try {{
          const outLen = this.args[6] && !this.args[6].isNull() ? this.args[6].readU32() : (this.args[5].toInt32 ? this.args[5].toInt32() : 0);
          const dumpLen = Math.min(outLen, 4096);
          if (dumpLen > 0) {{
            const bytes = this.args[4].readByteArray(dumpLen);
            send(Object.assign(leaveEvent, {{buffer_role: "crypto_output", buffer: String(this.args[4]), size: outLen, dumped: dumpLen}}), bytes);
            return;
          }}
        }} catch (e) {{ leaveEvent.dump_error = String(e); }}
      }}
      if ((api === "VirtualProtect" || api === "VirtualProtectEx")) {{
        try {{
          const base = api === "VirtualProtectEx" ? this.args[1] : this.args[0];
          const sizeArg = api === "VirtualProtectEx" ? this.args[2] : this.args[1];
          const regionSize = sizeArg.toInt32 ? sizeArg.toInt32() : 0;
          const dumpLen = Math.min(regionSize, 8192);
          if (base && !base.isNull() && dumpLen > 0) {{
            const bytes = base.readByteArray(dumpLen);
            send(Object.assign(leaveEvent, {{buffer_role: "rx_region_preview", base: String(base), size: regionSize, dumped: dumpLen}}), bytes);
            return;
          }}
        }} catch (e) {{ leaveEvent.dump_error = String(e); }}
      }}
      send(leaveEvent);
    }}
  }});
  send({{event: "hooked", api, module: moduleName, address: String(addr)}});
}}
for (const api of apis) hookAny(api);
"""
    path.write_text(script, encoding="utf-8")
    return path


def _plan_path(sample_name: str, mode: str, output_path: str) -> Path:
    base = EXPORTS_ROOT / "unpack"
    base.mkdir(parents=True, exist_ok=True)
    if output_path.strip():
        path = Path(output_path).expanduser().resolve()
        ensure_under(path, [base], "crypto/unpack plan output")
        path.parent.mkdir(parents=True, exist_ok=True)
        return path
    return base / f"{slug(Path(sample_name).stem)}-{mode}-crypto-unpack-plan-{_stamp()}.json"


def make_pe_crypto_unpack_plan(
    sample_path: str,
    summary_path: str = "",
    mode: str = "both",
    output_path: str = "",
    include_frida: bool = True,
    focus_limit: int = 12,
) -> dict[str, Any]:
    normalized_mode = mode.strip().lower() or "both"
    if normalized_mode not in {"crypto", "unpack", "both"}:
        raise ValueError("mode must be one of: crypto, unpack, both")

    sample = resolve_file(sample_path)
    imported_names, imports, import_source = _load_import_names(str(sample), summary_path)
    strings = _load_summary_strings(summary_path)

    selected_apis: list[str] = []
    if normalized_mode in {"crypto", "both"}:
        selected_apis.extend(CRYPTO_APIS)
    if normalized_mode in {"unpack", "both"}:
        selected_apis.extend(UNPACK_APIS)
    selected_apis.extend(CRT_CRYPTO_HINTS if normalized_mode in {"crypto", "both"} else [])
    selected_apis = list(dict.fromkeys(selected_apis))

    imported_crypto = _matching(CRYPTO_APIS, imported_names)
    imported_unpack = _matching(UNPACK_APIS, imported_names)
    imported_crt_hints = _matching(CRT_CRYPTO_HINTS, imported_names)
    string_hits = []
    for item in strings:
        value = str(item.get("value", ""))
        lowered = value.lower()
        if any(hint in lowered for hint in CRYPTO_STRING_HINTS):
            string_hits.append(item)

    focus_functions = _summary_focus(summary_path, normalized_mode, max(1, focus_limit))
    x64dbg_path = _x64dbg_script(sample.name, normalized_mode, selected_apis, focus_functions)
    frida_path = _frida_script(sample.name, normalized_mode, selected_apis) if include_frida else None
    destination = _plan_path(sample.name, normalized_mode, output_path)

    plan = {
        "sample_path": str(sample),
        "summary_path": summary_path,
        "mode": normalized_mode,
        "import_source": import_source,
        "selected_api_breakpoints": selected_apis,
        "imported_crypto_apis": imported_crypto,
        "imported_unpack_apis": imported_unpack,
        "imported_crt_crypto_hints": imported_crt_hints,
        "crypto_string_hits": string_hits[:50],
        "focus_functions": focus_functions,
        "x64dbg_script_path": str(x64dbg_path),
        "frida_script_path": str(frida_path) if frida_path else "",
        "next_actions": [
            "Run x64dbg script and exercise target input; inspect buffers after CryptDecrypt/BCryptDecrypt returns.",
            "Break on VirtualProtect/VirtualProtectEx and dump executable regions after permissions change.",
            "Use Frida probe for fast API telemetry if the sample can be launched safely in the lab VM.",
            "Feed dumped code or decrypted buffers back into Ghidra/Rizin and rerun sample_full_workup.",
        ],
    }
    destination.write_text(json.dumps(plan, ensure_ascii=False, indent=2), encoding="utf-8")
    plan["plan_path"] = str(destination)
    return plan
