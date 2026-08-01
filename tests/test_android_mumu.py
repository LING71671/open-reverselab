from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MCP_ROOT = ROOT / "tools" / "skills" / "mcp" / "ReverseLabToolsMCP"
sys.path.insert(0, str(MCP_ROOT))

from reverselab_mcp.errors import ToolError  # noqa: E402
from reverselab_mcp.tools import android_mumu  # noqa: E402


def test_loader_aware_template_is_declared_and_renderable():
    catalog = android_mumu.android_frida_template_library()
    template_ids = {item["template_id"] for item in catalog["templates"]}

    assert "native_module_load_hook" in template_ids
    rendered = android_mumu.android_frida_render_template(
        "native_module_load_hook", '{"library_name":"libguard.so"}'
    )

    script = rendered["script_source"]
    assert "native_module.loaded" in script
    assert "native_module.load_failed" in script
    assert "retval.isNull()" in script
    assert "android_dlopen_ext" in script
    assert "libguard.so" in script


def test_loader_aware_template_rejects_missing_library_name():
    try:
        android_mumu.android_frida_render_template("native_module_load_hook")
    except ToolError as exc:
        assert "missing placeholders" in str(exc)
    else:
        raise AssertionError("missing library_name must fail")


def test_register_natives_template_emits_bounded_mapping_evidence():
    rendered = android_mumu.android_frida_render_template("native_register_natives")
    script = rendered["script_source"]

    assert "RegisterNatives.method" in script
    assert "RegisterNatives.truncated" in script
    assert "Math.min(this.count, 64)" in script
    assert "jni_signature" in script
    assert "declaring_class" in script
    assert "strings_truncated" in script
    assert "Memory.readUtf8String(address, 256)" in script
    assert "function_in_module_range" in script
    assert "native_address" in script



def test_shell_mumu_fallback_escapes_quotes_without_python_312_syntax(monkeypatch):
    called = {}

    monkeypatch.setattr(android_mumu, "IS_WINDOWS", True)
    monkeypatch.setattr(android_mumu, "_is_default_mumu_serial", lambda serial: True)
    monkeypatch.setattr(android_mumu, "_adb", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("adb unavailable")))
    monkeypatch.setattr(
        android_mumu,
        "_mumu_cli",
        lambda args, **kwargs: (called.update({"args": args}) or (0, "", "")),
    )

    android_mumu._shell('echo "quoted"', as_root=False)

    assert 'su -c "echo \\"quoted\\""' in called["args"]


def test_crypto_recipe_templates_are_registered():
    catalog = android_mumu.android_frida_template_library()
    template_ids = {item["template_id"] for item in catalog["templates"]}
    requested = [item.strip() for item in android_mumu.ANDROID_CRYPTO_UNPACK_TEMPLATES.split(",")]

    assert requested
    assert set(requested).issubset(template_ids)
