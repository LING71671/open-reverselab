from __future__ import annotations

from conftest import load_script_module


public_release_check = load_script_module("scripts/misc/public_release_check.py", "public_release_check_test")


def test_secret_patterns_detect_user_paths_and_tokens():
    samples = {
        "Windows user path": "log=C:" + r"\Users\alice\AppData\Local\tool.log",
        "escaped Windows user path": '"path": "C:' + r"\\Users\\alice\\tool.log" + '"',
        "Unix user path": "/" + "home/alice/.config/tool",
        "GitHub token": "ghp_" + "abcdefghijklmnopqrstuvwxyz123456",
    }

    for label, text in samples.items():
        assert public_release_check.SECRET_PATTERNS[label].search(text)


def test_text_extensions_include_public_config_formats():
    assert ".toml" in public_release_check.TEXT_EXTS
    assert ".yml" in public_release_check.TEXT_EXTS
    assert ".json" in public_release_check.TEXT_EXTS


def test_kb_derived_dumps_are_exempt_from_credential_heuristic():
    # The generated LLM dumps aggregate KB articles verbatim, so they inherit the
    # KB's synthetic credential snippets and must be exempt like kb/ itself.
    assert "docs/llms-full.txt" in public_release_check.KB_DERIVED_FILES
    assert "docs/llms.txt" in public_release_check.KB_DERIVED_FILES
