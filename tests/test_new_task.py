from conftest import load_script_module


def load_module():
    return load_script_module("scripts/misc/new_task.py", "new_task_test")


def test_slugify_keeps_portable_names():
    module = load_module()
    assert module.slugify("JWT Lab #1") == "jwt-lab-1"
    assert module.slugify("  APK_case.test  ") == "apk_case.test"
    assert module.slugify("!!!") == "task"


def test_manifest_for_has_resume_fields():
    module = load_module()
    manifest = module.manifest_for("ctf-website", "JWT Lab", "jwt-lab")
    assert manifest["board"] == "ctf-website"
    assert manifest["autopilot"]["rounds"] == []
    assert manifest["evidence"] == []
    assert any("AI-USAGE.md" in action for action in manifest["next_actions"])

