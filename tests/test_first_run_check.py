from conftest import load_script_module


def load_module():
    return load_script_module("scripts/misc/first_run_check.py", "first_run_check_test")


def test_first_run_check_finds_reverse_lab_tools():
    module = load_module()
    checks = module.collect_checks(module.ROOT)
    failures = [check for check in checks if check.level == "FAIL"]
    assert not failures
    assert any(check.name == "MCP reverse_lab_tools" and check.level == "PASS" for check in checks)
