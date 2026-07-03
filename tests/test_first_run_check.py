from conftest import load_script_module


def load_module():
    return load_script_module("scripts/misc/first_run_check.py", "first_run_check_test")


def test_first_run_check_finds_reverse_lab_tools():
    module = load_module()
    checks = module.collect_checks(module.ROOT)
    failures = [check for check in checks if check.level == "FAIL"]
    assert not failures
    assert any(check.name == "MCP reverse_lab_tools" and check.level == "PASS" for check in checks)


def test_first_run_report_payload_has_recommendations_and_next_steps(tmp_path):
    module = load_module()
    checks = [
        module.Check("PASS", "Python", "3.x"),
        module.Check("WARN", "uv", "not found", "Install uv."),
    ]
    report_path = tmp_path / "first-run-report.json"
    payload = module.build_payload(checks, report_path)
    written = module.write_report(payload, report_path)

    assert payload["overall"] == "PASS"
    assert payload["summary"]["warn"] == 1
    assert payload["recommendations"][0]["name"] == "uv"
    assert "Codex APP" in payload["next_steps"][0]
    assert written.is_file()
