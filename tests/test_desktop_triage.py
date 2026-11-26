from __future__ import annotations

import hashlib
import zipfile

import pytest

from conftest import load_script_module

triage = load_script_module("scripts/misc/triage_target.py", "desktop_triage_test")


@pytest.mark.parametrize("name", ["missing.exe", "missing.apk", "crackme", "missing.bin"])
def test_nonexistent_targets_never_return_invented_metadata(tmp_path, name):
    with pytest.raises(FileNotFoundError):
        triage.triage_target(str(tmp_path / name))


def test_unknown_file_has_real_hash_but_no_assumed_architecture(tmp_path):
    target = tmp_path / "fixture.exe"
    target.write_bytes(b"Synthetic non-executable data")
    result = triage.triage_target(str(target))
    assert result["sha256"] == hashlib.sha256(target.read_bytes()).hexdigest()
    assert result["sizeBytes"] == target.stat().st_size
    assert "arch" not in result
    assert "compiler" not in result
    assert "capabilities" not in result
    assert result["fileType"] == "Generic Binary"


def test_empty_directory_has_an_observed_empty_inventory(tmp_path):
    result = triage.triage_target(str(tmp_path))
    assert result["isContainerDirectory"]
    assert result["discoveredSamples"] == []
    assert "resolvedBinary" not in result
    assert "sha256" not in result


def test_apk_directory_uses_real_package_contents(tmp_path):
    target = tmp_path / "fixture.apk"
    with zipfile.ZipFile(target, "w") as archive:
        archive.writestr("AndroidManifest.xml", "synthetic manifest")
    result = triage.triage_target(str(tmp_path))
    assert result["resolvedBinary"] == target.name
    assert result["hasManifest"]
    assert result["targetPath"] == str(target)
    assert "packer" not in result


def test_plain_zip_is_not_reported_as_android_package(tmp_path):
    target = tmp_path / "fixture.zip"
    with zipfile.ZipFile(target, "w") as archive:
        archive.writestr("data.txt", "synthetic data")
    result = triage.triage_target(str(target))
    assert result["fileType"] == "ZIP Archive"
    assert result["board"] == "general"


def test_web_triage_leaves_the_deadline_to_the_execution_runner(monkeypatch):
    class Response:
        status = 200
        headers = {"Content-Type": "text/plain"}

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

    observed = []

    def urlopen(request, *, timeout):
        observed.append(timeout)
        return Response()

    monkeypatch.setattr(triage.urllib.request, "urlopen", urlopen)
    result = triage.triage_target("https://fixture.example.test/")
    assert result["httpStatus"] == 200
    assert observed == [None]

def test_nested_executables_use_relative_names_and_include_the_primary_in_preview(tmp_path):
    for parent in ("one", "two"):
        folder = tmp_path / parent
        folder.mkdir()
        (folder / "sample.EXE").write_bytes(parent.encode())
    for index in range(31):
        (tmp_path / f"{index}.dll").write_bytes(b"longer")
    result = triage.triage_target(str(tmp_path))
    assert result["inventoryScan"]["sampleCount"] == 33
    assert result["inventoryScan"]["limitsReached"] == []
    assert len(result["discoveredSamples"]) == 30
    assert result["resolvedBinary"] == "one/sample.EXE"
    assert result["targetPath"] == str(tmp_path / "one" / "sample.EXE")
    assert [s["name"] for s in result["discoveredSamples"] if s["isPrimary"]] == ["one/sample.EXE"]


def test_nested_directory_scan_bounds(tmp_path, monkeypatch):
    nested = tmp_path / "one" / "two"
    nested.mkdir(parents=True)
    (nested / "nested.exe").write_bytes(b"nested")
    (tmp_path / "large.exe").write_bytes(b"oversize")
    (tmp_path / "small.dll").write_bytes(b"x")
    monkeypatch.setattr(triage, "MAX_SCAN_DEPTH", 1)
    monkeypatch.setattr(triage, "MAX_SAMPLE_BYTES", 5)
    result = triage.triage_target(str(tmp_path))
    assert [s["name"] for s in result["discoveredSamples"]] == ["small.dll"]
    assert result["inventoryScan"] == {
        "entriesScanned": 4, "sizeBytes": 1, "sampleCount": 1, "limitsReached": ["bytes", "depth"],
    }
    monkeypatch.setattr(triage, "MAX_SCAN_ENTRIES", 2)
    scan = triage.triage_target(str(tmp_path))["inventoryScan"]
    assert scan["entriesScanned"] == 2
    assert "entries" in scan["limitsReached"]


def test_directory_scan_skips_linked_directories(tmp_path):
    source, outside = tmp_path / "source", tmp_path / "outside"
    source.mkdir()
    outside.mkdir()
    (outside / "sample.exe").write_bytes(b"external")
    try:
        (source / "link").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlink privilege unavailable")
    assert triage.triage_target(str(source))["discoveredSamples"] == []
