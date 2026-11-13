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
