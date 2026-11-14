"""Behavioral checks for the portable draft authoring helper."""

import copy
import hashlib
import json
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile

import package_extension as pack

ASSETS = Path(__file__).resolve().parents[1] / "assets"


class PackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        shutil.copytree(ASSETS / "integrity-pack", self.source)

    def tearDown(self):
        self.temp.cleanup()

    def build(self, name="pack.zip"):
        output = self.root / name
        result = subprocess.run([sys.executable, str(Path(pack.__file__)), "build", str(self.source), str(output)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return output

    def change_json(self, payload, path, transform):
        data = json.loads(payload[path])
        transform(data)
        payload[path] = json.dumps(data).encode()

    def test_roundtrip_and_reproducible_build_excludes_unlisted_files(self):
        (self.source / "private-note.txt").write_text("local-only", encoding="utf-8")
        first = self.build()
        second = self.build("second.zip")
        self.assertEqual(first.read_bytes(), second.read_bytes())
        payload, is_archive = pack.load(first)
        manifest = pack.validate(payload, is_archive)
        self.assertNotIn("private-note.txt", payload)
        locked = json.loads(payload[pack.LOCK])
        for name in [pack.MANIFEST, *manifest["files"]]:
            self.assertEqual(payload[name], (self.source / name).read_bytes())
            self.assertEqual(locked["files"][name], hashlib.sha256(payload[name]).hexdigest())

    def test_changed_content_fails_archive_check(self):
        payload, _ = pack.load(self.build())
        payload["docs/read.md"] += b"\nchanged"
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            pack.validate(payload, True)

    def test_enclosing_github_directory(self):
        original = self.build()
        wrapped = self.root / "github.zip"
        with zipfile.ZipFile(original) as source, zipfile.ZipFile(wrapped, "w") as output:
            for name in source.namelist():
                output.writestr("example-main/" + name, source.read(name))
        payload, is_archive = pack.load(wrapped)
        self.assertEqual(pack.validate(payload, is_archive)["id"], "example.integrity")

    def test_bad_archive_paths_and_links(self):
        for name in ("../outside", "/absolute", "C:/target", "docs/CON", "docs/file."):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    pack.safe_path(name)
        path = self.root / "link.zip"
        with zipfile.ZipFile(path, "w") as output:
            info = zipfile.ZipInfo("linked")
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            output.writestr(info, "outside")
        with self.assertRaisesRegex(ValueError, "Unsupported archive entry"):
            pack.load(path)

    def test_case_collision_and_external_archive_member(self):
        payload, _ = pack.load(self.build())
        path = self.root / "collision.zip"
        with zipfile.ZipFile(path, "w") as output:
            for name, raw in payload.items():
                output.writestr(name, raw)
            output.writestr("DOCS/READ.md", b"duplicate")
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            pack.load(path)
        payload["unlisted.txt"] = b"extra"
        with self.assertRaisesRegex(ValueError, "file set"):
            pack.validate(payload, True)

    def test_missing_local_reference(self):
        payload, _ = pack.load(self.source)
        self.change_json(payload, "knowledge.json", lambda d: d["methods"][0].update(document="example.integrity/docs/missing"))
        with self.assertRaisesRegex(ValueError, "Missing documents reference"):
            pack.validate(payload, False)

    def test_cross_pack_reference_needs_declared_dependency(self):
        payload, _ = pack.load(self.source)
        self.change_json(payload, "knowledge.json", lambda d: d["methods"][0].update(document="another.pack/docs/read"))
        with self.assertRaisesRegex(ValueError, "Missing documents reference"):
            pack.validate(payload, False)
        self.change_json(payload, pack.MANIFEST, lambda d: d["requires"].append({"id": "another.pack", "version": "1.0.0", "source": "https://example.com/repository", "optional": False}))
        pack.validate(payload, False)

    def test_network_entrypoint_is_a_method_node(self):
        payload, _ = pack.load(self.source)
        self.change_json(payload, "knowledge.json", lambda d: d["networks"][0].update(entrypoints=["example.integrity/missing"]))
        with self.assertRaisesRegex(ValueError, "Entrypoint"):
            pack.validate(payload, False)

    def test_optional_metadata_roundtrip(self):
        path = self.source / pack.MANIFEST
        manifest = json.loads(path.read_bytes())
        manifest["extensions"] = {"publisher.note": {"nested": ["preserved", 2]}}
        path.write_text(json.dumps(manifest), encoding="utf-8")
        payload, is_archive = pack.load(self.build())
        self.assertEqual(pack.validate(payload, is_archive)["extensions"], manifest["extensions"])

    def test_mcp_inputs_and_stdio(self):
        payload, is_archive = pack.load(ASSETS / "http-mcp")
        pack.validate(payload, is_archive)
        data = json.loads(payload["connection.json"])
        bad = copy.deepcopy(data)
        bad["url"] = "${inputs.missing}"
        with self.assertRaisesRegex(ValueError, "Undeclared MCP input"):
            pack.validate_mcp(bad)
        bad = copy.deepcopy(data)
        bad["inputs"][0]["value"] = "local configuration"
        with self.assertRaisesRegex(ValueError, "locally"):
            pack.validate_mcp(bad)
        pack.validate_mcp({"transport": "stdio", "command": "python", "args": ["-m", "example_server"], "inputs": []})

    def test_does_not_replace_existing_output(self):
        output = self.build()
        before = output.read_bytes()
        result = subprocess.run([sys.executable, str(Path(pack.__file__)), "build", str(self.source), str(output)], capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(output.read_bytes(), before)

    def test_catalog_entries_match_real_templates(self):
        catalog = json.loads((ASSETS / "reverselab.registry.json").read_bytes())
        for entry in catalog["entries"]:
            payload, is_archive = pack.load(ASSETS / entry["path"])
            manifest = pack.validate(payload, is_archive)
            for field in ("id", "kind", "version"):
                self.assertEqual(entry[field], manifest[field])


if __name__ == "__main__":
    unittest.main()
