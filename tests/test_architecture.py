"""Isolated negative controls for the custom architectural harness."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from tools.architecture import (
    REQUIRED_ARTIFACTS,
    REQUIRED_NATIVE,
    dependency_errors,
    verify_contracts,
)


class ArchitectureTests(unittest.TestCase):
    def fixture(self, root: Path) -> None:
        vendor = root / "contracts/spec"
        vendor.mkdir(parents=True)
        data = b"fixture\n"
        (vendor / "data.txt").write_bytes(data)
        entries = {"data.txt": hashlib.sha256(data).hexdigest()}
        for name in REQUIRED_ARTIFACTS:
            target = vendor / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            entries[name] = hashlib.sha256(data).hexdigest()
        manifest = json.dumps({"contract_version": "fixture", "files": entries}).encode()
        (vendor / "manifest.json").write_bytes(manifest)
        native = root / "contracts/native"
        native.mkdir(parents=True)
        native_files = {}
        for name in REQUIRED_NATIVE:
            (native / name).write_bytes(data)
            native_files[name] = hashlib.sha256(data).hexdigest()
        native_manifest = json.dumps(
            {
                "contract_version": "fixture",
                "files": native_files,
                "sources": {
                    "generated/" + name: hashlib.sha256((vendor / name).read_bytes()).hexdigest()
                    for name in ["manifest.json", *entries]
                },
            }
        ).encode()
        (native / "manifest.json").write_bytes(native_manifest)
        (root / "spec.lock.json").write_text(
            json.dumps(
                {
                    "repository": "https://github.com/stanimirivanov/kryvola-spec",
                    "contract_version": "fixture",
                    "revision": "a" * 40,
                    "artifact_root": "contracts/spec",
                    "manifest_sha256": hashlib.sha256(manifest).hexdigest(),
                    "native_artifact_root": "contracts/native",
                    "native_manifest_sha256": hashlib.sha256(native_manifest).hexdigest(),
                }
            ),
            encoding="utf-8",
        )
        (root / "pyproject.toml").write_text(
            '[project]\nname="fixture"\ndependencies=[]\n', encoding="utf-8"
        )
        (root / "Cargo.toml").write_text("[workspace]\nmembers=[]\n", encoding="utf-8")
        (root / "src").mkdir()
        (root / "src/sample.py").write_text("from pathlib import Path\n", encoding="utf-8")

    def test_valid_isolated_fixture_passes(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            verify_contracts(root)
            self.assertEqual(dependency_errors(root, "kryvola-ml"), [])

    def test_modified_contract_and_missing_inputs_fail(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            (root / "contracts/spec/data.txt").write_bytes(b"tampered")
            with self.assertRaisesRegex(ValueError, "modified generated artifact"):
                verify_contracts(root)
            (root / "spec.lock.json").unlink()
            with self.assertRaises(OSError):
                verify_contracts(root)

    def test_native_tampering_and_mixed_bundles_fail(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            native = root / "contracts/native"
            (native / "descriptor.bin").write_bytes(b"tampered")
            with self.assertRaisesRegex(ValueError, "modified native"):
                verify_contracts(root)
            (native / "descriptor.bin").write_bytes(b"fixture\n")
            path = native / "manifest.json"
            manifest = json.loads(path.read_bytes())
            manifest["sources"]["generated/limits.json"] = "0" * 64
            path.write_text(json.dumps(manifest), encoding="utf-8")
            lock = json.loads((root / "spec.lock.json").read_bytes())
            lock["native_manifest_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
            (root / "spec.lock.json").write_text(json.dumps(lock), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "mixed generated/native"):
                verify_contracts(root)

    def test_forbidden_import_reports_location_and_cli_fails(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            # Runtime repos reject foreign imports; platform rejects local source dependencies.
            from tools.architecture import REPO

            forbidden = "kryvola_ml" if REPO != "kryvola-ml" else "kryvola_engines"
            if REPO == "kryvola-platform":
                (root / "pyproject.toml").write_text(
                    '[project]\nname="fixture"\ndependencies=[]\n'
                    '[tool.uv.sources]\nhelper={path="../outside"}\n',
                    encoding="utf-8",
                )
            else:
                (root / "src/sample.py").write_text(f"import {forbidden}\n", encoding="utf-8")
            errors = dependency_errors(root, REPO)
            self.assertIn(
                "local source" if REPO == "kryvola-platform" else "sample.py:1", errors[0]
            )
            result = subprocess.run(
                [sys.executable, "tools/architecture.py", "--root", str(root)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "local source" if REPO == "kryvola-platform" else "forbidden implementation import",
                result.stderr,
            )

    def test_declared_dependency_boundaries(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            (root / "Cargo.toml").write_text(
                '[workspace]\nmembers=[]\n[workspace.dependencies]\nhelper={path="../outside"}\n',
                encoding="utf-8",
            )
            self.assertIn("escapes repository", dependency_errors(root, "kryvola-ml")[0])
            (root / "Cargo.toml").write_text("[workspace]\nmembers=[]\n", encoding="utf-8")
            from tools.architecture import REPO

            foreign = "Kryvola-ML" if REPO != "kryvola-ml" else "Kryvola-Engines"
            for dependency in [f"{foreign}==1.0.0", "helper@file:../outside"]:
                (root / "pyproject.toml").write_text(
                    f'[project]\nname="fixture"\ndependencies=["{dependency}"]\n', encoding="utf-8"
                )
                errors = dependency_errors(root, REPO)
                if REPO == "kryvola-platform" and dependency.startswith(foreign):
                    self.assertEqual(errors, [])
                else:
                    self.assertIn("forbidden implementation/local dependency", errors[0])


if __name__ == "__main__":
    unittest.main()
