"""Offline publication controls; full CI exercises actual builds and signatures."""

import copy
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from zipfile import ZipFile

from tools import release

SOURCE = "a" * 40


class ReleaseTests(unittest.TestCase):
    def fixture(self, folder):
        wheel = f"kryvola_ml-{release.version(SOURCE)}-py3-none-any.whl"
        for name in ("LICENSE", "uv.lock", "sbom.spdx.json"):
            (folder / name).write_bytes(b"public-fixture")
        with ZipFile(folder / wheel, "w") as archive:
            archive.writestr(
                f"kryvola_ml-{release.version(SOURCE)}.dist-info/METADATA",
                f"Name: kryvola-ml\nVersion: {release.version(SOURCE)}\n",
            )
        release.write(
            folder / "provenance.json",
            {
                "_type": "https://in-toto.io/Statement/v1",
                "predicateType": "https://slsa.dev/provenance/v1",
                "subject": [{"name": wheel, "digest": {"sha256": release.sha(folder / wheel)}}],
                "predicate": {
                    "buildDefinition": {
                        "externalParameters": {
                            "repository": release.REPOSITORY,
                            "ref": SOURCE,
                            "version": release.version(SOURCE),
                        }
                    },
                    "runDetails": {
                        "builder": {"id": release.IDENTITY.removeprefix("https://github.com/")}
                    },
                },
            },
        )
        manifest = {
            "schema_version": "ml-publication-v1",
            "source": SOURCE,
            "version": release.version(SOURCE),
            "distribution": "EXPERIMENTAL_BASELINE_ONLY",
            "production_ready": False,
            "subjects": {
                name: release.sha(folder / name)
                for name in (wheel, "LICENSE", "uv.lock", "sbom.spdx.json", "provenance.json")
            },
        }
        release.write(folder / "manifest.json", manifest)
        return manifest

    def test_source_version_and_manifest_controls(self):
        for source in (None, "main", "A" * 40, "a" * 39):
            with self.assertRaises(ValueError):
                release.version(source)
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            manifest = self.fixture(folder)
            self.assertEqual(release.validate(folder, SOURCE), manifest)
            for field, value in (
                ("source", "b" * 40),
                ("version", "0.1.0"),
                ("production_ready", 0),
                ("distribution", "PRODUCTION"),
            ):
                bad = copy.deepcopy(manifest)
                bad[field] = value
                release.write(folder / "manifest.json", bad)
                with self.assertRaises(ValueError):
                    release.validate(folder, SOURCE)
            release.write(folder / "manifest.json", manifest)
            (folder / "unexpected.key").write_text("not a real key")
            with self.assertRaises(ValueError):
                release.validate(folder, SOURCE)

    def test_every_subject_tamper_missing_and_duplicate_json(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            manifest = self.fixture(folder)
            for name in manifest["subjects"]:
                path = folder / name
                original = path.read_bytes()
                path.write_bytes(original + b"tampered")
                with self.assertRaises(ValueError):
                    release.validate(folder, SOURCE)
                path.unlink()
                with self.assertRaises(ValueError):
                    release.validate(folder, SOURCE)
                path.write_bytes(original)
            (folder / "manifest.json").write_text('{"source":"a","source":"b"}')
            with self.assertRaisesRegex(ValueError, "DUPLICATE_RELEASE_KEY"):
                release.validate(folder, SOURCE)

    def test_publish_verifier_pins_identity_and_propagates_signature_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            self.fixture(folder)
            with (
                patch.object(release, "tool", return_value="cosign"),
                patch.object(release, "run") as run,
            ):
                release.verify(folder, SOURCE)
                args = run.call_args.args
                self.assertEqual(args[args.index("--certificate-identity") + 1], release.IDENTITY)
                self.assertEqual(args[args.index("--certificate-github-workflow-sha") + 1], SOURCE)
                self.assertNotIn("--insecure-ignore-tlog", args)
                run.side_effect = subprocess.CalledProcessError(1, "cosign")
                with self.assertRaises(subprocess.CalledProcessError):
                    release.verify(folder, SOURCE)

    def test_dirty_source_prevents_build(self):
        with patch.object(release, "git", side_effect=[SOURCE, " M pyproject.toml"]):
            with self.assertRaisesRegex(ValueError, "CLEAN_PINNED_SOURCE_REQUIRED"):
                release.build()

    def test_installed_wheel_rejects_each_missing_resource_family(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage = root / "stage"
            stage.mkdir()
            for name in ("src", "fixtures"):
                shutil.copytree(
                    release.ROOT / name, stage / name, ignore=shutil.ignore_patterns("__pycache__")
                )
            for name in ("pyproject.toml", "LICENSE", "README.md"):
                shutil.copyfile(release.ROOT / name, stage / name)
            subprocess.run(
                [sys.executable, "-m", "hatchling", "build", "-t", "wheel"],
                cwd=stage,
                check=True,
                capture_output=True,
            )
            wheel = next((stage / "dist").glob("*.whl"))
            for resource in ("_spec", "_wire", "_fixtures"):
                broken = root / f"missing-{resource}.whl"
                with ZipFile(wheel) as original, ZipFile(broken, "w") as target:
                    for entry in original.infolist():
                        if not entry.filename.startswith(f"kryvola_ml/{resource}/"):
                            target.writestr(entry, original.read(entry))
                result = subprocess.run(
                    [sys.executable, release.ROOT / "tools/check_wheel.py", "--wheel", broken],
                    capture_output=True,
                    timeout=60,
                )
                self.assertNotEqual(result.returncode, 0, resource)

    def test_provenance_and_builder_substitution_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            manifest = self.fixture(folder)
            provenance = release.read(folder / "provenance.json")
            provenance["predicate"]["buildDefinition"]["externalParameters"]["ref"] = "b" * 40
            release.write(folder / "provenance.json", provenance)
            manifest["subjects"]["provenance.json"] = release.sha(folder / "provenance.json")
            release.write(folder / "manifest.json", manifest)
            with self.assertRaisesRegex(ValueError, "RELEASE_PROVENANCE_MISMATCH"):
                release.validate(folder, SOURCE)
            self.fixture(folder)
            provenance = release.read(folder / "provenance.json")
            provenance["predicate"]["runDetails"]["builder"]["id"] = "wrong/publisher"
            release.write(folder / "provenance.json", provenance)
            manifest = release.read(folder / "manifest.json")
            manifest["subjects"]["provenance.json"] = release.sha(folder / "provenance.json")
            release.write(folder / "manifest.json", manifest)
            with (
                patch.object(release, "tool", return_value="cosign"),
                self.assertRaisesRegex(ValueError, "PUBLICATION_BUILDER_MISMATCH"),
            ):
                release.verify(folder, SOURCE)


if __name__ == "__main__":
    unittest.main()
