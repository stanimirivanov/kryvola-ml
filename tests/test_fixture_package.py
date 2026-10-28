"""Frozen bytes are independently pinned; tests never regenerate expected files."""

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from kryvola_ml.baseline import Operation, ReferenceCircuit
from kryvola_ml.baseline.fixture import FixtureError, benchmark_one, verify_fixture

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures/fhe-q1"


class FixtureTests(unittest.TestCase):
    def test_reproduction_and_independent_oracle(self):
        first = verify_fixture(FIXTURE)
        self.assertEqual(first, verify_fixture(FIXTURE))
        self.assertEqual((first["cases"], first["integer_mismatches"]), (100, 0))
        inputs = [
            tuple(map(int, line.split(",")))
            for line in (FIXTURE / "inputs.csv").read_text().splitlines()[1:]
        ]
        expected = (
            "y0,y1\n"
            + "".join(f"{(3 * x + 5 * y + 7) % 256},{(x * y + 11) % 256}\n" for x, y in inputs)
        ).encode("ascii")
        self.assertEqual(expected, (FIXTURE / "expected.csv").read_bytes())
        self.assertEqual(len(set(inputs)), 100)

    def test_altered_files_missing_and_rehashed_manifest_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            copy = Path(directory) / "fixture"
            shutil.copytree(FIXTURE, copy)
            for name in ("inputs.csv", "expected.csv", "program.txt", "LICENSE", "model-card.md"):
                path = copy / name
                original = path.read_bytes()
                path.write_bytes(original + b"\n")
                with self.subTest(name=name), self.assertRaises(FixtureError):
                    verify_fixture(copy)
                path.write_bytes(original)
            (copy / "inputs.csv").write_bytes(b"x0,x1\n0,0\n")
            manifest = json.loads((copy / "manifest.json").read_bytes())
            manifest["files"]["inputs.csv"] = hashlib.sha256(
                (copy / "inputs.csv").read_bytes()
            ).hexdigest()
            (copy / "manifest.json").write_text(json.dumps(manifest))
            with self.assertRaises(FixtureError):
                verify_fixture(copy)
            (copy / "manifest.json").write_bytes((FIXTURE / "manifest.json").read_bytes())
            (copy / "inputs.csv").unlink()
            with self.assertRaises(FixtureError):
                verify_fixture(copy)

    def test_changed_interpreter_semantics_fail(self):
        changed = ReferenceCircuit("uint8", 2, (), (Operation("ADD", 0, 1),), (2,))
        with patch("kryvola_ml.baseline.fixture.tiny_circuit", return_value=changed):
            with self.assertRaisesRegex(FixtureError, "FIXTURE_REJECTED"):
                verify_fixture(FIXTURE)
        with patch.object(ReferenceCircuit, "evaluate", return_value=(0, 0)):
            with self.assertRaisesRegex(FixtureError, "REFERENCE_MISMATCH"):
                verify_fixture(FIXTURE)
            with self.assertRaisesRegex(FixtureError, "REFERENCE_MISMATCH"):
                benchmark_one(b"0\n", FIXTURE)

    def test_adapter_bounds_and_telemetry(self):
        for request in (b"0\n", b"99\n"):
            stages = benchmark_one(request, FIXTURE)["stages_ns"]
            self.assertEqual(set(stages), {"decode", "manifest_verify", "evaluate", "verify"})
            self.assertTrue(all(type(ns) is int and ns >= 0 for ns in stages.values()))
        for request in (b"", b"0", b"00\n", b"-1\n", b"+1\n", b"100\n", b"1 \n", b"x\n"):
            with (
                self.subTest(request=request),
                self.assertRaisesRegex(FixtureError, "INVALID_REQUEST"),
            ):
                benchmark_one(request, FIXTURE)

    def test_cli_protocol_and_safe_failure(self):
        command = [
            sys.executable,
            "-m",
            "kryvola_ml.baseline.fixture",
            "benchmark",
            "--root",
            str(FIXTURE),
        ]
        good = subprocess.run(command, input=b"0\n", capture_output=True, check=True, timeout=10)
        self.assertEqual(set(json.loads(good.stdout)), {"stages_ns"})
        bad = subprocess.run(command, input=b"private-not-logged", capture_output=True, timeout=10)
        self.assertNotEqual(bad.returncode, 0)
        self.assertEqual(bad.stdout, b"")
        self.assertEqual(bad.stderr.replace(b"\r\n", b"\n"), b"FHE_Q1_FIXTURE_REJECTED\n")
