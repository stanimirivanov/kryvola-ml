"""Verify a frozen public plaintext corpus or emit local benchmark instrumentation."""

import argparse
import hashlib
import json
import sys
import time
from importlib.resources import files
from importlib.resources.abc import Traversable
from pathlib import Path

from kryvola_ml.baseline import ReferenceCircuit, tiny_circuit

MANIFEST_SHA256 = "16268b514e2d8618113d439052975909dd8642bb3c374c1e6bf53a2d477bac21"
_NAMES = {"program.txt", "inputs.csv", "expected.csv", "LICENSE", "model-card.md"}
_AXIS = (0, 1, 2, 7, 15, 63, 127, 128, 254, 255)
_CASES = tuple((left, right) for left in _AXIS for right in _AXIS)
_RESOURCES = files("kryvola_ml")


class FixtureError(ValueError):
    """Fixed diagnostic with no input data or parser details."""


def _read(root: Traversable, name: str) -> bytes:
    with root.joinpath(name).open("rb") as stream:
        raw = stream.read(131_073)
    if len(raw) > 131_072:
        raise FixtureError("FIXTURE_REJECTED")
    return raw


def _csv(header: str, rows: tuple[tuple[int, ...], ...]) -> bytes:
    return (header + "\n" + "".join(",".join(map(str, row)) + "\n" for row in rows)).encode("ascii")


def _program(circuit: ReferenceCircuit) -> bytes:
    return (
        f"dtype {circuit.dtype}\ninputs {circuit.input_count}\nconstants "
        + " ".join(map(str, circuit.constants))
        + "\n"
        + "".join(f"{op.operator} {op.left} {op.right}\n" for op in circuit.operations)
        + "outputs "
        + " ".join(map(str, circuit.outputs))
        + "\noverflow WRAP\nfractional_bits 0\n"
    ).encode("ascii")


def _load(root: Traversable | None) -> tuple[ReferenceCircuit, dict[str, bytes]]:
    root = root if root is not None else _RESOURCES.joinpath("_fixtures/fhe-q1")
    if {item.name for item in root.iterdir()} != _NAMES | {"manifest.json"}:
        raise FixtureError("FIXTURE_REJECTED")
    raw = _read(root, "manifest.json")
    if hashlib.sha256(raw).hexdigest() != MANIFEST_SHA256:
        raise FixtureError("FIXTURE_REJECTED")
    manifest = json.loads(raw)
    if set(manifest["files"]) != _NAMES:
        raise FixtureError("FIXTURE_REJECTED")
    data = {name: _read(root, name) for name in sorted(_NAMES)}
    if any(
        hashlib.sha256(raw).hexdigest() != manifest["files"][name] for name, raw in data.items()
    ):
        raise FixtureError("FIXTURE_REJECTED")
    # The synthetic descriptor supplies structural vocabulary, never an engine binding.
    model = json.loads(_RESOURCES.joinpath("_spec/fixtures/profiles/model.json").read_bytes())
    model["workload"]["operators"] = ["ADD", "MUL"]
    circuit = tiny_circuit(model)
    if data["program.txt"] != _program(circuit) or data["inputs.csv"] != _csv("x0,x1", _CASES):
        raise FixtureError("FIXTURE_REJECTED")
    return circuit, data


def verify_fixture(root: Traversable | None = None) -> dict[str, object]:
    circuit, data = _load(root)
    reproduced = _csv("y0,y1", tuple(circuit.evaluate(pair) for pair in _CASES))
    if reproduced != data["expected.csv"]:
        raise FixtureError("REFERENCE_MISMATCH")
    return {
        "fixture": "FHE-Q1-uint8-v1",
        "cases": len(_CASES),
        "integer_mismatches": 0,
        "manifest_sha256": MANIFEST_SHA256,
        "qualification": "PLAINTEXT_ONLY",
    }


def benchmark_one(request: bytes, root: Traversable | None = None) -> dict[str, dict[str, int]]:
    start = time.perf_counter_ns()
    if type(request) is not bytes or not 2 <= len(request) <= 3:
        raise FixtureError("INVALID_REQUEST")
    try:
        index = int(request)
    except ValueError:
        raise FixtureError("INVALID_REQUEST") from None
    if request != f"{index}\n".encode("ascii") or not 0 <= index < len(_CASES):
        raise FixtureError("INVALID_REQUEST")
    decoded = time.perf_counter_ns()
    circuit, data = _load(root)
    loaded = time.perf_counter_ns()
    output = circuit.evaluate(_CASES[index])
    evaluated = time.perf_counter_ns()
    expected_line = data["expected.csv"].splitlines()[index + 1]
    if ",".join(map(str, output)).encode("ascii") != expected_line:
        raise FixtureError("REFERENCE_MISMATCH")
    return {
        "stages_ns": {
            "decode": decoded - start,
            "manifest_verify": loaded - decoded,
            "evaluate": evaluated - loaded,
            "verify": time.perf_counter_ns() - evaluated,
        }
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["verify", "benchmark"])
    parser.add_argument(
        "--root",
        type=Path,
        help="explicit repository fixture directory; installed wheel needs no override",
    )
    args = parser.parse_args()
    try:
        result = (
            verify_fixture(args.root)
            if args.action == "verify"
            else benchmark_one(sys.stdin.buffer.read(4), args.root)
        )
    except OSError, ValueError, KeyError, TypeError:
        parser.exit(1, "FHE_Q1_FIXTURE_REJECTED\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
