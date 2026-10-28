"""CI-only wheel resource and isolated import check; no source checkout on sys.path."""

import json
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[1]
wheel = max((ROOT / "dist").glob("*.whl"), key=lambda path: path.stat().st_mtime_ns)
with ZipFile(wheel) as archive:
    for folder in ("_spec", "_wire"):
        source = ROOT / "src/kryvola_ml" / folder
        manifest = json.loads((source / "manifest.json").read_bytes())
        for name in ["manifest.json", *manifest["files"]]:
            assert archive.read(f"kryvola_ml/{folder}/{name}") == (source / name).read_bytes()
    fixture = ROOT / "fixtures/fhe-q1"
    for path in fixture.iterdir():
        assert archive.read(f"kryvola_ml/_fixtures/fhe-q1/{path.name}") == path.read_bytes()
SMOKE = """import json, sys
sys.path.insert(0, sys.argv[1])
import kryvola_ml
assert sys.argv[1] in kryvola_ml.__file__
from importlib.resources import files
from kryvola_ml.sdk.contracts import decode_control, validate_contract, validate_artifact_ref
root = files('kryvola_ml')
for vector in json.loads(root.joinpath('_wire/vectors.json').read_bytes()):
    assert decode_control(vector['type'], bytes.fromhex(vector['wire'])) == vector['value']
for name, path in [('ModelDescriptor', 'model'), ('MeasurementReport', 'measurement'),
                   ('ReleaseCandidate', 'release')]:
    fixture = root.joinpath('_spec/fixtures/profiles/'+path+'.json')
    validate_contract(name, json.loads(fixture.read_bytes()))
validate_artifact_ref(json.loads(root.joinpath('_spec/fixtures/artifact-ref.json').read_bytes()))
from kryvola_ml.baseline import tiny_circuit
model = json.loads(root.joinpath('_spec/fixtures/profiles/model.json').read_bytes())
model['workload']['operators'] = ['ADD', 'MUL']
assert tiny_circuit(model).evaluate((255, 255)) == (255, 12)
from kryvola_ml.baseline.fixture import verify_fixture, benchmark_one
assert verify_fixture()['cases'] == 100
assert set(benchmark_one(b'0\\n')) == {'stages_ns'}
"""
with TemporaryDirectory() as directory:
    subprocess.run(
        [sys.executable, "-I", "-c", SMOKE, str(wheel)], cwd=directory, check=True, timeout=60
    )
