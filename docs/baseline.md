# Deterministic plaintext integer reference (M0-PR27)

`kryvola_ml.baseline.ReferenceCircuit.from_descriptor` consumes the packaged spec
preview.10 `ModelDescriptor` through the existing structural validator. It accepts
FHE-Q1 unsigned `uint8`, `uint16`, `uint32`, `uint64`, `EXACT_MODULAR`, zero
fractional bits and `WRAP` overflow. The declared operator set must exactly match
the local program; duplicate declarations are rejected. No dependency is added.

The local Python API uses frozen `Operation(operator, left, right)` values and
tuples of public constants/operations/output indices. Registers are numbered from
zero: inputs first, then constants, then one appended result per operation.
Operands may reference only earlier registers, preventing cycles/forward reads.
Limits are 1–16 inputs/outputs, 0–32 constants and 1–64 operations. The descriptor
must declare one-dimensional shapes matching the actual input/output counts.
These Python values are an internal reference API, not a new wire/fixture schema.

Inputs/constants must be exact Python integers in `[0, 2**width - 1]`; booleans,
floats, signed/out-of-range values and implicit coercions are rejected. Evaluation
accepts a tuple and returns an ordered tuple. ADD and MUL explicitly mask **every
intermediate result** to the selected width. Python's unbounded intermediates are
used only to compute this specified modular result. Fractional quantization and
rounding never occur; comparison, argmax, division, signed reinterpretation and
saturation are unsupported and rejected, with no fallback operator behavior.

`tiny_circuit(descriptor)` provides a public two-input/two-output example:

```text
y0 = (3*x0 + 5*x1 + 7) mod 2**width
y1 = (x0*x1 + 11) mod 2**width
```

It executes three ADDs and three MULs, including intermediate wrapping. It is an
integer circuit rather than a trained classifier; its outputs are not labels.
For uint8, `(0, 0)` produces `(7, 11)` and `(255, 255)` produces `(255, 12)`.
Golden examples and an independent unbounded-polynomial oracle test all widths,
range/overflow boundaries, invalid graphs, descriptor mismatches and repeatability.
The circuit retains no mutable descriptor data and performs no logging/I/O.

Run `uv run --locked python -m unittest discover -s tests -p test_baseline.py -v`
and `uv run --locked python tools/verify.py fast` locally. The full CI gate
`uv run --locked python tools/verify.py full` also imports/executes the reference
from the built wheel in isolation. No heavy benchmark is required for this slice.

Descriptor validation here is structural plus local arithmetic/shape checks;
artifact/model/program/dataset digest bindings are not verified. Synthetic test
metadata is not release evidence. M0-PR28 owns the frozen public workload,
dataset/license/model card, exact program/fixture hashes and benchmark adapter.
No training/importer, private weights, crypto execution, accuracy claim, planner,
MeasurementReport or profile activation is supplied by this reference.
