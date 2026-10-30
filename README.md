# kryvola-ml

Python owner SDK contract and planner boundaries. This is an initial M0 foundation, with no production execution or security qualification. Existing Apache-2.0 licensing is preserved.

## Setup and verification

Prerequisites: Python 3.14.7 and uv 0.12.5. Python is pinned in `.python-version`; Rust is pinned in `rust-toolchain.toml` where applicable. Run from this repository root:

```sh
uv sync --locked
uv run --locked python tools/verify.py fast
uv run --locked python tools/verify.py full
uv run --locked python -m kryvola_ml
```

`fast` runs formatting/lint/type/provenance/dependency checks. `full` adds isolated positive/negative controls, contract tests and a wheel build. Missing tools or files fail the command. Apply Python formatting with `uv run --locked ruff format .` and lint fixes with `uv run --locked ruff check --fix .`; rerun affected checks after changes.

No service credentials or local databases are required for this scope. `spec.lock.json` pins immutable generated spec artifacts; a sibling checkout is unnecessary. Generated structural types are not native decoders or authorization. [Architecture and enforcement](docs/architecture.md), [progress](docs/progress.md), and the source references below describe limits.

## Contract previews (M0-PR16)

`kryvola_ml.sdk.contracts.validate_contract(kind, mapping)` validates an owned copy
against the published structural schemas. Supported kinds are the 17 native control
and Engine API records, plus `AssuranceProfile`, `AssuranceRequest`,
`ConsentDeclaration`, `ModelDescriptor`, `MeasurementReport` and `ReleaseCandidate`.
`validate_artifact_ref(mapping)` retains its existing signature, return type and errors.

`decode_control(kind, payload)` decodes immutable Protobuf bytes up to 65,536 bytes
using the pinned descriptor set. It rejects unknown fields recursively before
returning generated-schema-validated metadata. Ordinary Protobuf order/merge
semantics apply; this is not a canonical signing format. New entry points raise
`ContractError` with `INVALID_CONTRACT` or `CONTROL_TOO_LARGE`, without parser
diagnostics or exception chains. Avoid logging caller-supplied metadata.

The spec preview.10 bundles are pinned at
[`1a5b57a`](https://github.com/stanimirivanov/kryvola-spec/tree/1a5b57a590487ba116913050af8041f5e5f1fb52).
Both bundles ship inside the wheel; the pinned Protobuf runtime supplies decoding.
These are **structural** previews. Cross-field/cross-record consistency, exact-file
hash bindings, tenant authorization, fencing/deadline checks, evidence policy,
and release qualification still require the owning spec/runtime gates. A synthetic
model or measurement fixture cannot enable a profile or establish crypto feasibility.
No async inference method, planner behavior, key handling or network client is added.

The full harness builds a wheel, compares its packaged artifacts byte for byte,
and exercises imports and golden decoding from the wheel in an isolated process.
Run this heavier gate on CI: `uv run --locked python tools/verify.py full`.

## Authoritative context

- [Design v2](https://github.com/stanimirivanov/kryvola-spec/blob/647986b9ba9cb2c6d3b853046272e3869b6fea5e/docs/kryvola-design-v2.md)
- [Implementation plan v2](https://github.com/stanimirivanov/kryvola-spec/blob/647986b9ba9cb2c6d3b853046272e3869b6fea5e/docs/kryvola-implementation-plan-v2.md)
- [Schema-stack amendment](https://github.com/stanimirivanov/kryvola-spec/blob/647986b9ba9cb2c6d3b853046272e3869b6fea5e/docs/adr/0001-schema-authoring.md): Redocly for OpenAPI; Effect v4 / TypeScript 7 author other contracts. Generated JSON/native structural projections keep this repository's approved runtime intact.

The owner domain retains private keys. SDK/planner code consumes released spec contracts and packaged owner bindings, never fabric/engine internal source. The planner must reject unsupported trust/precision/evidence requirements; it remains unimplemented.

The [deterministic plaintext reference](docs/baseline.md) implements bounded
unsigned ADD/MUL circuits with explicit modular overflow. Its public example and
synthetic tests do not qualify a model or enable a profile. The separate
[frozen public workload](docs/model-card.md) packages 100 reproducible uint8 cases,
expected outputs, program/license bytes and a plaintext benchmark adapter.

Next planned work: KRY-009 a measured approved quantized model/profile, then KRY-013/014/015 owner crypto and SDK lifecycle.

[Experimental baseline publication](docs/publication.md) documents qualified
source-addressed wheels, manual publishing and independently pinned verification.
