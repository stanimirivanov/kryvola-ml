# Frozen public FHE-Q1 plaintext workload

The versioned [model card](../fixtures/fhe-q1/model-card.md), exact byte
[manifest](../fixtures/fhe-q1/manifest.json), program, licensed inputs and expected
outputs live together under `fixtures/fhe-q1`. They are included unchanged in
the wheel at `kryvola_ml/_fixtures/fhe-q1`.

Reproduce from a checkout (the explicit root avoids relying on editable package
resource mapping):

```sh
uv run --locked python -m kryvola_ml.baseline.fixture verify --root fixtures/fhe-q1
```

Installed wheels support the same command without `--root`. Verification checks
the independently pinned manifest, all file bytes, the current baseline graph,
the deterministic input grid and reproduced output bytes; it never updates pins.

The `benchmark` action accepts exactly a canonical decimal case index 0–99 plus
LF on stdin, e.g. bytes `0\n`. It emits only M0-PR25 `stages_ns` instrumentation
(`decode`, `manifest_verify`, `evaluate`, `verify`). Each request evaluates one
public pair; manifest verification includes local file reads/hash/graph checks,
and evaluate measures plaintext arithmetic only. Every process verifies the
fixture anew; this adapter supplies no warm engine/cache guarantee.

Use the installed ML environment's **absolute Python executable** and
`-m kryvola_ml.baseline.fixture benchmark` in the platform runner command array.
For checkout development add `--root` with an **absolute** fixture directory.
Pin both ML code and the manifest in operator-supplied software metadata; match
the four stage names and hash the exact request bytes. No sibling import or new
dependency is required. Platform still requires its generated ModelDescriptor
metadata: actual engine/parameter bindings must be supplied by later feasibility
work. This fixture publishes no fabricated engine descriptor or qualified report.
