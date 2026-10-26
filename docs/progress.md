# Foundation progress

Issue: #1. Scope: initial M0 repository scaffold, 25 October 2026.

- Implemented: python owner sdk contract and planner boundaries, versioned spec consumption, isolated architecture controls and diagnostics.
- Verified locally: frozen setup, full foundation checks, isolated negative controls, package/native builds and diagnostics.
- Configured but unverified remotely: the GitHub Actions workflow; branch protection/required checks remain maintainer configuration.
- Not claimed: complete M0 acceptance, full Engine API interoperability, cryptographic feasibility, latency measurements, independent security review or deployment.
- Deferred: later roadmap runtime/crypto features. A disabled capability is an explicit incomplete milestone, not an alternate implementation.
- Next: KRY-009 a measured approved quantized model/profile, then KRY-013/014/015 owner crypto and SDK lifecycle.

The authoritative [plan](https://github.com/stanimirivanov/kryvola-spec/blob/647986b9ba9cb2c6d3b853046272e3869b6fea5e/docs/kryvola-implementation-plan-v2.md) remains in force. Review and update only the affected roadmap evidence; no later milestone is marked complete by this scaffold.

## Observed acceptance evidence

On Windows with Python 3.14.7 / uv 0.12.5, `uv run --locked python tools/verify.py full` passed: Ruff formatting/lint, ty type checks, spec provenance and dependency checks, 8 Python tests, and Effect-generated JSON Schema validation, strict negative cases and Python wheel build.

A new disposable environment passed `uv sync --locked --no-editable`. The installed wheel loaded from that environment rather than the source checkout, and its packaged data/diagnostic worked. Diagnostics: `uv run --locked python -m kryvola_ml`.

Root AGENTS.md discovery through nested working directories and local documentation links were checked. Existing LICENSE bytes are unchanged. Schema source commit and manifest digests are recorded in `spec.lock.json`; no sibling checkout is required.

Blocked foundation work: none. Deferred roadmap items and remote CI/maintainer settings above remain explicit; this evidence does not qualify a production crypto engine, state machine or deployment.

Final harness-only normalization of package names and direct local URI dependencies was verified with Ruff, ty and the Python suite. Native code and package runtime content were unchanged after their passing build/clean-install checks.
