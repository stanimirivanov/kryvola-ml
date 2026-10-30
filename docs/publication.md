# Experimental baseline wheel publication

The manual main-only `.github/workflows/release.yml` publishes the existing ML
baseline wheel. It supplies an M0 artifact, not an owner SDK, native crypto binding,
profile activation or specialist approval. Legal/security decisions stay pending.

Qualification follows the existing fabric publisher: two copies of tracked clean
source build with SOURCE_DATE_EPOCH and staged source-addressed PEP 440 versions.
It compares wheel hashes, checks installed resources and reproduces the public
100-case fixture in isolation. Committed package metadata and locks stay unchanged.
This demonstrates repeatability within the declared environment, not independent
compiler or cross-platform reproducibility.

```sh
uv sync --locked
uv run --locked python tools/install_release.py
uv run --locked python tools/verify.py full
# Clean committed checkout and fresh ignored build/publication required:
uv run --locked python tools/release.py qualify
```

The explicit Linux x64 installer pins Cosign 3.1.3 and Syft 1.55.0 checksums; both
are Apache-2.0 build tools, not application dependencies. The SPDX wheel scan and
lock do not claim a complete installed dependency SBOM or legal clearance.
In-toto/SLSA-shaped provenance binds wheel, source, lock, contract/native manifests
and fixture identity; no SLSA level is claimed. Real ephemeral signatures exercise
wrong-key and altered-manifest rejection. Test keys and signatures are excluded.

Full CI retains offline tests and ordinary wheel checks. The separate manual
publisher additionally qualifies two builds and actual signatures, then signs
keylessly with GitHub OIDC. Only its publish job gets contents-write/OIDC. It
verifies exact workflow, issuer, source and dispatch trigger before uploading a
fresh draft experimental-FULL_SHA prerelease. Existing tags/releases are refused;
failed drafts require maintainer inspection. Server-enforced immutability and
branch protection remain maintainer settings. No push or PR publishes assets.

Consumers independently select the source, download the release assets and run:

```sh
uv run --locked python tools/release.py verify --folder DOWNLOADED_ASSETS --source FULL_COMMIT_SHA
```

Install the pinned verifier first. Publication verification does not expose a
caller-selected-key mode. Hashes, tags and package-supplied keys cannot establish
trust. Consumer admission must pin expected wheel/manifest bytes and dependency
locks separately. Re-run verification at use; publish withdrawal/supersession
records instead of replacing existing versions.
