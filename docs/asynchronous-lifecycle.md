# Asynchronous SDK lifecycle

Use `kryvola_ml.sdk.lifecycle.Lifecycle` with the same TLS `Client` used for
submission and the exact admitted operation metadata returned by `submit`.
Construction copies that metadata. Recreate the handle from the same metadata
after reconnecting; it creates no replacement operation, workflow or attempt.
A response with changed immutable bindings or workflow epoch is rejected.
Follow the authorized recovery workflow before adopting a successor operation.

```python
from kryvola_ml.sdk.lifecycle import Lifecycle, State

run = Lifecycle(client, admitted["operation"], assurance="CONFIDENTIALITY_ONLY")
observation = run.inspect()
# Inside an async function:
observation = await run.wait(timeout=30, poll_interval=0.5)
if observation.state == State.RELEASED:
    encrypted = run.fetch(exact_release_read_scope)
```

`inspect()` performs one bounded GET. `wait()` runs these requests outside the
async event loop and retries only transient unavailability and rate limits
until its caller-specified deadline (at most 300 seconds). It returns on release
or a terminal failure. Deadline expiry raises `TimeoutError`; cancelling the
Python await cancels observation, not the durable compute operation. A request
already running in the worker thread can finish within the client's transport
timeout. A new `wait()` resumes observation without changing identity.

The SDK exposes the public states separately:

| State | Meaning for the SDK caller |
|---|---|
| `RUNNING` | Fabric returned null: no public outcome is recorded yet. This does not prove a worker is running. |
| `COMPUTE_SELECTED` | One result is selected; it is not authorized for download or plaintext opening. |
| `EVIDENCE_PENDING` | Evidence remains pending. |
| `EVIDENCE_VERIFIED` | Evidence status is verified; output is still unreleased. |
| `RELEASED` | Release status is recorded; each read and opening still needs current authorization. |
| `EVIDENCE_FAILED`, `CANCELLED`, `EXPIRED` | Terminal failure for observation. |

These are observations, not local evidence verification or a plaintext result.
`Observation.terminal` describes the three terminal failure states. Release
causes `wait()` to return but can still be revoked or fenced before a read.
Only the fixed `CONFIDENTIALITY_ONLY` assurance is supported; requesting a
proof/stronger assurance raises `UnsupportedAssurance` before any request.

Call `run.cancel(stable_cancellation_key)` to request durable cancellation.
Retain that same key across response loss and reconnects. A handle rejects a
second key. The returned `Cancellation` preserves `CANCELLATION_PENDING`
without a fence, or committed `CANCELLED` with its fence. Pending does not
change an observation into cancelled. Repeated requests with the same key
let Fabric reconcile a lost acknowledgement. Cancellation grant providers
receive action `CANCEL_OPERATION`; inspect uses `GET_OPERATION`. Their target
is the exact registry scope (tenant, operation, workflow epoch, null attempt
and fence). These are operator-provisioned grants, not credentials issued by
this SDK.

## Authorized fetch and local opening

`OperationResponse` publishes status only. Obtain the exact
`ReadReleasedOutputRequest` from the trusted release workflow: tenant, stable
disclosure ID, recipient and output manifest digest. The SDK checks that the
scope matches the operation's disclosure identity and that a fresh inspection
is released. Fabric remains authoritative for current release eligibility.
The TLS credential provider receives `CONSUMER_READ` with a target containing
`scope` and `part_index` (null for the manifest). Supply a fresh single-use
grant for every request, including retries. Direct storage URLs, redirects,
compressed/partial responses and incorrect lengths are rejected.

`fetch(scope)` obtains a complete encrypted result within the native pair
limit. It verifies the canonical manifest commitment, tenant/key context,
fixed codec/profile, contiguous chunk offsets/lengths/digests and full blob
commitment. A failed read returns no `FetchedOutput`. Repeat the same exact
scope after a lost response; download does not select or release anything.
`FetchedOutput` excludes its encrypted contents from its representation.

For local opening, provision the published Fabric owner workflow first:
[owner-agent inputs and protocol](https://github.com/stanimirivanov/kryvola-fabric/blob/main/docs/local-result-opening.md).
The owner root must be an absolute resolved owner-only directory (0700).
Provision signed approval/release, reviewed opening policy, custody and
workload TLS files there. The SDK does not generate those authorities.

```python
from pathlib import Path
from kryvola_ml.sdk.owner import ResultOpener

opener = ResultOpener(
    Path("/opt/kryvola/bin/kryvola-owner-agent"),
    Path("/home/owner/private-custody"),
    Path("/opt/kryvola-owner/bin/python"),
    "result-slot",
    fresh_manifest_credential,  # accepts the exact read scope; returns one fresh bearer
)
plaintext_pair = run.open_result(exact_release_read_scope, opener)
```

Opening fetches encrypted bytes, checks the provisioned release scope, and
publishes `SLOT.ciphertext` atomically with mode 0600, without replacing an
existing file. Repeated delivery must match its existing bytes. Use a separate
reviewed slot for a different output. A crash before publication may leave a
private temporary ciphertext file; it confers no authority. The bridge passes
a fresh manifest bearer through a same-UID Unix stream to the bounded local
agent command. No bearer or plaintext is placed in command arguments or logs.
The agent independently verifies signatures, current release and approval,
live manifest authorization, custody, and native bindings before returning
exactly two uint8 bytes. Owner failures raise fixed `OwnerUnavailable`.

The ML gate exercises real workload TLS and the real Unix socket handoff with
controlled server/owner-command fixtures. It does not requalify CPU TFHE,
Secret Service custody or native signature enforcement; those remain the
Fabric/Engines qualification gates. There is no release-document discovery
endpoint in the current public operation response.
