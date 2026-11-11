# Encrypted SDK submission

Run the SDK inside the trusted owner environment. Install and qualify the
published `kryvola-owner==0.1.0.dev2` wheel there. The SDK consumes its public
opaque key interface. An existing restored `OwnerKey` can be supplied, or
`sdk.owner.installed_owner()` creates a new key from the pinned installed
binding. Retain the existing owner custody workflow for key persistence.

Call `sdk.submission.prepare_submission` with that owner handle, an approval
provider, the reviewed model descriptor, operation metadata, canonical key
context, consent and exactly two uint8 input bytes. Set
`assurance="CONFIDENTIALITY_ONLY"`. The operation supplies stable tenant, job,
operation and idempotency identifiers. Its key-context reference must commit
to the exact supplied context. The SDK checks the evaluation key against the
context, encrypts the input once, constructs immutable manifests and compiles
the fixed plan. The compiled plan digest fills the operation's plan reference.

The approval provider receives the compiled plan bytes and operation snapshot.
It must obtain independent owner approval and return the signed canonical v3
bundle with `approval`, `envelope`, and `assurance`. `sdk.owner.OwnerAgent`
adapts the published owner agent's `approve` and `verify-approval` commands.
Provision its reviewed slot policy and plan through the owner workflow before
using it. The SDK does not generate approval policy or signing keys. Fabric
verifies the signature and current approval authority at admission.

Preparation returns a frozen `PreparedSubmission` containing encrypted artifacts
and immutable metadata bytes. Keep this same snapshot across delivery attempts.
The snapshot's representation excludes artifact contents. Preparation may be
expensive and may request owner review, so call it once before delivery.

Configure `sdk.client.Client` with the Fabric host and port, a workload TLS
context and exact server SPIFFE URI, and a credential provider accepting an
action and target object. The TLS context must require certificate validation
and load the owner workload certificate and trust roots. For URI-SAN workload
certificates, disable DNS hostname checking in the context. The client checks
the exact Fabric URI SAN before sending the credential. The credential
provider supplies the operator-authorized submission grant for that exact
action and target. Credentials remain in the Authorization header.

Call `sdk.submission.submit(client, prepared)` to register the key context,
upload and finalize both inputs, register the signed approval, and admit the
operation. Binary data uses the dedicated part routes and bounded manifest
routes. Admission carries the exact approval and manifest references. The
server's returned bindings are checked before proceeding.

`SubmissionUnavailable` permits another delivery attempt using the same
snapshot. `RateLimited` signals HTTP 429. Apply caller-controlled backoff and
retry the original snapshot. `OwnerUnavailable` and `UnsupportedAssurance`
identify failures before admission. Other rejected input or server responses
raise `SubmissionError` with a fixed code. No automatic re-encryption occurs
when a submission response is lost. The caller must retain the prepared bytes
for the lifetime of its retries, including after a process restart.

The SDK test uses a recorded workload TLS server that loses the first admitted
operation response. It checks exact repeated admission, stable upload IDs,
reference-only control payloads, one encryption call and typed failures. The
approval provider and encryption in that test are controlled fixtures. Native
binding and owner-agent qualification remain separate gates.
