"""Prepare encryption once, then deliver exact approved submission snapshots."""

import json
from base64 import urlsafe_b64encode
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from importlib.resources import files
from typing import Protocol

from blake3 import blake3

from .client import (
    OwnerUnavailable,
    SubmissionError,
    UnsupportedAssurance,
    canonical,
)
from .contracts import ContractError, validate_contract

PAIR_MAX = 2 * ((1 << 20) + 8)
KEY_MAX = 65 << 20
CHUNK_MAX = 4 << 20


class Owner(Protocol):
    def evaluation_key(self) -> bytes: ...
    def encrypt_pair(self, values: bytes) -> bytes: ...


class Transport(Protocol):
    def request(self, method: str, path: str, body: bytes, action: str, target: dict) -> bytes: ...


def commitment(kind: str, version: int, data: bytes) -> str:
    return blake3(f"kryvola/{kind}/v{version}\0".encode() + data).hexdigest()


def encoded(data: bytes) -> str:
    return urlsafe_b64encode(data).rstrip(b"=").decode()


def checked(name: str, value: dict) -> dict:
    try:
        return validate_contract(name, value)
    except ContractError:
        raise SubmissionError("SUBMISSION_REJECTED") from None


@dataclass(frozen=True, slots=True, repr=False)
class Artifact:
    manifest: bytes
    data: bytes
    reservation: bytes


@dataclass(frozen=True, slots=True, repr=False)
class PreparedSubmission:
    """Owner-local encrypted snapshot. Retain this instance across delivery retries."""

    registration: bytes
    approval: bytes
    admission: bytes
    artifacts: tuple[Artifact, Artifact]


def artifact(data: bytes, kind: str, context: dict, reference: dict, operation: dict) -> Artifact:
    maximum = KEY_MAX if kind == "EVALUATION_KEY" else PAIR_MAX
    if type(data) is not bytes or not 1 <= len(data) <= maximum:
        raise OwnerUnavailable("OWNER_UNAVAILABLE")
    entries = []
    for index, offset in enumerate(range(0, len(data), CHUNK_MAX)):
        part = data[offset : offset + CHUNK_MAX]
        digest = blake3(
            b"kryvola/chunk/v1\0"
            + index.to_bytes(8, "little")
            + len(part).to_bytes(8, "little")
            + part
        ).hexdigest()
        entries.append(
            {
                "index": str(index),
                "byte_offset": str(offset),
                "byte_length": str(len(part)),
                "chunk_digest": digest,
            }
        )
    manifest = checked(
        "ManifestV2",
        {
            "schema_version": "2",
            "tenant_scope": reference["tenant_scope"],
            "object_type": "manifest",
            "artifact_kind": kind,
            "producer_identity": context["owner_identity"],
            "key_context_digest": reference["key_context_digest"],
            "native_codec_id": "tfhe-rs-safe",
            "native_codec_version": context["native_codec_version"],
            "parameters": context["parameters"],
            "precision": {"dtype": "uint8", "fractional_bits": "0", "overflow": "WRAP"},
            "shape": ["2"] if kind == "CIPHERTEXT" else ["1"],
            "serialized_bytes": str(len(data)),
            "max_expanded_bytes": str(maximum),
            "ordered_chunk_entries": entries,
            "full_blob_digest": commitment("blob", 1, data),
            "arithmetic": "EXACT_MODULAR",
        },
    )
    raw = canonical(manifest)
    reservation = checked(
        "CreateInputUploadRequest",
        {
            "schema_version": "1",
            "key_context_ref": reference,
            "manifest_digest": commitment("manifest", 2, raw),
            "idempotency_key": "input-"
            + blake3(
                canonical([operation["operation_id"], kind, manifest["full_blob_digest"]])
            ).hexdigest(),
            "artifact_kind": kind,
            "byte_length": len(data),
        },
    )
    return Artifact(raw, data, canonical(reservation))


def prepare_submission(
    owner: Owner | None,
    approve: Callable[[bytes, dict], bytes] | None,
    descriptor: Mapping,
    operation: Mapping,
    key_context: Mapping,
    consent: Mapping,
    *,
    values: bytes = b"",
    assurance: str = "CONFIDENTIALITY_ONLY",
) -> PreparedSubmission:
    if assurance != "CONFIDENTIALITY_ONLY":
        raise UnsupportedAssurance("UNSUPPORTED_ASSURANCE")
    try:
        return _prepare(owner, approve, descriptor, operation, key_context, consent, values)
    except SubmissionError:
        raise
    except Exception:
        raise SubmissionError("SUBMISSION_REJECTED") from None


def _prepare(owner, approve, descriptor, operation, key_context, consent, values):
    # Import here because the planner uses the SDK contract validators.
    from kryvola_ml.planner import ApprovedBindings, compile_fixed_plan

    operation = checked("Operation", dict(operation))
    context = checked("KeyContext", dict(key_context))
    consent = checked("ConsentDeclaration", dict(consent))
    reference = operation["key_context_ref"]
    raw_context = canonical(context)
    if (
        type(values) is not bytes
        or len(values) != 2
        or reference["key_context_digest"] != commitment("key-context", 1, raw_context)
        or any(
            reference[key] != context[key]
            for key in ("tenant_scope", "key_context_id", "key_epoch")
        )
        or any(
            operation[key]["tenant_scope"] != operation["tenant_scope"]
            for key in ("key_context_ref", "plan_ref", "disclosure_identity")
        )
        or operation["logical_job_id"] != operation["disclosure_identity"]["logical_job_id"]
        or operation["stage_id"] != operation["disclosure_identity"]["output_stage"]
        or context["native_codec_version"] != "tfhe-rs-1.8.1"
    ):
        raise SubmissionError("SUBMISSION_REJECTED")
    if owner is None or approve is None:
        raise OwnerUnavailable("OWNER_UNAVAILABLE")
    try:
        evaluation = owner.evaluation_key()
        if (
            type(evaluation) is not bytes
            or not 1 <= len(evaluation) <= KEY_MAX
            or context["evaluation_key_blob_digest"] != commitment("blob", 1, evaluation)
        ):
            raise SubmissionError("SUBMISSION_REJECTED")
        encrypted = owner.encrypt_pair(values)
    except SubmissionError:
        raise
    except Exception:
        raise OwnerUnavailable("OWNER_UNAVAILABLE") from None
    artifacts = (
        artifact(evaluation, "EVALUATION_KEY", context, reference, operation),
        artifact(encrypted, "CIPHERTEXT", context, reference, operation),
    )
    ciphertext_digest = json.loads(artifacts[1].reservation)["manifest_digest"]
    program = files("kryvola_ml").joinpath("_fixtures/fhe-q1/program.txt")
    if not program.is_file():
        # Source checkouts keep the same packaged fixture at the repository root.
        from pathlib import Path

        program = Path(__file__).resolve().parents[3] / "fixtures/fhe-q1/program.txt"
    model = checked("ModelDescriptor", dict(descriptor))
    bindings = ApprovedBindings(
        operation["tenant_scope"],
        reference["key_context_digest"],
        model["workload"]["model_digest"],
        model["workload"]["engine_digest"],
        ciphertext_digest,
        commitment("blob", 1, canonical(consent)),
    )
    plan = compile_fixed_plan(
        model, program.read_bytes(), bindings, assurance="CONFIDENTIALITY_ONLY"
    )
    operation["plan_ref"]["plan_digest"] = plan.plan_digest
    try:
        bundle = json.loads(approve(plan.plan_bytes, json.loads(canonical(operation))))
    except Exception:
        raise OwnerUnavailable("OWNER_UNAVAILABLE") from None
    approval = checked("ApprovalV3", bundle["approval"])
    signature = checked("SignatureV3", bundle["envelope"])
    expected = json.loads(plan.plan_bytes)
    if (
        bundle.get("assurance") != "CONFIDENTIALITY_ONLY"
        or approval["purpose"] != "COMPUTE"
        or approval["subject_kind"] != "plan"
        or approval["subject_digest"] != plan.plan_digest
        or approval["plan_digest"] != plan.plan_digest
        or any(
            approval[key] != operation[key]
            for key in (
                "tenant_scope",
                "logical_job_id",
                "operation_id",
                "workflow_epoch",
                "policy_digest",
            )
        )
        or any(
            approval[key] != expected[key]
            for key in (
                "model_digest",
                "program_digest",
                "consent_digest",
                "key_context_digest",
                "evidence_policy_digest",
            )
        )
        or any(
            approval[key] != operation["disclosure_identity"][key]
            for key in ("recipient", "output_stage", "disclosure_index")
        )
        or signature["payload_kind"] != "approval"
        or signature["payload_digest"] != commitment("approval", 3, canonical(approval))
    ):
        raise SubmissionError("SUBMISSION_REJECTED")
    registration = checked(
        "RegisterKeyContextRequest",
        {
            "schema_version": "1",
            "key_context_ref": reference,
            "key_context_base64url": encoded(raw_context),
        },
    )
    approval_request = checked(
        "RegisterComputeApprovalRequest",
        {
            "schema_version": "1",
            "plan_ref": operation["plan_ref"],
            "approval_digest": signature["payload_digest"],
            "plan_base64url": encoded(plan.plan_bytes),
            "consent_base64url": encoded(canonical(consent)),
            "approval_base64url": encoded(canonical(approval)),
            "signature_base64url": encoded(canonical(signature)),
        },
    )
    admission = checked(
        "AdmitApprovedOperationRequest",
        {
            "schema_version": "1",
            "operation": operation,
            "approval_digest": signature["payload_digest"],
            "evaluation_key_manifest_digest": json.loads(artifacts[0].reservation)[
                "manifest_digest"
            ],
            "input_manifest_digests": [ciphertext_digest],
        },
    )
    return PreparedSubmission(
        canonical(registration), canonical(approval_request), canonical(admission), artifacts
    )


def submit(transport: Transport, prepared: PreparedSubmission) -> dict:
    """An unavailable response can be retried with this exact prepared snapshot."""
    try:
        return _submit(transport, prepared)
    except SubmissionError:
        raise
    except Exception:
        raise SubmissionError("SUBMISSION_REJECTED") from None


def _submit(transport, prepared):
    if type(prepared) is not PreparedSubmission or len(prepared.artifacts) != 2:
        raise SubmissionError("SUBMISSION_REJECTED")
    registration = checked("RegisterKeyContextRequest", json.loads(prepared.registration))
    approval = checked("RegisterComputeApprovalRequest", json.loads(prepared.approval))
    admission = checked("AdmitApprovedOperationRequest", json.loads(prepared.admission))
    for raw in (prepared.registration, prepared.approval, prepared.admission):
        if type(raw) is not bytes or len(raw) > 65536 or canonical(json.loads(raw)) != raw:
            raise SubmissionError("SUBMISSION_REJECTED")
    digests = []
    for item, kind, maximum in zip(
        prepared.artifacts, ("EVALUATION_KEY", "CIPHERTEXT"), (KEY_MAX, PAIR_MAX), strict=True
    ):
        manifest = checked("ManifestV2", json.loads(item.manifest))
        reservation = checked("CreateInputUploadRequest", json.loads(item.reservation))
        digest = commitment("manifest", 2, item.manifest)
        if (
            type(item.data) is not bytes
            or not 1 <= len(item.data) <= maximum
            or len(item.manifest) > 65536
            or manifest["artifact_kind"] != kind
            or manifest["full_blob_digest"] != commitment("blob", 1, item.data)
            or manifest["serialized_bytes"] != str(len(item.data))
            or manifest["key_context_digest"]
            != registration["key_context_ref"]["key_context_digest"]
            or reservation["manifest_digest"] != digest
            or reservation["key_context_ref"] != registration["key_context_ref"]
            or reservation["artifact_kind"] != kind
            or reservation["byte_length"] != len(item.data)
        ):
            raise SubmissionError("SUBMISSION_REJECTED")
        digests.append(digest)
    if (
        admission["operation"]["key_context_ref"] != registration["key_context_ref"]
        or admission["operation"]["plan_ref"] != approval["plan_ref"]
        or admission["approval_digest"] != approval["approval_digest"]
        or admission["evaluation_key_manifest_digest"] != digests[0]
        or admission["input_manifest_digests"] != digests[1:]
    ):
        raise SubmissionError("SUBMISSION_REJECTED")

    def call(method, path, body, action, target, response=None):
        if method != "PUT" and len(body) > 65536:
            raise SubmissionError("SUBMISSION_REJECTED")
        raw = transport.request(method, path, body, action, target)
        if len(raw) > 65536:
            raise SubmissionError("SUBMISSION_REJECTED")
        return checked(response, json.loads(raw)) if response else None

    reference = registration["key_context_ref"]
    saved = call(
        "POST",
        "/v1/key-contexts",
        prepared.registration,
        "KEY_CONTEXT_REGISTER",
        reference,
        "KeyContextRef",
    )
    if saved != reference:
        raise SubmissionError("SUBMISSION_REJECTED")
    for item in prepared.artifacts:
        request = json.loads(item.reservation)
        saved = call(
            "POST",
            "/v1/input-uploads",
            item.reservation,
            "INPUT_UPLOAD_RESERVE",
            request,
            "CreateUploadResponse",
        )
        upload = saved["upload_id"]
        for index, offset in enumerate(range(0, len(item.data), CHUNK_MAX)):
            call(
                "PUT",
                f"/v1/input-uploads/{upload}/parts/{index}",
                item.data[offset : offset + CHUNK_MAX],
                "INPUT_UPLOAD_PART",
                {"upload_id": upload, "part_index": index},
            )
        call(
            "PUT",
            f"/v1/input-uploads/{upload}/manifest",
            item.manifest,
            "INPUT_UPLOAD_MANIFEST",
            {"upload_id": upload},
        )
        body = canonical(
            {
                "schema_version": "1",
                "tenant_scope": reference["tenant_scope"],
                "manifest_digest": request["manifest_digest"],
            }
        )
        saved = call(
            "POST",
            f"/v1/input-uploads/{upload}/finalize",
            body,
            "INPUT_UPLOAD_FINALIZE",
            {"upload_id": upload},
            "FinalizeUploadResponse",
        )
        if saved["manifest_digest"] != request["manifest_digest"]:
            raise SubmissionError("SUBMISSION_REJECTED")
    saved = call(
        "POST",
        "/v1/compute-approvals",
        prepared.approval,
        "COMPUTE_APPROVAL_REGISTER",
        {key: approval[key] for key in ("plan_ref", "approval_digest")},
        "RegisterComputeApprovalResponse",
    )
    if saved["approval_digest"] != approval["approval_digest"]:
        raise SubmissionError("SUBMISSION_REJECTED")
    saved = call(
        "POST",
        "/v1/operations/admit",
        prepared.admission,
        "APPROVED_OPERATION_ADMIT",
        admission,
        "OperationResponse",
    )
    if saved["operation"] != admission["operation"]:
        raise SubmissionError("SUBMISSION_REJECTED")
    return saved
