"""Observe durable execution without conflating selection, release and plaintext."""

import asyncio
import json
import math
from dataclasses import dataclass
from enum import StrEnum
from urllib.parse import quote

from blake3 import blake3

from .client import (
    RateLimited,
    SubmissionError,
    SubmissionUnavailable,
    UnsupportedAssurance,
    canonical,
)
from .submission import CHUNK_MAX, PAIR_MAX, checked, commitment


class State(StrEnum):
    RUNNING = "RUNNING"  # The published null status: no public outcome recorded yet.
    COMPUTE_SELECTED = "COMPUTE_SELECTED"
    EVIDENCE_PENDING = "EVIDENCE_PENDING"
    EVIDENCE_VERIFIED = "EVIDENCE_VERIFIED"
    RELEASED = "RELEASED"
    EVIDENCE_FAILED = "EVIDENCE_FAILED"
    CANCELLED = "CANCELLED"
    EXPIRED = "EXPIRED"


@dataclass(frozen=True, slots=True)
class Observation:
    state: State

    @property
    def terminal(self) -> bool:
        return self.state in (State.EVIDENCE_FAILED, State.CANCELLED, State.EXPIRED)


@dataclass(frozen=True, slots=True)
class Cancellation:
    outcome: str
    fence: str | None


@dataclass(frozen=True, slots=True, repr=False)
class FetchedOutput:
    scope: bytes
    manifest: bytes
    ciphertext: bytes


class Lifecycle:
    def __init__(self, transport, operation: dict, *, assurance="CONFIDENTIALITY_ONLY"):
        if assurance != "CONFIDENTIALITY_ONLY":
            raise UnsupportedAssurance("UNSUPPORTED_ASSURANCE")
        self._operation = canonical(checked("Operation", operation))
        self.transport = transport
        self._cancellation = None

    def _identity(self):
        operation = json.loads(self._operation)
        return {
            **{key: operation[key] for key in ("tenant_scope", "operation_id", "workflow_epoch")},
            "attempt_epoch": None,
            "fence": None,
        }

    def inspect(self) -> Observation:
        scope = self._identity()
        raw = self.transport.request(
            "GET",
            "/v1/operations/" + quote(scope["operation_id"], safe=""),
            b"",
            "GET_OPERATION",
            scope,
        )
        try:
            if len(raw) > 65536:
                raise ValueError
            saved = checked("OperationResponse", json.loads(raw))
            if canonical(saved["operation"]) != self._operation:
                raise ValueError
            return Observation(State(saved["public_status"] or "RUNNING"))
        except Exception:
            raise SubmissionError("LIFECYCLE_REJECTED") from None

    async def wait(self, *, timeout: float = 30, poll_interval: float = 0.5) -> Observation:
        if not all(math.isfinite(value) for value in (timeout, poll_interval)) or not (
            0 < timeout <= 300 and 0 < poll_interval <= 30
        ):
            raise SubmissionError("LIFECYCLE_REJECTED")
        async with asyncio.timeout(timeout):
            while True:
                try:
                    observed = await asyncio.to_thread(self.inspect)
                    if observed.terminal or observed.state == State.RELEASED:
                        return observed
                except SubmissionUnavailable, RateLimited:
                    pass
                await asyncio.sleep(poll_interval)

    def cancel(self, idempotency_key: str) -> Cancellation:
        scope = self._identity()
        body = canonical(
            checked(
                "CancelOperationRequest",
                {
                    "schema_version": "1",
                    "tenant_scope": scope["tenant_scope"],
                    "operation_id": scope["operation_id"],
                    "idempotency_key": idempotency_key,
                },
            )
        )
        if self._cancellation is not None and self._cancellation != body:
            raise SubmissionError("LIFECYCLE_REJECTED")
        self._cancellation = body
        raw = self.transport.request(
            "POST", "/v1/operations/cancel", body, "CANCEL_OPERATION", scope
        )
        try:
            if len(raw) > 65536:
                raise ValueError
            saved = checked("CancelOperationResponse", json.loads(raw))
            return Cancellation(saved["outcome"], saved.get("fence"))
        except Exception:
            raise SubmissionError("LIFECYCLE_REJECTED") from None

    def fetch(self, scope: dict) -> FetchedOutput:
        try:
            scope = checked("ReadReleasedOutputRequest", scope)
            operation = json.loads(self._operation)
            identity = operation["disclosure_identity"]
            if (
                scope["tenant_scope"] != operation["tenant_scope"]
                or scope["recipient"] != identity["recipient"]
                or scope["disclosure_id"]
                != commitment("disclosure-identity", 3, canonical(identity))
            ):
                raise ValueError
            if self.inspect().state != State.RELEASED:
                raise SubmissionError("OUTPUT_NOT_RELEASED")
            manifest = self.transport.read_output(scope)
            if (
                len(manifest) > 65536
                or commitment("manifest", 2, manifest) != scope["output_manifest_digest"]
            ):
                raise ValueError
            value = checked("ManifestV2", json.loads(manifest))
            if (
                canonical(value) != manifest
                or value["artifact_kind"] != "CIPHERTEXT"
                or value["tenant_scope"] != scope["tenant_scope"]
                or value["key_context_digest"] != operation["key_context_ref"]["key_context_digest"]
                or value["shape"] != ["2"]
                or value["precision"]
                != {"dtype": "uint8", "fractional_bits": "0", "overflow": "WRAP"}
                or value["arithmetic"] != "EXACT_MODULAR"
                or value["native_codec_version"] != "tfhe-rs-1.8.1"
                or not 0 < int(value["serialized_bytes"]) <= PAIR_MAX
            ):
                raise ValueError
            data = bytearray()
            for index, entry in enumerate(value["ordered_chunk_entries"]):
                size = int(entry["byte_length"])
                if (
                    entry["index"] != str(index)
                    or entry["byte_offset"] != str(len(data))
                    or not 0 < size <= CHUNK_MAX
                    or len(data) + size > PAIR_MAX
                ):
                    raise ValueError
                part = self.transport.read_output(scope, index)
                digest = blake3(
                    b"kryvola/chunk/v1\0"
                    + index.to_bytes(8, "little")
                    + size.to_bytes(8, "little")
                    + part
                ).hexdigest()
                if len(part) != size or digest != entry["chunk_digest"]:
                    raise ValueError
                data.extend(part)
            if (
                len(data) != int(value["serialized_bytes"])
                or commitment("blob", 1, bytes(data)) != value["full_blob_digest"]
            ):
                raise ValueError
            return FetchedOutput(canonical(scope), manifest, bytes(data))
        except SubmissionError:
            raise
        except Exception:
            raise SubmissionError("LIFECYCLE_REJECTED") from None

    def open_result(self, scope: dict, opener) -> bytes:
        """Fetch encrypted bytes, then delegate plaintext authority to the local owner agent."""
        return opener.open_result(self.fetch(scope))
