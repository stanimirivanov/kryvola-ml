"""Compile the single approved public FHE-Q1 program into unsigned v2 plan bytes."""

import json
from collections.abc import Mapping
from dataclasses import dataclass
from importlib.resources import files

from blake3 import blake3
from jsonschema import Draft202012Validator

from kryvola_ml.sdk.contracts import ContractError, validate_contract

# The frozen public program and CPU parameter profile from the FHE-Q1 research evidence.
_PROGRAM_DIGEST = "52687303e4a13081f0f40c15bfa0fafbf35812fb96a3d30f99206ee534c010f5"
_PARAMETER_DIGEST = "cda9e129d55cc6a17060d8913f6e0d554c5a990e62c967514db86bf57a524674"
_PAIR_MAX = str(2 * (8 + (1 << 20)))
_PRECISION = {"dtype": "uint8", "fractional_bits": "0", "overflow": "WRAP"}
_PLAN_SCHEMA = Draft202012Validator(
    json.loads(files("kryvola_ml").joinpath("_spec/canonical/v2/plan.schema.json").read_bytes())
)


class PlanError(ValueError):
    """Fixed rejection without descriptor or approval data."""


@dataclass(frozen=True, slots=True)
class ApprovedBindings:
    """References supplied by the owner after independent approval checks."""

    tenant_scope: str
    key_context_digest: str
    model_digest: str
    engine_digest: str
    input_manifest_digest: str
    consent_digest: str


@dataclass(frozen=True, slots=True)
class CompiledPlan:
    plan_bytes: bytes
    plan_digest: str
    sidecars: tuple[tuple[str, bytes], ...]


def _canonical(value: Mapping[str, object]) -> bytes:
    # This compiler emits only ASCII strings, arrays and string-keyed objects.
    # Sorted keys and compact JSON match Spec canonical bytes for that subset.
    return json.dumps(dict(value), sort_keys=True, separators=(",", ":")).encode("ascii")


_SIDECARS = tuple(
    (name, _canonical(value))
    for name, value in (
        (
            "output_contract",
            {
                "schema_version": "1",
                "shape": ["2"],
                "precision": _PRECISION,
                "arithmetic": "EXACT_MODULAR",
                "numerical_error_budget": "0",
                "encoding": "TFHE_RS_SAFE_PAIR_U64LE",
                "visibility": "OWNER_ONLY_PLAINTEXT",
            },
        ),
        (
            "resource_profile",
            {
                "schema_version": "1",
                "backend": "CPU",
                "input_pair_max_bytes": _PAIR_MAX,
                "output_pair_max_bytes": _PAIR_MAX,
                "evaluation_key_max_bytes": str(64 << 20),
                "additions": "3",
                "multiplications": "3",
                "public_constant_multiplications": "2",
            },
        ),
        (
            "evidence_policy",
            {
                "schema_version": "1",
                "assurance": "CONFIDENTIALITY_ONLY",
                "computation_integrity": "UNPROVEN",
                "consent": {
                    "allow_unverified_release": "REQUIRED",
                    "accept_declared_leakage": "REQUIRED",
                    "owner_endpoint_trust": "REQUIRED",
                    "exact_release_authorization": "REQUIRED",
                },
            },
        ),
        (
            "leakage_profile",
            {
                "schema_version": "1",
                "model_visibility": "PUBLIC",
                "residual_side_channels": "NOT_ELIMINATED",
                "metadata_leakage": [
                    "INPUT_SHAPE",
                    "MODEL_PROGRAM",
                    "CRYPTO_PAYLOAD_SIZE",
                    "TIMING",
                    "ACCESS_PATTERN",
                    "KEY_REUSE",
                    "CACHE_STATE",
                ],
            },
        ),
    )
)


def compile_fixed_plan(
    descriptor: Mapping[str, object],
    program: bytes,
    bindings: ApprovedBindings,
    *,
    assurance: str,
) -> CompiledPlan:
    """Return canonical signing input. The owner independently verifies the bindings."""
    if (
        type(bindings) is not ApprovedBindings
        or assurance != "CONFIDENTIALITY_ONLY"
        or type(program) is not bytes
        or len(program) > 4096
        or blake3(program).hexdigest() != _PROGRAM_DIGEST
    ):
        raise PlanError("PLAN_REJECTED")

    try:
        model = validate_contract("ModelDescriptor", descriptor)
    except ContractError:
        raise PlanError("PLAN_REJECTED") from None

    workload = model["workload"]
    required = {
        "profile_id": "FHE-Q1",
        "profile_version": "1",
        "parameter_set_digest": _PARAMETER_DIGEST,
        "model_digest": bindings.model_digest,
        "program_digest": _PROGRAM_DIGEST,
        "engine_digest": bindings.engine_digest,
        "arithmetic": "EXACT_MODULAR",
        "precision": _PRECISION,
        "input_shape": ["2"],
        "output_shape": ["2"],
    }
    if (
        any(workload[name] != value for name, value in required.items())
        or sorted(workload["operators"]) != ["ADD", "MUL"]
        or model["model_visibility"] != "PUBLIC"
        or model["numerical_error_budget"] != "0"
        or model["reference_program_digest"] != _PROGRAM_DIGEST
    ):
        raise PlanError("PLAN_REJECTED")

    plan = {
        "schema_version": "2",
        "object_type": "plan",
        "tenant_scope": bindings.tenant_scope,
        "display_name": "FHE-Q1 fixed public uint8 graph",
        "key_context_digest": bindings.key_context_digest,
        "model_digest": bindings.model_digest,
        "program_digest": _PROGRAM_DIGEST,
        "engine_digest": bindings.engine_digest,
        "parameters": {
            "scheme": "TFHE",
            "parameter_set_digest": _PARAMETER_DIGEST,
            "radix_bits": "8",
            "message_modulus": "4",
            "carry_modulus": "4",
        },
        "precision": _PRECISION,
        "input_shape": ["2"],
        "output_shape": ["2"],
        "operators": ["ADD", "MUL"],
        "input_manifest_digests": [bindings.input_manifest_digest],
        "consent_digest": bindings.consent_digest,
        "security_profile": "FHE-Q1",
        "arithmetic": "EXACT_MODULAR",
        **{
            f"{name}_digest": blake3(b"kryvola/blob/v1\0" + content).hexdigest()
            for name, content in _SIDECARS
        },
    }
    if not _PLAN_SCHEMA.is_valid(plan):
        raise PlanError("PLAN_REJECTED")
    content = _canonical(plan)
    return CompiledPlan(content, blake3(b"kryvola/plan/v2\0" + content).hexdigest(), _SIDECARS)
