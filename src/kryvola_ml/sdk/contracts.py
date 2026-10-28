"""Generated structural contract previews; acceptance grants no execution rights."""

import json
from collections.abc import Mapping
from copy import deepcopy
from importlib.resources import files
from typing import Any, cast

from google.protobuf import (
    descriptor_pb2,
    descriptor_pool,
    json_format,
    message_factory,
    unknown_fields,
)
from google.protobuf.message import DecodeError, Message
from jsonschema import Draft202012Validator, ValidationError

from kryvola_ml._spec.python.artifact_ref import ArtifactRef

_RESOURCES = files("kryvola_ml")
_SPEC = _RESOURCES.joinpath("_spec")
_WIRE = _RESOURCES.joinpath("_wire")
_LIMITS = json.loads(_SPEC.joinpath("limits.json").read_bytes())
_WIRE_SCHEMAS = json.loads(_WIRE.joinpath("schemas.json").read_bytes())
_SCHEMAS = {
    **_WIRE_SCHEMAS,
    **{
        name: json.loads(_SPEC.joinpath(path).read_bytes())
        for name, path in {
            "ModelDescriptor": "profiles/ModelDescriptor.schema.json",
            "MeasurementReport": "profiles/MeasurementReport.schema.json",
            "ReleaseCandidate": "profiles/ReleaseCandidate.schema.json",
            "AssuranceProfile": "assurance-profile.schema.json",
            "AssuranceRequest": "assurance-request.schema.json",
            "ConsentDeclaration": "consent-declaration.schema.json",
        }.items()
    },
}
_VALIDATORS = {name: Draft202012Validator(schema) for name, schema in _SCHEMAS.items()}
# Protobuf supplies these C-backed declarations dynamically; ty cannot model them.
_POOL = descriptor_pool.DescriptorPool()  # ty: ignore[possibly-missing-implicit-call]
for _file in descriptor_pb2.FileDescriptorSet.FromString(  # ty: ignore[unresolved-attribute] - generated export
    _WIRE.joinpath("descriptor.bin").read_bytes()
).file:
    _POOL.Add(_file)


class ContractError(ValueError):
    """Fixed public code with no payload, parser diagnostic or exception chain."""


def validate_contract(kind: str, value: Mapping[str, object]) -> dict[str, Any]:
    """Return an owned structural snapshot; spec semantic/release gates remain required."""
    if not isinstance(value, Mapping):
        raise ContractError("INVALID_CONTRACT")
    result = None
    try:
        snapshot = deepcopy(dict(value))
        _VALIDATORS[kind].validate(snapshot)
        result = snapshot
    except KeyError, TypeError, ValueError, ValidationError:
        pass
    if result is None:
        raise ContractError("INVALID_CONTRACT")
    return result


def _known(message: Message) -> bool:
    if list(unknown_fields.UnknownFieldSet(message)):
        return False
    return all(
        _known(child)
        for field, value in message.ListFields()
        if field.message_type
        for child in (value if field.is_repeated else [value])
    )


def decode_control(kind: str, payload: bytes) -> dict[str, Any]:
    """Decode bounded reference-only Protobuf metadata, rejecting nested unknown fields.

    Ordinary Protobuf merge/order semantics apply. These bytes are not canonical
    signing input; this function does not authorize tenants, attempts or disclosure.
    """
    if not isinstance(payload, bytes):
        raise ContractError("INVALID_CONTRACT")
    if len(payload) > int(_LIMITS["control_bytes"]):
        raise ContractError("CONTROL_TOO_LARGE")
    result = None
    try:
        if kind not in _WIRE_SCHEMAS:
            raise ValueError
        message = message_factory.GetMessageClass(
            _POOL.FindMessageTypeByName("kryvola.spec.v1." + kind)
        )()
        message.ParseFromString(payload)
        if not _known(message):
            raise ValueError
        value = json_format.MessageToDict(
            message, preserving_proto_field_name=True, always_print_fields_with_no_presence=True
        )
        _VALIDATORS[kind].validate(value)
        result = value
    except KeyError, TypeError, ValueError, DecodeError, ValidationError:
        pass
    if result is None:
        raise ContractError("INVALID_CONTRACT")
    return result


def validate_artifact_ref(value: Mapping[str, object]) -> ArtifactRef:
    resources = files("kryvola_ml").joinpath("_spec")
    schema = json.loads(resources.joinpath("artifact-ref.schema.json").read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(value)
    result = cast(ArtifactRef, dict(value))
    limits = json.loads(resources.joinpath("limits.json").read_text(encoding="utf-8"))
    if int(result["byte_length"]) > int(limits["artifact_max_bytes"]):
        raise ValueError("ArtifactRef.byte_length exceeds the foundation 1 GiB profile")
    return result
