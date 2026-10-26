"""Validate public reference metadata using the Effect-generated schema."""

import json
from collections.abc import Mapping
from importlib.resources import files
from typing import cast

from jsonschema import Draft202012Validator

from kryvola_ml._spec.python.artifact_ref import ArtifactRef


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
