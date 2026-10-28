import json
import traceback
import unittest
from copy import deepcopy
from importlib.resources import files

from google.protobuf import message_factory
from jsonschema import ValidationError

from kryvola_ml.sdk import contracts
from kryvola_ml.sdk.contracts import (
    ContractError,
    decode_control,
    validate_artifact_ref,
    validate_contract,
)


class ContractTests(unittest.TestCase):
    def fixture(self) -> dict[str, object]:
        return json.loads(
            files("kryvola_ml")
            .joinpath("_spec/fixtures/artifact-ref.json")
            .read_text(encoding="utf-8")
        )

    def test_effect_fixture_is_accepted(self) -> None:
        value = self.fixture()
        self.assertEqual(validate_artifact_ref(value), value)

    def test_inline_payloads_credentials_and_wrong_types_are_rejected(self) -> None:
        for update in [
            {"private_key": "forbidden"},
            {"ciphertext": "bytes"},
            {"byte_length": 1},
            {"manifest_digest": "A" * 64},
            {"byte_length": "01"},
        ]:
            with self.subTest(update=update), self.assertRaises(ValidationError):
                validate_artifact_ref({**self.fixture(), **update})

    def test_serialized_artifact_profile_limit_is_enforced(self) -> None:
        with self.assertRaisesRegex(ValueError, "1 GiB"):
            validate_artifact_ref({**self.fixture(), "byte_length": "1073741825"})

    def test_trailing_newlines_are_rejected_by_exported_constraints(self) -> None:
        for key, value in [
            ("tenant_scope", "tenant\n"),
            ("manifest_digest", "a" * 64 + "\n"),
            ("byte_length", "1\n"),
        ]:
            with self.subTest(key=key), self.assertRaises(ValidationError):
                validate_artifact_ref({**self.fixture(), key: value})


class ControlTests(unittest.TestCase):
    def resource(self, path):
        return json.loads(files("kryvola_ml").joinpath(path).read_bytes())

    def test_all_published_golden_vectors_decode_and_validate(self):
        for vector in self.resource("_wire/vectors.json"):
            with self.subTest(kind=vector["type"]):
                self.assertEqual(
                    decode_control(vector["type"], bytes.fromhex(vector["wire"])), vector["value"]
                )
                self.assertEqual(
                    validate_contract(vector["type"], vector["value"]), vector["value"]
                )

    def test_profile_model_and_assurance_fixtures_are_structurally_valid(self):
        for kind, path in {
            "ModelDescriptor": "profiles/model.json",
            "MeasurementReport": "profiles/measurement.json",
            "ReleaseCandidate": "profiles/release.json",
            "AssuranceProfile": "fhe-q1-assurance.json",
            "AssuranceRequest": "fhe-q1-request.json",
            "ConsentDeclaration": "fhe-q1-consent.json",
        }.items():
            value = self.resource("_spec/fixtures/" + path)
            with self.subTest(kind=kind):
                self.assertEqual(validate_contract(kind, value), value)
                version = "schema_version" if "schema_version" in value else "profile_version"
                for update in ({version: "2"}, {"private_key": "sensitive-marker"}):
                    with self.assertRaises(ContractError):
                        validate_contract(kind, {**value, **update})

    def test_nested_values_are_owned_and_canonical_strings_are_strict(self):
        original = self.resource("_spec/fixtures/profiles/model.json")
        snapshot = validate_contract("ModelDescriptor", original)
        snapshot["workload"]["input_shape"].append("9")
        self.assertNotEqual(snapshot, original)
        for path, bad in [
            (("workload", "input_shape"), ["01"]),
            (("workload", "model_digest"), "A" * 64),
            (("workload", "program_digest"), "a" * 64 + "\n"),
            (("workload", "precision", "fractional_bits"), 0),
        ]:
            value = deepcopy(original)
            parent = value
            for name in path[:-1]:
                parent = parent[name]
            parent[path[-1]] = bad
            with self.subTest(path=path), self.assertRaises(ContractError):
                validate_contract("ModelDescriptor", value)

    def test_wire_rejects_bad_versions_unknowns_malformed_and_over_budget(self):
        vectors = self.resource("_wire/vectors.json")
        execution = next(v for v in vectors if v["type"] == "ExecuteRequest")
        message = message_factory.GetMessageClass(
            contracts._POOL.FindMessageTypeByName("kryvola.spec.v1.ExecuteRequest")
        )()
        message.ParseFromString(bytes.fromhex(execution["wire"]))
        # A typed decoder would silently preserve/drop this unknown field inside Operation.
        message.operation.ParseFromString(message.operation.SerializeToString() + b"\xf8\x07\x01")
        cases = [
            ("ExecuteRequest", message.SerializeToString()),
            ("GetCapabilitiesRequest", b"\x0a\x01\x32"),
            ("GetCapabilitiesRequest", b"\x0a\x01\x31\xf8\x07\x01"),
            ("GetCapabilitiesRequest", b"\x0a\xff"),
            ("GetCapabilitiesRequest", b""),
            ("GetCapabilitiesRequest", b"x" * 65537),
            ("../descriptor.bin", b"\x0a\x01\x31"),
            ("ModelDescriptor", b"\x0a\x01\x31"),
        ]
        for kind, raw in cases:
            with self.subTest(kind=kind, length=len(raw)), self.assertRaises(ContractError):
                decode_control(kind, raw)
        with self.assertRaises(ContractError):
            # Deliberate violation of the immutable bytes API.
            decode_control("GetCapabilitiesRequest", bytearray(b"\x0a\x01\x31"))  # ty: ignore[invalid-argument-type]

    def test_new_errors_never_retain_sensitive_values_or_parser_diagnostics(self):
        for action in (
            lambda: validate_contract(
                "GetCapabilitiesRequest", {"private_key": "sensitive-marker"}
            ),
            lambda: decode_control("GetCapabilitiesRequest", b"\x0a\x10sensitive-marker"),
        ):
            with self.assertRaises(ContractError) as caught:
                action()
            error = caught.exception
            self.assertEqual(str(error), "INVALID_CONTRACT")
            self.assertIsNone(error.__cause__)
            self.assertIsNone(error.__context__)
            self.assertNotIn("sensitive-marker", "".join(traceback.format_exception(error)))
