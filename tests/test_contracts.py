import json
import unittest
from importlib.resources import files

from jsonschema import ValidationError

from kryvola_ml.sdk.contracts import validate_artifact_ref


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
