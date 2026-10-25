"""Inspect the packaged schema fixture; no inference is performed."""

import json
from importlib.resources import files

from kryvola_ml.sdk.contracts import validate_artifact_ref


def main() -> None:
    value = json.loads(
        files("kryvola_ml").joinpath("_spec/fixtures/artifact-ref.json").read_text(encoding="utf-8")
    )
    reference = validate_artifact_ref(value)
    print(
        json.dumps(
            {
                "component": "kryvola-ml",
                "status": "foundation",
                "fixture_valid": True,
                "schema_version": reference["schema_version"],
                "inference_available": False,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
