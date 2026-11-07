import json
import unittest
from dataclasses import replace
from importlib.resources import files
from pathlib import Path

from kryvola_ml.baseline import tiny_circuit
from kryvola_ml.planner import ApprovedBindings, PlanError, compile_fixed_plan

ROOT = Path(__file__).resolve().parents[1]
GRAPH = (ROOT / "fixtures/fhe-q1/program.txt").read_bytes()
PARAMETERS = "cda9e129d55cc6a17060d8913f6e0d554c5a990e62c967514db86bf57a524674"
PROGRAM = "52687303e4a13081f0f40c15bfa0fafbf35812fb96a3d30f99206ee534c010f5"
APPROVED = ApprovedBindings("tenant-fixture", "1" * 64, "2" * 64, "3" * 64, "4" * 64, "5" * 64)


def descriptor():
    model = json.loads(
        files("kryvola_ml").joinpath("_spec/fixtures/profiles/model.json").read_bytes()
    )
    model["workload"].update(
        operators=["ADD", "MUL"],
        parameter_set_digest=PARAMETERS,
        program_digest=PROGRAM,
        model_digest=APPROVED.model_digest,
        engine_digest=APPROVED.engine_digest,
    )
    model["reference_program_digest"] = PROGRAM
    return model


class PlannerTests(unittest.TestCase):
    def test_deterministic_bound_plan_and_metadata(self):
        from blake3 import blake3

        model = descriptor()
        result = compile_fixed_plan(model, GRAPH, APPROVED, assurance="CONFIDENTIALITY_ONLY")
        reordered = dict(reversed(list(model.items())))
        reordered["workload"]["operators"] = ["MUL", "ADD"]
        self.assertEqual(
            result, compile_fixed_plan(reordered, GRAPH, APPROVED, assurance="CONFIDENTIALITY_ONLY")
        )
        plan = json.loads(result.plan_bytes)
        self.assertEqual(plan["program_digest"], PROGRAM)
        self.assertEqual(plan["input_manifest_digests"], [APPROVED.input_manifest_digest])
        self.assertEqual(plan["consent_digest"], APPROVED.consent_digest)
        self.assertEqual(
            result.plan_digest, blake3(b"kryvola/plan/v2\0" + result.plan_bytes).hexdigest()
        )
        # Checked against Spec's canonicalBytes and commitment for plan v2.
        self.assertEqual(
            result.plan_digest,
            "7650f2818f613da49963d991ae091f2b66062d511db7419b0d7cee6b3bd99e31",
        )
        for name, content in result.sidecars:
            self.assertEqual(
                plan[f"{name}_digest"], blake3(b"kryvola/blob/v1\0" + content).hexdigest()
            )
        metadata = {name: json.loads(content) for name, content in result.sidecars}
        self.assertEqual(metadata["output_contract"]["numerical_error_budget"], "0")
        self.assertEqual(metadata["leakage_profile"]["model_visibility"], "PUBLIC")
        self.assertEqual(metadata["evidence_policy"]["computation_integrity"], "UNPROVEN")
        self.assertEqual(
            metadata["evidence_policy"]["consent"]["allow_unverified_release"], "REQUIRED"
        )
        self.assertEqual(
            metadata["resource_profile"]["input_pair_max_bytes"], str(2 * (8 + (1 << 20)))
        )
        self.assertEqual(tiny_circuit(model).evaluate((255, 255)), (255, 12))
        other = compile_fixed_plan(
            model,
            GRAPH,
            replace(APPROVED, consent_digest="6" * 64),
            assurance="CONFIDENTIALITY_ONLY",
        )
        self.assertNotEqual(other.plan_digest, result.plan_digest)

    def test_rejects_unsupported_or_unbound_inputs(self):
        for field, value in (
            ("operators", ["ADD", "DIV"]),
            ("operators", ["ADD", "ADD"]),
            ("input_shape", ["1", "2"]),
            ("output_shape", ["1"]),
            ("parameter_set_digest", "6" * 64),
            ("program_digest", "6" * 64),
            ("engine_digest", "6" * 64),
            ("model_digest", "6" * 64),
        ):
            model = descriptor()
            model["workload"][field] = value
            with self.subTest(field=field), self.assertRaises(PlanError):
                compile_fixed_plan(model, GRAPH, APPROVED, assurance="CONFIDENTIALITY_ONLY")
        for model, graph, bindings, assurance in (
            (
                descriptor() | {"model_visibility": "HIDDEN"},
                GRAPH,
                APPROVED,
                "CONFIDENTIALITY_ONLY",
            ),
            (descriptor() | {"weights": [3]}, GRAPH, APPROVED, "CONFIDENTIALITY_ONLY"),
            (
                descriptor() | {"numerical_error_budget": "1"},
                GRAPH,
                APPROVED,
                "CONFIDENTIALITY_ONLY",
            ),
            (
                descriptor(),
                GRAPH.replace(b"3 5 7 11", b"3 6 7 11"),
                APPROVED,
                "CONFIDENTIALITY_ONLY",
            ),
            (
                descriptor(),
                GRAPH,
                replace(APPROVED, consent_digest="missing"),
                "CONFIDENTIALITY_ONLY",
            ),
            (descriptor(), GRAPH, APPROVED, "VERIFIED_INTEGRITY"),
        ):
            with self.assertRaisesRegex(PlanError, "^PLAN_REJECTED$"):
                compile_fixed_plan(model, graph, bindings, assurance=assurance)
