"""Integer oracle vectors are synthetic examples, not a frozen model dataset."""

import copy
import json
import unittest
from dataclasses import FrozenInstanceError, replace
from importlib.resources import files

from kryvola_ml.baseline import Operation, ReferenceCircuit, ReferenceError, tiny_circuit


def descriptor():
    value = json.loads(
        files("kryvola_ml").joinpath("_spec/fixtures/profiles/model.json").read_bytes()
    )
    value["workload"]["operators"] = ["ADD", "MUL"]
    return value


class ReferenceTests(unittest.TestCase):
    def test_golden_vectors_and_repeat_identity(self):
        circuit = tiny_circuit(descriptor())
        vectors = (
            ((0, 0), (7, 11)),
            ((1, 2), (20, 13)),
            ((255, 255), (255, 12)),
            ((128, 128), (7, 11)),
            ((255, 1), (9, 10)),
            ((1, 255), (5, 10)),
        )
        for _ in range(10):
            for inputs, expected in vectors:
                self.assertEqual(circuit.evaluate(inputs), expected)

    def test_all_widths_against_unbounded_polynomial(self):
        for width in (8, 16, 32, 64):
            model = descriptor()
            model["workload"]["precision"]["dtype"] = f"uint{width}"
            circuit = tiny_circuit(model)
            modulus = 2**width
            for left in (0, 1, modulus // 2, modulus - 1):
                for right in (0, 1, modulus // 2, modulus - 1):
                    self.assertEqual(
                        circuit.evaluate((left, right)),
                        ((3 * left + 5 * right + 7) % modulus, (left * right + 11) % modulus),
                    )
            for operator, expected in (("ADD", modulus - 2), ("MUL", 1)):
                direct = ReferenceCircuit(f"uint{width}", 2, (), (Operation(operator, 0, 1),), (2,))
                self.assertEqual(direct.evaluate((modulus - 1, modulus - 1)), (expected,))

    def test_input_rejection_is_strict(self):
        circuit = tiny_circuit(descriptor())
        for inputs in (
            (-1, 0),
            (256, 0),
            (True, 0),
            (1.0, 0),
            ("1", 0),
            (0,),
            (0, 0, 0),
            [0, 0],
            (float("nan"), 0),
        ):
            with (
                self.subTest(inputs=inputs),
                self.assertRaisesRegex(ReferenceError, "^INVALID_INPUT$"),
            ):
                circuit.evaluate(inputs)  # ty: ignore[invalid-argument-type] - negative control

    def test_graph_validation_and_immutability(self):
        circuit = tiny_circuit(descriptor())
        invalid = (
            {"dtype": "int8"},
            {"input_count": True},
            {"input_count": 17},
            {"constants": (-1,)},
            {"constants": (256,)},
            {"constants": (True,)},
            {"constants": [3, 5, 7, 11]},
            {"operations": ()},
            {"operations": (Operation("LT", 0, 1),)},
            {"operations": (Operation("ADD", -1, 0),)},
            {"operations": (Operation("ADD", 6, 0),)},
            {"operations": (Operation("ADD", True, 0),)},
            {"operations": (Operation("ADD", 0, 1),) * 65},
            {"outputs": (100,)},
            {"outputs": (False,)},
            {"outputs": ()},
        )
        for fields in invalid:
            with self.subTest(fields=fields), self.assertRaises(ReferenceError):
                replace(circuit, **fields)
        with self.assertRaises(FrozenInstanceError):
            circuit.dtype = "uint64"  # ty: ignore[invalid-assignment] - runtime immutability control
        with self.assertRaises(FrozenInstanceError):
            circuit.operations[0].operator = "ADD"  # ty: ignore[invalid-assignment] - negative control

    def test_descriptor_semantics_and_owned_snapshot(self):
        original = descriptor()
        circuit = tiny_circuit(original)
        for mutate in (
            lambda d: d["workload"].update(operators=["ADD"]),
            lambda d: d["workload"].update(operators=["ADD", "ADD"]),
            lambda d: d["workload"].update(operators=["LT"]),
            lambda d: d["workload"].update(input_shape=["1", "2"]),
            lambda d: d["workload"].update(input_shape=["3"]),
            lambda d: d["workload"].update(output_shape=["1"]),
            lambda d: d["workload"]["precision"].update(fractional_bits="1"),
            lambda d: d["workload"]["precision"].update(overflow="SATURATE"),
            lambda d: d.update(model_visibility="PRIVATE"),
        ):
            candidate = copy.deepcopy(original)
            mutate(candidate)
            with self.assertRaises(ValueError):
                tiny_circuit(candidate)
        original["workload"]["precision"]["dtype"] = "uint64"
        self.assertEqual(circuit.dtype, "uint8")
        self.assertEqual(circuit.evaluate((255, 255)), (255, 12))

    def test_generic_descriptor_operator_match(self):
        model = descriptor()
        model["workload"].update(operators=["ADD"], output_shape=["1"])
        circuit = ReferenceCircuit.from_descriptor(model, (), (Operation("ADD", 0, 1),), (2,))
        self.assertEqual(circuit.evaluate((255, 1)), (0,))
