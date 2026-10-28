"""Bounded plaintext integer circuits; no cryptographic execution or qualification."""

from collections.abc import Mapping
from dataclasses import dataclass

from kryvola_ml.sdk.contracts import validate_contract

_WIDTHS = {"uint8": 8, "uint16": 16, "uint32": 32, "uint64": 64}


class ReferenceError(ValueError):
    """Invalid local circuit or input; messages do not include input values."""


@dataclass(frozen=True, slots=True)
class Operation:
    """ADD/MUL of two earlier register indices, appending one result register."""

    operator: str
    left: int
    right: int


@dataclass(frozen=True, slots=True)
class ReferenceCircuit:
    """Local immutable program, not a serialized product contract.

    Registers contain inputs, then public constants, then one result per operation.
    Every arithmetic operation wraps modulo 2**width, including intermediates.
    """

    dtype: str
    input_count: int
    constants: tuple[int, ...]
    operations: tuple[Operation, ...]
    outputs: tuple[int, ...]

    def __post_init__(self) -> None:
        if (
            type(self.dtype) is not str
            or self.dtype not in _WIDTHS
            or type(self.input_count) is not int
            or not 1 <= self.input_count <= 16
            or type(self.constants) is not tuple
            or len(self.constants) > 32
            or type(self.operations) is not tuple
            or not 1 <= len(self.operations) <= 64
            or type(self.outputs) is not tuple
            or not 1 <= len(self.outputs) <= 16
        ):
            raise ReferenceError("INVALID_REFERENCE")
        maximum = (1 << _WIDTHS[self.dtype]) - 1
        if any(type(value) is not int or not 0 <= value <= maximum for value in self.constants):
            raise ReferenceError("INVALID_REFERENCE")
        available = self.input_count + len(self.constants)
        for operation in self.operations:
            if (
                type(operation) is not Operation
                or type(operation.operator) is not str
                or operation.operator not in {"ADD", "MUL"}
                or any(
                    type(index) is not int or not 0 <= index < available
                    for index in (operation.left, operation.right)
                )
            ):
                raise ReferenceError("INVALID_REFERENCE")
            available += 1
        if any(type(index) is not int or not 0 <= index < available for index in self.outputs):
            raise ReferenceError("INVALID_REFERENCE")

    @classmethod
    def from_descriptor(
        cls,
        descriptor: Mapping[str, object],
        constants: tuple[int, ...],
        operations: tuple[Operation, ...],
        outputs: tuple[int, ...],
    ) -> ReferenceCircuit:
        """Check generated metadata and local semantics; does not verify artifact digests."""
        model = validate_contract("ModelDescriptor", descriptor)
        workload = model["workload"]
        if len(workload["input_shape"]) != 1:
            raise ReferenceError("UNSUPPORTED_SHAPE")
        circuit = cls(
            workload["precision"]["dtype"],
            int(workload["input_shape"][0]),
            constants,
            operations,
            outputs,
        )
        declared = workload["operators"]
        if workload["output_shape"] != [str(len(circuit.outputs))]:
            raise ReferenceError("UNSUPPORTED_SHAPE")
        if len(declared) != len(set(declared)) or set(declared) != {
            operation.operator for operation in operations
        }:
            raise ReferenceError("OPERATOR_MISMATCH")
        return circuit

    def evaluate(self, inputs: tuple[int, ...]) -> tuple[int, ...]:
        maximum = (1 << _WIDTHS[self.dtype]) - 1
        if (
            type(inputs) is not tuple
            or len(inputs) != self.input_count
            or any(type(value) is not int or not 0 <= value <= maximum for value in inputs)
        ):
            raise ReferenceError("INVALID_INPUT")
        registers = [*inputs, *self.constants]
        for operation in self.operations:
            left, right = registers[operation.left], registers[operation.right]
            value = left + right if operation.operator == "ADD" else left * right
            registers.append(value & maximum)
        return tuple(registers[index] for index in self.outputs)


def tiny_circuit(descriptor: Mapping[str, object]) -> ReferenceCircuit:
    """Public example: (3*x0 + 5*x1 + 7, x0*x1 + 11), modulo the selected width."""
    circuit = ReferenceCircuit.from_descriptor(
        descriptor,
        (3, 5, 7, 11),
        (
            Operation("MUL", 0, 2),
            Operation("MUL", 1, 3),
            Operation("ADD", 6, 7),
            Operation("ADD", 8, 4),
            Operation("MUL", 0, 1),
            Operation("ADD", 10, 5),
        ),
        (9, 11),
    )
    if circuit.input_count != 2:
        raise ReferenceError("UNSUPPORTED_SHAPE")
    return circuit
