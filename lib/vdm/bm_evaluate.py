"""Finite BUFFER/identity literal/raw01/primary-raw04/raw09/END evaluator.

This is not a general BM matcher. Unsupported grammar/context raises ValueError;
ordinary matching failure returns a result with the mutated reader preserved.
"""

from dataclasses import dataclass, replace

from .bm import BmClass, BmLiteral, buffer_backward_scan_transition, raw_04_05_byte_set
from .bm_program import BmExecutionProgram


@dataclass(frozen=True, slots=True)
class BmBufferReader:
    """Immutable backing and three-QWORD reader; cursor/limit are base-relative.

    base is a logical u64 pointer identity, never a Python subject index. The
    supplied bytes start at that base. v1 requires limit == len(subject).
    """

    subject: bytes
    base: int
    limit: int
    cursor: int

    def __post_init__(self) -> None:
        if not isinstance(self.subject, bytes):
            raise TypeError("finite reader requires immutable bytes backing")
        if any(
            type(value) is not int or not 0 <= value < 1 << 64
            for value in (self.base, self.limit, self.cursor)
        ):
            raise ValueError("finite reader fields must be u64")
        if self.limit != len(self.subject):
            raise ValueError("finite reader requires limit == len(subject)")


@dataclass(frozen=True, slots=True)
class BmFiniteMatchResult:
    matched: bool
    reader: BmBufferReader
    scratch: BmBufferReader | None


def evaluate_bm_snapshot_finite(
    program: BmExecutionProgram, entry: BmBufferReader, *, mode: int
) -> BmFiniteMatchResult:
    """Execute one invocation with identity bytes, null backrefs/vector.

    Each raw09 restores the original entry reader, then continues the suffix
    in this invocation. None scratch means unchanged caller sentinel; END
    writes the full reader before testing cursor <= limit. No PE mapping,
    candidate search, scalar wrapper outputs or allocation failures are modeled.
    """
    if (
        type(mode) is not int
        or mode not in (1, 3)
        or program.preparation != "identity"
        or not program.snapshot_finite_grammar
    ):
        raise ValueError("outside finite BUFFER/identity modes1/3 snapshot grammar")
    reader = entry
    for operation in program.invocations[program.root].prefix:
        if isinstance(operation, BmLiteral):
            for value in operation.value:
                if (
                    reader.cursor >= reader.limit
                    or reader.subject[reader.cursor] != value
                ):
                    return BmFiniteMatchResult(False, reader, None)
                reader = replace(reader, cursor=reader.cursor + 1)
        elif isinstance(operation, BmClass):
            # Primary raw04 runs in this invocation. It neither retries the
            # suffix nor refreshes the entry snapshot used by later raw09.
            accepted = raw_04_05_byte_set(
                operation.spec, pattern_preparation="identity"
            )
            for _ in range(operation.count):
                if (
                    reader.cursor >= reader.limit
                    or reader.subject[reader.cursor] not in accepted
                ):
                    return BmFiniteMatchResult(False, reader, None)
                reader = replace(reader, cursor=reader.cursor + 1)
        elif operation.raw[:2] == b"\x90\x01":
            # A failed skip leaves the cursor at the first unreadable byte.
            cursor = reader.cursor
            for _ in range(operation.raw[2]):
                if cursor >= reader.limit:
                    return BmFiniteMatchResult(
                        False, replace(reader, cursor=cursor), None
                    )
                cursor += 1
            reader = replace(reader, cursor=cursor)
        else:
            step = buffer_backward_scan_transition(
                entry.cursor, entry.limit, int.from_bytes(operation.raw[2:4], "little")
            )
            reader = replace(entry, cursor=step.cursor)
            if not step.suffix_reachable:
                return BmFiniteMatchResult(False, reader, None)
    return BmFiniteMatchResult(reader.cursor <= reader.limit, reader, reader)
