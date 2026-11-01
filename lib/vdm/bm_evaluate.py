"""Finite BUFFER/identity evaluators for separately qualified grammars.

This is not a general BM matcher. Unsupported grammar/context raises ValueError;
ordinary matching failure returns a result with the mutated reader preserved.
"""

from collections.abc import Callable
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


@dataclass(frozen=True, slots=True)
class BmEvaluationBudget:
    """Local analyzer limits, not engine format or match-failure limits."""

    steps: int = 1_000_000
    depth: int = 64


class BmEvaluationBudgetExceeded(ValueError):
    """Evaluation is inconclusive because the analyzer exhausted its budget."""


DEFAULT_BM_EVALUATION_BUDGET = BmEvaluationBudget()


def evaluate_bm_snapshot_finite(
    program: BmExecutionProgram,
    entry: BmBufferReader,
    *,
    mode: int,
    budget: BmEvaluationBudget = DEFAULT_BM_EVALUATION_BUDGET,
    trace: Callable[[tuple[object, ...]], None] | None = None,
) -> BmFiniteMatchResult:
    """Execute one invocation with identity bytes, null backrefs/vector.

    Each raw09 restores its current invocation's entry reader. raw02 early
    trials invoke the complete suffix with a fresh candidate snapshot; the
    endpoint continues with the parent's snapshot. None scratch means unchanged
    caller sentinel; END
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
    return _evaluate_bm_finite(program, entry, budget=budget, trace=trace)


def evaluate_bm_fixed_skip_finite(
    program: BmExecutionProgram,
    entry: BmBufferReader,
    *,
    mode: int,
    budget: BmEvaluationBudget = DEFAULT_BM_EVALUATION_BUDGET,
    trace: Callable[[tuple[object, ...]], None] | None = None,
) -> BmFiniteMatchResult:
    """Execute flat literal/raw01/primary-raw07/END with identity bytes.

    Null backrefs/vector, immutable finite backing, modes1/3. Raw07 counts
    bytes, mutating the cursor per checked step; short input preserves partial
    progress. Count zero does not read the subject. END writes scratch before
    its cursor <= limit check. This is a static-derived local evaluator, not
    new original-engine execution evidence or PE/caller equivalence.
    """
    if type(mode) is not int or not program.identity_fixed_skip_closed(
        reader_kind="BUFFER",
        identity_translation=True,
        worker_modes=(mode,),
        capture_enabled=False,
        matches_vector_supplied=False,
    ):
        raise ValueError("outside finite BUFFER/identity modes1/3 fixed-skip grammar")
    return _evaluate_bm_finite(program, entry, budget=budget, trace=trace)


def _evaluate_bm_finite(
    program: BmExecutionProgram,
    entry: BmBufferReader,
    *,
    budget: BmEvaluationBudget,
    trace: Callable[[tuple[object, ...]], None] | None,
) -> BmFiniteMatchResult:
    """Shared executor; callers qualify disjoint closed grammars first."""
    if any(type(x) is not int or x < 0 for x in (budget.steps, budget.depth)):
        raise ValueError("invalid local analyzer evaluation budget")
    operations = program.invocations[program.root].prefix
    raw = program.invocations[program.root].raw
    steps = 0

    def tick() -> None:
        nonlocal steps
        steps += 1
        if steps > budget.steps:
            raise BmEvaluationBudgetExceeded("local_evaluation_budget.steps")

    def emit(*event: object) -> None:
        if trace is not None:
            trace(event)

    def invoke(index: int, entry: BmBufferReader, depth: int) -> BmFiniteMatchResult:
        if depth > budget.depth:
            raise BmEvaluationBudgetExceeded("local_evaluation_budget.depth")
        tick()
        offset = operations[index].offset if index < len(operations) else len(raw) - 2
        emit("entry", depth, offset, entry.cursor, len(raw) - offset)
        reader = entry

        def finish(matched: bool, scratch: BmBufferReader | None = None):
            if scratch is not None:
                emit("scratch", depth, scratch.cursor)
            emit("return", depth, matched, reader.cursor)
            return BmFiniteMatchResult(matched, reader, scratch)

        while index < len(operations):
            tick()
            operation = operations[index]
            index += 1
            if operation.raw[:2] == b"\x90\x02":
                count = operation.raw[2]
                suffix = operation.offset + 3
                for _ in range(count):
                    tick()
                    # Only peek: child starts with the complete suffix and
                    # captures the unconsumed candidate as its own snapshot.
                    if not (
                        raw[suffix] != 0x90
                        and reader.cursor < reader.limit
                        and reader.subject[reader.cursor] != raw[suffix]
                    ):
                        child = invoke(index, reader, depth + 1)
                        if child.matched:
                            assert child.scratch is not None
                            reader = child.scratch
                            return finish(True, reader)
                        emit("failure_parent", depth, reader.cursor)
                    reader = replace(reader, cursor=(reader.cursor + 1) % (1 << 64))
                emit("endpoint", depth, reader.cursor)
                # Endpoint remains in this invocation, retaining its entry.
                continue
            if isinstance(operation, BmLiteral):
                for value in operation.value:
                    tick()
                    if (
                        reader.cursor >= reader.limit
                        or reader.subject[reader.cursor] != value
                    ):
                        return finish(False)
                    reader = replace(reader, cursor=reader.cursor + 1)
            elif isinstance(operation, BmClass):
                accepted = raw_04_05_byte_set(
                    operation.spec, pattern_preparation="identity"
                )
                for _ in range(operation.count):
                    tick()
                    if (
                        reader.cursor >= reader.limit
                        or reader.subject[reader.cursor] not in accepted
                    ):
                        return finish(False)
                    reader = replace(reader, cursor=reader.cursor + 1)
            elif operation.raw[:2] in (b"\x90\x01", b"\x90\x07"):
                for _ in range(int.from_bytes(operation.raw[2:], "little")):
                    tick()
                    if reader.cursor >= reader.limit:
                        return finish(False)
                    reader = replace(reader, cursor=reader.cursor + 1)
            elif operation.raw[:2] == b"\x90\x09":
                emit("raw09", depth, entry.cursor, entry.limit)
                step = buffer_backward_scan_transition(
                    entry.cursor,
                    entry.limit,
                    int.from_bytes(operation.raw[2:4], "little"),
                )
                reader = replace(entry, cursor=step.cursor)
                if not step.suffix_reachable:
                    return finish(False)
            else:
                raise ValueError("unqualified finite operation")
        tick()
        return finish(reader.cursor <= reader.limit, reader)

    try:
        return invoke(0, entry, 0)
    except RecursionError as error:
        raise BmEvaluationBudgetExceeded(
            "local_evaluation_budget.python_recursion"
        ) from error
