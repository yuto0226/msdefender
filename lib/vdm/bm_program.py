"""Bounded raw-authoritative BM invocation DAGs, independent of a renderer.

Each edge is a fresh worker invocation, not a continuation in its parent's
snapshot. Only immutable parsing is shared; no reader or matcher result lives
in this graph. Resource budgets describe this local analyzer, not the engine.
"""

from dataclasses import dataclass
from typing import Literal

from .bm import (
    BmAlternativeProgram,
    BmLiteral,
    BmPattern,
    BmSemanticOperation,
    decode_bm_pattern,
    interpret_bm_pattern,
    parse_bm_alternative_program,
    validate_bm_framing,
)


@dataclass(frozen=True, slots=True)
class BmProgramBudget:
    nodes: int = 1024
    depth: int = 64
    expanded_bytes: int = 1024 * 1024
    edges: int = 4096


DEFAULT_BM_PROGRAM_BUDGET = BmProgramBudget()


@dataclass(frozen=True, slots=True)
class BmProgramChoice:
    index: int
    source_span: tuple[int, int]
    suffix_span: tuple[int, int]
    invocation: int


@dataclass(frozen=True, slots=True)
class BmInvocation:
    id: int
    raw: bytes
    prefix: tuple[BmSemanticOperation, ...]
    prefix_raw: bytes
    terminal: Literal["end", "alternatives", "unsupported"]
    rewrite: BmAlternativeProgram | None = None
    choices: tuple[BmProgramChoice, ...] = ()
    issue: str | None = None
    ignored_after_end: bytes = b""


@dataclass(frozen=True, slots=True)
class BmExecutionProgram:
    profile: str
    preparation: str | None
    root: int
    invocations: tuple[BmInvocation, ...]
    issues: tuple[str, ...]

    @property
    def complete(self) -> bool:
        return not self.issues

    @property
    def primitive_closed(self) -> bool:
        return self.complete and all(
            operation.raw[:2] in (b"\x90\x01", b"\x90\x02")
            or isinstance(operation, BmLiteral)
            for node in self.invocations
            for operation in node.prefix
        )

    @property
    def root_end_tail_closed(self) -> bool:
        """Close only literal/raw01 root fragments, preserving the whole body.

        This is worker Boolean closure, not receiver acceptance or wrapper
        equivalence. Whole-body framing, derived flags, physical backref scans
        and mapper length guards remain upstream consumers of the original raw.
        """
        if not self.complete or len(self.invocations) != 1:
            return False
        root = self.invocations[self.root]
        if (
            self.profile != "1.443.903.0"
            or root.terminal != "end"
            or not root.ignored_after_end
            or b"\x90\x1b" in root.raw
            or not all(
                isinstance(operation, BmLiteral) or operation.raw[:2] == b"\x90\x01"
                for operation in root.prefix
            )
        ):
            return False
        try:
            validate_bm_framing(root.raw)
        except ValueError:
            return False
        return True


def build_bm_execution_program(
    pattern: BmPattern,
    *,
    preparation: str | None = None,
    budget: BmProgramBudget = DEFAULT_BM_PROGRAM_BUDGET,
) -> BmExecutionProgram:
    """Reparse raw bytes and stop each invocation at END or its first rewrite.

    A descriptor's shared block is never parsed in its parent's invocation.
    A choice is concatenated with the complete raw suffix before fresh decode.
    Identical children share parse nodes; edges keep distinct source provenance.
    """
    nodes: list[BmInvocation | None] = []
    memo: dict[bytes, int] = {}
    heights: dict[bytes, int] = {}
    issues: list[str] = []
    total_bytes = total_edges = 0

    def visit(raw: bytes, depth: int) -> int:
        nonlocal total_bytes, total_edges
        # Check depth on every path, including memoized references.
        if depth > budget.depth:
            raise ValueError("local_budget.depth")
        if raw in memo:
            if depth + heights[raw] > budget.depth:
                raise ValueError("local_budget.depth")
            return memo[raw]
        if len(nodes) >= budget.nodes:
            raise ValueError("local_budget.nodes")
        if total_bytes + len(raw) > budget.expanded_bytes:
            raise ValueError("local_budget.expanded_bytes")
        total_bytes += len(raw)
        identity = len(nodes)
        memo[raw] = identity
        nodes.append(None)
        decoded = decode_bm_pattern(raw, profile=pattern.profile)
        rewrite = None
        end = None
        for token in decoded.tokens:
            if token.kind == "END":
                end = token.offset
                break
            if token.kind == "OPCODE" and token.raw_id in (3, 0x17):
                rewrite = parse_bm_alternative_program(raw, token.offset)
                break
        prefix_end = rewrite.offset if rewrite is not None else end
        if prefix_end is None:
            prefix_end = decoded.consumed
        prefix_raw = raw[:prefix_end]
        prefix = interpret_bm_pattern(
            decode_bm_pattern(prefix_raw + b"\x90\x00", profile=pattern.profile)
        ).operations[:-1]
        if rewrite is not None:
            choices = []
            suffix_span = (rewrite.suffix_offset, len(raw) - rewrite.suffix_offset)
            for index, span in enumerate(rewrite.choice_spans):
                if total_edges >= budget.edges:
                    raise ValueError("local_budget.edges")
                total_edges += 1
                child_raw = rewrite.compose_choice(index)
                if len(child_raw) >= len(raw):
                    raise ValueError("invalid_nonshrinking_rewrite")
                child = visit(child_raw, depth + 1)
                choices.append(BmProgramChoice(index, span, suffix_span, child))
            node = BmInvocation(
                identity,
                raw,
                prefix,
                prefix_raw,
                "alternatives",
                rewrite,
                tuple(choices),
            )
        elif end is not None:
            node = BmInvocation(
                identity,
                raw,
                prefix,
                prefix_raw,
                "end",
                ignored_after_end=raw[end + 2 :],
            )
        else:
            reason = decoded.issue.code if decoded.issue else "missing_END"
            issues.append(reason)
            node = BmInvocation(
                identity,
                raw,
                prefix,
                prefix_raw,
                "unsupported",
                issue=reason,
            )
        heights[raw] = max(
            (1 + heights[nodes[edge.invocation].raw] for edge in node.choices),
            default=0,
        )
        nodes[identity] = node
        return identity

    try:
        root = visit(bytes(pattern.raw), 0)
    except ValueError as error:
        # An incomplete graph is deliberately not exposed as executable.
        return BmExecutionProgram(pattern.profile, preparation, 0, (), (str(error),))
    return BmExecutionProgram(
        pattern.profile,
        preparation,
        root,
        tuple(node for node in nodes if node is not None),
        tuple(issues),
    )
