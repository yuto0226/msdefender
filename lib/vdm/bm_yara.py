"""Strict lowering of the direct BM subset to a complete YARA string RHS."""

from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Literal

from .bm import (
    BmAlternatives,
    BmClass,
    BmControlFlow,
    BmEnd,
    BmExtension,
    BmGap,
    BmLiteral,
    BmOpaque,
    BmPattern,
    BmScan,
    BmSemanticOperation,
    interpret_bm_pattern,
    render_bm_printable_preview,
)


class BmYaraFidelity(StrEnum):
    EXACT = "exact"
    CONDITIONAL = "conditional"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True, slots=True)
class BmRenderIssue:
    code: str
    offset: int
    raw_id: int | None = None


@dataclass(frozen=True, slots=True)
class BmMatchContext:
    """Explicit worker facts; None means unknown, not a permissive default.

    Translation is either a complete 256-byte map or one explicitly modeled
    map. HSTR BYTE_EXACT is a wire flag, not evidence for worker_mode. Invalid
    or incompatible facts fail closed.
    """

    reader_kind: Literal["BUFFER", "FILE"] | None = None
    translation: bytes | Literal["ascii_lowercase"] | None = None
    worker_mode: int | None = None
    capture_enabled: bool | None = None


@dataclass(frozen=True, slots=True)
class BmYaraRender:
    """EXACT concerns Boolean pattern acceptance on the same subject only.

    It does not establish first-success offsets, match ends, capture behavior,
    scanner domains, validators, or reporting policy.
    A conditional body is a candidate under requirements, not an equivalence
    claim for a known incompatible worker context.
    """

    body: str | None
    fidelity: BmYaraFidelity
    diagnostics: tuple[BmRenderIssue, ...] = ()
    requirements: tuple[str, ...] = ()
    printable_preview: str | None = None


_IDENTITY_TRANSLATION = bytes(range(256))
_REQUIREMENTS = (
    "BUFFER reader",
    "identity 256-byte translation",
    "worker mode bit0 set",
    "capture disabled",
)
MAX_YARA_RHS_CHARS = 32 * 1024
# libyara 4.5.4's lexer accepts at most 8190 regex-content characters,
# excluding the delimiters. This is distinct from quantifier interval limits.
MAX_YARA_REGEX_RHS_CHARS = 8192
# Default libyara verification/compilation limits (limits.h, re.c). A regex
# that compiles can still silently miss a longer match; never truncate BM N.
MAX_YARA_REGEX_MATCH_BYTES = 1024
MAX_YARA_REGEX_SPLITS = 128
MAX_YARA_REGEX_PATHS = 1024

# Corpus- and engine-verified fixed byte sets. Keep raw IDs explicit: some
# aliases share a dispatch table entry but do not have identical evidence.
_FIXED_REPEAT_BYTES = {
    0x0D: bytes((0x09, 0x0A, 0x0D, 0x20)),
    0x26: bytes((0x09, 0x0A, 0x0D, 0x20)),
    0x0F: bytes(range(0x30, 0x3A)),
    0x28: bytes(range(0x30, 0x3A)),
    # 0x11 dispatches to g_ALRange. The worker rejects bitmap bit 1 and
    # consumes bit 0; under identity translation the accepted set is A-Z/a-z.
    0x11: bytes((*range(0x41, 0x5B), *range(0x61, 0x7B))),
    # RANGE_NEGATIVE_REPEAT names the IR operation, not an inverted byte set.
    0x1C: bytes((*range(0x30, 0x3A), *range(0x41, 0x5B), *range(0x61, 0x7B))),
    0x2E: bytes((*range(0x30, 0x3A), *range(0x41, 0x5B), *range(0x61, 0x7B))),
    0x1E: bytes(
        (
            *range(0x30, 0x3A),
            *range(0x41, 0x47),
            *range(0x61, 0x67),
        )
    ),
    0x30: bytes(
        (
            *range(0x30, 0x3A),
            *range(0x41, 0x47),
            *range(0x61, 0x67),
        )
    ),
}


def _context_requirements(
    context: BmMatchContext | None,
    *,
    range_search: bool = False,
) -> tuple[tuple[str, ...], tuple[BmRenderIssue, ...]]:
    requirements = (
        (*_REQUIREMENTS[:2], "worker mode 1", _REQUIREMENTS[3])
        if range_search
        else _REQUIREMENTS
    )
    if context is None:
        return requirements, ()
    missing = []
    issues = []
    facts = (
        ("reader", context.reader_kind, context.reader_kind == "BUFFER"),
        (
            "translation",
            context.translation,
            (
                isinstance(context.translation, bytes)
                and context.translation == _IDENTITY_TRANSLATION
            )
            or context.translation == "ascii_lowercase",
        ),
        (
            "worker_mode",
            context.worker_mode,
            type(context.worker_mode) is int
            and 0 <= context.worker_mode <= 0xFFFFFFFF
            and (
                context.worker_mode == 1
                if range_search
                else bool(context.worker_mode & 1)
            ),
        ),
        ("capture", context.capture_enabled, context.capture_enabled is False),
    )
    for requirement, (name, value, compatible) in zip(requirements, facts):
        if value is None:
            missing.append(requirement)
        elif not compatible:
            issues.append(BmRenderIssue(f"incompatible_context.{name}", 0))
    return tuple(missing), tuple(issues)


def _regex_byte_class(values: bytes) -> str:
    """A compact class of raw subject bytes, including high bytes and NUL."""
    ranges = []
    start = end = values[0]
    for value in values[1:]:
        if value == end + 1:
            end = value
        else:
            ranges.append((start, end))
            start = end = value
    ranges.append((start, end))
    return (
        "["
        + "".join(
            f"\\x{start:02X}" + (f"-\\x{end:02X}" if start != end else "")
            for start, end in ranges
        )
        + "]"
    )


def _regex_literal(data: bytes, lowercase_map: bool) -> str:
    return "".join(
        _regex_byte_class(bytes((byte & ~0x20, byte | 0x20)))
        if lowercase_map and (0x41 <= byte <= 0x5A or 0x61 <= byte <= 0x7A)
        else f"\\x{byte:02X}"
        for byte in data
    )


def _regex_repeat(atom: str, count: int, *, bounded: bool) -> str:
    """Repeat one grouped unit without exceeding YARA's 32767 interval limit.

    The bounded branches have disjoint lengths: 0..32767 and 32768..count.
    Keep the complete continuation outside this group. Splitting into adjacent
    optional ranges would instead introduce overlapping decompositions.
    """
    limit = 32767
    if not bounded:
        full, remainder = divmod(count, limit)
        # YARA forbids mixing greedy and lazy quantifiers even for {N},
        # whose accepted language is independent of this marker.
        return (f"{atom}{{{limit}}}?" * full) + (
            f"{atom}{{{remainder}}}?" if remainder else ""
        )
    if count <= limit:
        return f"{atom}{{0,{count}}}?"
    return (
        f"({atom}{{0,{limit}}}?|{atom}{{{limit}}}?{atom}"
        + _regex_repeat(atom, count - limit - 1, bounded=True)
        + ")"
    )


_SEARCH_RANGE_BYTES = {
    0x0C: bytes((0x0A, 0x0D)),
    0x0E: _FIXED_REPEAT_BYTES[0x0D],
    0x10: _FIXED_REPEAT_BYTES[0x0F],
    0x12: _FIXED_REPEAT_BYTES[0x11],
    0x1D: _FIXED_REPEAT_BYTES[0x1C],
    0x1F: _FIXED_REPEAT_BYTES[0x1E],
}


def _simplify_search_operations(
    operations: tuple[BmSemanticOperation, ...],
) -> tuple[BmSemanticOperation, ...]:
    """Boolean-only simplification; the original decoded/semantic IR stays intact."""
    nonempty = []
    for operation in operations:
        if (
            isinstance(operation, BmEnd)
            or (isinstance(operation, BmGap) and operation.maximum == 0)
            or (
                isinstance(operation, BmScan)
                and operation.kind in ("fixed_skip", "forward_search")
                and operation.operand == 0
            )
            or (
                isinstance(operation, BmExtension)
                and operation.name == "RANGE_SEARCH"
                and operation.value == 0
            )
        ):
            continue
        nonempty.append(operation)
    # The first candidate of a terminal search has an empty continuation and
    # succeeds at zero units. This removes no required subject consumption.
    while (
        nonempty
        and isinstance(nonempty[-1], BmExtension)
        and nonempty[-1].name == "RANGE_SEARCH"
    ):
        nonempty.pop()
    merged: list[BmSemanticOperation] = []
    for operation in nonempty:
        previous = merged[-1] if merged else None
        if (
            isinstance(previous, BmExtension)
            and isinstance(operation, BmExtension)
            and previous.name == operation.name == "RANGE_SEARCH"
            and previous.token.dispatch_id == operation.token.dispatch_id
            and (previous.token.descriptor_flags & 1)
            == (operation.token.descriptor_flags & 1)
        ):
            # R{0,N} R{0,M} = R{0,N+M}; only this rendering copy is merged.
            merged[-1] = replace(previous, value=previous.value + operation.value)
        else:
            merged.append(operation)
    return tuple(merged)


def render_bm_yara(
    pattern: BmPattern, *, context: BmMatchContext | None = None
) -> BmYaraRender:
    """Return one complete hex/regex RHS, or no body with typed diagnostics.

    Only interpreter-produced complete literal choices are lowered. Unsupported
    operations and malformed tails invalidate the whole candidate, never just
    a suffix. Direct fixed skips and forward searches use the same worker
    requirements as gaps. Zero jumps vanish before checking YARA's grammar.
    RANGE_SEARCH composes a bounded byte class with the complete continuation
    in a regex, restricted to BUFFER/mode 1/no captures and backend budgets.
    """
    operations = interpret_bm_pattern(pattern).operations
    range_search = any(
        isinstance(operation, BmExtension) and operation.name == "RANGE_SEARCH"
        for operation in operations
    )
    requirements, context_issues = _context_requirements(
        context, range_search=range_search
    )
    if range_search:
        operations = _simplify_search_operations(operations)
    issues = list(context_issues)
    printable_preview = render_bm_printable_preview(pattern)
    if pattern.issue is not None:
        issue = pattern.issue
        issues.append(BmRenderIssue(f"decode.{issue.code}", issue.offset, issue.raw_id))
    if pattern.remaining_raw:
        issues.append(BmRenderIssue("remaining_raw", pattern.consumed))

    parts: list[tuple[str, int, bool, int | None]] = []
    lowercase_map = context is not None and context.translation == "ascii_lowercase"
    output_limited = False
    has_required_bytes = False
    maximum_match_bytes = 0
    regex_splits = 0
    regex_paths = 1
    for operation in operations:
        if isinstance(operation, BmLiteral):
            if operation.value:
                has_required_bytes = True
                maximum_match_bytes += len(operation.value)
                if range_search:
                    estimated = sum(
                        10
                        if lowercase_map
                        and (0x41 <= byte <= 0x5A or 0x61 <= byte <= 0x7A)
                        else 4
                        for byte in operation.value
                    )
                    if (
                        sum(len(part[0]) for part in parts) + estimated + 2
                        > MAX_YARA_RHS_CHARS
                    ):
                        output_limited = True
                        issues.append(
                            BmRenderIssue("unsupported.output_limit", operation.offset)
                        )
                        continue
                    literal = _regex_literal(operation.value, lowercase_map)
                elif lowercase_map:
                    estimated = (
                        sum(
                            12 if 0x41 <= byte <= 0x5A or 0x61 <= byte <= 0x7A else 2
                            for byte in operation.value
                        )
                        + len(operation.value)
                        - 1
                    )
                    existing = sum(len(part[0]) for part in parts) + len(parts)
                    if existing + estimated + 4 > MAX_YARA_RHS_CHARS:
                        output_limited = True
                        issues.append(
                            BmRenderIssue("unsupported.output_limit", operation.offset)
                        )
                        continue
                    atoms = []
                    for byte in operation.value:
                        if 0x41 <= byte <= 0x5A:
                            byte += 0x20
                        if 0x61 <= byte <= 0x7A:
                            atoms.append(f"( {byte - 0x20:02X} | {byte:02X} )")
                        else:
                            atoms.append(f"{byte:02X}")
                    literal = " ".join(atoms)
                else:
                    literal = operation.value.hex(" ").upper()
                parts.append((literal, operation.offset, False, None))
        elif isinstance(operation, BmGap):
            if operation.maximum:
                has_required_bytes |= not operation.bounded
                maximum_match_bytes += operation.maximum
                regex_splits += int(operation.bounded)
                if operation.bounded:
                    regex_paths = min(
                        MAX_YARA_REGEX_PATHS + 1,
                        regex_paths * (operation.maximum + 1),
                    )
                jump = (
                    _regex_repeat(
                        r"[\x00-\xFF]", operation.maximum, bounded=operation.bounded
                    )
                    if range_search
                    else (
                        f"[0-{operation.maximum}]"
                        if operation.bounded
                        else f"[{operation.maximum}]"
                    )
                )
                parts.append((jump, operation.offset, True, operation.raw[1]))
        elif isinstance(operation, BmScan) and operation.kind in (
            "fixed_skip",
            "forward_search",
        ):
            if operation.operand:
                has_required_bytes |= operation.kind == "fixed_skip"
                maximum_match_bytes += operation.operand
                regex_splits += int(operation.kind == "forward_search")
                if operation.kind == "forward_search":
                    regex_paths = min(
                        MAX_YARA_REGEX_PATHS + 1,
                        regex_paths * (operation.operand + 1),
                    )
                # The forward search's final outer continuation tries p+N.
                jump = (
                    _regex_repeat(
                        r"[\x00-\xFF]",
                        operation.operand,
                        bounded=operation.kind == "forward_search",
                    )
                    if range_search
                    else (
                        f"[0-{operation.operand}]"
                        if operation.kind == "forward_search"
                        else f"[{operation.operand}]"
                    )
                )
                parts.append((jump, operation.offset, True, operation.raw[1]))
        elif isinstance(operation, BmAlternatives):
            if not operation.choices or any(not choice for choice in operation.choices):
                issues.append(
                    BmRenderIssue(
                        "empty_alternative", operation.offset, operation.token.raw_id
                    )
                )
            elif operation.token.raw_id == 0x17:
                issues.append(
                    BmRenderIssue(
                        "unsupported.first_success_alternatives",
                        operation.offset,
                        operation.token.raw_id,
                    )
                )
            elif lowercase_map:
                issues.append(
                    BmRenderIssue(
                        "unsupported.ascii_lowercase_alternatives",
                        operation.offset,
                        operation.token.raw_id,
                    )
                )
            else:
                has_required_bytes = True
                maximum_match_bytes += max(map(len, operation.choices))
                regex_splits += len(operation.choices) - 1
                regex_paths = min(
                    MAX_YARA_REGEX_PATHS + 1, regex_paths * len(operation.choices)
                )
                if range_search:
                    choices = "|".join(
                        _regex_literal(choice, False) for choice in operation.choices
                    )
                    alternative = f"({choices})"
                else:
                    choices = " | ".join(
                        choice.hex(" ").upper() for choice in operation.choices
                    )
                    alternative = f"( {choices} )"
                parts.append((alternative, operation.offset, False, None))
        elif (
            isinstance(operation, BmExtension)
            and operation.name == "RANGE_SEARCH"
            and operation.token.dispatch_id in _SEARCH_RANGE_BYTES
        ):
            # value is an effective BYTE budget. Alias units are class+NUL,
            # so wire_count counts pairs, never arbitrary byte candidates.
            unit_width = 2 if operation.token.descriptor_flags & 1 else 1
            wire_count = operation.value // unit_width
            if wire_count:
                maximum_match_bytes += operation.value
                regex_splits += 1
                regex_paths = min(
                    MAX_YARA_REGEX_PATHS + 1, regex_paths * (wire_count + 1)
                )
                atom = _regex_byte_class(
                    _SEARCH_RANGE_BYTES[operation.token.dispatch_id]
                )
                # All six sets are invariant under the modeled ASCII folding;
                # mapped-zero's preimage is exactly NUL for either allowed map.
                if unit_width == 2:
                    atom = f"({atom}\\x00)"
                parts.append(
                    (
                        _regex_repeat(atom, wire_count, bounded=True),
                        operation.offset,
                        False,
                        operation.token.raw_id,
                    )
                )
        elif lowercase_map and isinstance(operation, BmExtension):
            issues.append(
                BmRenderIssue(
                    "unsupported.ascii_lowercase_extension",
                    operation.offset,
                    operation.token.raw_id,
                )
            )
        elif (
            isinstance(operation, BmExtension)
            and operation.name in ("RANGE_REPEAT", "RANGE_NEGATIVE_REPEAT")
            and operation.token.raw_id in _FIXED_REPEAT_BYTES
        ):
            count = operation.value
            if count:
                has_required_bytes = True
                maximum_match_bytes += count
                values = _FIXED_REPEAT_BYTES[operation.token.raw_id]
                atom = "( " + " | ".join(f"{value:02X}" for value in values) + " )"
                if operation.token.descriptor_flags & 1:
                    # The IR count is a byte budget, but the worker consumes
                    # each alias unit as one class byte followed by mapped zero.
                    count //= 2
                    atom += " 00"
                if range_search:
                    atom = _regex_byte_class(values)
                    if operation.token.descriptor_flags & 1:
                        atom = f"({atom}\\x00)"
                    parts.append(
                        (
                            _regex_repeat(atom, count, bounded=False),
                            operation.offset,
                            False,
                            operation.token.raw_id,
                        )
                    )
                    continue
                # Check before multiplication so malformed or extreme counts
                # cannot allocate an unbounded candidate string.
                estimated = count * len(atom) + count - 1
                existing = sum(len(part[0]) for part in parts) + len(parts)
                if existing + estimated + 4 > MAX_YARA_RHS_CHARS:
                    output_limited = True
                    issues.append(
                        BmRenderIssue(
                            "unsupported.output_limit",
                            operation.offset,
                            operation.token.raw_id,
                        )
                    )
                else:
                    parts.append(
                        (" ".join((atom,) * count), operation.offset, False, None)
                    )
        elif isinstance(operation, BmEnd):
            continue
        else:
            raw_id = operation.raw[1]
            if isinstance(operation, BmScan):
                name = operation.kind
            elif isinstance(operation, BmClass):
                name = f"class_{operation.token.dispatch_id:02X}"
            elif isinstance(operation, BmExtension):
                name = operation.name
            elif isinstance(operation, BmControlFlow):
                name = operation.form
            elif isinstance(operation, BmOpaque):
                name = f"OP_{raw_id:02X}"
            issues.append(
                BmRenderIssue(f"unsupported.{name}", operation.offset, raw_id)
            )
    if not parts and not output_limited:
        issues.append(BmRenderIssue("empty_body", 0))
    elif parts:
        if parts[0][2]:
            issues.append(BmRenderIssue("leading_jump", parts[0][1], parts[0][3]))
        if parts[-1][2]:
            issues.append(BmRenderIssue("trailing_jump", parts[-1][1], parts[-1][3]))
        if range_search and not has_required_bytes:
            # YARA never scans a zero-byte subject, even for nullable regexes.
            # The worker can accept there; do not claim Boolean equivalence.
            issues.append(BmRenderIssue("unsupported.empty_match", 0))
    if range_search:
        if maximum_match_bytes > MAX_YARA_REGEX_MATCH_BYTES:
            issues.append(BmRenderIssue("unsupported.regex_span_limit", 0))
        if regex_splits > MAX_YARA_REGEX_SPLITS:
            issues.append(BmRenderIssue("unsupported.regex_complexity_limit", 0))
        if regex_paths > MAX_YARA_REGEX_PATHS:
            issues.append(BmRenderIssue("unsupported.regex_fiber_limit", 0))
    if issues:
        return BmYaraRender(
            None,
            BmYaraFidelity.UNSUPPORTED,
            tuple(issues),
            (),
            printable_preview,
        )
    projected_length = sum(len(part[0]) for part in parts) + (
        2 if range_search else 4 + max(0, len(parts) - 1)
    )
    if projected_length > MAX_YARA_RHS_CHARS:
        return BmYaraRender(
            None,
            BmYaraFidelity.UNSUPPORTED,
            (BmRenderIssue("unsupported.output_limit", 0),),
            (),
            printable_preview,
        )
    if range_search and projected_length > MAX_YARA_REGEX_RHS_CHARS:
        return BmYaraRender(
            None,
            BmYaraFidelity.UNSUPPORTED,
            (BmRenderIssue("unsupported.regex_limit", 0),),
            (),
            printable_preview,
        )
    body = (
        "/" + "".join(part for part, _, _, _ in parts) + "/"
        if range_search
        else "{ " + " ".join(part for part, _, _, _ in parts) + " }"
    )
    fidelity = BmYaraFidelity.CONDITIONAL if requirements else BmYaraFidelity.EXACT
    return BmYaraRender(
        body,
        fidelity,
        requirements=requirements,
        printable_preview=printable_preview,
    )
