"""Strict lowering of the direct BM subset to a complete YARA string RHS."""

from dataclasses import dataclass
from enum import StrEnum
from typing import Literal

from .bm import (
    BmAlternatives,
    BmClass,
    BmEnd,
    BmExtension,
    BmGap,
    BmLiteral,
    BmOpaque,
    BmPattern,
    BmScan,
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

    Translation is the complete 256-byte map. HSTR BYTE_EXACT is a wire flag,
    not evidence for worker_mode. Invalid or incompatible facts fail closed.
    """

    reader_kind: Literal["BUFFER", "FILE"] | None = None
    translation: bytes | None = None
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

# Corpus- and engine-verified fixed byte sets. Keep raw IDs explicit: some
# aliases share a dispatch table entry but do not have identical evidence.
_FIXED_REPEAT_BYTES = {
    0x0D: bytes((0x09, 0x0A, 0x0D, 0x20)),
    0x26: bytes((0x09, 0x0A, 0x0D, 0x20)),
    0x0F: bytes((*range(0x30, 0x3A), *range(0xF7, 0x100))),
    0x28: bytes((*range(0x30, 0x3A), *range(0xF7, 0x100))),
    # 0x11 dispatches to g_ALRange. The worker rejects bitmap bit 1 and
    # consumes bit 0; under identity translation the accepted set is A-Z/a-z.
    0x11: bytes((*range(0x41, 0x5B), *range(0x61, 0x7B))),
    0x1C: bytes((*range(0x30, 0x3A), *range(0x41, 0x5B), *range(0xF8, 0x100))),
    0x2E: bytes((*range(0x30, 0x3A), *range(0x41, 0x5B), *range(0xF8, 0x100))),
    0x1E: bytes(
        (
            *range(0x30, 0x3A),
            *range(0x41, 0x47),
            *range(0x61, 0x67),
            *range(0xF8, 0x100),
        )
    ),
    0x30: bytes(
        (
            *range(0x30, 0x3A),
            *range(0x41, 0x47),
            *range(0x61, 0x67),
            *range(0xF8, 0x100),
        )
    ),
}


def _context_requirements(
    context: BmMatchContext | None,
) -> tuple[tuple[str, ...], tuple[BmRenderIssue, ...]]:
    if context is None:
        return _REQUIREMENTS, ()
    missing = []
    issues = []
    facts = (
        ("reader", context.reader_kind, context.reader_kind == "BUFFER"),
        (
            "translation",
            context.translation,
            isinstance(context.translation, bytes)
            and context.translation == _IDENTITY_TRANSLATION,
        ),
        (
            "worker_mode",
            context.worker_mode,
            type(context.worker_mode) is int
            and 0 <= context.worker_mode <= 0xFFFFFFFF
            and bool(context.worker_mode & 1),
        ),
        ("capture", context.capture_enabled, context.capture_enabled is False),
    )
    for requirement, (name, value, compatible) in zip(_REQUIREMENTS, facts):
        if value is None:
            missing.append(requirement)
        elif not compatible:
            issues.append(BmRenderIssue(f"incompatible_context.{name}", 0))
    return tuple(missing), tuple(issues)


def render_bm_yara(
    pattern: BmPattern, *, context: BmMatchContext | None = None
) -> BmYaraRender:
    """Return one compilable hex-string RHS, or no body with typed diagnostics.

    Only interpreter-produced complete literal choices are lowered. Unsupported
    operations and malformed tails invalidate the whole candidate, never just
    a suffix. Direct fixed skips and forward searches use the same worker
    requirements as gaps. Zero jumps vanish before checking YARA's grammar.
    """
    requirements, context_issues = _context_requirements(context)
    issues = list(context_issues)
    printable_preview = render_bm_printable_preview(pattern)
    if pattern.issue is not None:
        issue = pattern.issue
        issues.append(BmRenderIssue(f"decode.{issue.code}", issue.offset, issue.raw_id))
    if pattern.remaining_raw:
        issues.append(BmRenderIssue("remaining_raw", pattern.consumed))

    parts: list[tuple[str, int, bool, int | None]] = []
    output_limited = False
    for operation in interpret_bm_pattern(pattern).operations:
        if isinstance(operation, BmLiteral):
            if operation.value:
                parts.append(
                    (operation.value.hex(" ").upper(), operation.offset, False, None)
                )
        elif isinstance(operation, BmGap):
            if operation.maximum:
                jump = (
                    f"[0-{operation.maximum}]"
                    if operation.bounded
                    else f"[{operation.maximum}]"
                )
                parts.append((jump, operation.offset, True, operation.raw[1]))
        elif isinstance(operation, BmScan) and operation.kind in (
            "fixed_skip",
            "forward_search",
        ):
            if operation.operand:
                # The forward search's final outer continuation tries p+N.
                jump = (
                    f"[0-{operation.operand}]"
                    if operation.kind == "forward_search"
                    else f"[{operation.operand}]"
                )
                parts.append((jump, operation.offset, True, operation.raw[1]))
        elif isinstance(operation, BmAlternatives):
            if not operation.choices or any(not choice for choice in operation.choices):
                issues.append(
                    BmRenderIssue(
                        "empty_alternative", operation.offset, operation.token.raw_id
                    )
                )
            else:
                choices = " | ".join(
                    choice.hex(" ").upper() for choice in operation.choices
                )
                parts.append((f"( {choices} )", operation.offset, False, None))
        elif (
            isinstance(operation, BmExtension)
            and operation.name in ("RANGE_REPEAT", "RANGE_NEGATIVE_REPEAT")
            and operation.token.raw_id in _FIXED_REPEAT_BYTES
        ):
            count = operation.value
            if count:
                values = _FIXED_REPEAT_BYTES[operation.token.raw_id]
                atom = "( " + " | ".join(f"{value:02X}" for value in values) + " )"
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
    if issues:
        return BmYaraRender(
            None,
            BmYaraFidelity.UNSUPPORTED,
            tuple(issues),
            (),
            printable_preview,
        )
    projected_length = 4 + sum(len(part[0]) for part in parts) + max(0, len(parts) - 1)
    if projected_length > MAX_YARA_RHS_CHARS:
        return BmYaraRender(
            None,
            BmYaraFidelity.UNSUPPORTED,
            (BmRenderIssue("unsupported.output_limit", 0),),
            (),
            printable_preview,
        )
    body = "{ " + " ".join(part for part, _, _, _ in parts) + " }"
    fidelity = BmYaraFidelity.CONDITIONAL if requirements else BmYaraFidelity.EXACT
    return BmYaraRender(
        body,
        fidelity,
        requirements=requirements,
        printable_preview=printable_preview,
    )
