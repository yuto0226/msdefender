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

    It does not establish scanner domains, validators, or reporting policy.
    A conditional body is a candidate under requirements, not an equivalence
    claim for a known incompatible worker context.
    """

    body: str | None
    fidelity: BmYaraFidelity
    diagnostics: tuple[BmRenderIssue, ...] = ()
    requirements: tuple[str, ...] = ()


_IDENTITY_TRANSLATION = bytes(range(256))
_REQUIREMENTS = (
    "BUFFER reader",
    "identity 256-byte translation",
    "worker mode bit0 set",
    "capture disabled",
)


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
    a suffix. Zero gaps vanish before checking YARA's boundary-jump grammar.
    """
    requirements, context_issues = _context_requirements(context)
    issues = list(context_issues)
    if pattern.issue is not None:
        issue = pattern.issue
        issues.append(BmRenderIssue(f"decode.{issue.code}", issue.offset, issue.raw_id))
    if pattern.remaining_raw:
        issues.append(BmRenderIssue("remaining_raw", pattern.consumed))

    parts: list[tuple[str, int, bool]] = []
    for operation in interpret_bm_pattern(pattern).operations:
        if isinstance(operation, BmLiteral):
            if operation.value:
                parts.append(
                    (operation.value.hex(" ").upper(), operation.offset, False)
                )
        elif isinstance(operation, BmGap):
            if operation.maximum:
                jump = (
                    f"[0-{operation.maximum}]"
                    if operation.bounded
                    else f"[{operation.maximum}]"
                )
                parts.append((jump, operation.offset, True))
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
                parts.append((f"( {choices} )", operation.offset, False))
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
    if not parts:
        issues.append(BmRenderIssue("empty_body", 0))
    else:
        if parts[0][2]:
            issues.append(BmRenderIssue("leading_jump", parts[0][1]))
        if parts[-1][2]:
            issues.append(BmRenderIssue("trailing_jump", parts[-1][1]))
    if issues:
        return BmYaraRender(
            None, BmYaraFidelity.UNSUPPORTED, tuple(issues), requirements
        )
    body = "{ " + " ".join(part for part, _, _ in parts) + " }"
    fidelity = BmYaraFidelity.CONDITIONAL if requirements else BmYaraFidelity.EXACT
    return BmYaraRender(body, fidelity, requirements=requirements)
