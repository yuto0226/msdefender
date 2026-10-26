"""Portable, renderer-independent serialization of the decoded BM view."""

from dataclasses import dataclass
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
)
from .core import JSONArray, JSONObject, SemanticIssue


def _object(items: dict[str, object]) -> JSONObject:
    return JSONObject(tuple((key, _value(value)) for key, value in items.items()))


def _value(value: object):
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, dict):
        return _object(value)
    if isinstance(value, (list, tuple)):
        return JSONArray(tuple(_value(item) for item in value))
    return value


OperationFidelity = Literal["exact", "conditional", "unsupported"]


@dataclass(frozen=True, slots=True)
class BmSemanticContext:
    """Caller-proven facts used for operation-specific IR fidelity."""

    reader_kind: Literal["BUFFER", "FILE"] | None = None
    translation: Literal["identity", "ascii_lowercase"] | None = None
    worker_modes: tuple[int, ...] | None = None
    capture_enabled: bool | None = None
    pattern_preparation: Literal["identity", "ascii_lowercase"] | None = None


def _pattern_preparation_is_exact(context: BmSemanticContext) -> bool:
    return (
        context.translation == "identity"
        and context.pattern_preparation in (None, "identity")
    ) or (
        context.translation == "ascii_lowercase"
        and context.pattern_preparation == "ascii_lowercase"
    )


def _raw_04_byte_set(spec: bytes, *, lowercase_pattern: bool) -> bytes:
    """Derive a bitmap from the wire spec plus caller-proven ingestion prep."""
    if lowercase_pattern:
        spec = bytes(byte + 0x20 if 0x41 <= byte <= 0x5A else byte for byte in spec)
    accepted = bytearray(256)
    cursor = 0
    while cursor < len(spec):
        if cursor + 2 < len(spec) and spec[cursor + 1] == 0x2D:
            low, high = spec[cursor], spec[cursor + 2]
            if low <= high:
                accepted[low : high + 1] = b"\x01" * (high - low + 1)
            cursor += 3
        else:
            accepted[spec[cursor]] = 1
            cursor += 1
    return bytes(index for index, present in enumerate(accepted) if present)


def _raw_04_context_is_exact(
    context: BmSemanticContext | None, pattern: BmPattern | None
) -> bool:
    return bool(
        context is not None
        and pattern is not None
        and pattern.issue is None
        and pattern.ended
        and not pattern.remaining_raw
        and b"\x90\x1b" not in pattern.raw
        and context.reader_kind == "BUFFER"
        and context.translation in ("identity", "ascii_lowercase")
        and _pattern_preparation_is_exact(context)
        and context.worker_modes == (1,)
        and context.capture_enabled is False
    )


def _operation_ir(
    operation: BmSemanticOperation,
    *,
    context: BmSemanticContext | None = None,
    pattern: BmPattern | None = None,
    explain_sequential_alternatives: bool = False,
    sequential_alternative_offsets: frozenset[int] = frozenset(),
) -> dict[str, object]:
    raw = operation.raw
    fidelity: OperationFidelity = "exact"
    requirements: list[str] = []
    result: dict[str, object] = {
        "kind": type(operation).__name__[2:].lower(),
        "raw_span": {"offset": operation.offset, "length": len(raw)},
        "raw_hex": raw.hex(),
        "raw_id": None,
        "dispatch": None,
        "operands_hex": "",
        "fidelity": fidelity,
        "requirements": requirements,
        "issues": [],
    }
    token = getattr(operation, "token", None)
    if token is not None:
        result["raw_id"] = token.raw_id
        result["dispatch"] = {
            "id": token.dispatch_id,
            "descriptor_flags": token.descriptor_flags,
        }
        result["operands_hex"] = token.operands.hex()

    decoded: dict[str, object] = {}
    if isinstance(operation, BmLiteral):
        decoded["value_hex"] = operation.value.hex()
    elif isinstance(operation, BmGap):
        decoded.update(
            minimum=operation.minimum,
            maximum=operation.maximum,
            bounded=operation.bounded,
        )
    elif isinstance(operation, BmAlternatives):
        decoded.update(
            widths=list(operation.widths),
            choices_hex=[choice.hex() for choice in operation.choices],
        )
    elif isinstance(operation, BmScan):
        decoded.update(kind=operation.kind, operand=operation.operand)
        result["fidelity"] = "conditional"
        result["requirements"] = [operation.support_note]
    elif isinstance(operation, BmClass):
        decoded.update(count=operation.count, spec_hex=operation.spec.hex())
        if (
            token is not None
            and token.raw_id == 0x04
            and token.dispatch_id == 0x04
            and token.descriptor_flags == 0x02
            and _raw_04_context_is_exact(context, pattern)
        ):
            assert context is not None
            accepted = _raw_04_byte_set(
                operation.spec,
                lowercase_pattern=context.translation == "ascii_lowercase",
            )
            decoded["engine_predicate"] = {
                "kind": "fixed_count_byte_class",
                "accepted_bytes_hex": accepted.hex(),
                "count": operation.count,
                "count_source": "token_byte_2",
                "cursor_advance_per_match": 1,
                "subject_translation": context.translation,
                "pattern_preparation": context.pattern_preparation,
                "class_spec_normalization": (
                    "BMPatternToLower_ascii_AZ"
                    if context.translation == "ascii_lowercase"
                    else "identity"
                ),
                "worker_modes": list(context.worker_modes),
            }
        else:
            result["fidelity"] = "conditional"
            result["requirements"] = [
                "requires BUFFER reader, known translation, worker mode 1, and no raw 90 1B byte sequence in the full pattern",
                "raw opcode 0x04 only; other class opcodes and aliases remain reader-specific",
                "ASCII-lowercase requires caller-proven pattern_preparation='ascii_lowercase'; BMPatternToLower normalizes literal/spec bytes, not count/framing",
            ]
    elif isinstance(operation, BmExtension):
        if operation.name == "RANGE_SEARCH":
            unit_width = 2 if token.descriptor_flags & 1 else 1
            decoded.update(
                name=operation.name,
                value=operation.value,
                value_unit="bytes",
                bitmap=operation.bitmap,
                wire_count=operation.value // unit_width,
                unit_width=unit_width,
                padding_mapped_byte=0 if unit_width == 2 else None,
            )
            exact_context = bool(
                context is not None
                and context.reader_kind == "BUFFER"
                and context.translation in ("identity", "ascii_lowercase")
                and _pattern_preparation_is_exact(context)
                and context.worker_modes == (1,)
                and context.capture_enabled is False
            )
            decoded["buffer_mode1_predicate"] = {
                "minimum_units": 0,
                "maximum_units": operation.value // unit_width,
                "candidate_order": "increasing unit boundaries, including endpoint",
                "membership": "the membership bit for the translated byte equals 0",
                "continuation": "retry the complete remaining pattern at each candidate",
                "suffix_before_membership": True,
                "failed_suffix_reader_committed": False,
                "scope": "Boolean acceptance; offsets and capture effects excluded",
                "pattern_preparation": (
                    context.pattern_preparation if context is not None else None
                ),
            }
            result["fidelity"] = "exact" if exact_context else "conditional"
            result["requirements"] = (
                []
                if exact_context
                else [
                    "BUFFER reader, identity or ASCII-lowercase translation, worker mode exactly 1, capture disabled",
                    "ASCII-lowercase requires caller-proven pattern_preparation='ascii_lowercase'; BMPatternToLower normalizes literal/spec bytes, not count/framing",
                ]
            )
        elif operation.name == "BACKREF_COMPARE":
            decoded.update(
                name=operation.name,
                capture_id=operation.value,
                lookup="BMBackrefCTX capture tree",
                comparison="translated subject bytes equal stored capture slice",
                failure="missing key, subject bounds, or byte mismatch",
            )
            result["requirements"] = [
                "requires a populated BM backref context for this capture_id",
                "capture producer and complete retry lifecycle are not modeled",
            ]
            result["fidelity"] = "conditional"
        else:
            decoded.update(
                name=operation.name, value=operation.value, bitmap=operation.bitmap
            )
            result["requirements"] = [
                "operation parameters are decoded, but reader state effects are not modeled"
            ]
            result["fidelity"] = "conditional"
    elif isinstance(operation, BmControlFlow):
        decoded.update(
            form=operation.form,
            displacement_source="subject",
            target_base=(
                "after_displacement"
                if operation.form in ("subject_rel8", "subject_rel16")
                else "decoded_instruction_end"
            ),
            displacement_width={
                "subject_rel8": 8,
                "subject_rel16": 16,
                "x86_relative_instruction": None,
            }[operation.form],
        )
        result["fidelity"] = "conditional"
        result["requirements"] = [
            "BUFFER reader must decode the displacement from the same subject",
            "worker mode controls translated-byte handling in the suffix",
            "capture state can save the span from the prior cursor to the target",
            "the remaining pattern must match from the computed target cursor",
        ]
    elif isinstance(operation, BmOpaque):
        result["kind"] = "opaque"
        result["fidelity"] = "unsupported"
        result["requirements"] = []
        result["issues"] = ["opcode semantics are unknown or unsupported"]
        if (
            explain_sequential_alternatives
            and pattern is not None
            and token is not None
            and token.raw_id == 0x03
            and operation.offset in sequential_alternative_offsets
        ):
            widths = tuple(token.operands)
            shared_start = operation.offset + len(operation.raw)
            shared_length = sum(widths)
            shared_end = shared_start + shared_length
            if widths and all(widths) and shared_end <= len(pattern.raw):
                shared = pattern.raw[shared_start:shared_end]
                choices = []
                cursor = 0
                for width in widths:
                    choices.append(shared[cursor : cursor + width].hex())
                    cursor += width
                decoded["engine_choice_model"] = {
                    "kind": "sequential_nonoverlapping_chunks",
                    "widths": list(widths),
                    "shared_raw_hex": shared.hex(),
                    "choices_hex": choices,
                    "suffix_offset": shared_end,
                    "suffix_lowering": "not_attempted",
                }
                result["requirements"] = [
                    "choices are attempted in order and each uses the same recursively matched suffix",
                    "YARA equivalence of suffix, reader state and output effects is unproven",
                ]
                result["issues"] = ["matcher_dependent_sequential_alternatives"]
    elif isinstance(operation, BmEnd):
        result["raw_id"] = 0
        decoded["terminator"] = True
    else:
        # Keep future operation variants lossless without inventing a wire name.
        result["kind"] = "unclassified"
        result["fidelity"] = "unsupported"
        result["issues"] = ["operation variant has no semantic serializer"]
    result["decoded"] = decoded
    return result


def serialize_bm_pattern(
    pattern: BmPattern,
    *,
    context: BmSemanticContext | None = None,
    explain_sequential_alternatives: bool = False,
) -> tuple[JSONObject, tuple[SemanticIssue, ...]]:
    """Serialize one decoder view, including its exact unparsed remainder."""
    semantic_pattern = interpret_bm_pattern(pattern)
    sequential_alternative_offsets: set[int] = set()
    consumed_until = 0
    for token in pattern.tokens:
        if token.offset < consumed_until:
            continue
        if token.kind == "OPCODE" and token.raw_id == 0x03:
            shared_start = token.offset + len(token.raw)
            shared_end = shared_start + sum(token.operands)
            if shared_end <= len(pattern.raw):
                sequential_alternative_offsets.add(token.offset)
                consumed_until = shared_end
                continue
        consumed_until = token.offset + len(token.raw)
    operations = [
        _operation_ir(
            operation,
            context=context,
            pattern=pattern,
            explain_sequential_alternatives=explain_sequential_alternatives,
            sequential_alternative_offsets=frozenset(sequential_alternative_offsets),
        )
        for operation in semantic_pattern.operations
    ]
    issues: list[dict[str, object]] = []
    semantic_issues: list[SemanticIssue] = []
    if pattern.issue is not None:
        issues.append(
            {
                "code": pattern.issue.code,
                "offset": pattern.issue.offset,
                "raw_id": pattern.issue.raw_id,
            }
        )
        semantic_issues.append(
            SemanticIssue(
                pattern.issue.code,
                "BM decoder stopped with an issue; remaining bytes are preserved.",
                (("offset", pattern.issue.offset),),
            )
        )
    if pattern.remaining_raw and pattern.ended:
        issues.append(
            {
                "code": "multi_segment_unparsed",
                "offset": pattern.consumed,
                "raw_hex": pattern.remaining_raw.hex(),
            }
        )
        semantic_issues.append(
            SemanticIssue(
                "multi_segment_unparsed",
                "Only the first BM segment is represented as operations.",
                (("offset", pattern.consumed),),
            )
        )
    remaining = {
        "offset": pattern.consumed,
        "length": len(pattern.remaining_raw),
        "raw_hex": pattern.remaining_raw.hex(),
    }
    data = _object(
        {
            "profile": pattern.profile,
            "pattern_preparation": (
                context.pattern_preparation if context is not None else None
            ),
            "raw_hex": pattern.raw.hex(),
            "consumed": pattern.consumed,
            "ended": pattern.ended,
            "operations": operations,
            "remaining_raw": remaining,
            "issues": issues,
        }
    )
    return data, tuple(semantic_issues)


__all__ = ["BmSemanticContext", "serialize_bm_pattern"]
