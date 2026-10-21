"""Portable, renderer-independent serialization of the decoded BM view."""

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


def _operation_ir(
    operation: BmSemanticOperation,
    *,
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
        result["fidelity"] = "conditional"
        result["requirements"] = ["reader-specific class predicates are not modeled"]
    elif isinstance(operation, BmExtension):
        decoded.update(
            name=operation.name, value=operation.value, bitmap=operation.bitmap
        )
        result["fidelity"] = "conditional"
        result["requirements"] = [
            "operation parameters are decoded, but reader state effects are not modeled"
        ]
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
            "raw_hex": pattern.raw.hex(),
            "consumed": pattern.consumed,
            "ended": pattern.ended,
            "operations": operations,
            "remaining_raw": remaining,
            "issues": issues,
        }
    )
    return data, tuple(semantic_issues)


__all__ = ["serialize_bm_pattern"]
