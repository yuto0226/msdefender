"""Portable, renderer-independent serialization of the decoded BM view."""

from bisect import bisect_right
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
    decode_bm_pattern,
    interpret_bm_pattern,
    parse_bm_alternative_program,
    raw_04_05_byte_set,
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
    match_offset_output_supplied: bool | None = None
    matches_vector_supplied: bool | None = None


def _pattern_preparation_is_exact(context: BmSemanticContext) -> bool:
    return (
        context.translation == "identity"
        and context.pattern_preparation in (None, "identity")
    ) or (
        context.translation == "ascii_lowercase"
        and context.pattern_preparation == "ascii_lowercase"
    )


def _worker_modes_are_mode1_equivalent(
    context: BmSemanticContext, pattern: BmPattern | None
) -> bool:
    """Keep mode1; admit only the proven identity/null-output mode1/3 domain."""
    if context.worker_modes == (1,):
        return True
    return bool(
        context.worker_modes == (1, 3)
        and context.reader_kind == "BUFFER"
        and context.translation == "identity"
        and context.pattern_preparation == "identity"
        and context.capture_enabled is False
        and context.match_offset_output_supplied is False
        and context.matches_vector_supplied is False
        and pattern is not None
        and pattern.issue is None
        and pattern.ended
        and not pattern.remaining_raw
        # BMInitBackrefs scans physical bytes, including operands and chunks.
        and b"\x90\x1b" not in pattern.raw
    )


def _primary_class_context_is_exact(
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
        and _worker_modes_are_mode1_equivalent(context, pattern)
        and context.capture_enabled is False
    )


def _relative_instruction_context_is_exact(
    context: BmSemanticContext | None, pattern: BmPattern | None
) -> bool:
    """Qualify the tested single-raw13 literal/raw01/END composition only."""
    if not (
        context is not None
        and pattern is not None
        and pattern.issue is None
        and pattern.ended
        and not pattern.remaining_raw
        and b"\x90\x1b" not in pattern.raw
        and context.reader_kind == "BUFFER"
        and context.translation == "identity"
        and context.pattern_preparation == "identity"
        and context.worker_modes in ((1,), (3,), (1, 3))
        and context.capture_enabled is False
        and context.match_offset_output_supplied is False
        and context.matches_vector_supplied is False
    ):
        return False
    raw_ids = [token.raw_id for token in pattern.tokens if token.kind == "OPCODE"]
    return raw_ids.count(0x13) == 1 and all(
        raw_id in (0x01, 0x13) for raw_id in raw_ids
    )


def _operation_ir(
    operation: BmSemanticOperation,
    *,
    context: BmSemanticContext | None = None,
    pattern: BmPattern | None = None,
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
        if (
            operation.kind == "backward_scan"
            and context is not None
            and context.reader_kind == "BUFFER"
            and context.worker_modes
            and all(mode in (1, 3) for mode in context.worker_modes)
        ):
            decoded["engine_transition"] = {
                "reader": "BUFFER",
                "worker_modes": list(context.worker_modes),
                "snapshot_anchor": "worker_invocation_entry",
                "restore": ["base", "limit", "cursor"],
                "count_source": "LE16 token operands",
                "count_unit": "byte",
                "cursor_width_bits": 64,
                "pre_decrement_failure": "cursor > snapshot.limit",
                "decrement": "cursor = (cursor - 1) modulo 2^64",
                "post_count_continuation": "cursor < snapshot.limit",
                "failure_preserves_mutated_cursor": True,
                "primitive": "buffer_backward_scan_transition",
                "engine_evidence": "BUFFER handler 0x1800EEA02..0x1800EEA7B; worker-entry snapshot 0x1800EDBBB/0x1800EDBCA/0x1800EDBD9",
                "success_means": "suffix is reachable; it must still match",
                "suffix_and_capture_effects_modeled": False,
            }
            result["requirements"] = [
                "requires the worker-invocation entry snapshot, not the current cursor",
                "only the mode1/3 byte-count transition is modeled; suffix acceptance and capture effects remain separate",
            ]
    elif isinstance(operation, BmClass):
        decoded.update(count=operation.count, spec_hex=operation.spec.hex())
        if (
            token is not None
            and token.raw_id in (0x04, 0x05)
            and token.dispatch_id == token.raw_id
            and token.descriptor_flags == 0x02
            and _primary_class_context_is_exact(context, pattern)
        ):
            assert context is not None
            accepted = raw_04_05_byte_set(
                operation.spec,
                pattern_preparation=(
                    "ascii_lowercase"
                    if context.translation == "ascii_lowercase"
                    else "identity"
                ),
            )
            decoded["engine_predicate"] = {
                "accepted_bytes_hex": accepted.hex(),
                "count_source": "token_byte_2",
                "subject_translation": context.translation,
                "pattern_preparation": context.pattern_preparation,
                "class_spec_normalization": (
                    "BMPatternToLower_ascii_AZ"
                    if context.translation == "ascii_lowercase"
                    else "identity"
                ),
                "worker_modes": list(context.worker_modes),
            }
            if token.raw_id == 0x04:
                decoded["engine_predicate"].update(
                    kind="fixed_count_byte_class",
                    count=operation.count,
                    cursor_advance_per_match=1,
                )
            else:
                decoded["engine_predicate"].update(
                    kind="bounded_byte_class_search",
                    minimum_units=0,
                    maximum_units=operation.count,
                    unit_width=1,
                    candidate_order="increasing unit boundaries, including endpoint",
                    continuation="retry the complete remaining pattern at each candidate",
                    suffix_before_membership=True,
                    failed_suffix_reader_committed=False,
                    scope=(
                        "guarded BUFFER/identity mode1/3 Boolean acceptance; outputs excluded"
                        if context.worker_modes == (1, 3)
                        else "BUFFER/mode1/capture disabled Boolean acceptance; offsets excluded"
                    ),
                    caller_address="0x1800EE352",
                    helper_address="0x1800F04C0",
                    engine_evidence=(
                        "primary raw05 caller; complete worker/helper mode dataflow and 3580 identity/null-output mode1/3 differential pairs"
                        if context.worker_modes == (1, 3)
                        else "primary raw05 caller and complete original-worker differential"
                    ),
                )
        else:
            result["fidelity"] = "conditional"
            result["requirements"] = [
                "requires BUFFER reader, known translation, worker mode 1 or the guarded identity mode1/3 profile, and no raw 90 1B byte sequence in the full pattern",
                "primary raw opcodes 0x04/0x05 only; other class opcodes and aliases remain reader-specific",
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
                and _worker_modes_are_mode1_equivalent(context, pattern)
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
            if exact_context and context is not None and context.worker_modes == (1, 3):
                decoded["buffer_mode1_predicate"]["worker_modes"] = [1, 3]
                decoded["buffer_mode1_predicate"]["mode_equivalence_scope"] = (
                    "guarded identity/raw-identity/null-output complete-pattern profile"
                )
            result["fidelity"] = "exact" if exact_context else "conditional"
            result["requirements"] = (
                []
                if exact_context
                else [
                    "BUFFER reader, mode1 with known translation or guarded identity mode1/3 profile, capture disabled",
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
        if token.raw_id == 0x13:
            decoded["engine_transition"] = {
                "primitive": "buffer_relative_instruction_transition",
                "reader": "BUFFER",
                "worker_modes": [1, 3],
                "subject_storage": "complete finite contiguous buffer; declared size equals len(subject)",
                "wire_operands": False,
                "instruction_source": "untranslated subject bytes at current cursor",
                "rel8_opcodes": ["70-7F", "E0-E3", "EB"],
                "rel32_opcodes": ["E8", "E9", "0F 80-8F"],
                "target": "(instruction_end + signed_displacement) modulo 2^64, except INT32_MIN",
                "rel32_int_min_target": "(instruction_end + 0x80000000) modulo 2^64",
                "target_bounds_checked_before_suffix": False,
                "decode_failure_preserves_consumed_bytes": True,
                "suffix_failure_parent_cursor": "computed target; no rollback",
                "suffix_success_parent_reader": "adopt successful child reader",
                "suffix_translation": "caller map applies to suffix, not instruction decode",
                "capture_effects_modeled": False,
                "qualified_capture_observation": {
                    "evaluator_support": False,
                    "cases": 12,
                    "domain": "initializer mode1; worker modes1/3; identity map; rel8; single key ID0; null offset outputs; allocation succeeds; captured bytes within supplied backing",
                    "producer": "original BMInitBackrefs, worker capture producer, AddBackref and STL; success-only guest operator new seam",
                    "nonnegative_span": "[original_cursor, target); observed lengths 5 (positive) and 2 (zero)",
                    "suffix_failure": "saved node remains; no capture rollback",
                    "negative_displacement": "capture enabled but AddBackref skipped; tree empty; raw1B fails for missing capture after successful literal",
                    "next_id": "2 after successful suffix literal; 1 after early literal failure",
                    "excluded": [
                        "initializer mode3",
                        "multiple keys and tree rotations",
                        "destructor and complete caller lifecycle",
                        "allocation failure and exceptions",
                        "captured bytes beyond supplied backing",
                    ],
                },
                "qualified_composition": "one raw13; literal/9090/raw01/END only; complete framing, no physical 90 1B; identity/raw preparation, null backrefs and external outputs",
                "engine_evidence": "raw13 handler 0x1800EEBB9; opcode/second-byte/rel8/rel32 size gates at 0x1800EEBC6/0x1800EF297/0x1800EEBE7/0x1800EF2B4; 148 original-machine-code Unicorn calls, not host-native",
            }
            result["requirements"] = [
                "requires BUFFER, identity map and raw preparation, null backrefs and null external outputs, worker modes1/3",
                "qualified composition requires a single raw13 with literal/9090/raw01/END prefix and suffix, complete framing and no physical 90 1B",
                "other readers, modes, translation/preparation profiles, suffix grammars and capture lifecycle remain conditional",
            ]
            if _relative_instruction_context_is_exact(context, pattern):
                result["fidelity"] = "exact"
                result["requirements"] = []
    elif isinstance(operation, BmOpaque):
        result["kind"] = "opaque"
        result["fidelity"] = "unsupported"
        result["requirements"] = []
        result["issues"] = ["opcode semantics are unknown or unsupported"]
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


def _program_structure(pattern: BmPattern) -> dict[str, object]:
    """Discover local rewrites in source order without building an execution AST."""
    source = pattern.raw
    nodes: list[dict[str, object]] = []
    stop: dict[str, object] | None = None
    cursor = 0
    first_end = pattern.consumed - 2 if pattern.ended else None
    token_offsets = [token.offset for token in pattern.tokens]

    def span(offset: int, length: int) -> dict[str, int]:
        return {"offset": offset, "length": length}

    for token in pattern.tokens:
        if token.offset < cursor:
            continue
        if token.kind == "END":
            break
        if token.kind != "OPCODE" or token.raw_id not in (0x03, 0x17):
            continue
        try:
            plan = parse_bm_alternative_program(source, token.offset)
        except ValueError as error:
            stop = {
                "offset": token.offset,
                "reason": "invalid_local_alternatives_bounds",
                "detail": str(error),
                "redecode_required": False,
            }
            break
        shared_start, shared_length = plan.shared_block_span
        suffix = span(plan.suffix_offset, len(source) - plan.suffix_offset)
        nodes.append(
            {
                "kind": "raw_alternatives_rewrite",
                "offset": plan.offset,
                "raw_id": plan.raw_id,
                "widths": list(plan.widths),
                "descriptor_span": span(plan.offset, plan.descriptor_length),
                "shared_block_span": span(shared_start, shared_length),
                "suffix_span": suffix,
                "choices": [
                    {
                        "index": index,
                        "width": length,
                        "choice_span": span(offset, length),
                        "parts": [span(offset, length), suffix],
                    }
                    for index, (offset, length) in enumerate(plan.choice_spans)
                ],
                "concatenate_before_decode": True,
                "descriptor_reachability": "unproven",
            }
        )
        cursor = plan.suffix_offset
        if first_end is not None and cursor > first_end:
            stop = {
                "offset": cursor,
                "reason": "shared_block_crosses_first_decoded_end",
                "redecode_required": True,
            }
            break
        containing_index = bisect_right(token_offsets, cursor) - 1
        containing = pattern.tokens[containing_index] if containing_index >= 0 else None
        if containing is not None and not (
            containing.offset < cursor < containing.offset + len(containing.raw)
        ):
            containing = None
        if containing is not None and not (
            containing.kind == "LITERAL" and containing.raw == containing.literal
        ):
            stop = {
                "offset": cursor,
                "reason": "suffix_starts_inside_opcode_or_escape",
                "redecode_required": True,
            }
            break
        if cursor > pattern.consumed:
            stop = {
                "offset": cursor,
                "reason": "suffix_beyond_decoder_view",
                "redecode_required": True,
            }
            break
    return {
        "view": "local_raw_rewrite",
        "source": {"field": "raw_hex", "view": "decoder_input_bytes"},
        "source_preparation_applied": None,
        "source_preparation_responsibility": "caller supplies wire or prepared bytes; no preparation is performed or inferred here",
        "execution_graph_complete": False,
        "descriptor_reachability": "unproven",
        "discovery": "source_order; shared blocks are not searched for top-level descriptors",
        "nodes": nodes,
        "discovery_stop": stop,
    }


def serialize_bm_pattern(
    pattern: BmPattern,
    *,
    context: BmSemanticContext | None = None,
) -> tuple[JSONObject, tuple[SemanticIssue, ...]]:
    """Serialize one decoder view, including its exact unparsed remainder."""
    pattern = decode_bm_pattern(pattern.raw, profile=pattern.profile)
    semantic_pattern = interpret_bm_pattern(pattern)
    operations = [
        _operation_ir(
            operation,
            context=context,
            pattern=pattern,
        )
        for operation in semantic_pattern.operations
    ]
    program_structure = _program_structure(pattern)
    structural_offsets = {node["offset"] for node in program_structure["nodes"]}
    for operation in operations:
        if (
            operation["kind"] == "opaque"
            and operation["raw_id"] in (0x03, 0x17)
            and operation["raw_span"]["offset"] in structural_offsets
        ):
            operation["issues"] = [
                "raw_alternatives_structure_known_execution_unmodeled"
            ]
            operation["decoded"]["program_structure_node"] = {
                "offset": operation["raw_span"]["offset"]
            }
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
            "program_structure": program_structure,
            "remaining_raw": remaining,
            "issues": issues,
        }
    )
    return data, tuple(semantic_issues)


__all__ = ["BmSemanticContext", "serialize_bm_pattern"]
