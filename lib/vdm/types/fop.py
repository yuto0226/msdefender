"""Lossless parsers for the FOP scanner signature payload family."""

from collections.abc import Callable
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final

from ..core import (
    DisplaySection,
    FamilySpec,
    FormatResult,
    JSONObject,
    RuleSemantics,
    SemanticIssue,
    SemanticJSONValue,
)

FOP_TYPES: Final = MappingProxyType(
    {
        0x7F: "FOP",
        0x89: "FOPEX",
        0xB4: "VBFOP",
        0xBA: "MSILFOP",
        0xC6: "MSILFOPEX",
        0xC7: "VBFOPEX",
        0xC8: "FOP64",
        0xC9: "FOPEX64",
    }
)
FOP_PLAIN_TYPES: Final = frozenset({0x7F, 0xB4, 0xBA, 0xC8})
FOP_EXTENDED_TYPES: Final = frozenset(FOP_TYPES) - FOP_PLAIN_TYPES
FOP_PLAIN_HEADER_SIZE: Final = 4
FOP_EXTENDED_HEADER_SIZE: Final = 10
FOP_PREVIEW_SIZE: Final = 64
_FOP_ROUTES: Final = MappingProxyType(
    {
        0x7F: "x86",
        0x89: "x86",
        0xB4: "vb",
        0xC7: "vb",
        0xBA: "msil",
        0xC6: "msil",
        0xC8: "x64",
        0xC9: "x64",
    }
)


@dataclass(frozen=True, slots=True)
class FopPayload:
    """Parsed FOP fields; section labels are neutral pending semantic analysis."""

    raw: bytes
    type_byte: int
    flags: int | None
    ignored_reason: str | None
    prefix: bytes
    pattern: bytes
    section1: bytes | None
    section2: bytes | None
    pattern_options: int | None


def parse_fop(payload: bytes, *, type_byte: int) -> FopPayload:
    """Mirror the FOP receiver's load/no-op/error disposition losslessly."""
    try:
        FOP_TYPES[type_byte]
    except KeyError as exc:
        raise ValueError(f"unsupported FOP family type 0x{type_byte:02X}") from exc

    header_size = (
        FOP_PLAIN_HEADER_SIZE
        if type_byte in FOP_PLAIN_TYPES
        else FOP_EXTENDED_HEADER_SIZE
    )
    if len(payload) <= header_size:
        return FopPayload(
            raw=payload,
            type_byte=type_byte,
            flags=payload[0] if payload else None,
            ignored_reason=f"payload size <= {header_size}-byte header",
            prefix=b"",
            pattern=b"",
            section1=None,
            section2=None,
            pattern_options=None,
        )

    flags = payload[0]
    if flags & 0xFE:
        return FopPayload(
            raw=payload,
            type_byte=type_byte,
            flags=flags,
            ignored_reason=f"reserved flag bits set (0x{flags & 0xFE:02X})",
            prefix=b"",
            pattern=b"",
            section1=None,
            section2=None,
            pattern_options=None,
        )

    prefix_len = payload[1]
    pattern_len = int.from_bytes(payload[2:4], "little")
    if type_byte in FOP_PLAIN_TYPES:
        expected_size = FOP_PLAIN_HEADER_SIZE + prefix_len + pattern_len
        if len(payload) != expected_size:
            raise ValueError(
                f"invalid FOP payload length: expected {expected_size}, got {len(payload)}"
            )
        prefix_start = FOP_PLAIN_HEADER_SIZE
        pattern_start = prefix_start + prefix_len
        return FopPayload(
            raw=payload,
            type_byte=type_byte,
            flags=flags,
            ignored_reason=None,
            prefix=payload[prefix_start:pattern_start],
            pattern=payload[pattern_start:],
            section1=None,
            section2=None,
            pattern_options=None,
        )

    section1_len = int.from_bytes(payload[4:6], "little")
    section2_len = int.from_bytes(payload[6:8], "little")
    pattern_options = int.from_bytes(payload[8:10], "little")
    expected_size = (
        FOP_EXTENDED_HEADER_SIZE
        + prefix_len
        + pattern_len
        + section1_len
        + section2_len
    )
    if len(payload) != expected_size:
        raise ValueError(
            f"invalid FOP payload length: expected {expected_size}, got {len(payload)}"
        )

    cursor = FOP_EXTENDED_HEADER_SIZE
    prefix = payload[cursor : cursor + prefix_len]
    cursor += prefix_len
    pattern = payload[cursor : cursor + pattern_len]
    cursor += pattern_len
    section1 = payload[cursor : cursor + section1_len]
    cursor += section1_len
    section2 = payload[cursor : cursor + section2_len]
    return FopPayload(
        raw=payload,
        type_byte=type_byte,
        flags=flags,
        ignored_reason=None,
        prefix=prefix,
        pattern=pattern,
        section1=section1,
        section2=section2,
        pattern_options=pattern_options,
    )


def _preview(raw: bytes) -> str:
    value = raw[:FOP_PREVIEW_SIZE].hex(" ") or "(empty)"
    if len(raw) > FOP_PREVIEW_SIZE:
        value += f" … (+{len(raw) - FOP_PREVIEW_SIZE} B)"
    return value


def _section_rows(name: str, raw: bytes) -> tuple[tuple[str, str], ...]:
    return ((f"{name}_length", f"{len(raw)} B"), (f"{name}_preview", _preview(raw)))


def render_fop(parsed: FopPayload) -> FormatResult:
    """Render normalized fields and byte-limited previews for each byte section."""
    name = FOP_TYPES[parsed.type_byte]
    rows = [
        ("type", f"{name} (0x{parsed.type_byte:02X})"),
        ("flags", "not read" if parsed.flags is None else f"0x{parsed.flags:02X}"),
    ]
    if parsed.ignored_reason is not None:
        rows.append(("receiver_disposition", f"ignored ({parsed.ignored_reason})"))
        return FormatResult(sections=(DisplaySection("FOP", rows=tuple(rows)),))

    assert parsed.flags is not None
    rows.extend(
        (
            ("receiver_disposition", "loaded"),
            ("flag_bit0", str(bool(parsed.flags & 1))),
            *_section_rows("prefix", parsed.prefix),
            *_section_rows("pattern", parsed.pattern),
        )
    )
    if parsed.pattern_options is not None:
        rows.append(("pattern_options", f"0x{parsed.pattern_options:04X}"))
        assert parsed.section1 is not None and parsed.section2 is not None
        rows.extend(_section_rows("section1", parsed.section1))
        rows.extend(_section_rows("section2", parsed.section2))
    return FormatResult(sections=(DisplaySection("FOP", rows=tuple(rows)),))


def export_fop_semantics(parsed: FopPayload) -> RuleSemantics:
    """Export the confirmed wire/route/matcher subset without verdict claims."""
    evidence = (
        "mpengine 1.443.903.0 FopScanner::Init @ 0x1805F0120",
        (
            "mpengine 1.443.903.0 FopScanner::AddNewPatternCommon "
            "@ 0x18046F9AC: wire flag mask 0x01 -> candidate metadata "
            "+0x12 mask 0x01; extended objects/options -> metadata"
        ),
        (
            "mpengine 1.443.903.0 FopScanner::AddToResults @ 0x1802BC7BC: "
            "metadata mask 0x01 -> result row byte +6; extended metadata "
            "gates byte-set filtering and BMMatchPEMapper"
        ),
        "mpengine 1.443.903.0 BMGetPatternFlags @ 0x1800FEBF4",
        "mpengine 1.443.903.0 BMMatchPEMapper @ 0x1803D5E44",
        "mpengine 1.443.903.0 FopScanner::ScanContext::GetChar @ 0x180250E5C",
        (
            "mpengine 1.443.903.0 FopScanner::Scan @ 0x18040AF48: "
            "result row byte +6 gates candidate aggregation/selection and is "
            "returned through the candidate out flag"
        ),
        "mpengine 1.443.903.0 x86_fop_processor::GetCharAtAddr @ 0x180250F70",
        "mpengine 1.443.903.0 x64_fop_processor::GetCharAtAddr @ 0x180250500",
        "mpengine 1.443.903.0 vb_fop_processor::GetCharAtAddr @ 0x180555210",
    )
    if parsed.ignored_reason is not None:
        return RuleSemantics(
            status="ignored",
            representation="fop.trie_matcher_subset.ir.v6",
            data=JSONObject(
                (
                    ("raw_hex", parsed.raw.hex()),
                    ("type_byte", parsed.type_byte),
                    ("ignored_reason", parsed.ignored_reason),
                )
            ),
            evidence=evidence,
            profile="mpengine-1.443.903.0",
        )

    assert parsed.flags is not None
    data_items: list[tuple[str, SemanticJSONValue]] = [
        ("raw_hex", parsed.raw.hex()),
        ("type_byte", parsed.type_byte),
        ("semantic_scope", "wire_route_and_core_trie_matcher_shape"),
        (
            "wire_layout",
            "plain" if parsed.type_byte in FOP_PLAIN_TYPES else "extended",
        ),
        ("route", _FOP_ROUTES[parsed.type_byte]),
        ("prefix_hex", parsed.prefix.hex()),
        ("pattern_hex", parsed.pattern.hex()),
        ("flag_bit0_raw", bool(parsed.flags & 1)),
        (
            "flag_bit0_runtime_effects",
            JSONObject(
                (
                    (
                        "wire_to_trie_metadata",
                        JSONObject(
                            (
                                ("source_mask", 1),
                                ("destination", "candidate_metadata+0x12 mask 0x01"),
                                ("evidence_address", "0x18046FB56"),
                            )
                        ),
                    ),
                    (
                        "trie_metadata_to_result_row",
                        JSONObject(
                            (
                                ("source", "candidate_metadata+0x12 mask 0x01"),
                                ("destination", "FopResultEntry+6"),
                                ("evidence_address", "0x1802BCA81"),
                            )
                        ),
                    ),
                    (
                        "scan_consumption",
                        JSONObject(
                            (
                                ("function", "FopScanner::Scan"),
                                ("address", "0x18040AF48"),
                                (
                                    "effects",
                                    (
                                        "flagged !# candidates skip "
                                        "MpAggregateAttributeEx; flagged ordinary-name "
                                        "candidates are selected only if no prior best "
                                        "RecID exists"
                                    ),
                                ),
                                (
                                    "out_flag",
                                    "selected candidate flag is returned through caller output",
                                ),
                            )
                        ),
                    ),
                    ("outer_verdict", "unknown"),
                )
            ),
        ),
        ("matcher", "processor_GetCharAtAddr_output_equals_trie_pattern_bytes"),
        ("engine_processor_required", True),
    ]
    issues = [
        SemanticIssue(
            "engine_processor_required",
            "The scanner trie is evaluated through the type-specific engine "
            "processor's GetCharAtAddr path; this export does not implement that "
            "processor.",
        ),
        SemanticIssue(
            "final_verdict_unknown",
            "This subset describes receiver routing, trie matching, and part of "
            "candidate selection; caller policy and final detection/report "
            "semantics remain unknown.",
        ),
        SemanticIssue(
            "flag_bit0_semantics_incomplete",
            "The confirmed subset covers FopScanner::Scan candidate aggregation "
            "and selection only; the product meaning, any other consumers, and "
            "complete reporting semantics remain unresolved.",
        ),
    ]
    if parsed.pattern_options is not None:
        assert parsed.section1 is not None and parsed.section2 is not None
        data_items[2] = (
            "semantic_scope",
            "wire_route_runtime_effects_and_core_trie_matcher_shape",
        )
        data_items.extend(
            (
                ("section1_raw_hex", parsed.section1.hex()),
                ("section2_raw_hex", parsed.section2.hex()),
                ("pattern_options_raw", parsed.pattern_options),
                (
                    "extended_runtime_effects",
                    JSONObject(
                        (
                            (
                                "section1",
                                JSONObject(
                                    (
                                        ("validated_by", "BMGetPatternFlags"),
                                        ("validation_address", "0x1800FEBF4"),
                                        (
                                            "stored_handle_offset",
                                            "candidate_metadata+0x14",
                                        ),
                                        ("storage_address", "0x18046FBEB"),
                                    )
                                ),
                            ),
                            (
                                "section2",
                                JSONObject(
                                    (
                                        (
                                            "stored_handle_offset",
                                            "candidate_metadata+0x20",
                                        ),
                                        ("length_offset", "candidate_metadata+0x1C"),
                                        ("storage_address", "0x1804700AE"),
                                        (
                                            "candidate_filter",
                                            (
                                                "each matched-prefix scan byte must "
                                                "occur in the section2 byte array"
                                            ),
                                        ),
                                        ("filter_address", "0x1802BCCEC"),
                                        (
                                            "trie_side_effect",
                                            (
                                                "each section2 byte clears its "
                                                "handle-associated scanner byte-table "
                                                "entry at scanner_state+0x21+byte"
                                            ),
                                        ),
                                    )
                                ),
                            ),
                            (
                                "pattern_options",
                                JSONObject(
                                    (
                                        (
                                            "storage",
                                            "raw u16 copied to candidate_metadata+0x10",
                                        ),
                                        ("storage_address", "0x18046FC36"),
                                        (
                                            "candidate_offset_use",
                                            "sign_extend_i16_then_add_to_scan_start_for_BMMatchPEMapper",
                                        ),
                                        ("use_address", "0x1802BCA52"),
                                    )
                                ),
                            ),
                            (
                                "candidate_gate",
                                JSONObject(
                                    (
                                        ("prefix_length_condition", "prefix_len > 8"),
                                        ("condition_address", "0x18046FC81"),
                                        ("mapper", "BMMatchPEMapper"),
                                        ("mapper_address", "0x1803D5E44"),
                                        ("false_result", "candidate_skipped"),
                                        ("false_branch_address", "0x1802BCA79"),
                                        ("pattern_input", "section1 kernel object"),
                                        ("pattern_length_input", "section1_len"),
                                        (
                                            "scan_offset",
                                            "start_offset + sign_extend_i16(pattern_options)",
                                        ),
                                        (
                                            "mode_argument",
                                            (
                                                "metadata gate flag derived when "
                                                "the relevant BMGetPatternFlags "
                                                "result flag is clear"
                                            ),
                                        ),
                                    )
                                ),
                            ),
                            ("final_verdict", "unknown"),
                        )
                    ),
                ),
            )
        )
        issues.append(
            SemanticIssue(
                "extended_field_business_domains_unknown",
                "Runtime storage and candidate-gate dataflow are confirmed, but "
                "the product domains represented by section1/section2, the "
                "policy meaning of pattern_options, flag bit 0, processor-"
                "equivalent matching, and subtype/report policy remain unresolved. "
                "This is a bounded subset, not a matching-equivalent rule.",
            )
        )
    return RuleSemantics(
        status="confirmed_subset",
        representation="fop.trie_matcher_subset.ir.v6",
        data=JSONObject(tuple(data_items)),
        evidence=evidence,
        profile="mpengine-1.443.903.0",
        issues=tuple(issues),
    )


def _parser_for(type_byte: int) -> Callable[[bytes], FopPayload]:
    def parser(payload: bytes) -> FopPayload:
        return parse_fop(payload, type_byte=type_byte)

    return parser


FOP_SPECS = tuple(
    FamilySpec(
        type_byte,
        name,
        _parser_for(type_byte),
        render_fop,
        semantic_exporter=export_fop_semantics,
    )
    for type_byte, name in FOP_TYPES.items()
)
