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
    SemanticClaim,
    SemanticEvidence,
    SemanticIssue,
    SemanticJSONValue,
    SemanticUnknown,
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
_FOP_WRAPPERS: Final = MappingProxyType(
    {
        0x7F: ("FopScanner::AddNewPattern_X86", "0x18046F950"),
        0x89: ("FopScanner::AddNewPatternEx_X86", "0x18046F980"),
        0xB4: ("FopScanner::AddNewPattern_VB", "0x18046F860"),
        0xBA: ("FopScanner::AddNewPattern_MSIL", "0x18046F920"),
        0xC6: ("FopScanner::AddNewPatternEx_MSIL", "0x180CAEA10"),
        0xC7: ("FopScanner::AddNewPatternEx_VB", "0x18046F8F0"),
        0xC8: ("FopScanner::AddNewPattern_X64", "0x18046F890"),
        0xC9: ("FopScanner::AddNewPatternEx_X64", "0x18046F8C0"),
    }
)
_FOP_PROCESSORS: Final = MappingProxyType(
    {
        "x86": (
            "x86_fop_processor::GetCharAtAddr",
            "0x180250F70",
            "mapped_byte_0",
            "successful_decode_length_1_to_32",
        ),
        "x64": (
            "x64_fop_processor::GetCharAtAddr",
            "0x180250500",
            "mapped_byte_0",
            "successful_decode_length_1_to_32",
        ),
        "vb": (
            "vb_fop_processor::GetCharAtAddr",
            "0x180555210",
            "mapped_byte_1_when_mapped_byte_0_is_0xFB_to_0xFF_else_mapped_byte_0",
            "VBpCode_table_length_plus_operand_adjustment; zero_byte_skips_two_addresses",
        ),
        "msil": (
            "msil_fop_processor::GetCharAtAddr",
            "0x180481140",
            "mapped_byte_1_when_mapped_byte_0_is_0xFE_else_mapped_byte_0",
            "token_length_table; byte_0_0x45_adds_4_times_operand_dword_plus_4",
        ),
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
    extended_u16: int | None


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
            extended_u16=None,
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
            extended_u16=None,
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
            extended_u16=None,
        )

    section1_len = int.from_bytes(payload[4:6], "little")
    section2_len = int.from_bytes(payload[6:8], "little")
    extended_u16 = int.from_bytes(payload[8:10], "little")
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
        extended_u16=extended_u16,
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
    if parsed.extended_u16 is not None:
        rows.append(("extended_u16", f"0x{parsed.extended_u16:04X}"))
        assert parsed.section1 is not None and parsed.section2 is not None
        rows.extend(_section_rows("section1", parsed.section1))
        rows.extend(_section_rows("section2", parsed.section2))
    return FormatResult(sections=(DisplaySection("FOP", rows=tuple(rows)),))


def export_fop_semantics(parsed: FopPayload) -> RuleSemantics:
    """Export the confirmed wire/route/matcher subset without verdict claims."""
    route = _FOP_ROUTES[parsed.type_byte]
    layout = "plain" if parsed.type_byte in FOP_PLAIN_TYPES else "extended"
    wrapper_name, wrapper_address = _FOP_WRAPPERS[parsed.type_byte]
    processor_name, processor_address, match_value, advance = _FOP_PROCESSORS[route]
    active = parsed.ignored_reason is None

    evidence = [
        "mpengine 1.443.903.0 FopScanner::Init @ 0x1805F0120",
        f"mpengine 1.443.903.0 {wrapper_name} @ {wrapper_address}",
        "mpengine 1.443.903.0 FopScanner::AddNewPatternCommon @ 0x18046F9AC",
    ]
    if active:
        evidence.extend(
            (
                "mpengine 1.443.903.0 FopScanner::AddToResults @ 0x1802BC7BC",
                "mpengine 1.443.903.0 FopScanner::ScanContext::GetChar @ 0x180250E5C",
                f"mpengine 1.443.903.0 {processor_name} @ {processor_address}",
                "mpengine 1.443.903.0 FopScanner::Scan @ 0x18040AF48",
            )
        )
        if layout == "extended":
            evidence.extend(
                (
                    "mpengine 1.443.903.0 BMGetPatternFlags @ 0x1800FEBF4",
                    "mpengine 1.443.903.0 BMMatchPEMapper @ 0x1803D5E44",
                )
            )

    claims: list[SemanticClaim] = [
        SemanticClaim(
            id="fop_wire_projection",
            scope="wire_layout",
            statement=(
                f"The {layout} receiver uses a "
                f"{FOP_PLAIN_HEADER_SIZE if layout == 'plain' else FOP_EXTENDED_HEADER_SIZE}-byte "
                "header and exact declared section lengths; short or reserved-flag "
                "payloads take the recorded no-op disposition before insertion."
            ),
            coverage="complete",
            evidence_refs=("fop_receiver",),
        ),
        SemanticClaim(
            id="fop_dispatch_path",
            scope="loader_dispatch",
            statement=(
                f"FopScanner::Init registers type 0x{parsed.type_byte:02X} to "
                f"{wrapper_name}, which selects the {route}/{layout} receiver route."
            ),
            coverage="subset",
            evidence_refs=("fop_dispatch",),
            unknowns=(
                SemanticUnknown(
                    "loader_dispatch",
                    "Outer scanner initialization and product enablement gates are not modeled.",
                ),
            ),
        ),
        SemanticClaim(
            id="fop_receiver_transform",
            scope="receiver_transform",
            statement=(
                "The common receiver returns the recorded no-op disposition without "
                "inserting a trie candidate."
                if not active
                else "The common receiver projects the validated fields into the "
                f"{route} trie candidate metadata for the {layout} route."
            ),
            coverage="subset",
            evidence_refs=("fop_receiver",),
            unknowns=(
                SemanticUnknown(
                    "receiver_transform",
                    "Allocation, kernel-object storage failures, and all surrounding state mutations are not projected.",
                ),
            ),
        ),
    ]

    if active:
        runtime_refs = ("fop_processor",)
        predicate_refs = (
            ("fop_processor", "fop_extended_gate")
            if layout == "extended"
            else ("fop_processor",)
        )
        claims.extend(
            (
                SemanticClaim(
                    id="fop_candidate_matcher",
                    scope="runtime_consumer",
                    statement=(
                        f"The {route} processor supplies mapped instruction/token bytes; "
                        "AddToResults compares them byte-for-byte with this record's trie pattern."
                    ),
                    coverage="subset",
                    evidence_refs=runtime_refs,
                    unknowns=(
                        SemanticUnknown(
                            "runtime_consumer",
                            "The engine mapper/decoder, candidate addresses, and scan context are not reproduced.",
                        ),
                    ),
                ),
                SemanticClaim(
                    id="fop_candidate_selection",
                    scope="runtime_consumer",
                    statement=(
                        "Wire flag bit 0 becomes candidate metadata bit 1, is normalized "
                        "into result-row byte +6, and participates in scanner-local "
                        "aggregation and best-candidate selection."
                    ),
                    coverage="subset",
                    evidence_refs=("fop_selection",),
                    unknowns=(
                        SemanticUnknown(
                            "runtime_consumer",
                            "The product meaning of the flag and any additional consumers are unresolved.",
                        ),
                    ),
                ),
                SemanticClaim(
                    id="fop_candidate_predicate",
                    scope="detection_predicate",
                    statement=(
                        "At candidate scope, the selected processor's mapped-byte equality"
                        + (
                            ", section2 byte-set filter, and conditional section1 BM gate must pass."
                            if layout == "extended"
                            else " must pass."
                        )
                    ),
                    coverage="subset",
                    evidence_refs=predicate_refs,
                    unknowns=(
                        SemanticUnknown(
                            "detection_predicate",
                            "Candidate success is not a raw-file predicate or a complete threat detection condition.",
                        ),
                    ),
                ),
            )
        )
    else:
        claims.extend(
            (
                SemanticClaim(
                    id="fop_candidate_matcher",
                    scope="runtime_consumer",
                    statement="No runtime matcher is projected for this receiver no-op payload.",
                    coverage="unknown",
                    unknowns=(
                        SemanticUnknown(
                            "runtime_consumer",
                            "The payload does not enter the confirmed trie insertion path.",
                        ),
                    ),
                ),
                SemanticClaim(
                    id="fop_candidate_selection",
                    scope="runtime_consumer",
                    statement="No candidate-selection effect is established for this no-op payload.",
                    coverage="unknown",
                    unknowns=(
                        SemanticUnknown(
                            "runtime_consumer",
                            "No candidate row is produced through the confirmed receiver path.",
                        ),
                    ),
                ),
                SemanticClaim(
                    id="fop_candidate_predicate",
                    scope="detection_predicate",
                    statement="No candidate predicate is established for this receiver no-op payload.",
                    coverage="unknown",
                    unknowns=(
                        SemanticUnknown(
                            "detection_predicate",
                            "The confirmed receiver path does not insert this payload as a candidate.",
                        ),
                    ),
                ),
            )
        )

    claims.extend(
        (
            SemanticClaim(
                id="fop_report_mapping",
                scope="report_mapping",
                statement="FOP candidate identity to product report mapping is unresolved.",
                coverage="unknown",
                unknowns=(
                    SemanticUnknown(
                        "report_mapping",
                        "The selected RecID and flag were not followed into a report policy.",
                    ),
                ),
            ),
            SemanticClaim(
                id="fop_final_verdict",
                scope="final_verdict",
                statement="A FOP candidate result is not a confirmed final verdict.",
                coverage="unknown",
                unknowns=(
                    SemanticUnknown(
                        "final_verdict",
                        "Outer scan arbitration and final report/cure policy remain unresolved.",
                    ),
                ),
            ),
        )
    )

    claim_evidence = [
        SemanticEvidence(
            id="fop_dispatch",
            axis="dispatch",
            kind="engine_static",
            source_ref="mpengine 1.443.903.0",
            locator=f"FopScanner::Init @ 0x1805F0120; {wrapper_name} @ {wrapper_address}",
            supports=("fop_dispatch_path",),
        ),
        SemanticEvidence(
            id="fop_receiver",
            axis="receiver",
            kind="engine_static",
            source_ref="mpengine 1.443.903.0",
            locator=(
                f"{wrapper_name} @ {wrapper_address}; "
                "FopScanner::AddNewPatternCommon @ 0x18046F9AC"
            ),
            supports=("fop_wire_projection", "fop_receiver_transform"),
        ),
    ]
    if active:
        claim_evidence.extend(
            (
                SemanticEvidence(
                    id="fop_processor",
                    axis="consumer",
                    kind="engine_static",
                    source_ref="mpengine 1.443.903.0",
                    locator=(
                        "FopScanner::AddToResults @ 0x1802BC7BC; "
                        "FopScanner::ScanContext::GetChar @ 0x180250E5C; "
                        f"{processor_name} @ {processor_address}"
                    ),
                    supports=("fop_candidate_matcher", "fop_candidate_predicate"),
                ),
                SemanticEvidence(
                    id="fop_selection",
                    axis="consumer",
                    kind="engine_static",
                    source_ref="mpengine 1.443.903.0",
                    locator=(
                        "FopScanner::AddNewPatternCommon @ 0x18046F9AC; "
                        "FopScanner::AddToResults @ 0x1802BC7BC; "
                        "FopScanner::Scan @ 0x18040AF48"
                    ),
                    supports=("fop_candidate_selection",),
                ),
            )
        )
        if layout == "extended":
            claim_evidence.append(
                SemanticEvidence(
                    id="fop_extended_gate",
                    axis="consumer",
                    kind="engine_static",
                    source_ref="mpengine 1.443.903.0",
                    locator=(
                        "FopScanner::AddToResults @ 0x1802BC7BC; "
                        "BMGetPatternFlags @ 0x1800FEBF4; "
                        "BMMatchPEMapper @ 0x1803D5E44"
                    ),
                    supports=("fop_candidate_predicate",),
                )
            )

    if parsed.ignored_reason is not None:
        return RuleSemantics(
            status="ignored",
            representation="fop.trie_matcher_subset.ir.v9",
            data=JSONObject(
                (
                    ("raw_hex", parsed.raw.hex()),
                    ("type_byte", parsed.type_byte),
                    ("wire_layout", layout),
                    ("route", route),
                    ("ignored_reason", parsed.ignored_reason),
                )
            ),
            evidence=tuple(evidence),
            profile="mpengine-1.443.903.0",
            claims=tuple(claims),
            claim_evidence=tuple(claim_evidence),
        )

    assert parsed.flags is not None
    data_items: list[tuple[str, SemanticJSONValue]] = [
        ("raw_hex", parsed.raw.hex()),
        ("type_byte", parsed.type_byte),
        ("semantic_scope", "wire_route_and_core_trie_matcher_shape"),
        (
            "wire_layout",
            layout,
        ),
        ("route", route),
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
                                ("transform", "2 * (flags & 1)"),
                                ("destination", "candidate_metadata+0x12 mask 0x02"),
                                ("evidence_address", "0x18046FB56"),
                            )
                        ),
                    ),
                    (
                        "trie_metadata_to_result_row",
                        JSONObject(
                            (
                                ("source", "candidate_metadata+0x12 mask 0x02"),
                                ("normalization", "bool((metadata_word >> 1) & 1)"),
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
        (
            "subject_stream",
            "route-specific mapped instruction or token stream; not raw-file-byte equivalent",
        ),
        (
            "processor_match_contract",
            JSONObject(
                (
                    ("route", route),
                    ("function", processor_name),
                    ("address", processor_address),
                    ("match_value", match_value),
                    ("advance", advance),
                    ("decode_failure", "-1_with_zero_consumed"),
                )
            ),
        ),
        ("engine_processor_required", True),
    ]
    issues = [
        SemanticIssue(
            "engine_processor_required",
            "Route-specific token extraction and advance behavior are recorded, "
            "but matching still depends on engine mapper and processor behavior; "
            "this export does not execute those components and must not be applied "
            "as a processor-independent raw-byte predicate.",
        ),
        SemanticIssue(
            "final_verdict_unknown",
            "This subset describes receiver routing, trie matching, and part of "
            "candidate selection; caller policy and final detection/report "
            "semantics remain unknown.",
        ),
        SemanticIssue(
            "flag_bit0_semantics_incomplete",
            "The confirmed subset covers processor token extraction and "
            "FopScanner::Scan candidate aggregation/selection; the product "
            "meaning, any other consumers, and complete reporting semantics "
            "remain unresolved.",
        ),
    ]
    if parsed.extended_u16 is not None:
        assert parsed.section1 is not None and parsed.section2 is not None
        data_items[2] = (
            "semantic_scope",
            "wire_route_runtime_effects_and_core_trie_matcher_shape",
        )
        data_items.extend(
            (
                ("section1_raw_hex", parsed.section1.hex()),
                ("section2_raw_hex", parsed.section2.hex()),
                ("extended_u16_raw", parsed.extended_u16),
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
                                "signed_displacement",
                                JSONObject(
                                    (
                                        (
                                            "storage",
                                            "raw u16 copied to candidate_metadata+0x10 and consumed as i16",
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
                                            "start_offset + sign_extend_i16(extended_u16_raw)",
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
                "product meaning of the extended u16, flag bit 0, processor-"
                "equivalent matching, and subtype/report policy remain unresolved. "
                "This is a bounded subset, not a matching-equivalent rule.",
            )
        )
    return RuleSemantics(
        status="confirmed_subset",
        representation="fop.trie_matcher_subset.ir.v9",
        data=JSONObject(tuple(data_items)),
        evidence=tuple(evidence),
        profile="mpengine-1.443.903.0",
        issues=tuple(issues),
        claims=tuple(claims),
        claim_evidence=tuple(claim_evidence),
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
