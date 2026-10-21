"""Lossless wire parser for MACRO_SOURCE (0x43) payloads."""

from dataclasses import dataclass
from typing import Final

from ..core import (
    DisplaySection,
    FamilySpec,
    FormatResult,
    JSONArray,
    JSONObject,
    RuleSemantics,
    SemanticClaim,
    SemanticEvidence,
    SemanticIssue,
    SemanticUnknown,
)

MACRO_SOURCE_TYPE: Final = 0x43
PRIMARY_PREVIEW_LIMIT: Final = 16
WORD_SIZE: Final = 4
SUBTYPE_METADATA: Final = {0: (0, 1), 2: (2,), 4: (3,), 8: (4,)}


@dataclass(frozen=True, slots=True)
class MacroSourcePayload:
    """Raw MACRO_SOURCE fields and normalized safecrc candidate pairs."""

    name_bytes: bytes
    name_preview: str
    packed_header: int
    metadata_raw: int
    count: int
    primary: tuple[int, ...]
    secondary: tuple[int, ...] | None
    pairs: tuple[tuple[int, int], ...]
    trailing: bytes


def parse_macro_source(payload: bytes) -> MacroSourcePayload:
    """Parse wire fields; retain name bytes and incomplete optional data raw."""
    if not payload:
        raise ValueError("truncated MACRO_SOURCE payload: missing name length")

    name_len = payload[0]
    header_offset = 1 + name_len
    if len(payload) < header_offset + WORD_SIZE:
        raise ValueError(
            "truncated MACRO_SOURCE payload: "
            f"need at least {header_offset + WORD_SIZE} bytes, have {len(payload)}"
        )

    name_bytes = payload[1:header_offset]
    packed_header = int.from_bytes(
        payload[header_offset : header_offset + WORD_SIZE], "little"
    )
    count = packed_header & 0x3F
    metadata_raw = packed_header >> 6
    primary_offset = header_offset + WORD_SIZE
    primary_end = primary_offset + count * WORD_SIZE
    if len(payload) < primary_end:
        raise ValueError(
            "truncated MACRO_SOURCE primary values: "
            f"need {count * WORD_SIZE} bytes, have {len(payload) - primary_offset}"
        )

    primary = tuple(
        int.from_bytes(payload[offset : offset + WORD_SIZE], "little")
        for offset in range(primary_offset, primary_end, WORD_SIZE)
    )
    remaining = len(payload) - primary_end
    if remaining >= count * WORD_SIZE:
        secondary_end = primary_end + count * WORD_SIZE
        secondary = tuple(
            int.from_bytes(payload[offset : offset + WORD_SIZE], "little")
            for offset in range(primary_end, secondary_end, WORD_SIZE)
        )
        trailing = payload[secondary_end:]
    else:
        secondary = None
        trailing = payload[primary_end:]

    effective_secondary = secondary if secondary is not None else (0,) * count
    pairs = tuple(zip(primary, effective_secondary, strict=True))
    return MacroSourcePayload(
        name_bytes=name_bytes,
        name_preview=name_bytes.decode("utf-8", errors="replace"),
        packed_header=packed_header,
        metadata_raw=metadata_raw,
        count=count,
        primary=primary,
        secondary=secondary,
        pairs=pairs,
        trailing=trailing,
    )


def render_macro_source(parsed: MacroSourcePayload) -> FormatResult:
    """Render stable summary fields and a bounded preview of identifier pairs."""
    rows = [
        ("name_bytes", parsed.name_bytes.hex(" ")),
        ("name_preview_utf8_lossy_unvalidated", repr(parsed.name_preview)),
        ("packed_header", f"0x{parsed.packed_header:08x}"),
        ("metadata_raw", f"0x{parsed.metadata_raw:x}"),
        ("count", str(parsed.count)),
        (
            "secondary",
            "present" if parsed.secondary is not None else "absent (effective zero)",
        ),
        ("trailing_length", str(len(parsed.trailing))),
    ]
    if parsed.trailing:
        rows.append(("trailing_preview", parsed.trailing[:16].hex(" ")))

    preview = parsed.pairs[:PRIMARY_PREVIEW_LIMIT]
    pair_rows = tuple(
        (f"pair[{index}]", f"0x{primary:08x}, 0x{secondary:08x}")
        for index, (primary, secondary) in enumerate(preview)
    )
    if len(parsed.pairs) > len(preview):
        pair_rows += (("remaining", str(len(parsed.pairs) - len(preview))),)

    return FormatResult(
        sections=(
            DisplaySection("MACRO_SOURCE", rows=tuple(rows)),
            DisplaySection("Pairs", rows=pair_rows),
        )
    )


def export_macro_source_semantics(parsed: MacroSourcePayload) -> RuleSemantics:
    """Export the confirmed source-pair lookup/match contract without guessing names."""
    header_offset = 1 + len(parsed.name_bytes)
    primary_offset = header_offset + WORD_SIZE
    primary_length = parsed.count * WORD_SIZE
    secondary_offset = primary_offset + primary_length
    secondary_length = parsed.count * WORD_SIZE if parsed.secondary is not None else 0
    raw = bytearray((len(parsed.name_bytes),))
    raw.extend(parsed.name_bytes)
    raw.extend(parsed.packed_header.to_bytes(WORD_SIZE, "little"))
    for value in parsed.primary:
        raw.extend(value.to_bytes(WORD_SIZE, "little"))
    if parsed.secondary is not None:
        for value in parsed.secondary:
            raw.extend(value.to_bytes(WORD_SIZE, "little"))
    raw.extend(parsed.trailing)

    issues = [
        SemanticIssue(
            "pair_dword_names_unknown",
            "The two safecrc DWORDs are retained by position; their business names are unknown.",
        ),
        SemanticIssue(
            "name_encoding_unknown",
            "The wire parser preserves raw name bytes, while the receiver uses "
            "them for signature properties/RecID construction and does not copy "
            "them into g_SourceSigs. Current-corpus names being ASCII-compatible "
            "does not establish a text encoding.",
        ),
        SemanticIssue(
            "subtype_enum_names_unknown",
            "Subtype compatibility values are confirmed, but their business enum names are unknown.",
        ),
        SemanticIssue(
            "final_verdict_unknown",
            "RME::reportvirus can accept the candidate into internal best-match "
            "state, but the outer scan result and host-visible verdict are unknown.",
        ),
    ]
    # A complete optional secondary vector and no unexplained suffix are the
    # only framing shape for which this semantic manifest is complete.
    if parsed.trailing:
        issues.append(
            SemanticIssue(
                "unconsumed_bytes",
                "Unconsumed bytes are retained verbatim and prevent a complete semantic export.",
                (("length", len(parsed.trailing)),),
            )
        )
    if parsed.metadata_raw not in SUBTYPE_METADATA:
        issues.append(
            SemanticIssue(
                "subtype_compatibility_unknown",
                "No confirmed subtype compatibility condition exists for this metadata value.",
                (("metadata_raw", parsed.metadata_raw),),
            )
        )

    pairs = JSONArray(
        tuple(
            JSONObject(
                (
                    ("index", index),
                    ("field0", first),
                    ("field1", second),
                    (
                        "raw_hex",
                        first.to_bytes(4, "little").hex()
                        + second.to_bytes(4, "little").hex(),
                    ),
                )
            )
            for index, (first, second) in enumerate(parsed.pairs)
        )
    )
    compatible = SUBTYPE_METADATA.get(parsed.metadata_raw, ())
    return RuleSemantics(
        status=(
            "confirmed_subset"
            if not parsed.trailing and parsed.metadata_raw in SUBTYPE_METADATA
            else "unsupported"
        ),
        representation="macro_source.matcher_manifest.v3",
        data=JSONObject(
            (
                ("record_type", MACRO_SOURCE_TYPE),
                ("raw_payload_hex", bytes(raw).hex()),
                (
                    "receiver_framing",
                    JSONObject(
                        (
                            ("name_length_offset", 0),
                            ("name_length", len(parsed.name_bytes)),
                            ("name_offset", 1),
                            ("name_length_bytes", len(parsed.name_bytes)),
                            ("name_encoding", "unknown"),
                            (
                                "name_bytes_ascii_compatible",
                                all(byte < 0x80 for byte in parsed.name_bytes),
                            ),
                            ("header_offset", header_offset),
                            ("header_width", WORD_SIZE),
                            ("header_byte_order", "little"),
                            ("packed_header", parsed.packed_header),
                            ("count_mask", 0x3F),
                            ("count", parsed.count),
                            ("metadata_raw", parsed.metadata_raw),
                            ("primary_offset", primary_offset),
                            ("primary_length", primary_length),
                            ("secondary_offset", secondary_offset),
                            (
                                "secondary_state",
                                "complete"
                                if parsed.secondary is not None
                                else "absent_or_incomplete",
                            ),
                            ("secondary_length", secondary_length),
                            (
                                "unconsumed_offset",
                                secondary_offset + secondary_length,
                            ),
                            (
                                "unconsumed_role",
                                "trailing_or_incomplete_secondary_raw",
                            ),
                            ("trailing_raw_hex", parsed.trailing.hex()),
                        )
                    ),
                ),
                (
                    "safecrc_pair_map",
                    JSONObject(
                        (
                            ("key_width", 8),
                            ("key_fields", JSONArray(("field0", "field1"))),
                            ("field_names_confirmed", False),
                            ("field0_source", "primary[index]"),
                            (
                                "field1_source",
                                "secondary[index], or zero when no complete vector exists",
                            ),
                            ("value", "source_entry_index"),
                            ("inserted_for_each_pair", True),
                            ("duplicate_keys_allowed", True),
                        )
                    ),
                ),
                (
                    "name_handling",
                    JSONObject(
                        (
                            ("wire_bytes_preserved_by_exporter", True),
                            (
                                "receiver_use",
                                "signature_properties_and_recid_input",
                            ),
                            ("copied_into_source_signature_entry", False),
                            ("encoding", "unknown"),
                        )
                    ),
                ),
                ("source_pairs", pairs),
                (
                    "candidate_matching",
                    JSONObject(
                        (
                            ("lookup", "safecrc_pair_map membership candidate lookup"),
                            (
                                "comparison",
                                (
                                    "each source entry pair must match a candidate pair "
                                    "under safecrc_t equality"
                                ),
                            ),
                            (
                                "field0_rule",
                                "the two field0 DWORDs must be equal",
                            ),
                            (
                                "field1_rule",
                                (
                                    "if either field1 upper 16 bits are zero, the pair "
                                    "matches; otherwise both full field1 DWORDs must be equal"
                                ),
                            ),
                            ("empty_candidate_pairs_match", False),
                            ("empty_source_entry_pairs_match", False),
                            (
                                "pair_order",
                                "source vector sorted for binary search; wire order is not proof of sortedness",
                            ),
                            ("pair_field_names", "unknown"),
                        )
                    ),
                ),
                (
                    "subtype_compatibility",
                    JSONObject(
                        (
                            ("metadata_raw", parsed.metadata_raw),
                            ("compatible_subtype_values", JSONArray(compatible)),
                            (
                                "confirmed_metadata_to_subtypes",
                                JSONArray(
                                    tuple(
                                        JSONObject(
                                            (
                                                ("metadata_raw", metadata),
                                                ("subtypes", JSONArray(subtypes)),
                                            )
                                        )
                                        for metadata, subtypes in sorted(
                                            SUBTYPE_METADATA.items()
                                        )
                                    )
                                ),
                            ),
                            ("enum_names", "unknown"),
                        )
                    ),
                ),
                (
                    "report_path",
                    JSONArray(
                        (
                            "RME::MatchSigs",
                            "RME::CompareSig",
                            "metadata subtype compatibility check",
                            "RME::reportvirus(recid, 0, EmptySha1, false)",
                        )
                    ),
                ),
                (
                    "report_effect",
                    JSONObject(
                        (
                            ("confirmed_scope", "RME_internal_best_match_state"),
                            ("outer_scan_result", "unknown"),
                            ("host_visible_verdict", "unknown"),
                        )
                    ),
                ),
            )
        ),
        evidence=(
            "mpengine 1.443.903.0 macro_source_push @ 0x180321B30 frames name/header and constructs safecrc pairs",
            "mpengine 1.443.903.0 RME::MatchSigs @ 0x18032348C retrieves source-entry indices from the pair map",
            "mpengine 1.443.903.0 RME::CompareSig @ 0x180373010 requires every source pair before subtype validation",
            "mpengine 1.443.903.0 safecrc_t::operator== @ 0x18037314C defines the pair comparison rule",
            "mpengine 1.443.903.0 RME::reportvirus @ 0x1805EBF24 receives the entry RecID after subtype compatibility succeeds",
        ),
        profile="mpengine-1.443.903.0",
        issues=tuple(issues),
        claims=(
            SemanticClaim(
                id="macro_source.wire",
                scope="wire_layout",
                statement=(
                    "MACRO_SOURCE contains a length-prefixed name, a packed "
                    "count/metadata DWORD, a required primary DWORD vector, and "
                    "an optional secondary vector consumed only when complete."
                ),
                coverage="complete",
                evidence_refs=("macro_source.receiver.static",),
            ),
            SemanticClaim(
                id="macro_source.dispatch",
                scope="loader_dispatch",
                statement=(
                    "The analyzed macro module registers type 0x43 to "
                    "macro_source_push."
                ),
                coverage="subset",
                evidence_refs=("macro_source.dispatch.static",),
                unknowns=(
                    SemanticUnknown(
                        "loader_dispatch",
                        "Module/category availability and registration failure paths "
                        "remain outside this type-to-callback mapping.",
                    ),
                ),
            ),
            SemanticClaim(
                id="macro_source.receiver",
                scope="receiver_transform",
                statement=(
                    "The receiver uses the name bytes for property/RecID creation "
                    "without copying them into g_SourceSigs, stores metadata_raw and "
                    "sorted safecrc pairs, and indexes each pair to the source entry."
                ),
                coverage="subset",
                evidence_refs=("macro_source.receiver.static",),
                unknowns=(
                    SemanticUnknown(
                        "receiver_transform",
                        "Name encoding, metadata enum names, pair field names, and "
                        "the role of unconsumed partial-secondary bytes are unknown.",
                    ),
                ),
            ),
            SemanticClaim(
                id="macro_source.consumer",
                scope="runtime_consumer",
                statement=(
                    "RME::MatchSigs uses the pair map as a candidate index, then "
                    "RME::CompareSig requires every stored source pair to be covered "
                    "and applies the observed subtype-to-metadata compatibility map."
                ),
                coverage="subset",
                evidence_refs=("macro_source.consumer.static",),
                unknowns=(
                    SemanticUnknown(
                        "runtime_consumer",
                        "Candidate-pair production and the complete subtype enum are "
                        "outside the analyzed lookup functions.",
                    ),
                ),
            ),
            SemanticClaim(
                id="macro_source.predicate",
                scope="detection_predicate",
                statement=(
                    "Within the analyzed source-signature path, a candidate requires "
                    "a non-empty candidate set, coverage of all stored pairs under "
                    "safecrc equality, subtype compatibility, and reportvirus success."
                ),
                coverage="subset",
                evidence_refs=("macro_source.consumer.static",),
                unknowns=(
                    SemanticUnknown(
                        "detection_predicate",
                        "The caller's scan context, candidate construction, and "
                        "higher-level macro predicate are not closed.",
                    ),
                ),
            ),
            SemanticClaim(
                id="macro_source.report",
                scope="report_mapping",
                statement=(
                    "A passing CompareSig candidate is submitted by stored RecID to "
                    "RME::reportvirus, whose success is required by CompareSig."
                ),
                coverage="subset",
                evidence_refs=("macro_source.report.static",),
                unknowns=(
                    SemanticUnknown(
                        "report_mapping",
                        "RME-local best-match arbitration and the outer scan reply "
                        "mapping are not fully modeled.",
                    ),
                ),
            ),
            SemanticClaim(
                id="macro_source.final",
                scope="final_verdict",
                statement=(
                    "A successful MACRO_SOURCE CompareSig/reportvirus path does not "
                    "establish the final host-visible verdict."
                ),
                coverage="unknown",
                unknowns=(
                    SemanticUnknown(
                        "final_verdict",
                        "Final scan arbitration lies outside the analyzed path.",
                    ),
                ),
            ),
        ),
        claim_evidence=(
            SemanticEvidence(
                id="macro_source.dispatch.static",
                axis="dispatch",
                kind="engine_static",
                source_ref="mpengine 1.443.903.0",
                locator=(
                    "macro_init_module @ 0x180BE28B0; macro_source_push @ 0x180321B30"
                ),
                supports=("macro_source.dispatch",),
            ),
            SemanticEvidence(
                id="macro_source.receiver.static",
                axis="receiver",
                kind="engine_static",
                source_ref="mpengine 1.443.903.0",
                locator="macro_source_push @ 0x180321B30",
                supports=("macro_source.wire", "macro_source.receiver"),
            ),
            SemanticEvidence(
                id="macro_source.consumer.static",
                axis="consumer",
                kind="engine_static",
                source_ref="mpengine 1.443.903.0",
                locator=("RME::MatchSigs @ 0x18032348C; RME::CompareSig @ 0x180373010"),
                supports=("macro_source.consumer", "macro_source.predicate"),
            ),
            SemanticEvidence(
                id="macro_source.report.static",
                axis="report",
                kind="engine_static",
                source_ref="mpengine 1.443.903.0",
                locator=(
                    "RME::CompareSig @ 0x180373010; RME::reportvirus @ 0x1805EBF24"
                ),
                supports=("macro_source.report",),
            ),
        ),
    )


SPEC = FamilySpec(
    MACRO_SOURCE_TYPE,
    "MACRO_SOURCE",
    parse_macro_source,
    render_macro_source,
    semantic_exporter=export_macro_source_semantics,
)
