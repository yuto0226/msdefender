"""Parser and concise renderer for KCRCE (0x80) payloads."""

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
from ..recid import RecIdTail, parse_recid_tail

KCRCE_TYPE: Final = 0x80
BASE_SIZE: Final = 16
UNRESOLVED_FLAGS_MASK: Final = 0x30000000
REQUIRE_FASTCRC_WHEN_PROVIDER_KEY_MISSING: Final = 0x40000000
SUPPRESS_WEAK_FASTCRC_FALLBACK: Final = 0x80000000
_COMMON_PE_CRC2: Final = JSONObject(
    (
        ("callable", "lib.vdm.kcrce_match.evaluate_kcrce_pe_crc2"),
        ("decode_callable", "lib.vdm.kcrce_match.decode_kcrce_pe_range"),
        ("context_type", "lib.vdm.kcrce_match.KcrcePeContext"),
        ("section_type", "lib.vdm.kcrce_match.KcrcePeSection"),
        ("range_type", "lib.vdm.kcrce_match.KcrcePeRange"),
        ("result_type", "lib.vdm.kcrce_match.KcrcePeCrc2Result"),
        (
            "applicability",
            "only when the actual scanner selects kcrc_callback@0x18044C1E0; never inferred from this record",
        ),
        (
            "scanner_source",
            "DO_KCRCE_SCAN selects normalized section index; raw offset/size are scanner fields pe+4048h/4044h+40*index, not an arbitrary unnormalized PE header",
        ),
        ("start", "u32(selected_section.raw_offset + ((length_flags >> 16) & 0xfff))"),
        ("length", "length_flags & 0xffff"),
        ("end", "u64(start) + length; not clamped to section size"),
        (
            "cold_gate",
            "index < section_count, raw_size >=512, successful prefetch yields at least512 bytes; prefetch requests min(raw_size,1024)",
        ),
        (
            "crc",
            "CRC_0 seed FFFFFFFF, no final XOR; successful short/EOF reads add only available bytes",
        ),
        (
            "match",
            "record_local_crc2_match compares record.crc2 even for reset-default or partial CRC; range_complete is independent",
        ),
        (
            "inputs",
            "complete immutable source bytes, actual normalized sections tuple and selected index; fresh provider and cold window",
        ),
        (
            "unknown_boundary",
            "no negative HRESULT, warm/cache origin, OEP/VMM/other callback domain, crc1/fastcrc arbitration, weak fallback, attribute/NID108 or final verdict model",
        ),
        (
            "high_flags_boundary",
            "only the analyzed stage2/common-PE path masks high four bits; global bits28-29 remain unresolved",
        ),
    )
)


@dataclass(frozen=True, slots=True)
class KcrcePayload:
    raw: bytes
    fastcrc: int
    crc1: int
    crc2: int
    length_flags: int
    callback_arg_low16: int
    callback_arg_bits16_27: int
    unresolved_flags: int
    require_fastcrc_when_provider_key_missing: bool
    suppress_weak_fastcrc_fallback: bool
    recid_tail: RecIdTail | None


def parse_kcrce(payload: bytes) -> KcrcePayload:
    """Parse the fixed KCRCE wire prefix and an optional shared RecID tail."""
    if len(payload) < BASE_SIZE:
        raise ValueError(
            f"truncated KCRCE header: need {BASE_SIZE} bytes, have {len(payload)}"
        )

    fastcrc = int.from_bytes(payload[0:4], "little")
    crc1 = int.from_bytes(payload[4:8], "little")
    crc2 = int.from_bytes(payload[8:12], "little")
    length_flags = int.from_bytes(payload[12:16], "little")
    return KcrcePayload(
        raw=payload,
        fastcrc=fastcrc,
        crc1=crc1,
        crc2=crc2,
        length_flags=length_flags,
        callback_arg_low16=length_flags & 0xFFFF,
        callback_arg_bits16_27=(length_flags >> 16) & 0xFFF,
        unresolved_flags=length_flags & UNRESOLVED_FLAGS_MASK,
        require_fastcrc_when_provider_key_missing=bool(
            length_flags & REQUIRE_FASTCRC_WHEN_PROVIDER_KEY_MISSING
        ),
        suppress_weak_fastcrc_fallback=bool(
            length_flags & SUPPRESS_WEAK_FASTCRC_FALLBACK
        ),
        recid_tail=parse_recid_tail(payload[BASE_SIZE:]),
    )


def _printable_preview(data: bytes) -> str | None:
    try:
        preview = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return preview if preview and all(char.isprintable() for char in preview) else None


def _format_flags(parsed: KcrcePayload) -> str:
    states = []
    if parsed.require_fastcrc_when_provider_key_missing:
        states.append("require_fastcrc_when_provider_key_missing")
    if parsed.suppress_weak_fastcrc_fallback:
        states.append("suppress_weak_fastcrc_fallback")
    if parsed.unresolved_flags:
        states.append(f"unresolved=0x{parsed.unresolved_flags:08x}")
    if not states:
        return f"none (0x{parsed.length_flags:08x})"
    return f"{', '.join(states)} (0x{parsed.length_flags:08x})"


def render_kcrce(parsed: KcrcePayload) -> FormatResult:
    """Render confirmed matching inputs while keeping callback scope cautious."""
    sections = [
        DisplaySection(
            "Match Parameters",
            rows=(
                ("callback_domain", "scanner-supplied; not encoded in this record"),
                ("callback_arg_low16", f"0x{parsed.callback_arg_low16:04x}"),
                (
                    "callback_arg_bits16_27",
                    f"0x{parsed.callback_arg_bits16_27:03x}",
                ),
                ("flags", _format_flags(parsed)),
            ),
        ),
        DisplaySection(
            "CRC Fingerprints",
            rows=(
                ("fastcrc", f"0x{parsed.fastcrc:08x}"),
                ("crc1", f"0x{parsed.crc1:08x}"),
                ("crc2", f"0x{parsed.crc2:08x}"),
            ),
        ),
    ]

    if parsed.recid_tail is not None:
        tail = parsed.recid_tail
        alias_rows = [
            ("name_length_limit", f"{tail.length_limit} B"),
            ("effective_name_length", f"{len(tail.object_raw)} B"),
        ]
        if tail.has_object:
            preview = _printable_preview(tail.object_raw)
            if preview is not None:
                alias_rows.append(("name_preview", preview))
        alias_rows.extend(
            (
                ("attribute", str(tail.object_raw.startswith(b"!#")).lower()),
                ("trailing_length", f"{len(tail.trailing_raw)} B"),
            )
        )
        sections.append(DisplaySection("Threat Alias", rows=tuple(alias_rows)))

    return FormatResult(sections=tuple(sections))


def _raw_span(offset: int, length: int) -> JSONObject:
    return JSONObject((("offset", offset), ("length", length)))


def _raw_frame(kind: str, offset: int, raw: bytes) -> JSONObject:
    return JSONObject(
        (
            ("kind", kind),
            ("raw_span", _raw_span(offset, len(raw))),
            ("raw_hex", raw.hex()),
        )
    )


def export_kcrce_semantics(parsed: KcrcePayload) -> RuleSemantics:
    """Export the confirmed KCRCE comparison pipeline, not a final verdict."""
    tail = parsed.recid_tail
    tail_raw = b"" if tail is None else tail.raw
    framing = JSONArray(
        (
            _raw_frame("fastcrc", 0, parsed.raw[0:4]),
            _raw_frame("crc1", 4, parsed.raw[4:8]),
            _raw_frame("crc2", 8, parsed.raw[8:12]),
            _raw_frame("length_flags", 12, parsed.raw[12:16]),
            _raw_frame("recid_tail", BASE_SIZE, tail_raw),
        )
    )
    issues = [
        SemanticIssue(
            "callback_family_not_encoded",
            "The scanner supplies the callback family that interprets the packed "
            "range; the record does not identify that family.",
        ),
        SemanticIssue(
            "outer_verdict_unknown",
            "A KCRCE lookup result does not by itself define the final scan report.",
        ),
    ]
    unsupported = bool(parsed.unresolved_flags)
    if parsed.unresolved_flags:
        issues.append(
            SemanticIssue(
                "unresolved_flags_present",
                "Unresolved length_flags bits are retained without assigning behavior.",
                (("mask", parsed.unresolved_flags),),
            )
        )
    if tail is not None:
        if tail.length_limit > len(tail.raw) - 1:
            issues.append(
                SemanticIssue(
                    "recid_tail_length_clamped",
                    "The receiver clamps the declared RecID name length to the available bytes.",
                    (
                        ("declared_length", tail.length_limit),
                        ("available_length", len(tail.raw) - 1),
                    ),
                )
            )
        if tail.trailing_raw:
            issues.append(
                SemanticIssue(
                    "recid_tail_suffix_ignored",
                    "createrecidpc ignores bytes after the bounded RecID name; "
                    "they are retained only for lossless wire export.",
                    (("length", len(tail.trailing_raw)),),
                )
            )

    return RuleSemantics(
        status="unsupported" if unsupported else "confirmed_subset",
        representation="kcrce.match_pipeline.ir.v2",
        data=JSONObject(
            (
                ("type", "kcrce_match_pipeline"),
                ("raw_hex", parsed.raw.hex()),
                ("framing", framing),
                (
                    "matching_pipeline",
                    JSONArray(
                        (
                            JSONObject(
                                (
                                    ("compare_stage", 0),
                                    ("callback_mode", 1),
                                    ("field", "crc1"),
                                    ("expected", parsed.crc1),
                                    ("source", "provider_callback_mode_1"),
                                    ("comparison", "exact"),
                                    ("index_role", "primary_equal_range"),
                                )
                            ),
                            JSONObject(
                                (
                                    ("compare_stage", 1),
                                    ("callback_mode", 0),
                                    ("field", "fastcrc"),
                                    ("expected", parsed.fastcrc),
                                    (
                                        "source",
                                        "cached_provider_key_or_callback_mode_0",
                                    ),
                                    (
                                        "comparison",
                                        "exact_if_provider_key_or_flag_0x40000000",
                                    ),
                                )
                            ),
                            JSONObject(
                                (
                                    ("compare_stage", 2),
                                    ("callback_mode", 2),
                                    ("field", "crc2"),
                                    ("expected", parsed.crc2),
                                    ("source", "provider_callback_mode_2"),
                                    ("comparison", "exact"),
                                )
                            ),
                        )
                    ),
                ),
                (
                    "callback",
                    JSONObject(
                        (
                            ("family_source", "scanner_supplied"),
                            ("family_encoded_in_record", False),
                            ("range_interpretation", "callback_specific"),
                        )
                    ),
                ),
                (
                    "common_pe_crc2_profile",
                    _COMMON_PE_CRC2,
                ),
                (
                    "packed_range",
                    JSONObject(
                        (
                            ("raw_low28", parsed.length_flags & 0x0FFFFFFF),
                            ("callback_arg_low16", parsed.callback_arg_low16),
                            (
                                "callback_arg_bits16_27",
                                parsed.callback_arg_bits16_27,
                            ),
                            (
                                "interpretation",
                                "callback-family-specific; not encoded by KCRCE",
                            ),
                        )
                    ),
                ),
                (
                    "flags",
                    JSONObject(
                        (
                            ("raw", parsed.length_flags),
                            ("unresolved_mask", parsed.unresolved_flags),
                            (
                                "require_fastcrc_when_provider_key_missing",
                                parsed.require_fastcrc_when_provider_key_missing,
                            ),
                            (
                                "suppress_weak_fastcrc_fallback",
                                parsed.suppress_weak_fastcrc_fallback,
                            ),
                        )
                    ),
                ),
                (
                    "crc2_mismatch_fallback",
                    JSONObject(
                        (
                            (
                                "required_gates",
                                JSONArray(
                                    (
                                        "flag_0x80000000_clear",
                                        "record_fastcrc_not_0xffffffff",
                                        "provider_fastcrc_exact",
                                        "resolved_threat_name_nonempty",
                                        "resolved_threat_name_not_attribute",
                                    )
                                ),
                            ),
                            ("result_policy", "not_represented"),
                        )
                    ),
                ),
                (
                    "recid_tail",
                    JSONObject(
                        (
                            ("raw_hex", tail_raw.hex()),
                            (
                                "declared_length",
                                None if tail is None else tail.length_limit,
                            ),
                            (
                                "effective_length",
                                None if tail is None else len(tail.object_raw),
                            ),
                            (
                                "length_rule",
                                "min(declared_length, available_length)",
                            ),
                            (
                                "ignored_suffix_raw_hex",
                                "" if tail is None else tail.trailing_raw.hex(),
                            ),
                        )
                    ),
                ),
            )
        ),
        evidence=(
            "mpengine 1.443.903.0 KCRCE RecordPush, CompareValues, and Lookup data flow",
        ),
        profile="mpengine-1.443.903.0",
        issues=tuple(issues),
        claims=(
            SemanticClaim(
                id="kcrce_wire_layout",
                scope="wire_layout",
                statement=(
                    "KCRCE has a 16-byte fixed prefix and an optional RecID tail "
                    "whose leading byte bounds the receiver-visible name."
                ),
                coverage="complete",
                evidence_refs=("kcrce_receiver",),
            ),
            SemanticClaim(
                id="kcrce_dispatch_path",
                scope="loader_dispatch",
                statement="DispatchRecords routes type 0x80 to KCRCE RecordPush.",
                coverage="complete",
                evidence_refs=("kcrce_dispatch",),
            ),
            SemanticClaim(
                id="kcrce_receiver_projection",
                scope="receiver_transform",
                statement=(
                    "RecordPush copies the fixed prefix, resolves an optional RecID "
                    "name using min(declared, available), ignores its later suffix, "
                    "and stores the resulting threat reference."
                ),
                coverage="subset",
                evidence_refs=("kcrce_receiver",),
                unknowns=(
                    SemanticUnknown(
                        "receiver_transform",
                        "Mini-threat generation and every downstream use of the "
                        "resolved threat reference are not modeled.",
                    ),
                ),
            ),
            SemanticClaim(
                id="kcrce_runtime_comparisons",
                scope="runtime_consumer",
                statement=(
                    "The analyzed lookup narrows by crc1 and applies an optional or "
                    "required fastcrc comparison plus crc2 through a caller-supplied "
                    "provider; the low 28 bits are an opaque provider callback argument."
                ),
                coverage="subset",
                evidence_refs=("kcrce_consumer",),
                unknowns=(
                    SemanticUnknown(
                        "runtime_consumer",
                        "The full callback-family/domain mapping is not encoded in the "
                        "record and is not closed.",
                    ),
                ),
            ),
            SemanticClaim(
                id="kcrce_common_pe_crc2_projection",
                scope="runtime_consumer",
                statement=(
                    "When the scanner selects the common PE callback, a fresh/cold provider "
                    "decodes low16 length and bits16-27 section-relative offset, wraps the initial "
                    "raw-offset sum at32 bits and hashes actual available bytes without clamping "
                    "to the section end. Skipped gates and partial reads retain comparable CRC values."
                ),
                coverage="subset",
                evidence_refs=("kcrce_common_pe_crc2_differential",),
                unknowns=(
                    SemanticUnknown(
                        "runtime_consumer",
                        "The callback family and normalized section view must be supplied by "
                        "the actual scanner. This complete immutable-byte model covers successful "
                        "EOF/short reads, not negative HRESULTs, warm/cache origin or OEP/VMM. "
                        "Bits28-29 global semantics, other compare stages, weak fallback, "
                        "attribute/NID policy and final verdict remain outside this projection.",
                    ),
                ),
            ),
            SemanticClaim(
                id="kcrce_candidate_predicate",
                scope="detection_predicate",
                statement=(
                    "The exact candidate path requires crc1, the bit-30-controlled "
                    "fastcrc gate, and crc2; the weak path additionally requires bit31 "
                    "clear, a non-sentinel exact fastcrc, and a nonempty nonattribute name."
                ),
                coverage="subset",
                evidence_refs=("kcrce_consumer",),
                unknowns=(
                    SemanticUnknown(
                        "detection_predicate",
                        "Bits 28-29, caller preconditions, and outer scan gates remain unknown.",
                    ),
                ),
            ),
            SemanticClaim(
                id="kcrce_report_route",
                scope="report_mapping",
                statement=(
                    "Matched entries resolve their threat name and route through "
                    "attribute aggregation or NID/detection/continuation handling; "
                    "the weak path records a distinct intermediate result."
                ),
                coverage="subset",
                evidence_refs=("kcrce_report",),
                unknowns=(
                    SemanticUnknown(
                        "report_mapping",
                        "Attribute, delayed-result, continuation, and outer arbitration "
                        "are not fully represented.",
                    ),
                ),
            ),
            SemanticClaim(
                id="kcrce_final_verdict",
                scope="final_verdict",
                statement="A KCRCE lookup result does not establish the final verdict.",
                coverage="unknown",
                unknowns=(
                    SemanticUnknown(
                        "final_verdict",
                        "Final scan-result arbitration has not been followed to completion.",
                    ),
                ),
            ),
        ),
        claim_evidence=(
            SemanticEvidence(
                id="kcrce_common_pe_crc2_differential",
                axis="engine_equivalent_test",
                kind="engine_equivalent_test",
                source_ref="mpengine 1.443.903.0 DLL SHA256 928e171c60a44bb326776d2a356412ae98d78469bdf8c94ebfbfa09f8ec4b4b3",
                locator=(
                    "tests/local_kcrce_pe_range_native.py (25 cases/34 native calls; SHA256 "
                    "daea4cd24b5d1425afdf16707045d26e7c5cf33d12688ef0b89e39dc9e47e6b5); "
                    "report SHA256 23ddfacffe03b5b62359ab8fe74792383a02c977142d81e8035a643020f73885; "
                    "tests/local_kcrce_pe_range_differential.py (22 source cases; SHA256 "
                    "06c1d0e77c27fc2d617f5e253bb302dc8e26ff776af0a53c32446892cd9dc5c0); "
                    "DO_KCRCE_SCAN@0x18022E260 -> common callback@0x18044C1E0 -> "
                    "HashOnFile@0x18044C380 -> CRCHashContext::Update@0x180415A70/CRC_0; "
                    "CompareValues@0x1801421D4/get_crc2@0x1801422D0; "
                    "docs/mpengine.dll/1.443.903.0/kcrce_pe_range_private.md; "
                    "explicit Ufs byte services, fresh/cold CRC2 value projection only; "
                    "warm-wrap fixture proves arithmetic, not cold source reconstruction"
                ),
                supports=("kcrce_common_pe_crc2_projection",),
            ),
            SemanticEvidence(
                id="kcrce_receiver",
                axis="receiver",
                kind="engine_static",
                source_ref="mpengine 1.443.903.0",
                locator=(
                    "RecordPush<kcrce_t> @ 0x1800FACD4; createrecidpc @ 0x180435F74"
                ),
                supports=("kcrce_wire_layout", "kcrce_receiver_projection"),
            ),
            SemanticEvidence(
                id="kcrce_dispatch",
                axis="dispatch",
                kind="engine_static",
                source_ref="mpengine 1.443.903.0",
                locator="DispatchRecords @ 0x1800F99A8: type 0x80 receiver table",
                supports=("kcrce_dispatch_path",),
            ),
            SemanticEvidence(
                id="kcrce_consumer",
                axis="consumer",
                kind="engine_static",
                source_ref="mpengine 1.443.903.0",
                locator=(
                    "Lookup<kcrce_t> @ 0x180141558; "
                    "CompareValues<kcrce_t> @ 0x1801421D4"
                ),
                supports=("kcrce_runtime_comparisons", "kcrce_candidate_predicate"),
            ),
            SemanticEvidence(
                id="kcrce_report",
                axis="report",
                kind="engine_static",
                source_ref="mpengine 1.443.903.0",
                locator=(
                    "Lookup<kcrce_t> @ 0x180141558; "
                    "SetDetectionData @ 0x1803D3590; "
                    "ShouldContinueScanning @ 0x1801449E4"
                ),
                supports=("kcrce_report_route",),
            ),
        ),
    )


SPEC = FamilySpec(
    KCRCE_TYPE,
    "KCRCE",
    parse_kcrce,
    render_kcrce,
    semantic_exporter=export_kcrce_semantics,
)
