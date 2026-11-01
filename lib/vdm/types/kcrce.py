"""Parser and concise renderer for KCRCE (0x80) payloads."""

import json
from dataclasses import dataclass
from typing import Final

from ..core import (
    Artifact,
    ArtifactExport,
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


def build_kcrce_oep_recipe_profile() -> JSONObject:
    """One shared conditional recipe for semantic and match-artifact exports."""
    return JSONObject(
        (
            ("representation", "kcrce.oep_adddata_recipe.v1"),
            ("evidence_tier", "engine_static"),
            ("callable", "lib.vdm.kcrce_oep.project_kcrce_oep_request"),
            ("context_type", "lib.vdm.kcrce_oep.KcrceOepContext"),
            ("result_type", "lib.vdm.kcrce_oep.KcrceOepRequest"),
            ("fresh_crc2_callable", "lib.vdm.kcrce_oep.project_kcrce_oep_fresh_crc2"),
            ("callback", "oepkcrc_callback@0x18003F0D0"),
            (
                "initial_candidate_key_mapping",
                "dynkcrc_check caller initial key request: start=candidate (not zero), length=0x20, flags=0x40000000; successful mapping feeds CRC_32 into provider key; separate from callback windows and does not establish mapped bytes",
            ),
            (
                "applicability",
                "external explicit callback family, kind0/1, candidate:u64, callback mode0/1/2, epoch and opaque same-epoch mapper profile; never inferred from wire",
            ),
            ("packed_low28", "length_flags & 0x0fffffff"),
            ("kind0_mode1", "start=u64(candidate-0x100); length=0x100"),
            (
                "kind0_mode2",
                "offset=bits16..27; nonzero offset skips mapping/AddData; otherwise start=u64(candidate-low16), length=low16",
            ),
            ("kind1_mode1", "start=candidate; length=0x100"),
            ("kind1_mode2", "start=u64(candidate+bits16..27); length=low16"),
            ("mode0", "no mapping or AddData in kind0/1; not a whole-record mismatch"),
            ("map_flags", 0x40000000),
            ("conditional_callback_entry_writes", "userdata+0x85=0; pe+0x83fd0=1"),
            ("conditional_mapping_null", "userdata+0x85=1; no AddData"),
            (
                "conditional_mapping_success",
                "AddData(mapped_pointer, requested_length); no local unmap",
            ),
            (
                "mapping_outcome",
                "unknown without separate resolved same-epoch mapper snapshot; zero length and u64 wrap still request mapping",
            ),
            (
                "fresh_crc2_boundary",
                "fresh get_crc2 Reset plus known no-AddData retains FFFFFFFF and can satisfy local stage2 equality; not whole Lookup or final verdict",
            ),
            (
                "unknown_boundary",
                "kind2 unsupported by this kind0/1 entrypoint; the separate oep_kind2_region_recipe_profile requires explicit snapshots; candidate origin/coordinate, VMM/mapper outcomes, bytes, successful AddData, crc1/fastcrc arbitration, weak fallback and final verdict remain outside this entrypoint",
            ),
            (
                "high_flags_boundary",
                "stage2 masks low28; global bits28-29 remain unresolved and existing status/issues stay unchanged",
            ),
        )
    )


def build_kcrce_kind2_recipe_profile() -> JSONObject:
    """Describe the separate kind2 snapshot contract without running its model."""
    return JSONObject(
        (
            ("representation", "kcrce.oep_kind2_region_recipe.v1"),
            ("evidence_tier", "engine_static"),
            ("callback", "oepkcrc_callback@0x18003F0D0"),
            ("callable", "lib.vdm.kcrce_kind2.project_kcrce_kind2"),
            (
                "mapping_helper_callable",
                "lib.vdm.kcrce_kind2.project_kcrce_kind2_mapping",
            ),
            ("snapshot_type", "lib.vdm.kcrce_kind2.K2Snapshot"),
            ("result_type", "lib.vdm.kcrce_kind2.K2Projection"),
            ("request_type", "lib.vdm.kcrce_kind2.K2Request"),
            ("event_type", "lib.vdm.kcrce_kind2.K2Event"),
            (
                "call_contract",
                "project_kcrce_kind2(packed=parsed.length_flags & 0x0fffffff, snapshot=explicit_K2Snapshot); exporting this static profile does not invoke it",
            ),
            (
                "applicability",
                "explicit callback family=oepkcrc_callback, kind=2, mode0/1/2 and same-epoch opaque mapper_profile; never selected from the wire record",
            ),
            (
                "packed_argument",
                "CompareValues stage2 supplies length_flags & 0x0fffffff; mode2 offset=(packed>>16)&0xfff and count=packed&0xffff",
            ),
            (
                "required_snapshots",
                JSONObject(
                    (
                        (
                            "top",
                            "K2Snapshot: epoch, callback_family, kind, mode, mapper_profile, page_size, iterator, pe, mode2_ptr, selected_length, selected_base, state_084",
                        ),
                        (
                            "iterator",
                            "K2Iterator: epoch, initialized, init_result, complete ordered ranges, next_index, current_index, cached_ptr, cached_offset, cached_length, cached_flags, locked",
                        ),
                        (
                            "region",
                            "K2Region: epoch, page_start:u64, page_count:u32, kind:u32, covering; current_index==len(ranges) means explicit NULL",
                        ),
                        (
                            "covering",
                            "K2Covering: epoch, search_complete, base, size, index, index_count, excluded; complete search with base=None denotes no covering entry",
                        ),
                        (
                            "pe",
                            "K2PeGates: epoch, allowed_start/end, bypass, complete ordered overlap intervals, special_start",
                        ),
                        (
                            "missing_facts",
                            "None means unknown; boolean/numeric facts have no implicit false/zero defaults; same-epoch validation applies to supplied nested snapshots",
                        ),
                        (
                            "path_requirements",
                            "only facts reached by the projected path are needed: mode0 needs no iterator; mode2 non-NULL userdata+0x98 reuse still needs selected-length bounds but no current/page_size; initialized enumeration needs no init_result",
                        ),
                        (
                            "initialization",
                            "uninitialized iterator needs explicit init_result; successful init starts at range index0; no init_enum_ranges service is executed or inferred",
                        ),
                    )
                ),
            ),
            (
                "coordinate_domains",
                JSONObject(
                    (
                        (
                            "descriptor",
                            "B=page_start*page_size within the normal uint64 subset, C=u32(page_count*page_size); u64 base wrap is a typed error; descriptor and page_size are explicit VMM facts, not disk offsets",
                        ),
                        (
                            "metadata",
                            "userdata+0xa8=B and +0xa0=C; if B==pe.allowed_start and C>0x1000, metadata base+=0x1000 and length-=0x1000; current descriptor is unchanged",
                        ),
                        (
                            "mapping",
                            "mode1 and cold mode2 map from descriptor B, never from adjusted metadata +0xa8; +0xa8+offset is not the byte-source formula",
                        ),
                        (
                            "lengths",
                            "descriptor C, selected metadata length, logical mapper request, page-aligned copy request and AddData count remain distinct",
                        ),
                    )
                ),
            ),
            (
                "mode0",
                "write userdata+0x85=0 and pe+0x83fd0=1 only; no mapping/AddData and no reset of userdata+0x84 or selected region",
            ),
            (
                "mode1",
                JSONObject(
                    (
                        (
                            "reset_order",
                            "entry writes; clear userdata+0x98/+0xa0/+0xa8/+0x84; each selection loop clears iterator.cached_ptr/flags but preserves length and locked",
                        ),
                        (
                            "selection",
                            "consume ordered ranges with next cursor; page-scaled descriptor and conditional prior-lock unlock; image interval/bypass accept, covering vdll exclusion skips, first overlap accepts unless fully covered, otherwise special_start with C==0x1000 skips; partial overlap does not clip descriptor",
                        ),
                        (
                            "request",
                            "C<0x100 skips; otherwise kind1 descriptor uses mmap64_lock(B,0x100,flags=1,out_locked); other descriptor kinds allocate/copy aligned 0x100 bytes from B",
                        ),
                        (
                            "success",
                            "only conditional service success writes cache length,pointer,flags,offset in that order, then userdata+0x84=1 and AddData(pointer,0x100)",
                        ),
                        (
                            "failure",
                            "init failure, exhaustion or mapping/allocation/copy failure does not set userdata+0x85; no unconditional post-AddData unlock",
                        ),
                    )
                ),
            ),
            (
                "mode2",
                JSONObject(
                    (
                        (
                            "bounds",
                            "bounds use the original u64 selected_length: zero sets userdata+0x85=1; offset+count>selected_length skips without setting error; count0 is not rejected by callback",
                        ),
                        (
                            "callback_cache",
                            "non-NULL userdata+0x98 reuses the full-range pointer; otherwise request u32(selected_length), flags1 from mmap_crt_range; first explicit helper parameter is unused",
                        ),
                        (
                            "iterator_cache",
                            "helper checks current!=NULL before warm cache; cached_offset0, positive cached_length>=request, flags&1 and non-NULL pointer hit before cold request0/capacity gates",
                        ),
                        (
                            "cold_request",
                            "unlock previous lock before page_size/capacity gates; request=u32(selected_length), truncating high32 after the u64 callback bounds check; request0 or request>C returns NULL; kind1 maps(B,request,1), otherwise allocate/copy page-aligned request",
                        ),
                        (
                            "success",
                            "helper cache writes offset,length,flags,pointer; callback caches pointer at userdata+0x98; AddData(pointer+offset,count), conditional on service success or explicit cache availability",
                        ),
                        (
                            "failure",
                            "NULL helper result caches NULL and sets userdata+0x85=1; userdata+0x84 is unchanged throughout mode2",
                        ),
                    )
                ),
            ),
            (
                "conditional_events",
                "K2Event target/value/condition preserve operation order; mapper_out_bool is an independent output during mapper_returned, before success cache writes; mapping_success and allocation_and_copy_success are unevaluated conditions, never observed outcomes; userdata+0x85=0 is not success and +0x84=1 does not establish current mode2 AddData",
            ),
            (
                "result_boundary",
                "projected means conditional recipe available, unknown means missing required facts; K2SnapshotError rejects wrong types, bool-as-uint, mixed epochs, malformed assertions and normal-subset u64 wrap; capacity product retains u32 wrap",
            ),
            (
                "runtime_boundary",
                "no default snapshots, automatic PE/VMM reads, mapper/allocation/copy services, byte source, CRC, local match, Lookup arbitration or final verdict; supplied facts do not establish mapping success",
            ),
            (
                "relation_to_kind0_1",
                "lib.vdm.kcrce_oep.project_kcrce_oep_request still returns unsupported for kind2; this separate snapshot-based entrypoint does not change its behavior or common PE file slicing",
            ),
            (
                "high_flags_boundary",
                "the stage2 low28 argument does not resolve global bits28-29; preserve raw flags, scoped known uses, unresolved issues and existing status",
            ),
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
                ("oep_adddata_recipe_profile", build_kcrce_oep_recipe_profile()),
                ("oep_kind2_region_recipe_profile", build_kcrce_kind2_recipe_profile()),
                (
                    "high_flags_known_uses",
                    JSONObject(
                        (
                            ("evidence_tier", "engine_static"),
                            ("raw_length_flags", parsed.length_flags),
                            ("unresolved_bits28_29", parsed.unresolved_flags),
                            (
                                "known_uses",
                                JSONArray(
                                    (
                                        "runtime_storage",
                                        "offline_cache_record_bytes",
                                        "full_length_flags_sort_tiebreak",
                                        "signature_identity_input",
                                    )
                                ),
                            ),
                            (
                                "crc2_argument",
                                JSONObject(
                                    (
                                        ("value", parsed.length_flags & 0x0FFFFFFF),
                                        ("mask", 0x0FFFFFFF),
                                        (
                                            "scope",
                                            "CompareValues<kcrce_t> stage2 -> get_crc2 callback argument and this path's cache key; bits28-29 excluded",
                                        ),
                                    )
                                ),
                            ),
                            (
                                "sort_tiebreak",
                                JSONObject(
                                    (
                                        ("field_offset", 12),
                                        ("value", parsed.length_flags),
                                        ("mask", 0xFFFFFFFF),
                                        (
                                            "comparison",
                                            "unsigned_u32_ascending_after_offset_and_length",
                                        ),
                                        (
                                            "scope",
                                            "analyzed kcrce_t insertion-sort comparator; includes bits28-29 after crc1, fastcrc, packed offset and length ties",
                                        ),
                                    )
                                ),
                            ),
                            (
                                "identity_input",
                                JSONObject(
                                    (
                                        ("offset", 0),
                                        ("length", 16),
                                        ("raw_hex", parsed.raw[:BASE_SIZE].hex()),
                                        (
                                            "consumers",
                                            JSONArray(
                                                (
                                                    "GetSigSeq -> CRC_1",
                                                    "Lookup -> MakeSigSha(type=0x80,length=16)",
                                                )
                                            ),
                                        ),
                                        (
                                            "scope",
                                            "original four DWORD prefix including full length_flags; excludes runtime threat_ref and wire RecID tail; no hash implementation or collision claim",
                                        ),
                                    )
                                ),
                            ),
                            (
                                "unknown_boundary",
                                "no global ignored-bit, dedup-absence, resolved predicate or equal report/final-verdict claim; preserve raw bytes and existing unresolved flags/status/issues",
                            ),
                        )
                    ),
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
                id="kcrce_oep_kind2_region_recipe",
                scope="runtime_consumer",
                statement=(
                    "With explicit same-epoch OEP kind2 iterator, current-region, selection "
                    "and cache snapshots, mode0/1/2 project conditional VMM service requests "
                    "and ordered state-write recipes; adjusted selected metadata does not "
                    "replace the descriptor mapping base, and full mapping/copy lengths "
                    "remain distinct from AddData offset/count."
                ),
                coverage="subset",
                evidence_refs=("kcrce_oep_kind2_static",),
                unknowns=(
                    SemanticUnknown(
                        "runtime_consumer",
                        "The wire does not identify this callback or supply snapshots. "
                        "Missing path facts remain unknown; service success, actual bytes, "
                        "CRC values, local match, outer arbitration and final verdict are "
                        "not projected. This adds no global semantics for bits28-29.",
                    ),
                ),
            ),
            SemanticClaim(
                id="kcrce_high_flags_scoped_uses",
                scope="runtime_consumer",
                statement=(
                    "In the analyzed KCRCE paths, bits28-29 are excluded from the stage2 "
                    "CRC2 callback argument/cache key but retained in record/cache bytes, "
                    "the full-DWORD unsigned sort tie-break and the original 16-byte "
                    "GetSigSeq/MakeSigSha input; the identity input excludes the RecID tail."
                ),
                coverage="subset",
                evidence_refs=("kcrce_high_flags_static",),
                unknowns=(
                    SemanticUnknown(
                        "runtime_consumer",
                        "Global predicate behavior and other consumers remain unresolved. "
                        "Different raw inputs do not establish distinct hashes or final verdicts; "
                        "no full-engine absence of deduplication is claimed.",
                    ),
                ),
            ),
            SemanticClaim(
                id="kcrce_oep_adddata_recipe",
                scope="runtime_consumer",
                statement=(
                    "With explicit OEP callback kind0/1 and caller mapping candidate, "
                    "mode1/2 project conditional u64 backward/forward mapping requests; "
                    "kind0 mode2 nonzero offset and mode0 do not AddData."
                ),
                coverage="subset",
                evidence_refs=("kcrce_oep_recipe_static",),
                unknowns=(
                    SemanticUnknown(
                        "runtime_consumer",
                        "Callback identity is not encoded; candidate origin and mapping outcome, "
                        "successful bytes/AddData and final verdict are not modeled by this "
                        "kind0/1 entrypoint; kind2 uses a separate snapshot-based recipe. "
                        "Fresh reset no-AddData can still equal record.crc2 locally.",
                    ),
                ),
            ),
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
                id="kcrce_oep_kind2_static",
                axis="consumer",
                kind="engine_static",
                source_ref="mpengine 1.443.903.0 DLL SHA256 928e171c60a44bb326776d2a356412ae98d78469bdf8c94ebfbfa09f8ec4b4b3",
                locator=(
                    "oepkcrc_callback@0x18003F0D0/0x772 kind2 entry@0x18003F113, "
                    "metadata stores@0x18003F37F and trim@0x18003F677, "
                    "mode1 success cache writes@0x18003F485..0x18003F493, "
                    "mode2 bounds/map/AddData@0x18003F6AE..0x18003F70D; "
                    "VMM_range_iterator::mmap_crt_range@0x18003EEA8/0x1E3 "
                    "current-before-warm@0x18003EEC0, cold unlock-before-gates@0x18003EEF9..0x18003EF64; "
                    "VMM_range_iterator::init@0x18013F538/0x119 and mmap_unlock@0x18003F08C/0x42; "
                    "docs/signature/KCRCE_kind2_region_next_private.md; "
                    "lib/vdm/kcrce_kind2.py source-only conditional recipe; "
                    "saved static disassembly/machine-byte evidence only, no runtime service execution"
                ),
                supports=("kcrce_oep_kind2_region_recipe",),
            ),
            SemanticEvidence(
                id="kcrce_high_flags_static",
                axis="consumer",
                kind="engine_static",
                source_ref="mpengine 1.443.903.0 DLL SHA256 928e171c60a44bb326776d2a356412ae98d78469bdf8c94ebfbfa09f8ec4b4b3",
                locator=(
                    "RecordPush@0x1800FACD4 copy@0x1800FAD94; "
                    "PostProcessRecordsWorker@0x1802C6770 cache WriteFile@0x1802C6EE3; "
                    "LoadCache@0x1802C62B4 map@0x1802C6646; "
                    "Insertion_sort_unchecked@0x1803A5A98 full-DWORD unsigned cmp@0x1803A5B9B "
                    "bytes 44 3b c8 72 b3 77 0d; "
                    "CompareValues@0x1801421EC..0x1801421FA low28 -> get_crc2@0x1801422D0; "
                    "GetSigSeq@0x1804F88F0 input length16@0x1804F8905 and full flags@0x1804F891C; "
                    "Lookup MakeSigSha calls@0x180141A29/0x180141BE9, "
                    "original prefix copies@0x1801419F0/0x180141BB3 and length16@0x180141A13/0x180141BD6; "
                    "docs/signature/KCRCE_bits28_29_scope_private.md; saved static callsite/byte evidence only"
                ),
                supports=("kcrce_high_flags_scoped_uses",),
            ),
            SemanticEvidence(
                id="kcrce_oep_recipe_static",
                axis="consumer",
                kind="engine_static",
                source_ref="mpengine 1.443.903.0",
                locator=(
                    "dynkcrc_check@0x180140788; oepkcrc_callback@0x18003F0D0 "
                    "kind0@0x18003F589/kind1@0x18003F662; "
                    "get_fwdepcrc@0x1804833FC; Reset@0x180142080; "
                    "get_crc2@0x1801422D0; CompareValues@0x1801421D4; "
                    "docs/signature/KCRCE_consumer_next_private.md; saved static source evidence only"
                ),
                supports=("kcrce_oep_adddata_recipe",),
            ),
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


def export_kcrce(parsed: KcrcePayload) -> ArtifactExport:
    """Export portable conditional IR; ready means an artifact is available."""
    parsed = parse_kcrce(parsed.raw)
    document = {
        "format": "kcrce.record.ir.v1",
        "payload_raw_hex": parsed.raw.hex(),
        "runtime_inputs_resolved": False,
        "record_local_match": None,
        "final_verdict": None,
        "semantics": export_kcrce_semantics(parsed).to_json(),
    }
    data = (json.dumps(document, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    return ArtifactExport(
        status="ready", artifacts=(Artifact("kcrce.json", "kcrce_rule_ir", data),)
    )


SPEC = FamilySpec(
    KCRCE_TYPE,
    "KCRCE",
    parse_kcrce,
    render_kcrce,
    exporter=export_kcrce,
    semantic_exporter=export_kcrce_semantics,
)
