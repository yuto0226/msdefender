"""Parser and concise renderer for STATIC (0x67) payloads."""

import json
from dataclasses import dataclass
from enum import IntEnum
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
    SemanticJSONValue,
    SemanticUnknown,
    semantic_json_to_data,
)
from ..recid import RecIdTail, parse_recid_tail
from ..static_runtime import static_runtime_recipes

STATIC_TYPE: Final = 0x67
HEADER_SIZE: Final = 18
ALLOW_LARGER_MASK: Final = 0x0001
MODE_MASK: Final = 0x7000
IGNORED_FLAGS_MASK: Final = 0x8FFE
CRC_PARAMETERS: Final = {
    "width": 32,
    "polynomial": "0x04C11DB7",
    "reflected_polynomial": "0xEDB88320",
    "refin": True,
    "refout": True,
    "initial_value": "0xFFFFFFFF",
    "final_xor": "0x00000000",
    "state_contract": (
        "STATIC call sites seed 0xFFFFFFFF; CRC_0 itself accepts caller state"
    ),
}

_ENGINE_HASH_DISPATCH: Final = {
    5: "SymCryptSha512",
    6: "LSH",
    7: "CTPH",
}


class StaticHashMode(IntEnum):
    MD5 = 0
    SHA1 = 1
    CRC_0 = 2
    SHA1_PREFIX4 = 3
    SHA256 = 4


_HASH_LENGTHS: Final = {
    StaticHashMode.MD5: 16,
    StaticHashMode.SHA1: 20,
    StaticHashMode.CRC_0: 4,
    StaticHashMode.SHA1_PREFIX4: 4,
    StaticHashMode.SHA256: 32,
}


@dataclass(frozen=True, slots=True)
class StaticPayload:
    raw: bytes
    first_page_crc: int
    tail_page_crc: int
    prefix_crc: int
    file_size: int
    flags: int
    allow_larger: bool
    mode_value: int
    mode: StaticHashMode | None
    hash_raw: bytes
    recid_tail: RecIdTail | None
    opaque_raw: bytes

    @property
    def ignored_flags(self) -> int:
        return self.flags & IGNORED_FLAGS_MASK


def parse_static(payload: bytes) -> StaticPayload:
    """Parse a STATIC payload while retaining every input byte."""
    if len(payload) < HEADER_SIZE:
        raise ValueError(
            f"truncated STATIC header: need {HEADER_SIZE} bytes, have {len(payload)}"
        )

    first_page_crc = int.from_bytes(payload[0:4], "little")
    tail_page_crc = int.from_bytes(payload[4:8], "little")
    prefix_crc = int.from_bytes(payload[8:12], "little")
    file_size = int.from_bytes(payload[12:16], "little")
    flags = int.from_bytes(payload[16:18], "little")
    mode_value = (flags >> 12) & 0x7
    allow_larger = bool(flags & ALLOW_LARGER_MASK)

    try:
        mode = StaticHashMode(mode_value)
    except ValueError:
        return StaticPayload(
            raw=payload,
            first_page_crc=first_page_crc,
            tail_page_crc=tail_page_crc,
            prefix_crc=prefix_crc,
            file_size=file_size,
            flags=flags,
            allow_larger=allow_larger,
            mode_value=mode_value,
            mode=None,
            hash_raw=b"",
            recid_tail=None,
            opaque_raw=payload[HEADER_SIZE:],
        )

    hash_size = _HASH_LENGTHS[mode]
    hash_end = HEADER_SIZE + hash_size
    if len(payload) < hash_end:
        raise ValueError(
            f"truncated STATIC {mode.name} hash: need {hash_size} bytes, "
            f"have {len(payload) - HEADER_SIZE}"
        )
    return StaticPayload(
        raw=payload,
        first_page_crc=first_page_crc,
        tail_page_crc=tail_page_crc,
        prefix_crc=prefix_crc,
        file_size=file_size,
        flags=flags,
        allow_larger=allow_larger,
        mode_value=mode_value,
        mode=mode,
        hash_raw=payload[HEADER_SIZE:hash_end],
        recid_tail=parse_recid_tail(payload[hash_end:]),
        opaque_raw=b"",
    )


def _printable_object(data: bytes) -> str | None:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if text and all(char.isprintable() for char in text):
        return text
    return None


def render_static(parsed: StaticPayload) -> FormatResult:
    if parsed.allow_larger:
        file_size = f">= {parsed.file_size} B"
    else:
        file_size = f"{parsed.file_size} B (exact)"

    if parsed.mode is None:
        hash_display = "unavailable"
    elif parsed.mode is StaticHashMode.CRC_0:
        hash_display = f"0x{int.from_bytes(parsed.hash_raw, 'little'):08X}"
    else:
        hash_display = parsed.hash_raw.hex()

    flag_parts = ["allow_larger" if parsed.allow_larger else "exact"]
    if parsed.ignored_flags:
        flag_parts.append(f"loader_ignored=0x{parsed.ignored_flags:04X}")

    hash_mode = (
        f"{parsed.mode.name}({parsed.mode_value})"
        if parsed.mode is not None
        else f"UNSUPPORTED({parsed.mode_value})"
    )
    policy_rows = (
        ("file_size", file_size),
        ("flags", f"{', '.join(flag_parts)} (0x{parsed.flags:04X})"),
        ("hash_mode", hash_mode),
    )
    fingerprint_rows = [
        ("first_page_crc", f"0x{parsed.first_page_crc:08X}"),
        ("tail_page_crc", f"0x{parsed.tail_page_crc:08X}"),
        ("prefix_crc", f"0x{parsed.prefix_crc:08X}"),
        ("hash", hash_display),
    ]
    if parsed.mode is None:
        fingerprint_rows.append(("opaque_len", f"{len(parsed.opaque_raw)} B"))

    sections = [
        DisplaySection("Match Policy", rows=policy_rows),
        DisplaySection("File Fingerprints", rows=tuple(fingerprint_rows)),
    ]
    if parsed.mode is not None and parsed.recid_tail is not None:
        tail = parsed.recid_tail
        identity_rows = [
            ("recid_tail_len", f"{len(tail.raw)} B"),
            ("object_length_limit", f"{tail.length_limit} B"),
            ("effective_object_len", f"{len(tail.object_raw)} B"),
        ]
        if tail.has_object:
            preview = _printable_object(tail.object_raw)
            if preview is not None:
                identity_rows.append(("object_preview", preview))
            else:
                identity_rows.append(("object_preview", "(nonprintable)"))
        else:
            identity_rows.append(("object", "absent"))
        if tail.trailing_raw:
            identity_rows.append(("trailing_len", f"{len(tail.trailing_raw)} B"))
        sections.append(DisplaySection("Record Identity", rows=tuple(identity_rows)))
    return FormatResult(sections=tuple(sections))


def _stage_profile(parsed: StaticPayload) -> JSONObject:
    """Describe the record-local STATIC stages without evaluating runtime inputs."""

    def obj(**values: SemanticJSONValue) -> JSONObject:
        return JSONObject(tuple(values.items()))

    def expr(operation: str, *operands: SemanticJSONValue) -> JSONObject:
        return obj(operation=operation, operands=JSONArray(operands))

    mode = parsed.mode
    hash_algorithm = (
        {
            StaticHashMode.MD5: "MD5",
            StaticHashMode.SHA1: "SHA1",
            StaticHashMode.CRC_0: "CRC_0",
            StaticHashMode.SHA1_PREFIX4: "SHA1",
            StaticHashMode.SHA256: "SHA256",
        }[mode]
        if mode is not None
        else None
    )
    compared_bytes = len(parsed.hash_raw) if mode is not None else None
    size_gate = obj(
        minimum=expr("greater_or_equal", "provider_size", "record_file_size"),
        exact_when_allow_larger_false=expr(
            "equal", "provider_size", "record_file_size"
        ),
        allow_larger=parsed.allow_larger,
    )
    return obj(
        format="static.stage_profile.v1",
        engine_profile="mpengine-1.443.903.0",
        comparison_supported=mode is not None,
        pipeline_result="requires_runtime_context"
        if mode is not None
        else "rejected_mode",
        mode=parsed.mode_value,
        mode_corpus_status=(
            "unobserved"
            if mode in {StaticHashMode.SHA1_PREFIX4, StaticHashMode.SHA256}
            else "unsupported"
            if mode is None
            else "observed"
        ),
        input=obj(
            source="provider_selected_scan_range",
            offset_source="runtime_provider_unknown_from_record",
            provider_size_source="runtime_provider_unknown_from_record",
            record_file_size=parsed.file_size,
            runtime_context_required=JSONArray(
                (
                    "provider_offset",
                    "provider_size",
                    "selected_file_bytes",
                    "scan_reply_first_page_buffer_when_offset_zero",
                    "configuration_gate",
                )
            ),
        ),
        crc=obj(**CRC_PARAMETERS),
        stages=JSONArray(
            (
                obj(
                    index=0,
                    name="first_page_crc_candidate_key",
                    caller="store_lookup_provider_operator",
                    expected_crc=parsed.first_page_crc,
                    offset_zero=obj(
                        source="SCAN_REPLY+0xC0",
                        byte_count=4096,
                        source_file_equivalence="unknown",
                        zero_padding="not_established",
                    ),
                    nonzero_offset=obj(
                        source="provider_selected_scan_range",
                        start="provider_offset",
                        byte_count=expr("min", "provider_size", 4096),
                        zero_padding=obj(side="append", total_byte_count=4096),
                    ),
                ),
                obj(
                    index=1,
                    name="prefix_crc",
                    caller="CompareValues",
                    size_gate=size_gate,
                    source="provider_selected_scan_range",
                    start="provider_offset",
                    byte_count=expr("min", "record_file_size", 65536),
                    zero_padding=None,
                    expected_crc=parsed.prefix_crc,
                ),
                obj(
                    index=2,
                    name="tail_page_crc",
                    caller="CompareValues",
                    size_gate=size_gate,
                    primary=obj(
                        source="provider_selected_scan_range",
                        start=expr(
                            "add",
                            "provider_offset",
                            expr(
                                "max",
                                expr("subtract", "record_file_size", 4096),
                                0,
                            ),
                        ),
                        byte_count=expr("min", "record_file_size", 4096),
                        zero_padding=obj(side="prepend", total_byte_count=4096),
                    ),
                    alternative=obj(
                        enabled=parsed.allow_larger,
                        when=expr("not", "primary_crc_equal"),
                        source="provider_selected_scan_range",
                        start=expr(
                            "add",
                            "provider_offset",
                            expr("max", expr("subtract", "provider_size", 4096), 0),
                        ),
                        byte_count=expr("min", "provider_size", 4096),
                        zero_padding="unknown_when_provider_shorter_than_4096",
                    ),
                    expected_crc=parsed.tail_page_crc,
                ),
                obj(
                    index=3,
                    name="mode_hash",
                    caller="CompareValues",
                    comparison_supported=mode is not None,
                    size_gate=size_gate,
                    pre_hash_configuration_gate=obj(
                        caller="CompareValues",
                        applicable_name_prefix="CFG:",
                        name_source="get_threat_name_after_first_character",
                        exception_name_check="IsExceptionName",
                        config_calls=obj(
                            A=1, M=3, P=2, arguments=JSONArray(("SCAN_REPLY", 0))
                        ),
                        predicate="all_applicable_CheckConfig_calls_succeed",
                        runtime_context_required=JSONArray(("configuration_gate",)),
                        false_result="no_match_before_GetHashes",
                        unknown_result="no_positive_match",
                        true_includes="caller_confirmed_no_applicable_gate",
                    ),
                    source="provider_selected_scan_range",
                    start="provider_offset",
                    byte_count=parsed.file_size,
                    algorithm=hash_algorithm,
                    computed_digest_bytes=(
                        20 if mode is StaticHashMode.SHA1_PREFIX4 else compared_bytes
                    ),
                    compared_bytes=compared_bytes,
                    compared_part=(
                        "digest_prefix"
                        if mode is StaticHashMode.SHA1_PREFIX4
                        else "complete_output"
                        if mode is not None
                        else None
                    ),
                    expected_hash_hex=parsed.hash_raw.hex()
                    if mode is not None
                    else None,
                    native_hash_range_validation=(
                        obj(
                            evidence_ref="static_mode2_hash_io_test",
                            stage_scope="stage3 mode_hash byte predicate only; no native first-page/prefix/tail stage pipeline",
                            path="CompareValues(stage3) -> GetHashes(mask4) -> CRC_0 -> CompareHash",
                            read_chunk_bytes=0x80000,
                            source_scope="immutable complete underlying bytes; successful exact UfsSeek/UfsRead services for provider_offset and record_file_size",
                            cache_scope="native cache reuse/grow/shrink tested; no portable cache lifecycle or mutable-source equivalence",
                            remaining_runtime="real OS/provider selection, metadata/ETW/name/CFG/sign policies, PLI/heartbeat/cancellation remain external or untested",
                            failure_scope="I/O failure is not hash mismatch; unavailable complete source remains unknown",
                        )
                        if mode is StaticHashMode.CRC_0
                        else None
                    ),
                    long_target_post_hash_gate=obj(
                        valid_signed_meaning="IsValidSigned policy-helper result; fixed IsSignedFile(reply,false,&local_id,&local_sha1,true,false,true,true); cache/friendly/trust paths; no provider offset/size; not hash-slice Authenticode validity",
                        when=expr("greater_than", "provider_size", "record_file_size"),
                        predicate=expr(
                            "or", "threat_exception_name", expr("not", "valid_signed")
                        ),
                        runtime_context_required=JSONArray(
                            ("threat_exception_name", "valid_signed_status")
                        ),
                    ),
                ),
            )
        ),
        record_local_match=None,
        recid_attribution=obj(
            tail_present=parsed.recid_tail is not None,
            may_replace_threat_association=parsed.recid_tail is not None,
            producer_meaning="unknown" if parsed.recid_tail is not None else None,
            part_of_byte_predicate=False,
        ),
        final_verdict=None,
    )


def _no_tail_name_bridge_recipe(parsed: StaticPayload) -> JSONObject:
    """Describe conditional name provenance without resolving runtime inputs."""
    return JSONObject(
        (
            ("callable", "lib.vdm.static_namespace.no_tail_static_name"),
            ("namespace_snapshot_type", "lib.vdm.threat_names.DirectFullNameSnapshot"),
            (
                "initialization_profile_type",
                "lib.vdm.threat_names.DirectFullNameProfile",
            ),
            ("status", "conditional_recipe_only"),
            ("runtime_inputs_resolved", False),
            (
                "ingress_unsupported_error_type",
                "lib.vdm.static_namespace.UnsupportedStaticNameBridge",
            ),
            (
                "namespace_unsupported_error_type",
                "lib.vdm.threat_names.UnsupportedThreatNamespace",
            ),
            (
                "record_eligible",
                parsed.mode is not None
                and len(parsed.raw) == HEADER_SIZE + len(parsed.hash_raw),
            ),
            (
                "raw_ingress",
                "reparse raw; complete mode0–4; exact18+hash_width; reject every tail",
            ),
            (
                "required_facts",
                JSONArray(
                    (
                        "explicit_u32_caller_threat_id_with_record_association",
                        "selected_effective_raw_THREAT_BEGIN_namespace",
                        "successful_normal_copy_value_preserving_storage",
                        "engine_published_unique_sorted_direct_full_rows",
                        "no_enabled_dependency_redirect_mini_fastpath_alternate_store_or_shadow",
                        "no_unresolved_base_delta_override_or_cross_stream_concatenation",
                        "explicit_threats_loaded_and_matching_nonempty_epoch",
                    )
                ),
            ),
            (
                "output",
                "raw narrow CString bytes or confirmed NULL; zero span NULL differs from nonzero empty CString",
            ),
            (
                "unsupported",
                "missing association/profile/epoch, magic IDs/ranges, dependencies, duplicates, unknown publication; typed error, never synthesized NULL",
            ),
            ("runtime_name", None),
            ("exception_name", None),
            (
                "remaining_external",
                JSONArray(
                    (
                        "resolved_GetCmdlineFlags_bit34",
                        "configuration",
                        "provider",
                        "match",
                        "final_verdict",
                    )
                ),
            ),
        )
    )


def export_static(parsed: StaticPayload) -> ArtifactExport:
    """Export a lossless inventory manifest, never a standalone matcher."""
    mode = parsed.mode
    if mode is None:
        mode_name = None
        hash_data: dict[str, object] | None = None
        matcher_status = "unsupported"
        matcher_boundary = (
            "STATIC modes 5-7 reach GetHashes dispatch but are rejected by the "
            "complete STATIC comparison path"
        )
    else:
        mode_name = mode.name
        if mode is StaticHashMode.CRC_0:
            hash_data = {
                "algorithm": "CRC_0",
                "value": int.from_bytes(parsed.hash_raw, "little"),
                "raw_hex": parsed.hash_raw.hex(),
                "input_projection": "selected_file_range_of_record_file_size",
                "parameters": CRC_PARAMETERS,
            }
        else:
            algorithm = {
                StaticHashMode.MD5: "MD5",
                StaticHashMode.SHA1: "SHA1",
                StaticHashMode.SHA1_PREFIX4: "SHA1_prefix4",
                StaticHashMode.SHA256: "SHA256",
            }[mode]
            digest_size = {
                StaticHashMode.MD5: 16,
                StaticHashMode.SHA1: 20,
                StaticHashMode.SHA1_PREFIX4: 20,
                StaticHashMode.SHA256: 32,
            }[mode]
            hash_data = {
                "algorithm": algorithm,
                "value_hex": parsed.hash_raw.hex(),
                "input_projection": "selected_file_range_of_record_file_size",
                "digest_size_bytes": digest_size,
                "portable_definition": {
                    StaticHashMode.MD5: "RFC 1321 MD5",
                    StaticHashMode.SHA1: "FIPS 180-4 SHA-1",
                    StaticHashMode.SHA1_PREFIX4: "FIPS 180-4 SHA-1",
                    StaticHashMode.SHA256: "FIPS 180-4 SHA-256",
                }[mode],
                "compared_output": (
                    "first_4_digest_bytes"
                    if mode is StaticHashMode.SHA1_PREFIX4
                    else "full_digest"
                ),
                "engine_primitive": {
                    StaticHashMode.MD5: "SymCryptMd5",
                    StaticHashMode.SHA1: "SymCryptSha1",
                    StaticHashMode.SHA1_PREFIX4: "SymCryptSha1",
                    StaticHashMode.SHA256: "SymCryptSha256",
                }[mode],
            }
        matcher_status = "not_emitted"
        matcher_boundary = (
            "Record-local manifest only; runtime file bytes and later conditions "
            "are required for a match"
        )

    tail = parsed.recid_tail
    tail_data: dict[str, object] | None = None
    if tail is not None:
        tail_data = {
            "raw_hex": tail.raw.hex(),
            "raw_offset": HEADER_SIZE + len(parsed.hash_raw),
            "declared_length": tail.length_limit,
            "object_raw_hex": tail.object_raw.hex(),
            "object_registered": tail.has_object,
            "trailing_raw_hex": tail.trailing_raw.hex(),
            "bounded_object_truncated": tail.length_limit > len(tail.raw) - 1,
            "object_meaning": "unknown",
        }

    manifest = {
        "format": "vdm.static.record.v2",
        "stage_profile": semantic_json_to_data(_stage_profile(parsed)),
        "runtime_recipes": semantic_json_to_data(static_runtime_recipes()),
        "no_tail_name_bridge": semantic_json_to_data(
            _no_tail_name_bridge_recipe(parsed)
        ),
        "record": {
            "type": STATIC_TYPE,
            "type_hex": f"0x{STATIC_TYPE:02X}",
            "name": "STATIC",
            "scope": "record_local",
            "threat_association": "not_included",
            "portable_matcher": matcher_status,
            "matcher_boundary": matcher_boundary,
        },
        "payload_length": len(parsed.raw),
        "payload_raw_hex": parsed.raw.hex(),
        "header": {
            "first_page_crc": parsed.first_page_crc,
            "first_page_crc_raw_hex": parsed.raw[0:4].hex(),
            "tail_page_crc": parsed.tail_page_crc,
            "tail_page_crc_raw_hex": parsed.raw[4:8].hex(),
            "prefix_crc": parsed.prefix_crc,
            "prefix_crc_raw_hex": parsed.raw[8:12].hex(),
            "crc_parameters": CRC_PARAMETERS,
            "crc_input_projections": {
                "first_page_crc": (
                    "offset_zero:SCAN_REPLY+0xC0 exactly_4096_buffer_bytes "
                    "(source-file equivalence not established); "
                    "nonzero_offset:read_up_to_4096_then_zero_append"
                ),
                "prefix_crc": "provider_offset:first_min(record_file_size,65536)_bytes",
                "tail_page_crc": "record_file_range_last_up_to_4096_bytes; zero_prefix_to_4096_when_short",
            },
            "file_size": parsed.file_size,
            "file_size_raw_hex": parsed.raw[12:16].hex(),
            "file_size_policy": "at_least" if parsed.allow_larger else "exact",
            "flags": parsed.flags,
            "flags_raw_hex": parsed.raw[16:18].hex(),
            "allow_larger": parsed.allow_larger,
            "mode_value": parsed.mode_value,
            "mode_name": mode_name,
            "mode_corpus_status": (
                "not_observed_in_mpas_or_mpav"
                if mode in {StaticHashMode.SHA1_PREFIX4, StaticHashMode.SHA256}
                else "not_applicable_unsupported"
                if mode is None
                else "observed"
            ),
            "engine_hash_dispatch_candidate": _ENGINE_HASH_DISPATCH.get(
                parsed.mode_value
            ),
            "loader_ignored_flags": parsed.ignored_flags,
        },
        "hash": hash_data,
        "engine_hash_dispatch_candidate": _ENGINE_HASH_DISPATCH.get(parsed.mode_value),
        "opaque_after_header_raw_hex": parsed.opaque_raw.hex(),
        "recid_tail": tail_data,
    }
    encoded = json.dumps(manifest, ensure_ascii=True, separators=(",", ":"))
    return ArtifactExport(
        "ready",
        artifacts=(
            Artifact(
                "static.json",
                "static_record_manifest",
                (encoded + "\n").encode("utf-8"),
            ),
        ),
    )


def _wire_field(kind: str, raw: bytes, offset: int) -> JSONObject:
    return JSONObject(
        (
            ("kind", kind),
            ("raw_span", JSONObject((("offset", offset), ("length", len(raw))))),
            ("raw_hex", raw.hex()),
        )
    )


def _recid_tail_semantics(tail: RecIdTail | None, offset: int) -> JSONObject | None:
    if tail is None:
        return None
    object_offset = offset + 1
    trailing_offset = object_offset + len(tail.object_raw)
    return JSONObject(
        (
            ("wire", _wire_field("recid_tail", tail.raw, offset)),
            ("length_limit", tail.length_limit),
            (
                "object",
                _wire_field("opaque_object", tail.object_raw, object_offset),
            ),
            ("object_present", tail.has_object),
            (
                "trailing",
                _wire_field("tail_surplus", tail.trailing_raw, trailing_offset),
            ),
            ("producer_meaning", None),
        )
    )


def export_static_semantics(parsed: StaticPayload) -> RuleSemantics:
    """Export the confirmed STATIC receiver and staged hash-match subset."""
    name_bridge_recipe = _no_tail_name_bridge_recipe(parsed)
    name_bridge_claim = SemanticClaim(
        id="static_no_tail_name_bridge",
        scope="runtime_consumer",
        statement=(
            "Complete mode0–4 no-tail STATIC Load retains the explicit caller threat ID. "
            "Only an explicitly selected same-epoch normal-copy published unique sorted "
            "direct-full namespace without redirects or overrides permits raw CString name "
            "projection; wire records and cache offsets alone establish none of these facts."
        ),
        coverage="subset",
        evidence_refs=("static_no_tail_name_sources",),
        unknowns=(
            SemanticUnknown(
                "runtime_consumer",
                "Caller association, effective publication/storage profile and epoch remain required external facts; no default record name is resolved.",
            ),
            SemanticUnknown(
                "final_verdict",
                "Name projection establishes neither flags/config/provider inputs, record-local match nor final verdict.",
            ),
        ),
    )
    name_bridge_evidence = SemanticEvidence(
        id="static_no_tail_name_sources",
        axis="consumer",
        kind="engine_static",
        source_ref="mpengine 1.443.903.0; docs/signature/STATIC_name_exception_source_next_private.md; docs/signature/STATIC_name_bridge_ir_scope_private.md",
        locator="staticrec_t::Load@0x1800FAABC; verified caller-ID store@0x1800FAB7C; get_threat_name@0x1800F7D10; threat_info_receiver@0x1809EB590; normal kstore_copy_buff@0x1800FC594; existing static evidence, not loader execution",
        supports=(name_bridge_claim.id,),
    )
    exception_recipe_claim = SemanticClaim(
        id="static_exception_name_recipe",
        scope="runtime_consumer",
        statement=(
            "IsExceptionName reads the raw first byte (# or ~) and, only for "
            "those prefixes, requires resolved GetCmdlineFlags bit34 clear. "
            "CFG and long-target projections share this derived same-epoch result; "
            "NULL is rejected by the caller before the helper."
        ),
        coverage="subset",
        evidence_refs=("static_exception_name_sources",),
        unknowns=(
            SemanticUnknown(
                "runtime_consumer",
                "Name provenance outside the explicitly selected direct-full profile remains external; the conditional bridge requires caller ID, effective namespace and epoch. Global/selected/default flags writers, GetOpt TLS selection and epoch coherence remain external; no command-line text parser is established here.",
            ),
            SemanticUnknown(
                "final_verdict",
                "The helper projection establishes neither record-local match nor final verdict.",
            ),
        ),
    )
    exception_recipe_evidence = SemanticEvidence(
        id="static_exception_name_sources",
        axis="consumer",
        kind="engine_static",
        source_ref="mpengine 1.443.903.0; docs/mpengine.dll/IsExceptionName.md; docs/mpengine.dll/GetCmdlineFlags.md",
        locator="IsExceptionName@0x180185370 (0x25 bytes); GetCmdlineFlags@0x180185894 (0x33 bytes); CompareValues@0x1800F8490; saved decompile and byte verification, not engine execution",
        supports=(exception_recipe_claim.id,),
    )
    runtime_recipe_claim = SemanticClaim(
        id="static_runtime_input_recipes",
        scope="runtime_consumer",
        statement=(
            "STATIC runtime recipes describe externally selected troj_scan_entry or "
            "rpf_check_static provider ranges and ordered narrow-CString CFG calls "
            "projected only from an explicitly coherent immutable snapshot; they "
            "do not identify the caller or resolve runtime inputs from a record."
        ),
        coverage="subset",
        evidence_refs=("static_runtime_recipe_sources",),
        unknowns=(
            SemanticUnknown(
                "runtime_consumer",
                "Actual caller, reply_size writer, UFS identity, first-page buffer producer, config/state/attribute producers and same-epoch provenance remain external.",
            ),
            SemanticUnknown(
                "detection_predicate",
                "IsValidSigned is a reply policy-helper result with cache/friendly/trust paths, not provider-slice Authenticode validity; trust policy remains external.",
            ),
            SemanticUnknown(
                "final_verdict",
                "Symbolic recipes do not establish a record-local match or final scan verdict.",
            ),
        ),
    )
    runtime_recipe_evidence = SemanticEvidence(
        id="static_runtime_recipe_sources",
        axis="consumer",
        kind="engine_static",
        source_ref="mpengine 1.443.903.0; existing per-function reverse-engineering documentation",
        locator=(
            "troj_scan@0x180B02760 (call 0x180B027CB); RpfAPI_CheckStaticSignatures@0x1802D87A0 "
            "(call 0x1802D87EF); initialize@0x1802D88A4; static_scan_worker@0x1800F94A0; "
            "CompareValues@0x1800F8490; CheckConfig@0x18009685C; "
            "IsSenseScan@0x180096984; IsReportLowfiScan@0x1800969A0; IsValidSigned@0x18058EA18"
        ),
        supports=(runtime_recipe_claim.id,),
    )
    issues = [
        SemanticIssue(
            "outer_verdict_not_determined",
            "A successful STATIC candidate comparison can populate detection "
            "state, but does not determine the outer scan or report verdict.",
        ),
    ]
    if parsed.allow_larger:
        issues.append(
            SemanticIssue(
                "allow_larger_gates_incomplete",
                "allow_larger relaxes only the local size comparison; later "
                "threat-exception and valid-signature gates still apply.",
            )
        )

    wire_claim = SemanticClaim(
        id="static_wire_layout",
        scope="wire_layout",
        statement=(
            "STATIC begins with three little-endian CRC words, a file-size word, "
            "a flags word, and a mode-dependent hash followed by an optional tail."
        ),
        coverage="complete" if parsed.mode is not None else "subset",
        evidence_refs=("static_receiver",),
        unknowns=(
            ()
            if parsed.mode is not None
            else (
                SemanticUnknown(
                    "wire_layout",
                    "The post-header width for mode values 5 through 7 is not an "
                    "accepted STATIC comparison layout.",
                ),
            )
        ),
    )
    dispatch_claim = SemanticClaim(
        id="static_loader_dispatch",
        scope="loader_dispatch",
        statement="The analyzed registration path binds type 0x67 to STATIC.",
        coverage="subset",
        evidence_refs=("static_dispatch",),
        unknowns=(
            SemanticUnknown(
                "loader_dispatch",
                "Other database profiles and engine versions are not covered.",
            ),
        ),
    )
    if parsed.mode is None:
        receiver_statement = (
            "The loader reads the fixed header but does not accept this mode as a "
            "complete STATIC comparison record."
        )
        receiver_evidence_refs = ("static_receiver",)
        receiver_unknown_reason = "No accepted hash width or optional-tail boundary is established for this mode."
    else:
        receiver_statement = (
            "The loader materializes the fixed header and accepted mode hash; an "
            "optional bounded tail is converted to RecID metadata that may replace "
            "the stored threat association but is not part of the hash predicate."
        )
        receiver_evidence_refs = ("static_receiver", "static_tail_receiver")
        receiver_unknown_reason = (
            "The producer meaning of the optional bounded tail object is unknown."
        )
    receiver_claim = SemanticClaim(
        id="static_receiver_projection",
        scope="receiver_transform",
        statement=receiver_statement,
        coverage="subset",
        evidence_refs=receiver_evidence_refs,
        unknowns=(SemanticUnknown("receiver_transform", receiver_unknown_reason),),
    )
    corpus_claim = SemanticClaim(
        id="static_corpus_modes",
        scope="corpus_observation",
        statement=(
            "The scanned mpas.sig and mpav.sig corpora contain STATIC modes 0, 1, "
            "and 2; modes 3 through 7 were not observed."
        ),
        coverage="complete",
        evidence_refs=("static_corpus",),
    )
    crc_primitive_claim = SemanticClaim(
        id="static_crc_primitive",
        scope="runtime_consumer",
        statement=(
            "For the tested DLL's CRC_0 and CRC_1 entry points, both compute "
            "raw reflected CRC-32 state without final XOR; CRC_0 accepts the "
            "caller state and CRC_1 starts from 0xFFFFFFFF."
        ),
        coverage="subset",
        evidence_refs=("static_crc_differential",),
        unknowns=(
            SemanticUnknown(
                "runtime_consumer",
                "STATIC CompareValues/GetHashes, runtime ranges, hash comparison, "
                "signature matching, and final verdict were not tested.",
            ),
        ),
    )
    hash_comparison_claim = SemanticClaim(
        id="static_hash_comparison_primitive",
        scope="runtime_consumer",
        statement=(
            "Differential execution of staticrec_t::CompareHash supports inline "
            "and extra-store equality/order behavior and length gates for modes "
            "0-4 (widths 16/20/4/4/32); mode 3 compares only the caller's "
            "four-byte digest prefix."
        ),
        coverage="subset",
        evidence_refs=("static_hash_comparison_differential",),
        unknowns=(
            SemanticUnknown(
                "runtime_consumer",
                "Hash generation/GetHashes, I/O ranges, stage aggregation, signature "
                "policy, and final verdict are not covered. Modes 5-7 length-zero "
                "equality does not establish complete-comparator acceptance; "
                "caller rejection has not been differentially validated.",
            ),
        ),
    )
    common_evidence = (
        SemanticEvidence(
            id="static_dispatch",
            axis="dispatch",
            kind="engine_static",
            source_ref="mpengine 1.443.903.0",
            locator="staticrec_t::Register @ 0x180489A7C",
            supports=(dispatch_claim.id,),
        ),
        SemanticEvidence(
            id="static_receiver",
            axis="receiver",
            kind="engine_static",
            source_ref="mpengine 1.443.903.0",
            locator="staticrec_t::Load @ 0x1800FAABC",
            supports=(wire_claim.id, receiver_claim.id),
        ),
        SemanticEvidence(
            id="static_corpus",
            axis="corpus",
            kind="corpus",
            source_ref="mpas.sig and mpav.sig exhaustive STATIC census",
            locator="modes 0/1/2 observed; modes 3-7 absent",
            supports=(corpus_claim.id,),
        ),
        SemanticEvidence(
            id="static_crc_differential",
            axis="engine_equivalent_test",
            kind="engine_equivalent_test",
            source_ref=(
                "mpengine path label 1.443.903.0; PE fixed version 1.1.25110.1; "
                "SHA-256 928e171c60a44bb326776d2a356412ae98d78469bdf8c94ebfbfa09f8ec4b4b3"
            ),
            locator=(
                "tests/local_static_engine_differential.py; "
                "functions CRC_0 @ 0x180704738 and CRC_1 @ 0x180705184; "
                "61 vectors (empty through 65536 bytes, alignments/seeds as applicable)"
            ),
            supports=(crc_primitive_claim.id,),
        ),
        SemanticEvidence(
            id="static_hash_comparison_differential",
            axis="engine_equivalent_test",
            kind="engine_equivalent_test",
            source_ref=(
                "mpengine path label 1.443.903.0; PE fixed version 1.1.25110.1; "
                "SHA-256 928e171c60a44bb326776d2a356412ae98d78469bdf8c94ebfbfa09f8ec4b4b3"
            ),
            locator=(
                "ignored harness tests/local_static_engine_differential.py; "
                "staticrec_t::CompareHash @ 0x18055D644, "
                "MpSignatureExtraStore::Get @ 0x1800F930C, "
                "memcmp @ 0x180D38C00; 40 new vectors "
                "(101 total including 61 CRC vectors)"
            ),
            supports=(hash_comparison_claim.id,),
        ),
    )
    mode = parsed.mode
    if mode is None:
        consumer_claim = SemanticClaim(
            id="static_hash_consumer",
            scope="runtime_consumer",
            statement=(
                "The analyzed hash dispatcher names primitives for modes 5 through "
                "7, but the complete STATIC comparison path rejects these modes."
            ),
            coverage="subset",
            evidence_refs=("static_consumer",),
            unknowns=(
                SemanticUnknown(
                    "runtime_consumer",
                    "No accepted STATIC matcher semantics are established for this mode.",
                ),
            ),
        )
        return RuleSemantics(
            status="unsupported",
            representation="static.match.ir.v2",
            data=JSONObject(
                (
                    ("type", "STATIC"),
                    ("raw_hex", parsed.raw.hex()),
                    ("mode_value", parsed.mode_value),
                    (
                        "engine_hash_dispatch",
                        _ENGINE_HASH_DISPATCH.get(parsed.mode_value),
                    ),
                    (
                        "engine_hash_input_projection",
                        "provider_offset:file_start; length=record_file_size"
                        if parsed.mode_value in _ENGINE_HASH_DISPATCH
                        else None,
                    ),
                    ("comparison_supported", False),
                    ("stage_profile", _stage_profile(parsed)),
                    ("runtime_recipes", static_runtime_recipes()),
                    ("no_tail_name_bridge", name_bridge_recipe),
                    ("hash", None),
                    (
                        "opaque_after_header",
                        _wire_field("opaque", parsed.opaque_raw, HEADER_SIZE),
                    ),
                )
            ),
            evidence=(
                (
                    "mpengine 1.443.903.0 staticrec_t::Load "
                    "(0x1800FAABC) modes 5-7 assertion path"
                ),
                (
                    "mpengine 1.443.903.0 StaticHashProvider::CompareValues "
                    "(0x1800F8490) rejects modes 5-7 after GetHashes dispatch"
                ),
                (
                    "mpengine 1.443.903.0 GetHashes (0x1803B9F7C) dispatch: "
                    "mode 5 SHA-512, mode 6 LSH, mode 7 CTPH"
                ),
                "mpas.sig/mpav.sig corpus: modes 0-2 observed; modes 3-7 absent",
            ),
            profile="mpengine-1.443.903.0",
            issues=(
                SemanticIssue(
                    "unsupported_hash_mode",
                    "Modes 5 through 7 are not accepted for complete STATIC hash "
                    "matching.",
                    (("mode", parsed.mode_value),),
                ),
            ),
            claims=(
                runtime_recipe_claim,
                exception_recipe_claim,
                name_bridge_claim,
                corpus_claim,
                crc_primitive_claim,
                hash_comparison_claim,
                wire_claim,
                dispatch_claim,
                receiver_claim,
                consumer_claim,
                SemanticClaim(
                    id="static_detection_predicate",
                    scope="detection_predicate",
                    statement="No accepted STATIC detection predicate is established for this mode.",
                    coverage="unknown",
                    unknowns=(
                        SemanticUnknown(
                            "detection_predicate",
                            "The current comparison path rejects mode values 5 through 7.",
                        ),
                    ),
                ),
                SemanticClaim(
                    id="static_report_mapping",
                    scope="report_mapping",
                    statement="STATIC report mapping is not established for a rejected mode.",
                    coverage="unknown",
                    unknowns=(
                        SemanticUnknown(
                            "report_mapping",
                            "No accepted candidate reaches a confirmed report path.",
                        ),
                    ),
                ),
                SemanticClaim(
                    id="static_final_verdict",
                    scope="final_verdict",
                    statement="The record does not establish a final scan verdict.",
                    coverage="unknown",
                    unknowns=(
                        SemanticUnknown(
                            "final_verdict",
                            "Final scan-result arbitration is outside the analyzed path.",
                        ),
                    ),
                ),
            ),
            claim_evidence=common_evidence
            + (runtime_recipe_evidence, exception_recipe_evidence, name_bridge_evidence)
            + (
                SemanticEvidence(
                    id="static_consumer",
                    axis="consumer",
                    kind="engine_static",
                    source_ref="mpengine 1.443.903.0",
                    locator=(
                        "StaticHashProvider::CompareValues @ 0x1800F8490; "
                        "GetHashes @ 0x1803B9F7C"
                    ),
                    supports=(consumer_claim.id,),
                ),
            ),
        )

    hash_size = len(parsed.hash_raw)
    hash_offset = HEADER_SIZE
    tail_offset = hash_offset + hash_size
    unresolved = parsed.ignored_flags
    if unresolved:
        issues.append(
            SemanticIssue(
                "loader_ignored_flag_bits",
                "These flag bits are ignored by the STATIC loader; no semantic "
                "names are assigned.",
                (("value", unresolved),),
            )
        )
    if mode in {StaticHashMode.SHA1_PREFIX4, StaticHashMode.SHA256}:
        issues.append(
            SemanticIssue(
                "mode_not_observed_in_corpus",
                "This mode is confirmed by current-binary code paths but has no "
                "mpas.sig or mpav.sig sample.",
                (("mode", int(mode)),),
            )
        )
    if parsed.allow_larger:
        issues.append(
            SemanticIssue(
                "larger_file_match_is_conditional",
                "allow_larger permits a size mismatch through an early stage only; "
                "later conditions still apply.",
            )
        )
    if parsed.recid_tail is not None and parsed.recid_tail.has_object:
        issues.append(
            SemanticIssue(
                "recid_object_meaning_unknown",
                "The bounded object is passed to createrecidpc, but its producer "
                "meaning is unknown.",
            )
        )
    if (
        parsed.recid_tail is not None
        and parsed.recid_tail.length_limit > len(parsed.recid_tail.raw) - 1
    ):
        issues.append(
            SemanticIssue(
                "recid_object_truncated",
                "The RecID object is shorter than its declared length.",
                (
                    ("declared_length", parsed.recid_tail.length_limit),
                    ("available_length", len(parsed.recid_tail.raw) - 1),
                ),
            )
        )
    if parsed.recid_tail is not None and parsed.recid_tail.trailing_raw:
        issues.append(
            SemanticIssue(
                "recid_tail_surplus_uninterpreted",
                "Bytes beyond the length-limited RecID object are retained without "
                "semantics.",
                (("length", len(parsed.recid_tail.trailing_raw)),),
            )
        )

    hash_data: JSONObject
    if mode is StaticHashMode.CRC_0:
        hash_data = JSONObject(
            (
                ("algorithm", "CRC_0"),
                (
                    "input_projection",
                    "provider_offset:file_start; length=record_file_size",
                ),
                ("parameters", JSONObject(tuple(CRC_PARAMETERS.items()))),
                ("wire", _wire_field("crc_u32le", parsed.hash_raw, hash_offset)),
                ("value", int.from_bytes(parsed.hash_raw, "little")),
            )
        )
    else:
        algorithm = {
            StaticHashMode.MD5: "MD5",
            StaticHashMode.SHA1: "SHA1",
            StaticHashMode.SHA1_PREFIX4: "SHA1_prefix4",
            StaticHashMode.SHA256: "SHA256",
        }[mode]
        digest_size = {
            StaticHashMode.MD5: 16,
            StaticHashMode.SHA1: 20,
            StaticHashMode.SHA1_PREFIX4: 20,
            StaticHashMode.SHA256: 32,
        }[mode]
        hash_data = JSONObject(
            (
                ("algorithm", algorithm),
                (
                    "input_projection",
                    "provider_offset:file_start; length=record_file_size",
                ),
                ("digest_size_bytes", digest_size),
                (
                    "portable_definition",
                    {
                        StaticHashMode.MD5: "RFC 1321 MD5",
                        StaticHashMode.SHA1: "FIPS 180-4 SHA-1",
                        StaticHashMode.SHA1_PREFIX4: "FIPS 180-4 SHA-1",
                        StaticHashMode.SHA256: "FIPS 180-4 SHA-256",
                    }[mode],
                ),
                (
                    "computed_primitive",
                    {
                        StaticHashMode.MD5: "SymCryptMd5",
                        StaticHashMode.SHA1: "SymCryptSha1",
                        StaticHashMode.SHA1_PREFIX4: "SymCryptSha1",
                        StaticHashMode.SHA256: "SymCryptSha256",
                    }[mode],
                ),
                (
                    "compared_output",
                    "first_4_digest_bytes"
                    if mode is StaticHashMode.SHA1_PREFIX4
                    else "full_digest",
                ),
                ("wire", _wire_field("hash_bytes", parsed.hash_raw, hash_offset)),
                ("value_hex", parsed.hash_raw.hex()),
            )
        )

    recid_unsupported = parsed.recid_tail is not None and (
        parsed.recid_tail.has_object
        or bool(parsed.recid_tail.trailing_raw)
        or parsed.recid_tail.length_limit > len(parsed.recid_tail.raw) - 1
    )
    predicate_unknowns = [
        SemanticUnknown(
            "detection_predicate",
            "CFG outcomes and long-target gates depend on stubbed services; the "
            "complete caller, real provider/I/O/hash services, and final verdict "
            "are not closed.",
        )
    ]
    if parsed.allow_larger:
        predicate_unknowns.append(
            SemanticUnknown(
                "detection_predicate",
                "allow_larger only relaxes the local size comparison and remains conditional on later gates.",
            )
        )
    consumer_claim = SemanticClaim(
        id="static_hash_consumer",
        scope="runtime_consumer",
        statement=(
            "The analyzed lookup and comparator consume CRC candidate keys, size "
            "gates, prefix/tail CRC checks with larger-file tail fallback, and "
            "mode-hash comparison over the record-selected range."
        ),
        coverage="subset",
        evidence_refs=("static_consumer",),
        unknowns=(
            SemanticUnknown(
                "runtime_consumer",
                "Real OS/provider selection, cache lifetime, untested branches and "
                "non-mode2 GetHashes integration remain outside the bounded byte model.",
            ),
        ),
    )
    predicate_claim = SemanticClaim(
        id="static_detection_predicate",
        scope="detection_predicate",
        statement=(
            "At the local STATIC matcher boundary, size policy, "
            "prefix/tail CRC, applicable CFG prehash gates, and hash comparison "
            "must pass; longer targets also depend on exception-name or "
            "valid-signature checks."
        ),
        coverage="subset",
        evidence_refs=("static_consumer",),
        unknowns=tuple(predicate_unknowns),
    )
    control_flow_claim = SemanticClaim(
        id="static_comparison_control_flow",
        scope="runtime_consumer",
        statement=(
            "In 27 bounded differential cases, real CompareValues control flow "
            "confirmed the mode filter, size gates, prefix/tail CRC fallback, "
            "CFG prehash gates, and long-target signed/exception gates."
        ),
        coverage="subset",
        evidence_refs=("static_comparison_control_flow_test",),
        unknowns=(
            SemanticUnknown(
                "runtime_consumer",
                "UfsSeekRead, get_threat_name, IsExceptionName, CheckConfig, "
                "GetHashes, and IsValidSigned were stubbed; untested branches, "
                "real provider/I/O/hash services, and final result remain unknown.",
            ),
        ),
    )
    mode2_claims = (
        (
            SemanticClaim(
                id="static_mode2_hash_range",
                scope="runtime_consumer",
                statement=(
                    "For mode2, real CompareValues stage3 calls GetHashes(mask4), "
                    "CRC_0 and CompareHash starting at provider_offset for record_file_size "
                    "bytes; bounded immutable successful-byte-service cases agree with "
                    "the StaticMatchContext stage3 mode-hash predicate, including empty/"
                    "nonzero-offset and 512KiB chunk boundaries."
                ),
                coverage="subset",
                evidence_refs=("static_mode2_hash_io_test",),
                unknowns=(
                    SemanticUnknown(
                        "runtime_consumer",
                        "UfsSeek/UfsRead are explicit byte services, not a real OS loader. "
                        "Metadata/ETW/name/CFG/sign policies remain services. Native cache "
                        "partial failures and mutable-source reuse are not modeled as hash "
                        "mismatches or rollback; PLI/heartbeat/cancellation, provider selection, "
                        "other primitives, the full first-page/prefix/tail pipeline and final "
                        "verdict remain outside this evidence.",
                    ),
                ),
            ),
        )
        if mode is StaticHashMode.CRC_0
        else ()
    )
    mode2_evidence = (
        (
            SemanticEvidence(
                id="static_mode2_hash_io_test",
                axis="engine_equivalent_test",
                kind="engine_equivalent_test",
                source_ref=(
                    "mpengine path 1.443.903.0; PE FileVersion 1.1.25110.1; DLL SHA256 "
                    "928e171c60a44bb326776d2a356412ae98d78469bdf8c94ebfbfa09f8ec4b4b3"
                ),
                locator=(
                    "tests/local_static_mode2_hash_io_native.py (20 cases/36 calls; SHA256 "
                    "6888a89f617c2c47c657bf48eead6da4577241400214517b82bd4cb7810986f9); "
                    "report SHA256 72c317e91ac917adbfffc26ee0e0c7ef4cda9e82d29d369c86e4934c2122f43b; "
                    "CompareValues@0x1800F8490 -> GetHashes@0x1803B9F7C(mask4) -> "
                    "CRC_0@0x180704738 -> CompareHash@0x18055D644; "
                    "docs/mpengine.dll/1.443.903.0/static_mode2_hash_io_private.md; "
                    "explicit Ufs byte/policy services, immutable successful complete-source subset; "
                    "not a full I/O/cache/engine equivalence claim"
                ),
                supports=("static_mode2_hash_range",),
            ),
        )
        if mode is StaticHashMode.CRC_0
        else ()
    )
    return RuleSemantics(
        status="unsupported" if recid_unsupported else "confirmed_subset",
        representation="static.match.ir.v2",
        data=JSONObject(
            (
                ("type", "STATIC"),
                ("raw_hex", parsed.raw.hex()),
                (
                    "header",
                    JSONObject(
                        (
                            (
                                "first_page_crc",
                                JSONObject(
                                    (
                                        ("value", parsed.first_page_crc),
                                        ("algorithm", "CRC_1"),
                                        (
                                            "input_projection",
                                            (
                                                "offset_zero:SCAN_REPLY+0xC0 "
                                                "exactly_4096_buffer_bytes "
                                                "(source-file equivalence not "
                                                "established); nonzero_offset:"
                                                "read_up_to_4096_then_zero_append"
                                            ),
                                        ),
                                        (
                                            "parameters",
                                            JSONObject(tuple(CRC_PARAMETERS.items())),
                                        ),
                                        (
                                            "wire",
                                            _wire_field(
                                                "first_4096_crc_u32le",
                                                parsed.raw[0:4],
                                                0,
                                            ),
                                        ),
                                    )
                                ),
                            ),
                            (
                                "tail_page_crc",
                                JSONObject(
                                    (
                                        ("value", parsed.tail_page_crc),
                                        ("algorithm", "CRC_0"),
                                        (
                                            "input_projection",
                                            "last_up_to_4096_record_file_bytes; zero_prefix_to_4096_when_short",
                                        ),
                                        (
                                            "parameters",
                                            JSONObject(tuple(CRC_PARAMETERS.items())),
                                        ),
                                        (
                                            "wire",
                                            _wire_field(
                                                "tail_4096_crc_u32le",
                                                parsed.raw[4:8],
                                                4,
                                            ),
                                        ),
                                    )
                                ),
                            ),
                            (
                                "prefix_crc",
                                JSONObject(
                                    (
                                        ("value", parsed.prefix_crc),
                                        ("algorithm", "CRC_1_or_incremental_CRC_0"),
                                        (
                                            "input_projection",
                                            "provider_offset:first_min(record_file_size,65536)_bytes",
                                        ),
                                        (
                                            "parameters",
                                            JSONObject(tuple(CRC_PARAMETERS.items())),
                                        ),
                                        (
                                            "wire",
                                            _wire_field(
                                                "prefix_crc_u32le",
                                                parsed.raw[8:12],
                                                8,
                                            ),
                                        ),
                                    )
                                ),
                            ),
                            (
                                "file_size",
                                JSONObject(
                                    (
                                        ("value", parsed.file_size),
                                        (
                                            "wire",
                                            _wire_field(
                                                "file_size_u32le",
                                                parsed.raw[12:16],
                                                12,
                                            ),
                                        ),
                                        (
                                            "comparison",
                                            "at_least"
                                            if parsed.allow_larger
                                            else "exact",
                                        ),
                                    )
                                ),
                            ),
                        )
                    ),
                ),
                (
                    "flags",
                    JSONObject(
                        (
                            (
                                "wire",
                                _wire_field("flags_u16le", parsed.raw[16:18], 16),
                            ),
                            ("allow_larger", parsed.allow_larger),
                            ("mode", int(mode)),
                            ("loader_ignored_bits", unresolved),
                        )
                    ),
                ),
                ("hash", hash_data),
                ("stage_profile", _stage_profile(parsed)),
                ("runtime_recipes", static_runtime_recipes()),
                ("no_tail_name_bridge", name_bridge_recipe),
                (
                    "match_pipeline",
                    JSONArray(
                        (
                            "first_page_crc_candidate_key",
                            "prefix_crc_up_to_min(file_size, 65536)",
                            "tail_crc_of_record_tail_up_to_4096_bytes_zero_prefixed_when_short",
                            "file_size_policy",
                            "applicable_CFG_pre_hash_gate",
                            "mode_specific_hash_validation",
                            "long_target_exception_or_signature_gate",
                        )
                    ),
                ),
                (
                    "recid_tail",
                    _recid_tail_semantics(parsed.recid_tail, tail_offset),
                ),
            )
        ),
        evidence=(
            (
                "mpengine 1.443.903.0 staticrec_t::Load (0x1800FAABC) "
                "mode lengths and hash storage"
            ),
            (
                "mpengine 1.443.903.0 StaticHashProvider::CompareValues "
                "(0x1800F8490) staged CRC/size/hash flow"
            ),
            (
                "mpengine 1.443.903.0 GetHashes (0x1803B9F7C), CompareHash "
                "(0x18055D644), CRC_0 (0x180704738), and CRC_1 "
                "(0x180705184) establish hash and CRC contracts"
            ),
            "mpas.sig STATIC modes 0/1/2 counts 66/17235/279357; modes 3/4 absent",
            "mpav.sig STATIC modes 0/1/2 counts 52/73572/1866880; modes 3/4 absent",
        ),
        profile="mpengine-1.443.903.0",
        issues=tuple(issues),
        claims=(
            runtime_recipe_claim,
            exception_recipe_claim,
            name_bridge_claim,
            corpus_claim,
            crc_primitive_claim,
            hash_comparison_claim,
            wire_claim,
            dispatch_claim,
            receiver_claim,
            consumer_claim,
            predicate_claim,
            control_flow_claim,
            *mode2_claims,
            SemanticClaim(
                id="static_report_mapping",
                scope="report_mapping",
                statement="A local STATIC match can update detection state, but its report mapping is unresolved.",
                coverage="unknown",
                unknowns=(
                    SemanticUnknown(
                        "report_mapping",
                        "No complete STATIC-to-report dataflow is established.",
                    ),
                ),
            ),
            SemanticClaim(
                id="static_final_verdict",
                scope="final_verdict",
                statement="A local STATIC match does not by itself establish the final scan verdict.",
                coverage="unknown",
                unknowns=(
                    SemanticUnknown(
                        "final_verdict",
                        "Final scan-result arbitration has not been followed to completion.",
                    ),
                ),
            ),
        ),
        claim_evidence=common_evidence
        + (runtime_recipe_evidence, exception_recipe_evidence, name_bridge_evidence)
        + (
            SemanticEvidence(
                id="static_tail_receiver",
                axis="receiver",
                kind="engine_static",
                source_ref="mpengine 1.443.903.0",
                locator="createrecidpc @ 0x180435F74",
                supports=(receiver_claim.id,),
            ),
            SemanticEvidence(
                id="static_consumer",
                axis="consumer",
                kind="engine_static",
                source_ref="mpengine 1.443.903.0",
                locator=(
                    "STATIC Lookup @ 0x1800F8C98; "
                    "StaticHashProvider::CompareValues @ 0x1800F8490"
                ),
                supports=(consumer_claim.id, predicate_claim.id),
            ),
            SemanticEvidence(
                id="static_comparison_control_flow_test",
                axis="engine_equivalent_test",
                kind="engine_equivalent_test",
                source_ref=(
                    "mpengine path label 1.443.903.0; PE fixed version "
                    "1.1.25110.1; SHA-256 "
                    "928e171c60a44bb326776d2a356412ae98d78469bdf8c94ebfbfa09f8ec4b4b3"
                ),
                locator=(
                    "ignored tests/local_static_engine_differential.py; "
                    "docs/mpengine.dll/1.443.903.0/STATIC_comparevalues_differential_probe.md; "
                    "27 new cases (128 total); real CompareValues/GetSize/CRC_0/CRC_1/"
                    "CRCZeroes/CompareHash/Get/memcmp/strncmp; stubbed UfsSeekRead, "
                    "get_threat_name, IsExceptionName, CheckConfig, GetHashes, "
                    "IsValidSigned"
                ),
                supports=(control_flow_claim.id,),
            ),
        )
        + mode2_evidence,
    )


SPEC = FamilySpec(
    STATIC_TYPE,
    "STATIC",
    parse_static,
    render_static,
    exporter=export_static,
    semantic_exporter=export_static_semantics,
)
