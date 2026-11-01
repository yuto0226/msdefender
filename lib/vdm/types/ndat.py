"""Parser and renderer for NDAT (0xA9) payloads."""

import json
from dataclasses import dataclass
from typing import Final

from ..core import (
    Artifact,
    ArtifactExport,
    DisplaySection,
    FamilySpec,
    FormatResult,
    JSONObject,
    RuleSemantics,
    SemanticClaim,
    SemanticEvidence,
    SemanticIssue,
    SemanticUnknown,
)

NDAT_TYPE: Final = 0xA9
PREVIEW_SIZE: Final = 16


@dataclass(frozen=True, slots=True)
class NdatPayload:
    """NDAT wire fields consumed by ``ReceiveNewTemplate``."""

    raw: bytes
    data_length: int
    data_raw: bytes
    callback_index: int
    record_id_suffix_raw: bytes | None
    trailing_raw: bytes


class UnsupportedNdatHttpUrlPattern(ValueError):
    """The record is outside the non-null callback-15 pattern framing profile."""


@dataclass(frozen=True, slots=True)
class NdatHttpUrlPattern:
    """Byte pattern input for the engine Boost backend, not a portable regex."""

    raw: bytes
    counted_data: bytes
    effective_pattern: bytes
    after_pattern_terminator: bytes
    record_id_suffix_raw: bytes | None
    trailing_raw: bytes
    syntax_flags: int = 0x500000


def project_ndat_http_url_pattern(parsed: NdatPayload) -> NdatHttpUrlPattern:
    """Project decimal callback 15 (0x0F), reparsing authoritative wire bytes.

    Only nonempty counted data ending in NUL is accepted by this projector.
    The constructor reads through the first NUL; later counted bytes still
    participate in the callback's final-byte check. Framing does not establish
    that an arbitrary pattern compiles or matches. No regex engine is invoked.
    """
    parsed = parse_ndat(parsed.raw)
    if parsed.callback_index != 15:
        raise UnsupportedNdatHttpUrlPattern("requires callback decimal 15 (0x0F)")
    data = parsed.data_raw
    if not data or data[-1] != 0:
        raise UnsupportedNdatHttpUrlPattern(
            "requires nonempty counted data ending in NUL"
        )
    first_nul = data.index(0)
    return NdatHttpUrlPattern(
        parsed.raw,
        data,
        data[:first_nul],
        data[first_nul + 1 :],
        parsed.record_id_suffix_raw,
        parsed.trailing_raw,
    )


def _http_url_manifest(parsed: NdatPayload) -> JSONObject:
    try:
        pattern = project_ndat_http_url_pattern(parsed)
    except UnsupportedNdatHttpUrlPattern as exc:
        return JSONObject((("framing_supported", False), ("reason", str(exc))))
    return JSONObject(
        (
            ("format", "vdm.ndat.http-url.boost-pattern.v1"),
            ("callback_decimal", 15),
            ("callback_hex", "0x0F"),
            ("framing_supported", True),
            ("raw_hex", pattern.raw.hex()),
            ("counted_data_length", len(pattern.counted_data)),
            ("counted_data_hex", pattern.counted_data.hex()),
            ("effective_pattern_hex", pattern.effective_pattern.hex()),
            ("first_nul_offset", len(pattern.effective_pattern)),
            ("after_pattern_terminator_hex", pattern.after_pattern_terminator.hex()),
            (
                "record_id_suffix_hex",
                None
                if pattern.record_id_suffix_raw is None
                else pattern.record_id_suffix_raw.hex(),
            ),
            ("trailing_raw_hex", pattern.trailing_raw.hex()),
            ("syntax_flags_u32", pattern.syntax_flags),
            ("syntax_flags_hex", "0x500000"),
            (
                "backend",
                "engine Boost regex; boost::re_detail_500; narrow char w32_regex_traits<char>",
            ),
            (
                "grammar_dispatch",
                "raw flags low two bits 0 select parse_extended; no portable grammar equivalence claimed",
            ),
            (
                "locale_dependency",
                "GetUserDefaultLCID at traits construction; cached LCID-dependent w32 narrow-byte traits",
            ),
            ("traits_internal_lcid", None),
            (
                "subject",
                "Original input+8 URI WCHAR CString converted by CP_UTF8/flags0 through first WCHAR NUL; upstream canonicalization unknown",
            ),
            (
                "query",
                "RegExState::Match CString through first byte NUL -> perl_matcher::find_imp; backend search, not fullmatch",
            ),
            (
                "post_match",
                "RegExStringMatch separately invokes ProcessMatchedSignature with runtime RecID/SigSeq; outer policy not evaluated",
            ),
            ("runtime_record_id", None),
            ("runtime_sigseq", None),
            (
                "record_id_source",
                "loader createrecid/createrecidz, separate from counted pattern bytes",
            ),
            ("compile_valid", None),
            ("record_local_match", None),
            ("final_verdict", None),
            ("projector", "lib.vdm.types.ndat.project_ndat_http_url_pattern"),
            ("projection_type", "lib.vdm.types.ndat.NdatHttpUrlPattern"),
            ("unsupported_error", "lib.vdm.types.ndat.UnsupportedNdatHttpUrlPattern"),
            ("evaluator", None),
            (
                "validation_scope",
                "Pinned DLL host compiled frozen corpus 226 patterns and completed 686 queries; not arbitrary-pattern compile validity, full URI caller execution or portable regex conformance",
            ),
        )
    )


def export_ndat(parsed: NdatPayload) -> ArtifactExport:
    """Export only callback-15 Boost input and its required backend contract."""
    parsed = parse_ndat(parsed.raw)
    try:
        pattern = project_ndat_http_url_pattern(parsed)
    except UnsupportedNdatHttpUrlPattern as exc:
        return ArtifactExport("unsupported", reason=str(exc))
    manifest = dict(_http_url_manifest(parsed).items)
    return ArtifactExport(
        "ready",
        (
            Artifact("http-url-pattern.boost.bin", "binary", pattern.effective_pattern),
            Artifact(
                "http-url-pattern.json",
                "json",
                json.dumps(manifest, ensure_ascii=True, indent=2).encode("utf-8")
                + b"\n",
            ),
        ),
    )


@dataclass(frozen=True, slots=True)
class NdatProcessPrefix:
    """A prefix stage result, not an accepted or matched NDAT rule."""

    suffix_prepared_process: str
    prefix: str
    consumed_utf16_units: int
    process: str
    process_flags: int


def parse_ndat_process_prefix(suffix_prepared_process: str) -> NdatProcessPrefix:
    """Decode a process field after successful GetEFlagsFromPath preparation.

    The caller supplies UTF-16 text content before its terminating NUL, before
    path/environment expansion. Embedded NUL is outside this API's input domain;
    rejecting it does not assert that the engine rejects an equivalent wire blob.
    This helper performs no wire decoding, field splitting, or suffix conversion.
    """
    if "\0" in suffix_prepared_process:
        raise ValueError("prefix stage requires text content without a NUL terminator")
    bits = {">": 1, "<": 2, "!": 4, "?": 8}
    flags = 0
    consumed = 0
    for character in suffix_prepared_process:
        bit = bits.get(character)
        if bit is None:
            break
        flags |= bit
        consumed += 1
    # Every consumed prefix character is one UTF-16 code unit.
    return NdatProcessPrefix(
        suffix_prepared_process,
        suffix_prepared_process[:consumed],
        consumed,
        suffix_prepared_process[consumed:],
        flags,
    )


def evaluate_ndat_stream_gate(
    process_flags: int,
    *,
    stream_present: bool,
    stream_mode: int,
    stream_event: int,
) -> bool:
    """Evaluate only ConfirmMatch's mode/event gate in a valid caller context.

    A true result, including a null-stream bypass, does not establish a rule match.
    Valid PID/context, earlier checks, process comparison and interface effects
    remain the caller's responsibility. Arguments are required unsigned DWORDs;
    no mode/event names or defaults are inferred.
    """
    for name, value in (
        ("process_flags", process_flags),
        ("stream_mode", stream_mode),
        ("stream_event", stream_event),
    ):
        if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
            raise ValueError(f"{name} must be an unsigned DWORD")
    if type(stream_present) is not bool:
        raise ValueError("stream_present must be a bool")
    if not stream_present:
        return True
    modes = process_flags & 3
    if modes and not (
        (stream_mode == 0 and modes & 1) or (stream_mode == 1 and modes & 2)
    ):
        return False
    return not process_flags & 8 or stream_event == 5


def _process_stage_contract() -> JSONObject:
    return JSONObject(
        (
            ("field_index", 1),
            ("input_stage", "GetEFlagsFromPath-successful UTF-16 process content"),
            (
                "input_requirement",
                "before terminating NUL and path/environment expansion",
            ),
            ("wire_projection", None),
            ("whole_rule_evaluator", False),
            ("prefix_bits", JSONObject(((">", 1), ("<", 2), ("!", 4), ("?", 8)))),
            ("prefix_consumption", "leading run only; OR repeats; no whitespace trim"),
            ("process_flags_entry_offset", 0x60),
            (
                "stream_gate",
                "null stream bypasses; otherwise mask 0x03 selects mode 0/1 by masks 0x01/0x02 and mask 0x08 requires event 5",
            ),
            (
                "stream_gate_requirement",
                "valid caller/PID context; other checks remain",
            ),
            ("process_dispatch_order", "after the mode/event gate"),
            (
                "process_early_success",
                "first character '*' with any tail, or empty process with PID 4",
            ),
            (
                "early_success_effect",
                "skips interface override and out_record_id write",
            ),
            (
                "mask_0x04_effect",
                "selects ComparePartialProcessName 0x1803CF7C4; not negation",
            ),
            ("without_mask_0x04", "selects CompareIgnoringDeviceVolume 0x1803CF85C"),
            ("interface_effect", "may overwrite the process comparison result"),
        )
    )


def parse_ndat(payload: bytes) -> NdatPayload:
    """Parse the counted data, callback index, and optional record-ID suffix."""
    if len(payload) < 4:
        raise ValueError(
            f"truncated NDAT payload: need 4-byte data length, have {len(payload)}"
        )

    data_length = int.from_bytes(payload[:4], "little")
    callback_offset = 4 + data_length
    if callback_offset >= len(payload):
        available = max(0, len(payload) - 4)
        raise ValueError(
            "truncated NDAT payload: "
            f"declared {data_length} data bytes and callback byte, have {available}"
        )

    suffix_and_trailing = payload[callback_offset + 1 :]
    record_id_suffix_raw: bytes | None = None
    trailing_raw = b""
    if suffix_and_trailing:
        terminator = suffix_and_trailing.find(b"\0")
        if terminator < 0:
            raise ValueError("unterminated NDAT record-ID suffix")
        record_id_suffix_raw = suffix_and_trailing[: terminator + 1]
        trailing_raw = suffix_and_trailing[terminator + 1 :]

    return NdatPayload(
        raw=payload,
        data_length=data_length,
        data_raw=payload[4:callback_offset],
        callback_index=payload[callback_offset],
        record_id_suffix_raw=record_id_suffix_raw,
        trailing_raw=trailing_raw,
    )


def _text_preview(data: bytes) -> str:
    preview = data[:PREVIEW_SIZE]
    text = "".join(chr(byte) if 0x20 <= byte <= 0x7E else "." for byte in preview)
    if len(data) > PREVIEW_SIZE:
        text += "..."
    return text or "(empty)"


def _preview_rows(data: bytes) -> tuple[tuple[str, str], ...]:
    return (
        ("hex_preview", data[:PREVIEW_SIZE].hex(" ") or "(empty)"),
        ("text_preview", _text_preview(data)),
    )


def render_ndat(parsed: NdatPayload) -> FormatResult:
    suffix = parsed.record_id_suffix_raw
    rows = [
        ("data_length", f"{parsed.data_length} B"),
        ("callback_index", f"{parsed.callback_index} (0x{parsed.callback_index:02x})"),
        ("record_id_suffix", _text_preview(suffix[:-1]) if suffix else "not present"),
    ]
    if parsed.trailing_raw:
        rows.append(("ignored_trailing_length", f"{len(parsed.trailing_raw)} B"))

    return FormatResult(
        sections=(
            DisplaySection("NDAT Metadata", rows=tuple(rows)),
            DisplaySection("NDAT Data", rows=_preview_rows(parsed.data_raw)),
        )
    )


def export_ndat_semantics(parsed: NdatPayload) -> RuleSemantics:
    """Export only NDAT callbacks tied to a static registration and consumer."""
    callback_targets = {
        1: "VbasicPathNdatCallback",
        3: "VdllNdatDontCountCallback",
        4: "VdllNdatFireEventCallback",
        5: "LogSkipNdatCallback",
        6: "VdllNdatVfsLinkCallback",
        7: "VdllNdatApiAttributeCallback",
        8: "RkpatCallback",
        10: "PdbPathNdatCallback",
        12: "DnsCacheInfoNdatCallback_0",
        13: "GenericRegExpNdatCallback",
        15: "HttpUrlNdatCallback",
        16: "HttpHeaderNdatCallback",
        17: "MsgBodyNdatCallback",
        18: "SSLCertNdatCallback",
        19: "RawBodyNdatCallback",
        20: "RawSSLCertNdatCallback",
        21: "AsrAutoEnableNdatCallback",
        22: "CAsrNotAllowedNdatCallback",
        23: "McpServersNdatCallback",
    }
    callback_semantics = {
        5: "logskip_rule_ingest",
        22: "custom_asr_not_allowed_rule_ingest",
    }
    callback_target = callback_targets.get(parsed.callback_index)
    has_http_url_consumer = parsed.callback_index == 15
    business_semantics = (
        "boost_w32_byte_pattern_ingest_and_uri_search"
        if has_http_url_consumer
        else callback_semantics.get(parsed.callback_index, "unknown")
    )
    has_logskip_consumer = parsed.callback_index in callback_semantics
    issues = []
    if has_http_url_consumer:
        issues.append(
            SemanticIssue(
                "http_url_backend_required",
                "The manifest requires the engine Boost w32 byte-regex backend; "
                "there is no portable regex evaluator or final network verdict.",
            )
        )
    if callback_target is None:
        issues.append(
            SemanticIssue(
                "ndat_callback_business_semantics_unknown",
                "No registration target or consumer semantics are confirmed "
                "for this callback index.",
                details=(("callback_index", parsed.callback_index),),
            )
        )
    elif business_semantics == "unknown":
        issues.append(
            SemanticIssue(
                "ndat_callback_business_semantics_unknown",
                "The callback table target is confirmed, but this exporter does "
                "not claim its input/output business effect without a direct "
                "handler and consumer dataflow trace.",
                details=(
                    ("callback_index", parsed.callback_index),
                    ("dispatch_target", callback_target),
                ),
            )
        )
    if parsed.record_id_suffix_raw is not None:
        issues.append(
            SemanticIssue(
                "record_name_encoding_unknown",
                "The NUL-terminated bytes are passed to createrecidz as a name, "
                "but their text encoding is not established.",
            )
        )
    if parsed.trailing_raw:
        issues.append(
            SemanticIssue(
                "trailing_bytes_uninterpreted",
                "Bytes following the first record-name terminator are retained "
                "without confirmed receiver semantics.",
                details=(("length", len(parsed.trailing_raw)),),
            )
        )
    status = (
        "unsupported"
        if parsed.trailing_raw
        else "confirmed_subset"
        if callback_target is not None
        else "observed_only"
    )
    if has_http_url_consumer and (not parsed.data_raw or parsed.data_raw[-1] != 0):
        issues.append(
            SemanticIssue(
                "http_url_nonnull_pattern_framing_unsupported",
                "The manifest requires nonempty counted data ending in NUL; it does not model NULL finalize or compile failure.",
            )
        )
    return RuleSemantics(
        status=status,
        representation="ndat.counted_data_callback_suffix.v4",
        data=JSONObject(
            (
                ("type", "NDAT"),
                ("raw_hex", parsed.raw.hex()),
                ("data_length", parsed.data_length),
                ("data_raw_hex", parsed.data_raw.hex()),
                (
                    "callback",
                    JSONObject(
                        (
                            ("index", parsed.callback_index),
                            ("index_hex", f"0x{parsed.callback_index:02x}"),
                            ("dispatch_target", callback_target),
                            ("dispatch_mechanism_confirmed", True),
                            ("dispatch_target_confirmed", callback_target is not None),
                            ("business_semantics", business_semantics),
                            (
                                "is_final_detection",
                                False
                                if parsed.callback_index in callback_semantics
                                else None,
                            ),
                        )
                    ),
                ),
                (
                    "record_name_raw_hex",
                    parsed.record_id_suffix_raw.hex()
                    if parsed.record_id_suffix_raw is not None
                    else None,
                ),
                ("trailing_raw_hex", parsed.trailing_raw.hex()),
                (
                    "http_url_pattern",
                    _http_url_manifest(parsed) if has_http_url_consumer else None,
                ),
                (
                    "process_stage_contract",
                    _process_stage_contract() if has_logskip_consumer else None,
                ),
                (
                    "loader_handoff",
                    JSONObject(
                        (
                            ("entry_stride", 0x18),
                            ("record_id_entry_offset", 0x04),
                            ("record_id_descriptor", 0x1017),
                            ("record_id_is_wire_dword", False),
                            (
                                "record_id_source",
                                "createrecidz"
                                if parsed.record_id_suffix_raw is not None
                                else "createrecid",
                            ),
                            ("record_id_value", None),
                            (
                                "record_id_value_requirement",
                                "loader context and record-ID creation state",
                            ),
                            ("post_callback_record_id_argument", 3),
                        )
                    ),
                ),
                (
                    "record_name_role",
                    "absent"
                    if parsed.record_id_suffix_raw is None
                    else "nul_terminated_name_for_createrecidz",
                ),
            )
        ),
        evidence=(
            "mpengine 1.443.903.0 ReceiveNewTemplate 0x1803224D0/0xB70",
            "mpengine 1.443.903.0 NdatPostCallback 0x180464800/0x186",
            "mpengine 1.443.903.0 LogSkip::Initialize 0x180B53F80/0x41",
            "mpengine 1.443.903.0 logskip_init_module 0x180B54A70/0x12F",
            "mpengine 1.443.903.0 cksig_init_module 0x1805648A0/0x31D",
            "mpengine 1.443.903.0 callback table base 0x181280FF0; NdatPostCallback table[index] read 0x180464883",
            "mpengine 1.443.903.0 dllsupp_init 0x180CA6240/0x6E0 writes indices 3,4,7 at 0x180CA67D1/0x180CA67E6/0x180CA67F4",
            "mpengine 1.443.903.0 fssupp_init 0x18048B180/0x1C7 writes index 6 at 0x18048B283",
            "mpengine 1.443.903.0 filepathscan_init 0x180CAC350/0x67 writes indices 1,2,10,11",
            "mpengine 1.443.903.0 cksig_init_module 0x1805648A0/0x31D initializes table and writes indices 8,12,14",
            "mpengine 1.443.903.0 vlib_init_module 0x180C50820/0x156 writes index 13",
            "mpengine 1.443.903.0 NetworkHips_init_module 0x180C75A60/0x1BB writes indices 15-20",
            "mpengine 1.443.903.0 hips_init_module 0x18048C8E0/0x7A2 writes index 21",
            "mpengine 1.443.903.0 retarget_init_module 0x180BDDF60/0x163 writes index 23",
            "mpengine 1.443.903.0 callback bodies lookup: VbasicPathNdatCallback 0x1805861F0/0x15; VdllNdatDontCountCallback 0x180CA5640/0x201; VdllNdatFireEventCallback 0x180CA5850/0x48C; VdllNdatVfsLinkCallback 0x180429B00/0x287; VdllNdatApiAttributeCallback 0x180CA53F0/0x247",
            "mpengine 1.443.903.0 callback bodies lookup: RkpatCallback 0x18055BBD0/0xC3; PdbPathNdatCallback 0x180573920/0x15; DnsCacheInfoNdatCallback 0x180BBAE20/0x10C; GenericRegExpNdatCallback 0x1804B3FA0/0x8A",
            "mpengine 1.443.903.0 callback bodies lookup: HttpUrlNdatCallback 0x180526C00/0xC8; HttpHeaderNdatCallback 0x1805BA660/0xC5; MsgBodyNdatCallback 0x180C75990/0xC5; SSLCertNdatCallback 0x18055D720/0xC5; RawBodyNdatCallback 0x1804B4E70/0xBE; RawSSLCertNdatCallback 0x1804B4DA0/0xC8",
            "mpengine 1.443.903.0 callback bodies lookup: AsrAutoEnableNdatCallback 0x1805BC650/0x228; McpServersNdatCallback 0x180BDF100/0xA9",
            "mpengine 1.443.903.0 LogSkip::Initialize 0x180B53F80/0x41 writes indices 5 and 22",
            "mpengine 1.443.903.0 LogSkipNdatCallback 0x18005B7C0/0x68",
            "mpengine 1.443.903.0 CAsrNotAllowedNdatCallback 0x1805009C0/0x59",
            "mpengine 1.443.903.0 LogSkip::AddString 0x18005C630/0xE66",
            "mpengine 1.443.903.0 CustomAsrIsNotAllowed 0x180B53EF0/0x8E",
            "mpengine 1.443.903.0 LogSkip::Check 0x180287DE0/0x1104",
        ),
        profile="mpengine-1.443.903.0",
        issues=tuple(issues),
        claims=(
            *(
                (
                    SemanticClaim(
                        "ndat-http-url-pattern-contract",
                        "runtime_consumer",
                        "Callback decimal 15 (0x0F) stores a first-NUL byte pattern "
                        "for the engine Boost w32 narrow-char backend with raw flags "
                        "0x500000. The original URI WCHAR CString is converted to UTF8 "
                        "for find_imp search; RecID/SigSeq post-match policy is separate. "
                        "Pinned-host validation compiled the frozen 226 corpus patterns "
                        "and completed 686 queries, not arbitrary-pattern validation.",
                        "subset",
                        ("ndat-http-url-static", "ndat-http-url-native-host"),
                        (
                            SemanticUnknown(
                                "runtime_consumer",
                                "Traits depend on runtime default LCID; its internal cached "
                                "value was not read. Compile/API/resource failure, arbitrary "
                                "grammar portability, upstream URI canonicalization, actual "
                                "NetworkHipsMatch execution and ProcessMatchedSignature policy "
                                "remain outside the manifest projector.",
                            ),
                        ),
                    ),
                )
                if has_http_url_consumer
                else ()
            ),
            SemanticClaim(
                "ndat-wire-framing",
                "wire_layout",
                "NDAT frames counted data, a callback index, and an optional NUL-terminated record-ID suffix.",
                "subset",
                ("ndat-wire-evidence",),
                (
                    SemanticUnknown(
                        "wire_layout",
                        "The data blob schema is callback-specific.",
                    ),
                ),
            ),
            SemanticClaim(
                "ndat-callback-dispatch",
                "loader_dispatch",
                "The callback index dispatches through the registered callback table.",
                "subset",
                ("ndat-dispatch-evidence",),
                (
                    SemanticUnknown(
                        "loader_dispatch",
                        "The per-callback payload schema is callback-specific.",
                    ),
                ),
            ),
            SemanticClaim(
                "ndat-record-id-handoff",
                "receiver_transform",
                "Descriptor 0x1017 creates the normalized entry +0x04 record ID "
                "with createrecid or createrecidz; NdatPostCallback passes it as "
                "callback argument 3. This DWORD is not a wire flags field.",
                "subset",
                ("ndat-record-id-receiver-evidence",),
                (
                    SemanticUnknown(
                        "receiver_transform",
                        "The numeric record ID depends on loader context and "
                        "record-ID creation state; suffix bytes alone do not "
                        "establish its value.",
                    ),
                ),
            ),
            SemanticClaim(
                "ndat-callback-schema",
                "runtime_consumer",
                (
                    "For callback 5/22 accepting non-null data (callback 5 "
                    "outside the sandbox), the loader-created record ID is "
                    "passed as LogSkip::AddString argument 4. On the ordinary "
                    "LogSkipEntry path it is stored at +0x6C; the trusted-process "
                    "branch does not forward that ID. ConfirmMatch's "
                    "full-success path copies "
                    "it to out_record_id; Check uses that value for WPP logging. "
                    "The separate +0x60 process flags derive from rule-string "
                    "prefixes, not the loader DWORD. This traces ingestion and "
                    "record-ID provenance, not a complete matching predicate."
                    if has_logskip_consumer
                    else "The backend-specific HttpUrl pattern and URI contract "
                    "is exported separately; complete compiler and post-match "
                    "policy are not projected."
                    if has_http_url_consumer
                    else "The callback target does not establish a traced "
                    "callback-specific schema or downstream business effect."
                ),
                "subset" if has_logskip_consumer else "unknown",
                ("ndat-logskip-consumer-evidence",) if has_logskip_consumer else (),
                (
                    SemanticUnknown(
                        "runtime_consumer",
                        (
                            "The complete callback-specific rule grammar, "
                            "matching behavior, and downstream policy are not "
                            "modeled; alternate AddString storage paths are "
                            "outside this ordinary-entry claim. ConfirmMatch "
                            "also has an early-success "
                            "path that does not write out_record_id."
                            if has_logskip_consumer
                            else "Complete compiler acceptance, caller context "
                            "and post-match policy are not modeled."
                            if has_http_url_consumer
                            else "Callback-specific schema and effects are "
                            "unresolved for this record."
                        ),
                    ),
                ),
            ),
            *(
                (
                    SemanticClaim(
                        "ndat-process-stage",
                        "runtime_consumer",
                        "For callback 5/22, the suffix-prepared process field's "
                        "leading '>', '<', '!', '?' characters OR bits 1/2/4/8 without "
                        "whitespace trimming. After the stream gate, a leading "
                        "'*' or empty process with PID 4 selects early success, "
                        "skipping interface/output writes; otherwise mask 0x04 "
                        "selects the ComparePartialProcessName callee, not "
                        "negation. A later "
                        "interface may overwrite the comparison result.",
                        "subset",
                        ("ndat-process-stage-static", "ndat-process-stage-native"),
                        (
                            SemanticUnknown(
                                "runtime_consumer",
                                "Wire UTF-8/NUL ingestion, field splitting, "
                                "GetEFlags suffix conversion, expansion, "
                                "comparison callees and interface behavior are "
                                "outside the portable prefix stage.",
                            ),
                        ),
                    ),
                    SemanticClaim(
                        "ndat-stream-gate",
                        "detection_predicate",
                        "Only ConfirmMatch's mode/event subpredicate is modeled: "
                        "null stream bypasses it; otherwise mask 0x03 equal to zero "
                        "allows any mode, or mask 0x01 permits mode 0 and mask "
                        "0x02 mode 1 (union). Mask 0x08 additionally requires event 5. Other "
                        "DWORD bits do not participate in this gate.",
                        "subset",
                        ("ndat-stream-gate-static", "ndat-stream-gate-native"),
                        (
                            SemanticUnknown(
                                "detection_predicate",
                                "A valid caller/PID context and other rule "
                                "checks are required; gate success is not a "
                                "complete match. Native cases cover flags "
                                "0..15, not every DWORD; ignoring higher bits "
                                "follows the static masks.",
                            ),
                        ),
                    ),
                )
                if has_logskip_consumer
                else ()
            ),
            SemanticClaim(
                "ndat-verdict",
                "final_verdict",
                "NDAT framing and callback dispatch do not establish a broad business interpretation or final verdict.",
                "unknown",
                (),
                (
                    SemanticUnknown(
                        "final_verdict",
                        "The callback and downstream policy do not establish final disposition.",
                    ),
                ),
            ),
        ),
        claim_evidence=(
            *(
                (
                    SemanticEvidence(
                        "ndat-http-url-static",
                        "consumer",
                        "engine_static",
                        "mpengine 1.443.903.0",
                        ("ndat-http-url-pattern-contract",),
                        "HttpUrlNdatCallback@180526C00; construct@180549304; "
                        "basic_regex ctor@1801FBFE4; parse@1801FE260; "
                        "regex_data@1801FC5F0 GetUserDefaultLCID; "
                        "NetworkHipsProcess@18008D8CC -> NetworkHipsMatch@18008E460 "
                        "URI input+8 -> UtilWideCharToUtf8@18066895C -> "
                        "RegExStringMatch@18002E528 -> Match@1800B6D64/find_imp@1800B55EC; "
                        "docs/mpengine.dll/1.443.903.0/NetworkHipsMatch.md",
                    ),
                    SemanticEvidence(
                        "ndat-http-url-native-host",
                        "consumer",
                        "engine_runtime",
                        "Pinned mpengine 1.443.903.0 native_host; isolated Windows child processes",
                        ("ndat-http-url-pattern-contract",),
                        "DLL SHA256 928e171c60a44bb326776d2a356412ae98d78469bdf8c94ebfbfa09f8ec4b4b3; "
                        "tests/local_boost_native_corpus_probe_v1.py SHA256 "
                        "82f614c3374a14dfbbf9d03d13adb3bf116fdeb6209a996145a8f44fb42ca475; "
                        ".tmp/local_boost_native_corpus_probe_v1_manifest.json SHA256 "
                        "51757058c8164cbe4eb3b185289853cfc5a4c83a40050d68855b8f7cd3dab259; "
                        ".tmp/local_boost_native_corpus_probe_v1_results.jsonl SHA256 "
                        "7509a8dca0ae53df6d6fb69ea21e1ccda716300521fada2284190da1b6c47093; "
                        ".tmp/local_boost_native_corpus_probe_v1_summary.json SHA256 "
                        "d9c87becb08685f1519b324fef48e592c1a344083b0a4ad3617ee0db20b5bae1; "
                        "offline manifest/native-input bridge tests/local_ndat_httpurl_manifest_bridge.py SHA256 "
                        "a4c76ec9c16942831ccd4a12f4cd298d6d62ed6ed308a6c12974d7dd8fd02ee8; "
                        "226 constructors / 686 completed Match AL queries; loaded-code pins/canaries/"
                        "timeouts/child exits, no Unicorn PC/GPR/XMM trace; observed host LCID1033 "
                        "ACP1252 environment, not direct traits-internal locale measurement; "
                        "no full NetworkHipsMatch or ProcessMatchedSignature execution",
                    ),
                )
                if has_http_url_consumer
                else ()
            ),
            SemanticEvidence(
                "ndat-wire-evidence",
                "wire_parser",
                "engine_static",
                "ReceiveNewTemplate NDAT field decoding",
                ("ndat-wire-framing",),
            ),
            SemanticEvidence(
                "ndat-dispatch-evidence",
                "dispatch",
                "engine_static",
                "ReceiveNewTemplate / NdatPostCallback callback table and registration sites",
                ("ndat-callback-dispatch",),
            ),
            SemanticEvidence(
                "ndat-record-id-receiver-evidence",
                "receiver",
                "engine_static",
                "ReceiveNewTemplate 0x1803224D0/0xB70: descriptor 0x1017 "
                "createrecidz call 0x180322983 / createrecid call 0x1803229D5, "
                "store 0x1803226C7 to entry +4; NdatPostCallback "
                "0x180464800/0x186 reads +4 at 0x18046488C, dispatches at "
                "0x180464899 (pseudocode anchor 0x18046489F)",
                ("ndat-record-id-handoff",),
            ),
            *(
                (
                    SemanticEvidence(
                        "ndat-logskip-consumer-evidence",
                        "consumer",
                        "engine_static",
                        "LogSkipNdatCallback 0x18005B7C0/0x68 and "
                        "CAsrNotAllowedNdatCallback 0x1805009C0/0x59 forward "
                        "record ID to LogSkip::AddString 0x18005C630/0xE66 "
                        "argument 4 (v77), vector construction 0x18005CBEC; "
                        "LogSkipEntry constructor 0x180218F7C/0x140 stores "
                        "+0x6C at 0x180218FF6; ConfirmMatch "
                        "0x180288EE4/0x470 full-success output 0x18028931E; "
                        "Check 0x180287DE0/0x1104 sigseqfromrecid WPP use "
                        "0x1802881C4; process flags remain separate at +0x60",
                        ("ndat-callback-schema",),
                    ),
                    SemanticEvidence(
                        "ndat-process-stage-static",
                        "consumer",
                        "engine_static",
                        "LogSkip::AddString 0x18005C630/0xE66 process field "
                        "after GetEFlagsFromPath and before expansion; "
                        "ConfirmMatch 0x180288EE4/0x470 process dispatch and "
                        "interface CFG call 0x1802892D9 (pseudocode anchor "
                        "0x1802892DF, result overwrite)",
                        ("ndat-process-stage",),
                        "prefix 0x18005C819..0x18005C85A and remote loop blocks; "
                        "process branch 0x180289119..0x180289189",
                    ),
                    SemanticEvidence(
                        "ndat-process-stage-native",
                        "engine_equivalent_test",
                        "engine_equivalent_test",
                        "Pinned mpengine SHA256 "
                        "928e171c60a44bb326776d2a356412ae98d78469bdf8c94ebfbfa09f8ec4b4b3; "
                        "NDAT_process_prefix_differential_probe: 1372 "
                        "suffix-prepared prefix cases and 128 process branch "
                        "selections; original instruction slices with guarded "
                        "synthetic interior contexts; no comparator execution "
                        "or whole AddString ingestion",
                        ("ndat-process-stage",),
                        "prefix 0x18005C819..0x18005C85A plus remote blocks; "
                        "process selector 0x180289119..0x180289189",
                    ),
                    SemanticEvidence(
                        "ndat-stream-gate-static",
                        "consumer",
                        "engine_static",
                        "LogSkip::ConfirmMatch 0x180288EE4/0x470: DWORD masks "
                        "0x03 and 0x08 select the mode/event gate",
                        ("ndat-stream-gate",),
                        "0x180288FCD..0x180289119; reject 0x180288FC1",
                    ),
                    SemanticEvidence(
                        "ndat-stream-gate-native",
                        "engine_equivalent_test",
                        "engine_equivalent_test",
                        "Pinned mpengine SHA256 "
                        "928e171c60a44bb326776d2a356412ae98d78469bdf8c94ebfbfa09f8ec4b4b3; "
                        "NDAT_process_prefix_differential_probe: 640 original "
                        "stream-gate slice cases, flags 0..15, modes "
                        "0/1/2/3/0xFFFFFFFF, events 0/2/5/0xFFFFFFFF, stream "
                        "present/null with a valid synthetic PID context; "
                        "not a complete ConfirmMatch execution",
                        ("ndat-stream-gate",),
                        "0x180288FCD..0x180289119; reject 0x180288FC1",
                    ),
                )
                if has_logskip_consumer
                else ()
            ),
        ),
    )


NDAT_SPEC = FamilySpec(
    NDAT_TYPE,
    "NDAT",
    parse_ndat,
    render_ndat,
    exporter=export_ndat,
    semantic_exporter=export_ndat_semantics,
)
