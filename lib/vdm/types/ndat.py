"""Parser and renderer for NDAT (0xA9) payloads."""

import hashlib
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
    semantic_json_to_data,
)
from ..raw_ssl_cert import (
    RawSslBytePattern,
    UnsupportedRawSslPattern,
    compile_raw_ssl_byte_pattern,
    raw_ssl_yara_rhs,
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


class UnsupportedNdatGenericRegexPattern(ValueError):
    """The record is outside callback-13 non-null pattern registration."""


@dataclass(frozen=True, slots=True)
class NdatGenericRegexPattern:
    """Narrow byte pattern input for generic NDAT's original Boost backend."""

    raw: bytes
    counted_data: bytes
    effective_pattern: bytes
    after_pattern_terminator: bytes
    record_id_suffix_raw: bytes | None
    trailing_raw: bytes
    syntax_flags: int = 0x400000


def project_ndat_generic_regex_pattern(parsed: NdatPayload) -> NdatGenericRegexPattern:
    """Reparse callback decimal 13 (0x0D) without decoding its pattern bytes.

    The non-null registration profile requires nonempty counted data ending in
    NUL. Effective bytes before the first NUL include any leading 04 and exclude
    that terminator; counted bytes after it are retained separately. This does not validate regex
    compilation, identify the bytes' business domain, or evaluate a Lua query.
    """
    parsed = parse_ndat(parsed.raw)
    if parsed.callback_index != 13:
        raise UnsupportedNdatGenericRegexPattern("requires callback decimal 13 (0x0D)")
    data = parsed.data_raw
    if not data or data[-1] != 0:
        raise UnsupportedNdatGenericRegexPattern(
            "requires nonempty counted data ending in NUL"
        )
    first_nul = data.index(0)
    return NdatGenericRegexPattern(
        parsed.raw,
        data,
        data[:first_nul],
        data[first_nul + 1 :],
        parsed.record_id_suffix_raw,
        parsed.trailing_raw,
    )


def _generic_regex_manifest(parsed: NdatPayload) -> JSONObject:
    try:
        pattern = project_ndat_generic_regex_pattern(parsed)
    except UnsupportedNdatGenericRegexPattern as exc:
        return JSONObject((("framing_supported", False), ("reason", str(exc))))
    return JSONObject(
        (
            ("format", "vdm.ndat.generic-regex.boost-pattern.v1"),
            ("callback_decimal", 13),
            ("callback_hex", "0x0D"),
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
            ("syntax_flags_hex", "0x400000"),
            (
                "backend",
                "engine Boost regex; boost::re_detail_500; narrow char w32_regex_traits<char>",
            ),
            (
                "grammar_dispatch",
                "raw flags low two bits 0 select parse_extended; bit20 is clear; no portable grammar equivalence claimed",
            ),
            (
                "locale_dependency",
                "GetUserDefaultLCID at traits construction; cached LCID-dependent w32 narrow-byte traits",
            ),
            ("traits_internal_lcid", None),
            (
                "subject",
                "Lua argument 2 result of luaL_checklstring(length_out=NULL), passed as a byte CString through first NUL; caller encoding, coercion and upstream normalization unknown",
            ),
            (
                "query",
                "LsaMpCommonLib::NdatRegExpMatch checks selector low32 == 13; RegExState::Match -> perl_matcher::find_imp searches each row until the first match",
            ),
            (
                "runtime_order",
                "Actual postcallback-ingested vector order required; NdatCmp orders callback/length/full counted bytes ascending then threat ID descending; wire arrival or a stable host sort is not a winner oracle",
            ),
            (
                "post_match",
                "First matched row's runtime RecID -> namefromrecid -> UnpackVirusName; success returns Lua true/name/RecID, miss returns only false; namespace/unpack failures are Lua errors",
            ),
            ("runtime_record_id", None),
            ("runtime_name", None),
            (
                "record_id_source",
                "loader createrecid/createrecidz, separate from counted pattern bytes; row stride24 stores RecID but no SigSeq",
            ),
            ("compile_valid", None),
            ("record_local_match", None),
            ("final_verdict", None),
            ("projector", "lib.vdm.types.ndat.project_ndat_generic_regex_pattern"),
            ("projection_type", "lib.vdm.types.ndat.NdatGenericRegexPattern"),
            (
                "unsupported_error",
                "lib.vdm.types.ndat.UnsupportedNdatGenericRegexPattern",
            ),
            ("evaluator", None),
            (
                "validation_scope",
                "Pinned DLL host compiled frozen corpus 82 raw patterns and completed 410 queries, 102 true; not arbitrary compile validity, Lua/namespace end-to-end execution or portable regex conformance",
            ),
        )
    )


def _export_generic_regex_pattern(parsed: NdatPayload) -> ArtifactExport:
    try:
        pattern = project_ndat_generic_regex_pattern(parsed)
    except UnsupportedNdatGenericRegexPattern as exc:
        return ArtifactExport("unsupported", reason=str(exc))
    manifest = dict(_generic_regex_manifest(parsed).items)
    return ArtifactExport(
        "ready",
        (
            Artifact(
                "generic-regex-pattern.boost.bin", "binary", pattern.effective_pattern
            ),
            Artifact(
                "generic-regex-pattern.json",
                "json",
                json.dumps(manifest, ensure_ascii=True, indent=2).encode("utf-8")
                + b"\n",
            ),
        ),
    )


class UnsupportedNdatSslCertPattern(ValueError):
    """The record is outside callback-18 non-null pattern registration."""


@dataclass(frozen=True, slots=True)
class NdatSslCertPattern:
    """Original Boost pattern bytes for formatted certificate subjects."""

    raw: bytes
    counted_data: bytes
    effective_pattern: bytes
    after_pattern_terminator: bytes
    record_id_suffix_raw: bytes | None
    trailing_raw: bytes
    syntax_flags: int = 0x500000


def project_ndat_ssl_cert_pattern(parsed: NdatPayload) -> NdatSslCertPattern:
    """Reparse decimal callback 18 (0x12), preserving arbitrary pattern bytes.

    Nonempty counted data ending in NUL defines this non-null registration
    profile. The effective pattern excludes its first NUL; later counted bytes
    and the independent record-ID suffix/trailing bytes remain separate.
    No certificate parse, regex compilation or query occurs here.
    """
    parsed = parse_ndat(parsed.raw)
    if parsed.callback_index != 18:
        raise UnsupportedNdatSslCertPattern("requires callback decimal 18 (0x12)")
    data = parsed.data_raw
    if not data or data[-1] != 0:
        raise UnsupportedNdatSslCertPattern(
            "requires nonempty counted data ending in NUL"
        )
    first_nul = data.index(0)
    return NdatSslCertPattern(
        parsed.raw,
        data,
        data[:first_nul],
        data[first_nul + 1 :],
        parsed.record_id_suffix_raw,
        parsed.trailing_raw,
    )


def _ssl_cert_subject_recipes() -> JSONObject:
    return JSONObject(
        (
            (
                "dn",
                JSONObject(
                    (
                        ("builder", "lib.vdm.ssl_cert_subject.build_ssl_dn_subject"),
                        ("row_type", "lib.vdm.ssl_cert_subject.SslDnStringRow"),
                        (
                            "input",
                            "parsed runtime 24-byte DN rows: type u32 at +0, resolved physical WCHAR CString pointer at +16; not raw DER",
                        ),
                        ("type_order", JSONArray((12, 5, 4, 3, 2, 1, 0))),
                        (
                            "short_labels",
                            JSONArray(("EMAIL", "CN", "OU", "O", "L", "ST", "C")),
                        ),
                        (
                            "selection",
                            "first matching row, including NULL that shadows later duplicates; unknown-type value storage is not selected",
                        ),
                        (
                            "values",
                            "NULL skips; non-NULL empty retains label=; first aligned WCHAR NUL ends each value, later fields still append",
                        ),
                        (
                            "format",
                            "Subject: or Issuer: prefix, then label=value joined by comma-space; no trim or escaping",
                        ),
                        (
                            "caller_roles",
                            "Subject uses certificate+0x40 DN; Issuer uses certificate+0x30 DN",
                        ),
                        (
                            "success_domain",
                            "ASCII selected WCHAR content projected to narrow bytes; non-ASCII/insufficient physical CString storage is typed unsupported, not mismatch",
                        ),
                        (
                            "native_format",
                            "TrNewSprintfA(%s: %ls) -> narrow CRT __stdio_common_vsprintf(locale=NULL); no CP_UTF8 or ACP equivalence claimed",
                        ),
                    )
                ),
            ),
            (
                "validity",
                JSONObject(
                    (
                        (
                            "builder",
                            "lib.vdm.ssl_cert_subject.build_ssl_validity_subject",
                        ),
                        (
                            "snapshot_type",
                            "lib.vdm.ssl_cert_subject.SslValiditySnapshot",
                        ),
                        ("from_words_offset", 88),
                        ("to_words_offset", 104),
                        ("words_per_time", 8),
                        ("used_word_indices", JSONArray((0, 1, 3, 4, 5, 6))),
                        ("offset_dword_offsets", JSONArray((120, 124, 128, 132))),
                        (
                            "gate",
                            "either first year WORD zero supplies no recipe-local subject; original global-pattern-vector gate remains external",
                        ),
                        (
                            "format",
                            "ValidFrom: YYYY-MM-DD hh:mm:ss (UTC + uu:uu) ValidTo: YYYY-MM-DD hh:mm:ss (UTC + uu:uu)",
                        ),
                        (
                            "numeric_rules",
                            "raw unsigned u16/u32, minimum widths 4 for year and 2 otherwise; literal UTC +; no date validation, signed-zone adjustment or current-time test",
                        ),
                    )
                ),
            ),
            ("result_type", "lib.vdm.ssl_cert_subject.SslCertSubject"),
            ("unsupported_error", "lib.vdm.ssl_cert_subject.UnsupportedSslCertSubject"),
            (
                "availability",
                "subject_available is recipe-local only; no regex/NRI/post-match result or complete engine-query eligibility",
            ),
        )
    )


def _ssl_cert_manifest(parsed: NdatPayload) -> JSONObject:
    try:
        pattern = project_ndat_ssl_cert_pattern(parsed)
    except UnsupportedNdatSslCertPattern as exc:
        return JSONObject((("framing_supported", False), ("reason", str(exc))))
    return JSONObject(
        (
            ("format", "vdm.ndat.ssl-cert.boost-pattern.v1"),
            ("callback_decimal", 18),
            ("callback_hex", "0x12"),
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
                "locale_dependency",
                "runtime GetUserDefaultLCID-dependent regex traits, separate from the narrow CRT DN formatter locale; internal locale values not directly read",
            ),
            ("subject_recipes", _ssl_cert_subject_recipes()),
            (
                "certificate_input",
                "NetworkHipsMatch metadata+0x40 blob view (+4 size/+8 pointer); one BE24 length at bytes3..5 selects bytes+6 for ParsePkcs6Certificate; not a portable ASN.1 or TLS-chain parser",
            ),
            (
                "query",
                "RegExStringMatch -> RegExState::Match/find_imp searches each formatted Subject/Issuer/Validity CString with the original backend",
            ),
            (
                "policy",
                "DN field NRI checks can independently affect builder return; RegExStringMatch invokes ProcessMatchedSignature with runtime RecID/SigSeq; neither is evaluated by these recipes",
            ),
            ("runtime_record_id", None),
            ("runtime_sigseq", None),
            ("compile_valid", None),
            ("record_local_match", None),
            ("final_verdict", None),
            ("projector", "lib.vdm.types.ndat.project_ndat_ssl_cert_pattern"),
            ("projection_type", "lib.vdm.types.ndat.NdatSslCertPattern"),
            ("unsupported_error", "lib.vdm.types.ndat.UnsupportedNdatSslCertPattern"),
            ("evaluator", None),
            (
                "validation_scope",
                "278 corpus patterns compiled and 1652 original Match calls completed; formatter/builder evidence is separately scoped, not arbitrary regex validity or full certificate/NRI/scan policy",
            ),
        )
    )


def _export_ssl_cert_pattern(parsed: NdatPayload) -> ArtifactExport:
    try:
        pattern = project_ndat_ssl_cert_pattern(parsed)
    except UnsupportedNdatSslCertPattern as exc:
        return ArtifactExport("unsupported", reason=str(exc))
    return ArtifactExport(
        "ready",
        (
            Artifact("ssl-cert-pattern.boost.bin", "binary", pattern.effective_pattern),
            Artifact(
                "ssl-cert-pattern.json",
                "json",
                json.dumps(
                    semantic_json_to_data(_ssl_cert_manifest(parsed)),
                    ensure_ascii=True,
                    indent=2,
                ).encode("utf-8")
                + b"\n",
            ),
        ),
    )


class UnsupportedNdatRawSslPattern(ValueError):
    """Outside callback-20 non-NULL pattern-registration framing."""


@dataclass(frozen=True, slots=True)
class NdatRawSslPattern:
    raw: bytes
    counted_data: bytes
    effective_pattern: bytes
    after_pattern_terminator: bytes
    record_id_suffix_raw: bytes | None
    trailing_raw: bytes
    portable_pattern: RawSslBytePattern | None
    portable_reason: str | None
    syntax_flags: int = 0x400000


def project_ndat_raw_ssl_pattern(parsed: NdatPayload) -> NdatRawSslPattern:
    """Reparse callback20; preserve Boost bytes even outside portable grammar.

    Nonempty counted data must end in NUL. Constructor input excludes its first
    NUL, with later counted bytes preserved separately from suffix/trailing.
    This framing is not compile validation or a NULL-finalize classification.
    """
    parsed = parse_ndat(parsed.raw)
    if parsed.callback_index != 20:
        raise UnsupportedNdatRawSslPattern("requires callback decimal 20 (0x14)")
    data = parsed.data_raw
    if not data or data[-1] != 0:
        raise UnsupportedNdatRawSslPattern(
            "requires nonempty counted data ending in NUL"
        )
    first = data.index(0)
    effective = data[:first]
    try:
        portable = compile_raw_ssl_byte_pattern(effective)
        reason = None
    except UnsupportedRawSslPattern as exc:
        portable, reason = None, str(exc)
    return NdatRawSslPattern(
        parsed.raw,
        data,
        effective,
        data[first + 1 :],
        parsed.record_id_suffix_raw,
        parsed.trailing_raw,
        portable,
        reason,
    )


def _raw_ssl_manifest(parsed: NdatPayload) -> JSONObject:
    try:
        pattern = project_ndat_raw_ssl_pattern(parsed)
    except UnsupportedNdatRawSslPattern as exc:
        return JSONObject(
            (
                ("format", "vdm.ndat.raw-ssl-cert.boost-pattern.v1"),
                ("framing_supported", False),
                ("reason", str(exc)),
            )
        )
    portable = pattern.portable_pattern
    return JSONObject(
        (
            ("format", "vdm.ndat.raw-ssl-cert.boost-pattern.v1"),
            ("framing_supported", True),
            ("callback_decimal", 20),
            ("counted_data_hex", pattern.counted_data.hex()),
            ("effective_pattern_hex", pattern.effective_pattern.hex()),
            ("after_pattern_terminator_hex", pattern.after_pattern_terminator.hex()),
            (
                "record_id_suffix_hex",
                None
                if pattern.record_id_suffix_raw is None
                else pattern.record_id_suffix_raw.hex(),
            ),
            ("trailing_hex", pattern.trailing_raw.hex()),
            ("syntax_flags_u32", 0x400000),
            ("search_match_flags_u32", 0x400),
            (
                "backend",
                "original Boost re_detail_500 w32_regex_traits<char>; unsigned-char iterator regex_search, not BM or CString subject",
            ),
            (
                "locale_dependency",
                "runtime default LCID traits; host LCID/ACP evidence is environment only, not internal traits readback",
            ),
            (
                "subject_recipe",
                JSONObject(
                    (
                        ("projector", "lib.vdm.raw_ssl_cert.project_raw_ssl_subject"),
                        ("view_type", "lib.vdm.raw_ssl_cert.RawSslMetadataView"),
                        ("result_type", "lib.vdm.raw_ssl_cert.RawSslSubject"),
                        (
                            "unsupported_error",
                            "lib.vdm.raw_ssl_cert.UnsupportedRawSslSubject",
                        ),
                        (
                            "source",
                            "metadata+0x40 resolved view; u32 size+4, physical buffer pointer+8",
                        ),
                        (
                            "gates",
                            "NULL view/buffer, size<6 or BE24 buffer[3:6]>size-6 skip this local branch; insufficient physical bytes are unsupported",
                        ),
                        (
                            "subject",
                            "buffer[6:size], including declared-certificate suffix bytes and embedded NUL; parser_span=buffer[6:6+BE24] is separate",
                        ),
                        (
                            "boundary",
                            "prefix[0:3] semantics/upstream mapping/global patterns/resources/post-policy are external; no TLS/DER parser",
                        ),
                    )
                ),
            ),
            (
                "portable_projection",
                JSONObject(
                    (
                        ("supported", portable is not None),
                        ("reason", pattern.portable_reason),
                        (
                            "language",
                            "nonempty fixed-width ASCII \\xHH, literal H and [^\\xHH] tokens only; case-sensitive bytes",
                        ),
                        (
                            "atoms",
                            None
                            if portable is None
                            else JSONArray(
                                tuple(
                                    JSONObject(
                                        (("value", a.value), ("negated", a.negated))
                                    )
                                    for a in portable.atoms
                                )
                            ),
                        ),
                        (
                            "yara_rhs",
                            None if portable is None else raw_ssl_yara_rhs(portable),
                        ),
                        (
                            "rule_name",
                            None
                            if portable is None
                            else "ndat_raw_ssl_"
                            + hashlib.sha256(pattern.raw).hexdigest(),
                        ),
                        (
                            "compiler",
                            "lib.vdm.raw_ssl_cert.compile_raw_ssl_byte_pattern",
                        ),
                        ("pattern_type", "lib.vdm.raw_ssl_cert.RawSslBytePattern"),
                        ("atom_type", "lib.vdm.raw_ssl_cert.RawSslByteAtom"),
                        ("predicate", "lib.vdm.raw_ssl_cert.search_raw_ssl_bytes"),
                        ("rhs_exporter", "lib.vdm.raw_ssl_cert.raw_ssl_yara_rhs"),
                        (
                            "unsupported_error",
                            "lib.vdm.raw_ssl_cert.UnsupportedRawSslPattern",
                        ),
                        (
                            "scope",
                            "Boolean predicate/YARA applied only to identical explicit subject slice; not complete Boost grammar or policy",
                        ),
                        ("yara_compile_valid", None),
                        (
                            "yara_minimum_version",
                            "4.3.0"
                            if portable is not None
                            and any(a.negated for a in portable.atoms)
                            else None,
                        ),
                        (
                            "validated_yara_version",
                            "4.5.4 (frozen corpus/recorded-span differential only)",
                        ),
                    )
                ),
            ),
            ("projector", "lib.vdm.types.ndat.project_ndat_raw_ssl_pattern"),
            ("pattern_type", "lib.vdm.types.ndat.NdatRawSslPattern"),
            ("unsupported_error", "lib.vdm.types.ndat.UnsupportedNdatRawSslPattern"),
            (
                "query",
                "RegExBinaryMatch searches every row, then ProcessMatchedSignature consumes runtime RecID/SigSeq/context; regex hit is not policy success",
            ),
            ("runtime_record_id", None),
            ("runtime_signature_sequence", None),
            ("compile_valid", None),
            ("record_local_match", None),
            ("final_verdict", None),
        )
    )


def _export_raw_ssl_pattern(parsed: NdatPayload) -> ArtifactExport:
    try:
        pattern = project_ndat_raw_ssl_pattern(parsed)
    except UnsupportedNdatRawSslPattern as exc:
        return ArtifactExport("unsupported", reason=str(exc))
    artifacts = [
        Artifact("raw-ssl-cert-pattern.boost.bin", "binary", pattern.effective_pattern),
        Artifact(
            "raw-ssl-cert-pattern.json",
            "json",
            json.dumps(
                semantic_json_to_data(_raw_ssl_manifest(parsed)),
                ensure_ascii=True,
                indent=2,
            ).encode()
            + b"\n",
        ),
    ]
    if pattern.portable_pattern is not None:
        rhs = raw_ssl_yara_rhs(pattern.portable_pattern)
        artifacts.append(
            Artifact(
                "raw-ssl-cert-pattern.yar",
                "yara",
                (
                    "// Apply only to the selected explicit raw subject span; no engine policy.\nrule ndat_raw_ssl_"
                    + hashlib.sha256(pattern.raw).hexdigest()
                    + " {\n strings:\n  $a = "
                    + rhs
                    + "\n condition:\n  $a\n}\n"
                ).encode("ascii"),
            )
        )
    return ArtifactExport("ready", tuple(artifacts))


def export_ndat(parsed: NdatPayload) -> ArtifactExport:
    """Export supported NDAT pattern inputs with their distinct backend contracts."""
    parsed = parse_ndat(parsed.raw)
    if parsed.callback_index == 20:
        return _export_raw_ssl_pattern(parsed)
    if parsed.callback_index == 18:
        return _export_ssl_cert_pattern(parsed)
    if parsed.callback_index == 13:
        return _export_generic_regex_pattern(parsed)
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
    has_generic_regex_consumer = parsed.callback_index == 13
    has_ssl_cert_consumer = parsed.callback_index == 18
    has_raw_ssl_consumer = parsed.callback_index == 20
    business_semantics = (
        "boost_w32_byte_pattern_ingest_and_uri_search"
        if has_http_url_consumer
        else "boost_w32_byte_pattern_ingest_and_lua_search"
        if has_generic_regex_consumer
        else "boost_w32_pattern_ingest_and_formatted_certificate_search"
        if has_ssl_cert_consumer
        else "boost_w32_binary_pattern_ingest_and_explicit_raw_span_search"
        if has_raw_ssl_consumer
        else callback_semantics.get(parsed.callback_index, "unknown")
    )
    has_logskip_consumer = parsed.callback_index in callback_semantics
    issues = []
    if has_raw_ssl_consumer:
        issues.append(
            SemanticIssue(
                "raw_ssl_explicit_span_and_policy_boundary",
                "A strict fixed-byte subset supplies local predicate/YARA on the exact selected raw remaining span; original compiler/resources/namespace and ProcessMatchedSignature remain external.",
            )
        )
        if not parsed.data_raw or parsed.data_raw[-1] != 0:
            issues.append(
                SemanticIssue(
                    "raw_ssl_nonnull_pattern_profile_unsupported",
                    "Outside non-NULL pattern registration, without declaring generic wire malformed or NULL finalize.",
                )
            )
    if has_ssl_cert_consumer:
        issues.append(
            SemanticIssue(
                "ssl_cert_backend_and_runtime_view_required",
                "Only pattern input and parsed-runtime ASCII DN/raw validity recipes are projected; "
                "ASN.1 parsing, regex/NRI/namespace and final policy remain external.",
            )
        )
    if has_generic_regex_consumer:
        issues.append(
            SemanticIssue(
                "generic_regex_backend_required",
                "The generic pattern manifest requires the original Boost w32 byte backend; "
                "Lua subject generation, runtime order/name resolution and final policy are external.",
            )
        )
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
    if has_generic_regex_consumer and (not parsed.data_raw or parsed.data_raw[-1] != 0):
        issues.append(
            SemanticIssue(
                "generic_regex_nonnull_pattern_profile_unsupported",
                "The projector requires nonempty counted data ending in NUL; this is not "
                "a wire-framing verdict or proof that the loader supplies NULL for zero length.",
            )
        )
    if has_ssl_cert_consumer and (not parsed.data_raw or parsed.data_raw[-1] != 0):
        issues.append(
            SemanticIssue(
                "ssl_cert_nonnull_pattern_profile_unsupported",
                "Nonempty counted data ending in NUL defines this projector's non-NULL "
                "registration profile, not a wire rejection or inferred NULL finalize.",
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
                *(
                    (("raw_ssl_pattern", _raw_ssl_manifest(parsed)),)
                    if has_raw_ssl_consumer
                    else (("ssl_cert_pattern", _ssl_cert_manifest(parsed)),)
                    if has_ssl_cert_consumer
                    else ()
                ),
                *(
                    (("generic_regex_pattern", _generic_regex_manifest(parsed)),)
                    if has_generic_regex_consumer
                    else ()
                ),
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
                        "ndat-raw-ssl-byte-predicate",
                        "runtime_consumer",
                        "Callback20 constructs first-NUL Boost w32 patterns with syntax flags0x400000; binary Search uses explicit pointer+length. A nonempty fixed byte/negated-single-byte subset provides Boolean search and hex YARA on the same selected span. The metadata view selects buffer[6:size]; BE24 length gates bounds and selects a separate parser span, not the raw remaining range.",
                        "subset",
                        ("ndat-raw-ssl-static", "ndat-raw-ssl-native-differential"),
                        (
                            SemanticUnknown(
                                "runtime_consumer",
                                "Complete regex acceptance, native exceptions/resources, upstream metadata, runtime RecID/SigSeq and ProcessMatchedSignature remain outside the local predicate; no certificate trust or final verdict.",
                            ),
                        ),
                    ),
                )
                if has_raw_ssl_consumer
                else ()
            ),
            *(
                (
                    SemanticClaim(
                        "ndat-ssl-cert-pattern-contract",
                        "runtime_consumer",
                        "Callback18 (0x12) stores first-NUL Boost w32 byte patterns with flags0x500000. "
                        "The consumer searches formatted Subject/Issuer DN and validity strings, not raw certificate bytes. "
                        "278 frozen corpus patterns compiled and 1652 backend queries completed; arbitrary compile validity is not projected.",
                        "subset",
                        ("ndat-ssl-cert-static", "ndat-ssl-cert-backend-native-host"),
                        (
                            SemanticUnknown(
                                "runtime_consumer",
                                "Complete certificate parsing, default-LCID traits, runtime RecID/SigSeq/NRI and ProcessMatchedSignature policy remain outside the data projector.",
                            ),
                        ),
                    ),
                    SemanticClaim(
                        "ndat-ssl-cert-subject-recipes",
                        "runtime_consumer",
                        "Parsed runtime DN rows use fixed type order and first matching row, preserving NULL masking/empty values/CString boundaries; the narrow success projection is ASCII. "
                        "Validity formats raw SYSTEMTIME words and four unsigned DWORDs with minimum decimal widths and a zero-year local gate, without current-time logic.",
                        "subset",
                        (
                            "ndat-ssl-cert-static",
                            "ndat-ssl-cert-formatter-native-host",
                            "ndat-ssl-cert-builders-native-host",
                        ),
                        (
                            SemanticUnknown(
                                "runtime_consumer",
                                "Subject availability is recipe-local: global pattern presence, CRT/resource failure, ASN.1/OID mapping, field NRI checks and regex/post-match policy are not modeled; non-ASCII selected values are typed unsupported, not false.",
                            ),
                        ),
                    ),
                )
                if has_ssl_cert_consumer
                else ()
            ),
            *(
                (
                    SemanticClaim(
                        "ndat-generic-regex-pattern-contract",
                        "runtime_consumer",
                        "Callback decimal13 (0x0D) forwards raw counted bytes to a first-NUL "
                        "Boost w32 narrow-char pattern with flags0x400000, preserving leading04. "
                        "The Lua arg2 CString consumer searches rows in runtime order; its first "
                        "match resolves RecID/name and returns Lua values, not a scan verdict. "
                        "Pinned-host evidence compiled 82 frozen corpus patterns and completed "
                        "410 queries; the data projector does not validate arbitrary regexes.",
                        "subset",
                        ("ndat-generic-regex-static", "ndat-generic-regex-native-host"),
                        (
                            SemanticUnknown(
                                "runtime_consumer",
                                "Default-LCID traits, upstream Lua subject encoding/coercion, runtime "
                                "row order and namespace/name resolution remain dependencies. Lua errors, "
                                "allocation/compiler failure and full Lua/outer policy execution are "
                                "not projected; no portable regex evaluator or business-domain label.",
                            ),
                        ),
                    ),
                )
                if has_generic_regex_consumer
                else ()
            ),
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
                    else "The generic Boost pattern and Lua byte-subject contract is "
                    "exported separately; complete compiler and first-match namespace "
                    "behavior are not projected."
                    if has_generic_regex_consumer
                    else "The formatted-certificate pattern/subject contract is exported separately; complete parser, NRI and query policy are not projected."
                    if has_ssl_cert_consumer
                    else "The raw binary pattern/explicit remaining-span contract and strict byte predicate are exported separately; compiler and post-match policy remain external."
                    if has_raw_ssl_consumer
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
                            else "Lua subject generation, actual vector/namespace state "
                            "and complete compiler/query errors remain external."
                            if has_generic_regex_consumer
                            else "Full certificate parser, non-ASCII CRT conversion and regex/NRI/post-match state are external."
                            if has_ssl_cert_consumer
                            else "Whole Boost grammar, upstream metadata and native exception/resource/namespace/post-match state remain external."
                            if has_raw_ssl_consumer
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
                        "ndat-raw-ssl-static",
                        "consumer",
                        "engine_static",
                        "mpengine 1.443.903.0",
                        ("ndat-raw-ssl-byte-predicate",),
                        "RawSSLCertNdatCallback1804B4DA0/C8 -> append1804B4F30/5A or reallocate1804B4F8C/18F -> ctor1801FBFE4 syntax400000; row32 regex16/RecID+16/SigSeq+24. NetworkHipsMatch18008EB33 reads metadata+40 view, NULL buffer gate8EB44, size+4; 8EC2F sends buffer+6,size-6 before ParsePkcs6Certificate; RegExBinaryMatch1801F10D0 -> Search1801F1170/1F -> unsigned iterator regex_search1801F1190/180, matchflags400/find_imp; docs/mpengine.dll/1.443.903.0/ndat_raw_ssl_cert_contract_private.md",
                    ),
                    SemanticEvidence(
                        "ndat-raw-ssl-native-differential",
                        "consumer",
                        "engine_runtime",
                        "Pinned original Windows DLL binary Search and YARA4.5.4 recorded-span differential",
                        ("ndat-raw-ssl-byte-predicate",),
                        "DLL SHA256 928e171c60a44bb326776d2a356412ae98d78469bdf8c94ebfbfa09f8ec4b4b3; tests/local_cb20_binary_search_native_v1.py SHA256 8fdb76348d8e63aa76ae158229cc7bcb6e1683bf6f4d1f24b0a7221680526191; manifest bc7a0635b2680ffc8249f4b2e08cd89a0fa96d73ca8a4f76bc5f24e37f3ed731; results 391e6529ddf531ce65b2693f310ea8b5e1b2cc6dfdc30eb233f83579b8d96732. 118 constructors (117 corpus),1320 Search calls; tests/local_cb20_yara_differential.py SHA256 c1a657eea4cf2da36bc9b41af90b93917676f834d1044ac9a46bcca8500deaf7; .tmp/local_cb20_yara_differential_final_v2.json SHA256 3981dceb6d0d799407851e8bdd2e7edd98a34105b08406d668d388a03823b135: 117 corpus+synthetic compiled,1320 same-span comparisons/0 mismatch. Host code pins/canaries/isolated children; no Unicorn trace, metadata caller/DER parser or full policy execution. "
                        "Current offline production bridge tests/local_ndat_raw_ssl_bridge.py SHA256 fe3b290bf6d64f250118f1b4c0ddef185d8ac3d5d44b4baad4ee4d673d081839.",
                    ),
                )
                if has_raw_ssl_consumer
                else ()
            ),
            *(
                (
                    SemanticEvidence(
                        "ndat-ssl-cert-static",
                        "consumer",
                        "engine_static",
                        "mpengine 1.443.903.0",
                        (
                            "ndat-ssl-cert-pattern-contract",
                            "ndat-ssl-cert-subject-recipes",
                        ),
                        "SSLCertNdatCallback18055D720/C5 -> construct180549304/reallocate1801FB41C flags500000 row32; "
                        "NetworkHipsMatch18008E460 metadata+40 blob -> ParsePkcs6Certificate1801B2788; "
                        "Matchx509Dn18044DCA4 uses cert+40 Subject/+30 Issuer -> GetString1802951C0/lambda18044DF4C -> TrNewSprintfA180668528 -> CRT localeNULL; "
                        "Matchx509Validity18002E344 reads+88/+104 words and+120/+124/+128/+132 DWORDs; RegExStringMatch18002E528; "
                        "docs/mpengine.dll/1.443.903.0/ndat_ssl_cert_contract_private.md",
                    ),
                    SemanticEvidence(
                        "ndat-ssl-cert-backend-native-host",
                        "consumer",
                        "engine_runtime",
                        "Pinned DLL original Boost in isolated Windows children",
                        ("ndat-ssl-cert-pattern-contract",),
                        "DLL SHA256 928e171c60a44bb326776d2a356412ae98d78469bdf8c94ebfbfa09f8ec4b4b3; "
                        "tests/local_boost_native_cb18_corpus_probe_v1.py SHA256 4f77de32acb5c15fc5842f72e837f04353f9a5d5792682765398deaa63ee272f; "
                        ".tmp/local_boost_native_cb18_corpus_probe_v1_manifest.json SHA256 b00adb75397b2d3bcd8ee363c069737424f8432c26ec38c5536eef108e485f23; "
                        "results SHA256 a4f4b07b01dd475124a58b9223e5c43b56205e340c8a626a17f760eb202f6a4e; summary SHA256 118851b2f7e9ec69539f8a985461ffe194f49a0f89e5f4b1da14145f08349c77; "
                        "278 constructors/1652 completed queries (1390 baseline false +262 selected literal-DN witnesses true); "
                        "no original DN/certificate pipeline in this batch, no portable regex or Unicorn PC/register-trace claim; "
                        "current offline source bridge tests/local_ndat_ssl_cert_bridge.py SHA256 3a7a357b50bd8a7d0adb048484f939fde592fbbb11b61d767feb4f84874b5e63",
                    ),
                    SemanticEvidence(
                        "ndat-ssl-cert-builders-native-host",
                        "consumer",
                        "engine_runtime",
                        "Original DN/validity builders and CRT with downstream hooks returning false",
                        ("ndat-ssl-cert-subject-recipes",),
                        "tests/.tmp/ssl_dn_native_hook_v2.py SHA256 499f5002d6b63a4e674e1729ba024805ff07be65ebcc61db49c758c456631a7f; "
                        "manifest fd67dbd580a96db3a78109ab8c7b6621c0092a852b4b6324b1d4b41c650d037e; results 462dc94e4cabbfcf21fa822685112e6485463710eaaca145775bbcb5d9bc2924; "
                        "tests/.tmp/ssl_validity_native_hook_v1.py SHA256 04806ad5d1c7633b4f838454d239e0f3d2b4c795b1ff8b4c598667b709403dbe; "
                        "manifest 555691ebaef86b56878547a9785c5fb14c6bc6f65146cca5e872a10b6f4e6aa1; results 663aeaad5929543d984a666cd7f95104b1d21a17d5a28a0c4c1ee6880a9794df; "
                        "8 DN cases/7 subjects and 7 validity cases/4 subjects; exact code/global restoration and input canaries; "
                        "RegExStringMatch and DN CheckWSTRWSTR controlled false, not real regex/NRI policy; "
                        "root DN subset d574ca189769c7f9ca01afc15e0b0c4ce69c718003dc8a3277e5c392141f9ba1; validity subset 01337cd69595393432d63548fd0cdc8d98ac72a0617108f35ea285e2d8ef35b3; "
                        "current offline source bridge tests/local_ndat_ssl_cert_bridge.py SHA256 3a7a357b50bd8a7d0adb048484f939fde592fbbb11b61d767feb4f84874b5e63",
                    ),
                    SemanticEvidence(
                        "ndat-ssl-cert-formatter-native-host",
                        "consumer",
                        "engine_runtime",
                        "Original narrow CRT formatter in isolated Windows children",
                        ("ndat-ssl-cert-subject-recipes",),
                        "tests/local_cb18_formatter_probe_v1.py SHA256 93597d6f42592da145ef44a43ccbf20b03ec8d3e03cbf71dc4a09a5c54bb71b3; "
                        ".tmp/local_cb18_formatter_probe_v1.manifest.json SHA256 53faab4e989aefb8481637121125dbd318eb6e7506b12705c0ff7094d533d737; "
                        "results SHA256 d552cdb609ae44fa9bbadc33109d4a530cba8083fb84a1c600f4cc7bd4e12a19; "
                        "7 isolated inputs: ASCII/WCHAR-NUL/label-NUL New success then Tr same bytes; concrete mixed-BMP/astral/unpaired-surrogate inputs New E_FAIL NULL, Tr skipped; "
                        "not all non-ASCII rejection or measured CRT locale, and not original full DN/policy execution",
                    ),
                )
                if has_ssl_cert_consumer
                else ()
            ),
            *(
                (
                    SemanticEvidence(
                        "ndat-generic-regex-static",
                        "consumer",
                        "engine_static",
                        "mpengine 1.443.903.0",
                        ("ndat-generic-regex-pattern-contract",),
                        "cksig NDAT descriptor180E4DFB0:1000/100F/1002/1017 -> "
                        "ReceiveNewTemplate@1803224D0 kstore flags0 -> NdatPostCallback@180464800; "
                        "GenericRegExpNdatCallback@1804B3FA0 -> emplace@1804B402C/reallocate@1804B4108 "
                        "ctor1801FBFE4 flags400000; LsaMpCommonLib::NdatRegExpMatch@180C8FA50 "
                        "luaL_checklstring -> Match@1800B6D64 -> first RecID/name; "
                        "docs/mpengine.dll/1.443.903.0/ndat_generic_regex_contract_private.md",
                    ),
                    SemanticEvidence(
                        "ndat-generic-regex-native-host",
                        "consumer",
                        "engine_runtime",
                        "Pinned mpengine 1.443.903.0 native_host isolated children",
                        ("ndat-generic-regex-pattern-contract",),
                        "DLL SHA256 928e171c60a44bb326776d2a356412ae98d78469bdf8c94ebfbfa09f8ec4b4b3; "
                        "tests/local_boost_native_cb13_corpus_probe_v3.py SHA256 "
                        "7a7f5ed8368222eedaf95f509d1832e1511b108c42eae39a140ac10aaa9f9721; "
                        ".tmp/local_boost_native_cb13_corpus_probe_v3_manifest.json SHA256 "
                        "4993310661a2be659ca515f31f9eac634e2901bec7e622506fe125badc4f8325; "
                        ".tmp/local_boost_native_cb13_corpus_probe_v3_results.jsonl SHA256 "
                        "8610c56229debbc26efaa7dc0ebb72d1b104dd332bc8d85177048e704e7e85fd; "
                        ".tmp/local_boost_native_cb13_corpus_probe_v3_summary.json SHA256 "
                        "92f22205397b35adf70845eeb4c5756bddf895931cb85dcc3f8407de9a1a5479; "
                        "current offline bridge tests/local_ndat_generic_regex_manifest_bridge.py SHA256 "
                        "0cb2a30896c8afd7fd138df1912cbf9d8e691af34aa032f559471332458e3bee; "
                        "82 constructors/410 completed queries/102 true; v2 NUL-fixture failure is historical; "
                        "loaded-code pins/canaries/timeout/child exits, no Unicorn PC/GPR/XMM trace; "
                        "host LCID1033 ACP1252 environment, not direct traits-internal locale reading; "
                        "no original Lua binding/name resolution or final scan-policy execution",
                    ),
                )
                if has_generic_regex_consumer
                else ()
            ),
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
