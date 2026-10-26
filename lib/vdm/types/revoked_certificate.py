"""Lossless parser and concise renderer for REVOKED_CERTIFICATE (0x6C)."""

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from types import MappingProxyType
from typing import Final, Literal

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
from ._certificate_key import parse_certificate_key

REVOKED_CERTIFICATE_TYPE: Final = 0x6C
POLICY_TRAILER_SIZE: Final = 12
FILETIME_EPOCH: Final = datetime(1601, 1, 1, tzinfo=UTC)
SKIP_SIGNED_FILE_GATE_FLAG: Final = 0x00000001

_KEY_TYPES = MappingProxyType({1: "HASH", 2: "BY", 3: "TO", 4: "BADHASH", 5: "TEAMID"})


@dataclass(frozen=True, slots=True)
class RevokedCertificate:
    raw: bytes
    key_len: int
    key_data: bytes
    mode: Literal["binary", "string"]
    key_type: int
    prefix: str | None
    prefix_raw: bytes
    key_material_raw: bytes
    key_text: str | None
    text_raw: bytes
    terminator_raw: bytes
    string_trailing_raw: bytes
    decode_error: str | None
    filetime_raw: bytes
    filetime: int
    timestamp_utc: datetime | None
    timestamp_error: str | None
    revoke_flags_raw: bytes
    revoke_flags: int
    recid_tail_raw: bytes
    recid_tail: RecIdTail | None

    @property
    def skips_signed_file_gate(self) -> bool:
        return bool(self.revoke_flags & SKIP_SIGNED_FILE_GATE_FLAG)

    @property
    def unknown_flag_bits(self) -> int:
        return self.revoke_flags & ~SKIP_SIGNED_FILE_GATE_FLAG


def _filetime_to_utc(value: int) -> tuple[datetime | None, str | None]:
    if value == 0:
        return None, None
    try:
        # datetime stops at microseconds; the exact 100 ns value remains in
        # filetime/filetime_raw even when this presentation value truncates.
        microseconds = value // 10
        timestamp = FILETIME_EPOCH + timedelta(microseconds=microseconds)
    except (OverflowError, ValueError) as exc:
        return None, str(exc)
    return timestamp, None


def parse_revoked_certificate(payload: bytes) -> RevokedCertificate:
    if len(payload) < 2:
        raise ValueError(
            f"truncated REVOKED_CERTIFICATE key_len: need 2 bytes, have {len(payload)}"
        )

    key_len = int.from_bytes(payload[:2], "little")
    if key_len < 2:
        raise ValueError(
            f"invalid REVOKED_CERTIFICATE key_len: need at least 2, have {key_len}"
        )
    key_end = 2 + key_len
    if key_end > len(payload):
        raise ValueError(
            "truncated REVOKED_CERTIFICATE key_data: "
            f"need {key_len} bytes, have {len(payload) - 2}"
        )

    trailer_end = key_end + POLICY_TRAILER_SIZE
    if trailer_end > len(payload):
        raise ValueError(
            "truncated REVOKED_CERTIFICATE policy trailer: "
            f"need {POLICY_TRAILER_SIZE} bytes, have {len(payload) - key_end}"
        )

    key_data = payload[2:key_end]
    key = parse_certificate_key(key_data)
    filetime_raw = payload[key_end : key_end + 8]
    filetime = int.from_bytes(filetime_raw, "little")
    timestamp_utc, timestamp_error = _filetime_to_utc(filetime)
    revoke_flags_raw = payload[key_end + 8 : trailer_end]
    recid_tail_raw = payload[trailer_end:]

    return RevokedCertificate(
        raw=payload,
        key_len=key_len,
        key_data=key_data,
        mode=key.mode,
        key_type=key.key_type,
        prefix=key.prefix,
        prefix_raw=key.prefix_raw,
        key_material_raw=key.material_raw,
        key_text=key.text,
        text_raw=key.text_raw,
        terminator_raw=key.terminator_raw,
        string_trailing_raw=key.trailing_raw,
        decode_error=key.decode_error,
        filetime_raw=filetime_raw,
        filetime=filetime,
        timestamp_utc=timestamp_utc,
        timestamp_error=timestamp_error,
        revoke_flags_raw=revoke_flags_raw,
        revoke_flags=int.from_bytes(revoke_flags_raw, "little"),
        recid_tail_raw=recid_tail_raw,
        recid_tail=parse_recid_tail(recid_tail_raw),
    )


def _certificate_key_rows(parsed: RevokedCertificate) -> tuple[tuple[str, str], ...]:
    label = _KEY_TYPES.get(parsed.key_type)
    key_type = f"0x{parsed.key_type:02x}"
    if label is not None:
        key_type += f" ({label})"
    rows = [
        ("key_len", f"{parsed.key_len} B"),
        ("mode", parsed.mode),
        ("key_type", key_type),
    ]
    if parsed.mode == "binary":
        rows.append(("key_material_raw", parsed.key_material_raw.hex(" ") or "(empty)"))
    else:
        rows.append(("prefix", parsed.prefix or "(none; defaults to TO)"))
        if parsed.key_text is not None:
            rows.append(("key_text", json.dumps(parsed.key_text, ensure_ascii=False)))
        else:
            rows.extend(
                (
                    ("decode_error", f"invalid UTF-16LE: {parsed.decode_error}"),
                    ("text_raw", parsed.text_raw.hex(" ") or "(empty)"),
                )
            )
        rows.append(("terminator", "NUL" if parsed.terminator_raw else "not present"))
        if parsed.string_trailing_raw:
            rows.append(("string_trailing_len", f"{len(parsed.string_trailing_raw)} B"))
    return tuple(rows)


def _record_identity_rows(tail: RecIdTail) -> tuple[tuple[str, str], ...]:
    rows = [
        ("recid_tail_len", f"{len(tail.raw)} B"),
        ("object_length_limit", f"{tail.length_limit} B"),
        ("effective_object_len", f"{len(tail.object_raw)} B"),
        ("object", "present" if tail.has_object else "absent"),
    ]
    if tail.trailing_raw:
        rows.append(("trailing_len", f"{len(tail.trailing_raw)} B"))
    return tuple(rows)


def render_revoked_certificate(parsed: RevokedCertificate) -> FormatResult:
    if parsed.filetime == 0:
        timestamp_rows = [("timestamp_filetime", "0 (no lower-bound effect)")]
    else:
        timestamp_rows = [("timestamp_filetime", f"0x{parsed.filetime:016x}")]
        if parsed.timestamp_utc is not None:
            timestamp_rows.append(
                (
                    "timestamp_utc",
                    parsed.timestamp_utc.isoformat().replace("+00:00", "Z"),
                )
            )
        else:
            timestamp_rows.append(("timestamp_utc", "out of range"))
        if parsed.timestamp_error is not None:
            timestamp_rows.append(("timestamp_note", parsed.timestamp_error))

    policy_rows = [
        *timestamp_rows,
        ("revoke_flags", f"0x{parsed.revoke_flags:08x}"),
        (
            "signed_file_gate",
            "skipped (bit 0 set)"
            if parsed.skips_signed_file_gate
            else "not skipped when report policy is enforced (bit 0 clear)",
        ),
    ]
    if parsed.unknown_flag_bits:
        policy_rows.append(("unknown_flag_bits", f"0x{parsed.unknown_flag_bits:08x}"))

    sections = [
        DisplaySection("Certificate Key", rows=_certificate_key_rows(parsed)),
        DisplaySection("Revocation Policy", rows=tuple(policy_rows)),
    ]
    if parsed.recid_tail is not None:
        sections.append(
            DisplaySection(
                "Record Identity", rows=_record_identity_rows(parsed.recid_tail)
            )
        )
    return FormatResult(sections=tuple(sections))


def export_revoked_certificate_semantics(
    parsed: RevokedCertificate,
) -> RuleSemantics:
    """Export only byte spans whose boundaries are established by this parser.

    The receiver, certificate lookup, and time/flag gate are confirmed for this
    engine profile. Portable data contains raw framing; behavior is separate.
    """
    key_start = 2
    key_end = key_start + parsed.key_len
    trailer_end = key_end + POLICY_TRAILER_SIZE
    spans = (
        ("key_len", 0, 2),
        ("key_data", key_start, parsed.key_len),
        ("policy_trailer", key_end, POLICY_TRAILER_SIZE),
        ("recid_tail", trailer_end, len(parsed.recid_tail_raw)),
    )

    unsupported_reasons: list[SemanticIssue] = []
    if parsed.recid_tail_raw:
        unsupported_reasons.append(
            SemanticIssue(
                "recid_metadata_meaning_unknown",
                "The receiver uses the tail to derive the stored threat/RecID "
                "association, but its producer-side object meaning is unknown.",
                (("length", len(parsed.recid_tail_raw)),),
            )
        )
    if parsed.unknown_flag_bits:
        unsupported_reasons.append(
            SemanticIssue(
                "unknown_revoke_flags",
                "At least one policy trailer flag has no confirmed meaning.",
                (("unknown_bits", parsed.unknown_flag_bits),),
            )
        )
    if parsed.key_type not in _KEY_TYPES:
        unsupported_reasons.append(
            SemanticIssue(
                "unknown_key_type",
                "The key type byte is preserved, but its lookup meaning is unknown.",
                (("key_type", parsed.key_type),),
            )
        )
    elif parsed.key_type == 4:
        unsupported_reasons.append(
            SemanticIssue(
                "key_type_not_used_by_confirmed_consumer",
                "The loader recognizes BADHASH, but IsRevokedCert does not query "
                "key type 4 and no type-4 consumer is confirmed in the analyzed paths.",
                (("key_type", parsed.key_type),),
            )
        )
    if parsed.mode == "string" and not parsed.terminator_raw:
        unsupported_reasons.append(
            SemanticIssue(
                "unterminated_engine_string",
                "The engine receiver reads wide key strings without a key_len "
                "bound; this record has no NUL terminator inside key_data.",
            )
        )
    if parsed.decode_error is not None:
        unsupported_reasons.append(
            SemanticIssue(
                "invalid_utf16le_key",
                "The string-like key bytes cannot be decoded as UTF-16LE; "
                "the raw key remains available.",
            )
        )

    issues = list(unsupported_reasons)
    if parsed.key_type in {1, 2, 3, 5}:
        consumer_claim = SemanticClaim(
            id="revoked_certificate_consumers",
            scope="runtime_consumer",
            statement=(
                "IsRevokedCert queries key types 3, 2, 1, and 5 with policy 0; "
                "ScanCertificate queries types 1, 2, and 3 with policy 1."
            ),
            coverage="subset",
            evidence_refs=("revoked_certificate_consumers_evidence",),
            unknowns=(
                SemanticUnknown(
                    "runtime_consumer",
                    "The analyzed paths do not cover every possible caller or key source.",
                ),
            ),
        )
        predicate_claim = SemanticClaim(
            id="revoked_certificate_policy_predicate",
            scope="detection_predicate",
            statement=(
                "Both analyzed paths require exact normalized-key equality and "
                "query FILETIME at least the record FILETIME; policy 1 additionally "
                "uses flag bit 0 to decide whether to skip the IsSignedFile gate."
            ),
            coverage="subset",
            evidence_refs=("revoked_certificate_policy",),
            unknowns=(
                SemanticUnknown(
                    "detection_predicate",
                    "Unknown flag bits and outer caller arbitration remain unresolved.",
                ),
            ),
        )
    else:
        consumer_claim = SemanticClaim(
            id="revoked_certificate_consumers",
            scope="runtime_consumer",
            statement=(
                "No runtime consumer is confirmed for this loader-recognized "
                f"certificate key type ({parsed.key_type})."
            ),
            coverage="unknown",
            unknowns=(
                SemanticUnknown(
                    "runtime_consumer",
                    "The analyzed IsRevokedCert and ScanCertificate paths do not query this key type.",
                ),
            ),
        )
        predicate_claim = SemanticClaim(
            id="revoked_certificate_policy_predicate",
            scope="detection_predicate",
            statement="No detection predicate is established for this key type.",
            coverage="unknown",
            unknowns=(
                SemanticUnknown(
                    "detection_predicate",
                    "Without a confirmed runtime consumer, the record policy cannot be applied to a query.",
                ),
            ),
        )
    if parsed.key_type in {1, 2, 3, 5}:
        report_claim = SemanticClaim(
            id="revoked_certificate_report_mapping",
            scope="report_mapping",
            statement=(
                "The analyzed trust path can map an accepted revoked-certificate "
                "result to the MpTrustCheck_RevokedCert attribute."
            ),
            coverage="subset",
            evidence_refs=("revoked_certificate_report",),
            unknowns=(
                SemanticUnknown(
                    "report_mapping",
                    "The complete trust-result and scan-report arbitration is unresolved.",
                ),
            ),
        )
    else:
        report_claim = SemanticClaim(
            id="revoked_certificate_report_mapping",
            scope="report_mapping",
            statement="No report mapping is established for an unconsumed key type.",
            coverage="unknown",
            unknowns=(
                SemanticUnknown(
                    "report_mapping",
                    "No confirmed runtime match exists to enter the analyzed report branch.",
                ),
            ),
        )
    return RuleSemantics(
        status="unsupported" if unsupported_reasons else "confirmed_subset",
        representation="revoked_certificate.raw_spans.ir.v1",
        data=JSONObject(
            (
                ("raw_hex", parsed.raw.hex()),
                (
                    "framing",
                    JSONArray(
                        tuple(
                            JSONObject(
                                (
                                    ("kind", name),
                                    ("offset", offset),
                                    ("length", length),
                                    (
                                        "raw_hex",
                                        parsed.raw[offset : offset + length].hex(),
                                    ),
                                )
                            )
                            for name, offset, length in spans
                        )
                    ),
                ),
                (
                    "engine_profile_semantics",
                    JSONObject(
                        (
                            ("profile", "mpengine-1.443.903.0"),
                            ("signature_type", REVOKED_CERTIFICATE_TYPE),
                            ("lookup_key_type", parsed.key_type),
                            (
                                "confirmed_consumers",
                                JSONArray(
                                    tuple(
                                        path
                                        for path in (
                                            JSONObject(
                                                (
                                                    ("name", "IsRevokedCert"),
                                                    ("policy", 0),
                                                    (
                                                        "queried_key_types",
                                                        JSONArray((3, 2, 1, 5)),
                                                    ),
                                                    (
                                                        "predicate",
                                                        "exact_normalized_key_and_query_time_at_least_record_filetime",
                                                    ),
                                                    ("signed_file_gate", "not_called"),
                                                )
                                            )
                                            if parsed.key_type in {1, 2, 3, 5}
                                            else None,
                                            JSONObject(
                                                (
                                                    ("name", "ScanCertificate"),
                                                    ("policy", 1),
                                                    (
                                                        "queried_key_types",
                                                        JSONArray((1, 2, 3)),
                                                    ),
                                                    (
                                                        "predicate",
                                                        "exact_normalized_key_and_query_time_at_least_record_filetime",
                                                    ),
                                                    (
                                                        "signed_file_gate",
                                                        "skipped_when_flag_bit0_set; otherwise_IsSignedFile",
                                                    ),
                                                )
                                            )
                                            if parsed.key_type in {1, 2, 3}
                                            else None,
                                        )
                                        if path is not None
                                    )
                                ),
                            ),
                            (
                                "type4_consumer",
                                "unknown" if parsed.key_type == 4 else "not_applicable",
                            ),
                            ("record_filetime", parsed.filetime),
                            (
                                "policy1_skips_signed_file_gate",
                                parsed.skips_signed_file_gate,
                            ),
                            (
                                "recid_tail_role",
                                "receiver_threat_association_metadata; not_a_policy_gate",
                            ),
                        )
                    ),
                ),
            )
        ),
        evidence=(
            "local REVOKED_CERTIFICATE parser bounds key_len and the 12-byte trailer",
            (
                "mpengine 1.443.903.0 getsigtype at 0x180468C40 maps 0x6C to "
                "SIGNATURE_TYPE_REVOKED_CERTIFICATE"
            ),
            ("mpengine 1.443.903.0 revokedcert_t subtype Register is at 0x1805DF5F0"),
            (
                "mpengine 1.443.903.0 revokedcert_t::Load at 0x180320808 reads "
                "key_data, FILETIME, flags, and optional RecID"
            ),
            (
                "mpengine 1.443.903.0 IsRevokedCert at 0x1802D816C queries "
                "certificate keys 3, 2, 1, and 5 against the revoked store"
            ),
            (
                "mpengine 1.443.903.0 ShouldReport at 0x18057971C enforces "
                "the FILETIME lower bound and signed-file flag-bit-0 gate"
            ),
            (
                "mpengine 1.443.903.0 ScanCertificate at 0x1802952B0 supplies "
                "certificate identity and signing FILETIME to the store lookup"
            ),
            (
                "mpengine 1.443.903.0 IsTrustedFile at 0x1802D8950 references "
                "IsRevokedCert and AddMpAttributes; AddMpAttributes maps its revoked "
                "result input to MpTrustCheck_RevokedCert"
            ),
            (
                "mpas.sig corpus has 52,815 records with type 0x6C; key types "
                "1, 2, 3, and 5 are observed"
            ),
        ),
        profile="mpengine-1.443.903.0",
        issues=tuple(issues),
        claims=(
            SemanticClaim(
                id="revoked_certificate_wire_layout",
                scope="wire_layout",
                statement=(
                    "REVOKED_CERTIFICATE contains a u16-bounded key, an 8-byte "
                    "FILETIME, a 4-byte flags word, and an optional RecID tail."
                ),
                coverage="complete",
                evidence_refs=("revoked_certificate_receiver",),
            ),
            SemanticClaim(
                id="revoked_certificate_loader_dispatch",
                scope="loader_dispatch",
                statement="The analyzed registration path binds type 0x6C to REVOKED_CERTIFICATE.",
                coverage="subset",
                evidence_refs=("revoked_certificate_dispatch",),
                unknowns=(
                    SemanticUnknown(
                        "loader_dispatch",
                        "Other database profiles and engine versions are not covered.",
                    ),
                ),
            ),
            SemanticClaim(
                id="revoked_certificate_receiver_projection",
                scope="receiver_transform",
                statement=(
                    "Load normalizes the certificate key, stores FILETIME and flags, "
                    "and uses a present tail to derive the stored threat association."
                ),
                coverage="subset",
                evidence_refs=("revoked_certificate_receiver",),
                unknowns=(
                    SemanticUnknown(
                        "receiver_transform",
                        "The producer meaning of the optional RecID metadata object is unknown.",
                    ),
                ),
            ),
            consumer_claim,
            predicate_claim,
            report_claim,
            SemanticClaim(
                id="revoked_certificate_final_verdict",
                scope="final_verdict",
                statement="A local revoked-certificate match does not establish the final product verdict.",
                coverage="unknown",
                unknowns=(
                    SemanticUnknown(
                        "final_verdict",
                        "Final scan, UI, and remediation arbitration has not been followed to completion.",
                    ),
                ),
            ),
        ),
        claim_evidence=(
            SemanticEvidence(
                id="revoked_certificate_dispatch",
                axis="dispatch",
                kind="engine_static",
                source_ref="mpengine 1.443.903.0",
                locator="REVOKED_CERTIFICATE Register @ 0x1805DF5F0",
                supports=("revoked_certificate_loader_dispatch",),
            ),
            SemanticEvidence(
                id="revoked_certificate_receiver",
                axis="receiver",
                kind="engine_static",
                source_ref="mpengine 1.443.903.0",
                locator=(
                    "REVOKED_CERTIFICATE RecordPush @ 0x180320624; "
                    "revokedcert_t::Load @ 0x180320808"
                ),
                supports=(
                    "revoked_certificate_wire_layout",
                    "revoked_certificate_receiver_projection",
                ),
            ),
            SemanticEvidence(
                id="revoked_certificate_consumers_evidence",
                axis="consumer",
                kind="engine_static",
                source_ref="mpengine 1.443.903.0",
                locator=("IsRevokedCert @ 0x1802D816C; ScanCertificate @ 0x1802952B0"),
                supports=("revoked_certificate_consumers",),
            ),
            SemanticEvidence(
                id="revoked_certificate_policy",
                axis="consumer",
                kind="engine_static",
                source_ref="mpengine 1.443.903.0",
                locator=(
                    "RevokedCertProvider::CompareValues; ShouldReport @ 0x18057971C"
                ),
                supports=("revoked_certificate_policy_predicate",),
            ),
            SemanticEvidence(
                id="revoked_certificate_report",
                axis="report",
                kind="engine_static",
                source_ref="mpengine 1.443.903.0",
                locator="IsTrustedFile @ 0x1802D8950; AddMpAttributes",
                supports=("revoked_certificate_report_mapping",),
            ),
        ),
    )


def export_revoked_certificate(parsed: RevokedCertificate) -> ArtifactExport:
    """Export a lossless policy observation without X.509 field guesses."""
    key_end = 2 + parsed.key_len
    trailer_end = key_end + POLICY_TRAILER_SIZE
    binary_getkey_profile = _binary_getkey_profile(parsed)
    manifest = {
        "schema": "vdm.revoked_certificate.artifact.v1",
        "record_type": {
            "byte": REVOKED_CERTIFICATE_TYPE,
            "name": "REVOKED_CERTIFICATE",
        },
        "raw_hex": parsed.raw.hex(),
        "key": {
            "length": parsed.key_len,
            "length_raw_hex": parsed.raw[:2].hex(),
            "raw_hex": parsed.key_data.hex(),
            "offset": 2,
            "mode": parsed.mode,
            "key_type": parsed.key_type,
            "prefix_raw_hex": parsed.prefix_raw.hex(),
            "key_material_raw_hex": parsed.key_material_raw.hex(),
            "text_raw_hex": parsed.text_raw.hex(),
            "terminator_raw_hex": parsed.terminator_raw.hex(),
            "trailing_raw_hex": parsed.string_trailing_raw.hex(),
            "normalization_profile": binary_getkey_profile,
        },
        "policy": {
            "filetime": parsed.filetime,
            "filetime_raw_hex": parsed.filetime_raw.hex(),
            "timestamp_utc": (
                None
                if parsed.timestamp_utc is None
                else parsed.timestamp_utc.isoformat().replace("+00:00", "Z")
            ),
            "timestamp_error": parsed.timestamp_error,
            "flags": parsed.revoke_flags,
            "flags_raw_hex": parsed.revoke_flags_raw.hex(),
            "skip_signed_file_gate": parsed.skips_signed_file_gate,
            "unknown_flag_bits": parsed.unknown_flag_bits,
        },
        "recid_tail": {"raw_hex": parsed.recid_tail_raw.hex(), "offset": trailer_end},
        "matcher_boundary": {
            "confirmed_key_types_queried": [1, 2, 3, 5],
            "match": "certificate_key_lookup_subject_to_filetime_and_signed_file_gates",
            "x509_field_mapping": "unknown",
            "final_trust_or_scan_verdict": "unknown",
            "recid_tail_effect": (
                "loader_validates_tail_and_may_replace_stored_threat_id; "
                "portable_attribution_and_other_consumers_unknown"
            ),
            "reuse_profile": {
                "profile": "mpengine-1.443.903.0",
                "status": "bounded_engine_behavior_profile",
                "query_key_inputs": [
                    {
                        "consumer": "IsRevokedCert",
                        "key_types": [3, 2, 1, 5],
                        "input_shapes": {
                            "3": "optional wchar_t* to_name passed to wide GetKey",
                            "2": "optional wchar_t* by_name passed to wide GetKey",
                            "1": "optional wchar_t* hash passed to wide GetKey",
                            "5": "optional wchar_t* team_id passed to wide GetKey",
                        },
                    },
                    {
                        "consumer": "ScanCertificate",
                        "key_types": [1, 2, 3],
                        "input_shapes": {
                            "1": "binary identity/hash byte span",
                            "2": "wide string from certificate DN GetString(type=5)",
                            "3": "wide string from certificate DN GetString(type=5)",
                        },
                    },
                ],
                "binary_getkey": {
                    "fast_path_types": [1, 4],
                    "applies_to_query_path": "ScanCertificate type 1 binary identity/hash span only",
                    "fast_path_input_shape": "exactly 20 binary bytes",
                    "fast_path": "copy 20 bytes; add type modulo 256 to byte 0",
                    "other_input_shape": "type_byte concatenated with binary bytes",
                    "other_normalization": "SHA1(type_byte || data)",
                    "normalized_key_hex": _binary_getkey_normalize(
                        parsed.key_type, parsed.key_material_raw
                    ).hex()
                    if parsed.mode == "binary"
                    else None,
                    "query_identity_mapping": "not_fully_established",
                },
                "wide_getkey": {
                    "algorithm_known": True,
                    "summary": (
                        "types 1/4 hex-decode, with the 20-byte fast path; "
                        "other types hash type plus UTF-8, falling back to "
                        "UTF-16 raw bytes on conversion failure"
                    ),
                    "implementation": "not_implemented",
                    "identity_mapping": "unknown",
                },
                "policy_paths": [
                    {
                        "consumer": "IsRevokedCert",
                        "policy": 0,
                        "query_time_source": "IsRevokedCert caller argument",
                        "record_filetime_lower_bound": parsed.filetime,
                        "time_gate": "query_filetime >= record_filetime",
                        "signed_file_gate": "not_called",
                    },
                    {
                        "consumer": "ScanCertificate",
                        "policy": 1,
                        "query_time_source": "signer-info +0x80 SYSTEMTIME converted to FILETIME; missing/failed conversion leaves zero",
                        "record_filetime_lower_bound": parsed.filetime,
                        "time_gate": "query_filetime >= record_filetime",
                        "signed_file_gate": (
                            "skipped_when_flag_bit0_set; otherwise_IsSignedFile"
                        ),
                        "skip_signed_file_gate_flag_bit0": parsed.skips_signed_file_gate,
                    },
                ],
                "unknowns": [
                    "wide_key_identity_mapping",
                    "portable_RecID_attribution_and_other_consumers",
                    "unknown_revoke_flag_bits",
                    "final_trust_or_scan_verdict",
                ],
                "portable_revocation_rule": "not_established",
            },
        },
    }
    data = (
        json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")
    digest = hashlib.sha256(parsed.raw).hexdigest()[:16]
    return ArtifactExport(
        "ready",
        artifacts=(
            Artifact(f"6c-{digest}.json", "revoked_certificate_json_manifest", data),
        ),
    )


def _binary_getkey_profile(parsed: RevokedCertificate) -> dict[str, object]:
    is_binary = parsed.mode == "binary"
    fast_path_eligible = (
        is_binary and parsed.key_type in {1, 4} and len(parsed.key_material_raw) == 20
    )
    return {
        "status": "normalized" if is_binary else "not_modeled",
        "input_shape": "binary" if is_binary else "wide UTF-16LE string",
        "key_type": parsed.key_type,
        "fast_path_eligible": fast_path_eligible,
        "fast_path": (
            "copy 20 bytes; add type modulo 256 to byte 0" if is_binary else None
        ),
        "fallback": "SHA1(type_byte || data)" if is_binary else None,
        "normalization": "not_modeled" if not is_binary else "GetKey_binary",
        "applicable_to_confirmed_query_path": (
            "ScanCertificate.type1" if is_binary and parsed.key_type == 1 else None
        ),
        "normalized_key_hex": (
            _binary_getkey_normalize(parsed.key_type, parsed.key_material_raw).hex()
            if is_binary
            else None
        ),
    }


def _binary_getkey_normalize(key_type: int, data: bytes) -> bytes:
    """Apply the confirmed binary GetKey transform without matching records."""
    if not 0 <= key_type <= 0xFF:
        raise ValueError(f"binary GetKey type must fit in one byte: {key_type}")
    if key_type in {1, 4} and len(data) == 20:
        return bytes(((data[0] + key_type) & 0xFF,)) + data[1:]
    return hashlib.sha1(bytes((key_type,)) + data).digest()


SPEC = FamilySpec(
    REVOKED_CERTIFICATE_TYPE,
    "REVOKED_CERTIFICATE",
    parse_revoked_certificate,
    render_revoked_certificate,
    exporter=export_revoked_certificate,
    semantic_exporter=export_revoked_certificate_semantics,
)
