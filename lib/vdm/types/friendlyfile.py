import json
from dataclasses import dataclass
from typing import Final

from ..core import (
    Artifact,
    ArtifactExport,
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

FRIENDLYFILE_SHA256_TYPE: Final = 0xA0
SHA256_SIZE: Final = 32


@dataclass(frozen=True, slots=True)
class FriendlyFileSha256:
    raw: bytes
    sha256: bytes
    recid_tail: RecIdTail | None


def parse_friendlyfile_sha256(payload: bytes) -> FriendlyFileSha256:
    if len(payload) < SHA256_SIZE:
        raise ValueError(
            "truncated FRIENDLYFILE_SHA256 digest: "
            f"need {SHA256_SIZE} bytes, have {len(payload)}"
        )
    return FriendlyFileSha256(
        raw=payload,
        sha256=payload[:SHA256_SIZE],
        recid_tail=parse_recid_tail(payload[SHA256_SIZE:]),
    )


def render_friendlyfile_sha256(parsed: FriendlyFileSha256) -> FormatResult:
    fields = [
        ("sha256", parsed.sha256.hex()),
        ("digest_match", "exact 32-byte comparison"),
    ]
    if parsed.recid_tail is not None:
        tail = parsed.recid_tail
        fields.extend(
            (
                ("recid_tail_len", f"{len(tail.raw)} B"),
                ("object_length_limit", f"{tail.length_limit} B"),
                ("effective_object_len", f"{len(tail.object_raw)} B"),
                (
                    "object_registration",
                    "created"
                    if tail.has_object
                    else "suppressed: empty or leading NUL",
                ),
                ("lookup_tail_usage", "not read by FRIENDLYFILE lookup"),
            )
        )
        if tail.trailing_raw:
            fields.append(("trailing_len", f"{len(tail.trailing_raw)} B"))
    return FormatResult(fields=tuple(fields))


def export_friendlyfile_sha256(parsed: FriendlyFileSha256) -> ArtifactExport:
    """Export one lossless, record-local JSON manifest; no verdict is implied."""
    tail = parsed.recid_tail
    tail_json: dict[str, object] | None = None
    if tail is not None:
        tail_json = {
            "raw_hex": tail.raw.hex(),
            "raw_offset": SHA256_SIZE,
            "declared_length": tail.length_limit,
            "object_raw_hex": tail.object_raw.hex(),
            "object_offset": SHA256_SIZE + 1,
            "object_registered": tail.has_object,
            "trailing_raw_hex": tail.trailing_raw.hex(),
            "trailing_offset": SHA256_SIZE + 1 + len(tail.object_raw),
        }
    manifest = {
        "format": "vdm.friendly_file_sha256.record.v3",
        "record": {
            "type": FRIENDLYFILE_SHA256_TYPE,
            "type_hex": f"0x{FRIENDLYFILE_SHA256_TYPE:02X}",
            "name": "FRIENDLYFILE_SHA256",
            "scope": "record_local",
            "threat_association": "not_included_in_record_local_artifact",
            "verdict_scope": "lookup_key_only; no final verdict asserted",
        },
        "payload_length": len(parsed.raw),
        "payload_raw_hex": parsed.raw.hex(),
        "sha256": {
            "algorithm": "SHA-256",
            "digest_hex": parsed.sha256.hex(),
            "raw_offset": 0,
            "raw_length": SHA256_SIZE,
            "comparison": "exact_32_bytes",
        },
        "reuse": {
            "role": "friendly_file_lookup_key",
            "comparison": "exact_32_bytes",
            "digest_subject": None,
            "observed_digest_profile": {
                "producer": "troj_scan @ 0x180B03685..0x180B036D6",
                "hash": "SHA-256",
                "input": "complete current UFS scan object bytes [0, SCAN_REPLY+0x50) when GetHashes succeeds",
                "normalization": "none_observed_in_analyzed_chain",
                "length_producer": "UfsFile::GetSize via UfsClientRequest::SyncScanReplyFileSize; writes reply+0x50",
                "disk_file_identity": None,
                "lookup_gate": {
                    "store_exists": True,
                    "pool_plus_0x90_nonzero": True,
                    "lookup_result": 1,
                    "nid64searchrecid_133_result": "not_1",
                    "reply_plus_0x2990_mask_0x4000000000000": 0,
                },
                "consumer_effect": "sets_friendly_attribute_and_optional_ttl",
                "final_allow_or_bypass": None,
            },
            "final_policy": None,
            "portable_allowlist": None,
            "standalone_detection": False,
            "limitations": [
                "Final scan verdict is not established by this lookup key.",
                "A universal file-hash scope is not established across all provider callers.",
                "Portable allowlist behavior is unknown.",
                "Standalone detection behavior is not established by this record.",
            ],
        },
        "recid_tail": tail_json,
    }
    encoded = json.dumps(manifest, ensure_ascii=True, separators=(",", ":"))
    data = (encoded + "\n").encode("utf-8")
    return ArtifactExport(
        "ready",
        artifacts=(
            Artifact("friendlyfile.json", "friendlyfile_sha256_manifest", data),
        ),
    )


def _raw_span(offset: int, length: int) -> JSONObject:
    return JSONObject((("offset", offset), ("length", length)))


def _recid_tail_semantics(tail: RecIdTail | None) -> JSONObject | None:
    if tail is None:
        return None

    object_offset = SHA256_SIZE + 1
    return JSONObject(
        (
            ("raw_span", _raw_span(SHA256_SIZE, len(tail.raw))),
            ("raw_hex", tail.raw.hex()),
            (
                "declared_length",
                JSONObject(
                    (
                        ("value", tail.length_limit),
                        ("raw_span", _raw_span(SHA256_SIZE, 1)),
                        ("raw_hex", tail.raw[:1].hex()),
                    )
                ),
            ),
            (
                "object",
                JSONObject(
                    (
                        ("raw_span", _raw_span(object_offset, len(tail.object_raw))),
                        ("raw_hex", tail.object_raw.hex()),
                        ("registered", tail.has_object),
                        ("producer_meaning", None),
                    )
                ),
            ),
            (
                "trailing",
                JSONObject(
                    (
                        (
                            "raw_span",
                            _raw_span(
                                object_offset + len(tail.object_raw),
                                len(tail.trailing_raw),
                            ),
                        ),
                        ("raw_hex", tail.trailing_raw.hex()),
                        ("meaning", None),
                    )
                ),
            ),
            ("lookup_usage", "not_read"),
        )
    )


def export_friendlyfile_sha256_semantics(
    parsed: FriendlyFileSha256,
) -> RuleSemantics:
    """Export the confirmed friendly-file lookup key without claiming a verdict."""
    tail = parsed.recid_tail
    issues: list[SemanticIssue] = []
    unsupported = False

    issues.append(
        SemanticIssue(
            "outer_verdict_not_modeled",
            "The exact digest lookup does not by itself define the final scan verdict.",
        )
    )
    if tail is not None and tail.length_limit > len(tail.raw) - 1:
        unsupported = True
        issues.append(
            SemanticIssue(
                "recid_object_truncated",
                "The RecID object is shorter than its declared length.",
                (
                    ("declared_length", tail.length_limit),
                    ("available_length", len(tail.raw) - 1),
                ),
            )
        )
    if tail is not None and tail.has_object:
        unsupported = True
        issues.append(
            SemanticIssue(
                "recid_object_meaning_unknown",
                "The optional RecID object bytes have no confirmed producer-side meaning.",
                (("length", len(tail.object_raw)),),
            )
        )
    if tail is not None and tail.trailing_raw:
        unsupported = True
        issues.append(
            SemanticIssue(
                "recid_trailing_bytes_uninterpreted",
                "Bytes after the bounded RecID object are retained without semantics.",
                (("length", len(tail.trailing_raw)),),
            )
        )

    tail_length = 0 if tail is None else len(tail.raw)
    data = JSONObject(
        (
            ("type", "friendly_file_sha256_lookup_entry"),
            ("raw_hex", parsed.raw.hex()),
            (
                "framing",
                JSONArray(
                    (
                        JSONObject(
                            (
                                ("kind", "sha256"),
                                ("raw_span", _raw_span(0, SHA256_SIZE)),
                                ("raw_hex", parsed.sha256.hex()),
                            )
                        ),
                        JSONObject(
                            (
                                ("kind", "recid_tail"),
                                ("raw_span", _raw_span(SHA256_SIZE, tail_length)),
                                (
                                    "raw_hex",
                                    "" if tail is None else tail.raw.hex(),
                                ),
                            )
                        ),
                    )
                ),
            ),
            (
                "lookup",
                JSONObject(
                    (
                        ("algorithm", "sha256"),
                        ("digest_hex", parsed.sha256.hex()),
                        ("comparison", "exact_32_bytes"),
                        ("role", "friendly_file_lookup_key"),
                    )
                ),
            ),
            (
                "runtime_identity",
                JSONObject(
                    (
                        ("kind", "index_based_synthetic_identity"),
                        ("threat_sentinel", 0x7FFFFFFF),
                        ("source", "matched_digest_and_lookup_index"),
                        ("recid_tail_effect", "none_on_loaded_entry_or_lookup"),
                    )
                ),
            ),
            ("recid_tail", _recid_tail_semantics(tail)),
            (
                "caller_digest_profile",
                JSONObject(
                    (
                        ("algorithm", "sha256"),
                        (
                            "input",
                            "complete_current_ufs_scan_object_when_GetHashes_succeeds",
                        ),
                        ("raw_span", "[0, SCAN_REPLY+0x50)"),
                        ("normalization", "none_observed_in_analyzed_chain"),
                        (
                            "length_producer",
                            "UfsFile::GetSize via UfsClientRequest::SyncScanReplyFileSize; writes reply+0x50",
                        ),
                        ("disk_file_identity", None),
                        (
                            "lookup_gate",
                            JSONArray(
                                (
                                    "friendly_store_exists",
                                    "pool+0x90 != 0",
                                    "friendly_lookup == 1",
                                    "nid64searchrecid(133, NULL, reply+0x90) != 1",
                                    "(reply+0x2990 & 0x4000000000000) == 0",
                                )
                            ),
                        ),
                        (
                            "matched_effect",
                            "sets MpMoacFriendlyAdd and optional MpMoacFriendlyAddTTL",
                        ),
                        ("final_allow_or_bypass", None),
                    )
                ),
            ),
        )
    )
    return RuleSemantics(
        status="unsupported" if unsupported else "confirmed_subset",
        representation="friendlyfile.sha256_lookup.ir.v2",
        data=data,
        evidence=(
            (
                "mpengine 1.443.903.0 FRIENDLYFILE_SHA256 RecordPush "
                "@ 0x18040A300 and Lookup @ 0x1802D6E60"
            ),
            (
                "mpengine 1.443.903.0 FRIENDLYFILE_SHA256 GetThreatDetails "
                "@ 0x180B01F30 returns an index-based synthetic identity"
            ),
        ),
        profile="mpengine-1.443.903.0",
        issues=tuple(issues),
        claims=(
            SemanticClaim(
                id="friendlyfile_sha256_wire_layout",
                scope="wire_layout",
                statement=(
                    "FRIENDLYFILE_SHA256 contains a 32-byte digest followed by an "
                    "optional bounded RecID-construction tail."
                ),
                coverage="complete",
                evidence_refs=("friendlyfile_sha256_receiver",),
            ),
            SemanticClaim(
                id="friendlyfile_sha256_loader_dispatch",
                scope="loader_dispatch",
                statement=(
                    "The analyzed registration path binds type 0xA0 to the "
                    "friendly-file SHA-256 store."
                ),
                coverage="subset",
                evidence_refs=("friendlyfile_sha256_dispatch",),
                unknowns=(
                    SemanticUnknown(
                        "loader_dispatch",
                        "Other database profiles and engine versions are not covered.",
                    ),
                ),
            ),
            SemanticClaim(
                id="friendlyfile_sha256_receiver_projection",
                scope="receiver_transform",
                statement=(
                    "RecordPush copies only the first 32 bytes into the digest table; "
                    "an optional tail must pass RecID construction, but its successful "
                    "return value is discarded and does not alter the stored entry."
                ),
                coverage="subset",
                evidence_refs=("friendlyfile_sha256_receiver",),
                unknowns=(
                    SemanticUnknown(
                        "receiver_transform",
                        "The producer meaning and any consumer outside this subtype for the tail object are unknown.",
                    ),
                ),
            ),
            SemanticClaim(
                id="friendlyfile_sha256_lookup_consumer",
                scope="runtime_consumer",
                statement=(
                    "The analyzed lookup compares the provider digest with a stored "
                    "32-byte entry using exact memcmp semantics; it does not read the tail."
                ),
                coverage="subset",
                evidence_refs=("friendlyfile_sha256_consumer",),
                unknowns=(
                    SemanticUnknown(
                        "runtime_consumer",
                        "Provider digest generation and all lookup callers are not closed.",
                    ),
                ),
            ),
            SemanticClaim(
                id="friendlyfile_sha256_local_predicate",
                scope="detection_predicate",
                statement=(
                    "At the local store boundary, the 32-byte provider digest must "
                    "exactly equal the stored digest."
                ),
                coverage="subset",
                evidence_refs=("friendlyfile_sha256_consumer",),
                unknowns=(
                    SemanticUnknown(
                        "detection_predicate",
                        "Subsequent NID64, attribute, and scan-policy branches are not part of this local predicate.",
                    ),
                ),
            ),
            SemanticClaim(
                id="friendlyfile_sha256_report_branch",
                scope="report_mapping",
                statement=(
                    "A matched digest can enter attribute aggregation or detection-data "
                    "branches using a synthetic 0xA0 identity derived independently of the tail."
                ),
                coverage="subset",
                evidence_refs=("friendlyfile_sha256_report",),
                unknowns=(
                    SemanticUnknown(
                        "report_mapping",
                        "NID64 and outer scan-policy outcomes are not closed.",
                    ),
                ),
            ),
            SemanticClaim(
                id="friendlyfile_sha256_caller_digest_profile",
                scope="runtime_consumer",
                statement=(
                    "In the analyzed troj_scan caller slice, when GetHashes succeeds, "
                    "SHA-256 is computed over the complete current UFS scan object "
                    "bytes [0, SCAN_REPLY+0x50); UfsFile::GetSize supplies the length "
                    "through UfsClientRequest::SyncScanReplyFileSize, and no "
                    "normalization is observed in this chain."
                ),
                coverage="subset",
                evidence_refs=(
                    "friendlyfile_sha256_caller",
                    "friendlyfile_sha256_length_producer",
                ),
                unknowns=(
                    SemanticUnknown(
                        "runtime_consumer",
                        "Other provider callers are not globally closed, and the current UFS object is not established as the on-disk file.",
                    ),
                ),
            ),
            SemanticClaim(
                id="friendlyfile_sha256_caller_match_effect",
                scope="runtime_consumer",
                statement=(
                    "When the friendly lookup and caller gates pass, troj_scan "
                    "sets the MpMoacFriendlyAdd state attribute."
                ),
                coverage="subset",
                evidence_refs=("friendlyfile_sha256_caller",),
                unknowns=(
                    SemanticUnknown(
                        "runtime_consumer",
                        "Optional TTL behavior and any final allow or bypass effect are unknown.",
                    ),
                ),
            ),
            SemanticClaim(
                id="friendlyfile_sha256_final_verdict",
                scope="final_verdict",
                statement="An exact friendly-file digest lookup does not establish a final allow or scan verdict.",
                coverage="unknown",
                unknowns=(
                    SemanticUnknown(
                        "final_verdict",
                        "Final trust, scan, and remediation arbitration remains unresolved.",
                    ),
                ),
            ),
        ),
        claim_evidence=(
            SemanticEvidence(
                id="friendlyfile_sha256_caller",
                axis="consumer",
                kind="engine_static",
                source_ref="mpengine 1.443.903.0",
                locator=(
                    "troj_scan @ 0x180B03685..0x180B036D6; "
                    "IsFriendlyFileEntry @ 0x1802D7AB0"
                ),
                supports=(
                    "friendlyfile_sha256_caller_digest_profile",
                    "friendlyfile_sha256_caller_match_effect",
                ),
            ),
            SemanticEvidence(
                id="friendlyfile_sha256_length_producer",
                axis="consumer",
                kind="engine_static",
                source_ref="mpengine 1.443.903.0",
                locator=(
                    "UfsClientRequest::SyncScanReplyFileSize @ 0x1801D7B14 "
                    "writes UfsFile::GetSize to reply+0x50; "
                    "UfsNode::Open @ 0x18011A71C opens via plugin before "
                    "the size sync"
                ),
                supports=("friendlyfile_sha256_caller_digest_profile",),
            ),
            SemanticEvidence(
                id="friendlyfile_sha256_dispatch",
                axis="dispatch",
                kind="engine_static",
                source_ref="mpengine 1.443.903.0",
                locator="FRIENDLYFILE_SHA256 Register @ 0x18048ADC4",
                supports=("friendlyfile_sha256_loader_dispatch",),
            ),
            SemanticEvidence(
                id="friendlyfile_sha256_receiver",
                axis="receiver",
                kind="engine_static",
                source_ref="mpengine 1.443.903.0",
                locator="FRIENDLYFILE_SHA256 RecordPush @ 0x18040A300",
                supports=(
                    "friendlyfile_sha256_wire_layout",
                    "friendlyfile_sha256_receiver_projection",
                ),
            ),
            SemanticEvidence(
                id="friendlyfile_sha256_consumer",
                axis="consumer",
                kind="engine_static",
                source_ref="mpengine 1.443.903.0",
                locator="FRIENDLYFILE_SHA256 Lookup @ 0x1802D6E60",
                supports=(
                    "friendlyfile_sha256_lookup_consumer",
                    "friendlyfile_sha256_local_predicate",
                ),
            ),
            SemanticEvidence(
                id="friendlyfile_sha256_report",
                axis="report",
                kind="engine_static",
                source_ref="mpengine 1.443.903.0",
                locator="FRIENDLYFILE_SHA256 Lookup @ 0x1802D6E60 matched-entry branches",
                supports=("friendlyfile_sha256_report_branch",),
            ),
        ),
    )


SPEC = FamilySpec(
    FRIENDLYFILE_SHA256_TYPE,
    "FRIENDLYFILE_SHA256",
    parse_friendlyfile_sha256,
    render_friendlyfile_sha256,
    exporter=export_friendlyfile_sha256,
    semantic_exporter=export_friendlyfile_sha256_semantics,
)
