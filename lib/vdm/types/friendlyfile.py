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
    semantic_json_to_data,
)
from ..recid import RecIdTail, parse_recid_tail

FRIENDLYFILE_SHA256_TYPE: Final = 0xA0
SHA256_SIZE: Final = 32
_CACHE_PRECONDITION: Final = (
    "GetHashes may return a provided cache without hashing/I/O; caller must confirm "
    "cache/source consistency; success alone is insufficient"
)
_PORTABLE_CANDIDATE: Final = JSONObject(
    (
        ("callable", "lib.vdm.friendlyfile_match.evaluate_friendlyfile_sha256"),
        ("result_type", "lib.vdm.friendlyfile_match.FriendlyFileSha256Candidate"),
        (
            "caller_profiles",
            JSONArray(
                (
                    "IsSignedFile.full_current_ufs_object",
                    "troj_scan.full_current_ufs_object",
                )
            ),
        ),
        (
            "profile_selection",
            "explicit statically observed caller use; native tests execute shared GetHashes/Lookup/IsFriendlyFileEntry, not whole IsSignedFile or troj_scan",
        ),
        (
            "input",
            "complete immutable current UFS scan object bytes; not necessarily an on-disk container/file identity",
        ),
        (
            "byte_projection",
            "cold full-object SHA256 computation or caller-confirmed source-consistent cache value; no normalization",
        ),
        ("cache_precondition", _CACHE_PRECONDITION),
        (
            "output",
            "computed_sha256 bytes and record_local_friendly_candidate boolean; raw A0 digest reparsed; tail not a digest input",
        ),
        (
            "policy_boundary",
            "does not establish record admission, store result1, NID108/133, namespace, reply flag, TTL, friendly attributes or final allow/bypass/verdict",
        ),
        ("provides_allow_or_bypass_decision", False),
        ("malicious_ioc", False),
    )
)


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
                "input": "complete current UFS scan object bytes [0, SCAN_REPLY+0x50) for cold computation or caller-confirmed source-consistent cache",
                "cache_precondition": _CACHE_PRECONDITION,
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
            "portable_candidate": semantic_json_to_data(_PORTABLE_CANDIDATE),
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
                            "complete_current_ufs_scan_object_for_cold_or_source_consistent_cache_projection",
                        ),
                        ("cache_precondition", _CACHE_PRECONDITION),
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
            ("portable_candidate", _PORTABLE_CANDIDATE),
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
                    "The analyzed caller slices request the complete current UFS "
                    "object range [0, SCAN_REPLY+0x50) for SHA-256. GetHashes can "
                    "compute it or return a provided cache without hashing/I/O; a "
                    "full-byte projection requires cold computation or confirmed "
                    "cache/source consistency. UfsFile::GetSize supplies the length "
                    "through UfsClientRequest::SyncScanReplyFileSize, and no "
                    "normalization is observed in this chain."
                ),
                coverage="subset",
                evidence_refs=(
                    "friendlyfile_sha256_caller",
                    "friendlyfile_sha256_length_producer",
                    "friendlyfile_sha256_native_candidate_test",
                ),
                unknowns=(
                    SemanticUnknown(
                        "runtime_consumer",
                        "Other provider callers and cache lifetime are not globally closed; "
                        "GetHashes success alone does not prove recomputation or source consistency. "
                        "The current UFS object is not established as the on-disk file.",
                    ),
                ),
            ),
            SemanticClaim(
                id="friendlyfile_sha256_native_candidate",
                scope="runtime_consumer",
                statement=(
                    "In bounded cold full-UFS byte cases, original GetHashes SHA256 and "
                    "the A0 equal-range/full32 comparison agree with the record-local "
                    "friendly digest candidate. Native IsFriendlyFileEntry separately "
                    "rejects Lookup2, NID133 raw1 and the reply blocking flag."
                ),
                coverage="subset",
                evidence_refs=("friendlyfile_sha256_native_candidate_test",),
                unknowns=(
                    SemanticUnknown(
                        "runtime_consumer",
                        "Caller-profile selection is a static-use assertion, not whole IsSignedFile/troj_scan execution. Ufs I/O, namespace, NID, actions, continuation and locks are services; source/cache consistency, full TTL/attribute/allow/bypass and final verdict are not inferred from a digest candidate.",
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
                id="friendlyfile_sha256_native_candidate_test",
                axis="engine_equivalent_test",
                kind="engine_equivalent_test",
                source_ref="mpengine 1.443.903.0 DLL SHA256 928e171c60a44bb326776d2a356412ae98d78469bdf8c94ebfbfa09f8ec4b4b3",
                locator=(
                    "tests/local_a0_friendly_native.py (29 cases/57 calls; SHA256 "
                    "53031f925e3681fe4c0c299471f0980a717d93bf13f5e8132089cd3e91c5cc9a); "
                    "report SHA256 1c91d1f9c391ac39db331291f44d762882b20acc17e131799a0c128c345574ba; "
                    "tests/local_a0_friendly_differential.py (18 source cases; SHA256 0160a231c92fc55431ca210d8664b1d057f46d07d01f50052a3f3ae24c2c8af1); "
                    "native GetHashes@0x1803B9F7C(mask10h)/SymCryptSha256 portable ul1 -> "
                    "store/subtype Lookup@0x1802D6D24/0x1802D6E60/equal_range@0x1802D6C20 -> "
                    "IsFriendlyFileEntry@0x1802D855C; original MakeSigSha SHA1/ScanInfoAuto restore; "
                    "docs/mpengine.dll/1.443.903.0/a0_friendly_candidate_private.md; "
                    "IsSignedFile@0x1802D799C and troj_scan@0x180B02760 caller profiles "
                    "remain static callsite evidence, not whole-caller native execution; "
                    "provided-cache case is not recomputation; policy services are explicit"
                ),
                supports=(
                    "friendlyfile_sha256_native_candidate",
                    "friendlyfile_sha256_caller_digest_profile",
                ),
            ),
            SemanticEvidence(
                id="friendlyfile_sha256_caller",
                axis="consumer",
                kind="engine_static",
                source_ref="mpengine 1.443.903.0",
                locator=(
                    "troj_scan @ 0x180B03685..0x180B036D6; "
                    "IsFriendlyFileEntry @ 0x1802D855C; IsSignedFile GetHashes callsite @ 0x1802D7AB0"
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
