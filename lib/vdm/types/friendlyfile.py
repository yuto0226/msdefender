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
    SemanticIssue,
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
        "format": "vdm.friendly_file_sha256.record.v2",
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
    issues.append(
        SemanticIssue(
            "original_threat_attribution_unknown",
            "Runtime lookup uses an index-based synthetic identity; no confirmed "
            "path restores the enclosing VDM threat ID or name for a digest hit.",
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
                        ("original_threat_attribution", "not_established"),
                    )
                ),
            ),
            ("recid_tail", _recid_tail_semantics(tail)),
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
    )


SPEC = FamilySpec(
    FRIENDLYFILE_SHA256_TYPE,
    "FRIENDLYFILE_SHA256",
    parse_friendlyfile_sha256,
    render_friendlyfile_sha256,
    exporter=export_friendlyfile_sha256,
    semantic_exporter=export_friendlyfile_sha256_semantics,
)
