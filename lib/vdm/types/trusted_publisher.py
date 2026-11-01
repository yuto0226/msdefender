"""Lossless TRUSTED_PUBLISHER framing and bounded key interpretation."""

import hashlib
import json
from dataclasses import dataclass
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
from ._certificate_key import certificate_key_profile, parse_certificate_key

TRUSTED_PUBLISHER_TYPE: Final = 0x70

_KEY_TYPES = MappingProxyType({1: "HASH", 2: "BY", 3: "TO", 4: "BADHASH", 5: "TEAMID"})


@dataclass(frozen=True, slots=True)
class TrustedPublisher:
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
    recid_tail_raw: bytes
    recid_tail: RecIdTail | None


def parse_trusted_publisher(payload: bytes) -> TrustedPublisher:
    """Parse the WORD-sized key and retain opaque or malformed key contents.

    Load at 0x18032039C rejects keys shorter than two bytes. Its string GetKey
    overload scans for NUL without a length; this parser stays within key_len.
    UTF-16LE is confirmed by wcsnicmp and the wide-string GetKey overload.
    """
    if len(payload) < 2:
        raise ValueError(
            f"truncated TRUSTED_PUBLISHER key_len: need 2 bytes, have {len(payload)}"
        )
    key_len = int.from_bytes(payload[:2], "little")
    if key_len < 2:
        raise ValueError(
            f"invalid TRUSTED_PUBLISHER key_len: need at least 2, have {key_len}"
        )
    key_end = 2 + key_len
    if key_end > len(payload):
        raise ValueError(
            "truncated TRUSTED_PUBLISHER key_data: "
            f"need {key_len} bytes, have {len(payload) - 2}"
        )

    key_data = payload[2:key_end]
    recid_tail_raw = payload[key_end:]
    key = parse_certificate_key(key_data)

    # The signature hash covers payload[:key_end], excluding this RecID tail;
    # Load also ORs (key_end << 40) and 0x7000000000 into its CRC result. Key
    # material itself is not universally a digest (see both GetKey overloads).
    return TrustedPublisher(
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
        recid_tail_raw=recid_tail_raw,
        recid_tail=parse_recid_tail(recid_tail_raw),
    )


def render_trusted_publisher(parsed: TrustedPublisher) -> FormatResult:
    label = _KEY_TYPES.get(parsed.key_type)
    key_type = f"0x{parsed.key_type:02x}"
    if label is not None:
        key_type += f" ({label})"
    fields = (
        ("key_len", str(parsed.key_len)),
        ("mode", parsed.mode),
        ("key_type", key_type),
    )
    rows = list(fields)
    if parsed.mode == "binary":
        rows.append(("key_material_raw", parsed.key_material_raw.hex(" ") or "(empty)"))
    if parsed.mode == "string":
        rows.append(("prefix", parsed.prefix or "(none; defaults to TO)"))
        if parsed.key_text is not None:
            rows.append(("key_text", json.dumps(parsed.key_text, ensure_ascii=False)))
        else:
            rows.append(("decode_error", f"invalid UTF-16LE: {parsed.decode_error}"))
            rows.append(("text_raw", parsed.text_raw.hex(" ") or "(empty)"))
        rows.append(
            (
                "terminator",
                "NUL"
                if parsed.terminator_raw
                else "(missing within key_len; engine reads an unbounded string)",
            )
        )
        if parsed.string_trailing_raw:
            rows.append(("string_trailing_len", f"{len(parsed.string_trailing_raw)} B"))
    sections = [DisplaySection("Publisher key", rows=tuple(rows))]
    if parsed.recid_tail_raw:
        sections.append(
            DisplaySection(
                "RecID tail",
                rows=(("recid_tail_len", f"{len(parsed.recid_tail_raw)} B"),),
            )
        )
    return FormatResult(sections=tuple(sections))


def export_trusted_publisher_semantics(parsed: TrustedPublisher) -> RuleSemantics:
    """Export the confirmed normalized-key lookup without claiming trust policy."""
    type_name = _KEY_TYPES.get(parsed.key_type)
    unsupported_reasons: list[SemanticIssue] = []
    if type_name is None:
        unsupported_reasons.append(
            SemanticIssue(
                "unknown_key_type",
                "The receiver's meaning for this key type is not confirmed.",
                (("key_type", parsed.key_type),),
            )
        )
    if parsed.mode == "string" and not parsed.terminator_raw:
        unsupported_reasons.append(
            SemanticIssue(
                "unbounded_wide_string",
                "The engine's wide GetKey call can read beyond key_len when the "
                "key material has no NUL terminator.",
            )
        )
    if parsed.recid_tail_raw:
        unsupported_reasons.append(
            SemanticIssue(
                "recid_metadata_meaning_unknown",
                "The optional tail is consumed by createrecidp to derive the stored "
                "threat/signature association; its producer-side object meaning is unknown.",
            )
        )
    if parsed.key_type == 4:
        unsupported_reasons.append(
            SemanticIssue(
                "key_type_consumer_unknown",
                "The loader recognizes BADHASH/type 4, but the analyzed "
                "CheckPublisher consumer does not issue a type-4 query.",
                (("key_type", parsed.key_type),),
            )
        )

    issues = [
        SemanticIssue(
            "policy_effect_unknown",
            "An accepted publisher-key lookup does not by itself establish the "
            "final IsTrustedFile or scan verdict policy.",
        ),
        *unsupported_reasons,
    ]
    unsupported = bool(unsupported_reasons)
    key_descriptor_items: list[tuple[str, str | int | None]] = [
        ("kind", parsed.mode),
        ("key_type", parsed.key_type),
        ("key_type_name", type_name),
    ]
    if parsed.mode == "binary":
        key_descriptor_items.append(
            ("key_material_raw_hex", parsed.key_material_raw.hex())
        )
    else:
        key_descriptor_items.extend(
            (
                ("prefix", parsed.prefix),
                ("text", parsed.key_text),
                ("text_raw_hex", parsed.text_raw.hex()),
                ("terminator_raw_hex", parsed.terminator_raw.hex()),
                ("string_trailing_raw_hex", parsed.string_trailing_raw.hex()),
            )
        )

    normalization_profile = certificate_key_profile(
        parse_trusted_publisher(parsed.raw).key_data
    )
    normalized_hex = normalization_profile["normalized_key_hex"]
    normalized_key = (
        bytes.fromhex(normalized_hex) if isinstance(normalized_hex, str) else None
    )
    normalization = normalization_profile["operation"] or "unsupported"

    if parsed.key_type in {1, 2, 3, 5}:
        consumer_claim = SemanticClaim(
            id="trusted_publisher_lookup_consumer",
            scope="runtime_consumer",
            statement=(
                "CheckPublisher queries normalized key types 1, 3, 2, and 5; "
                "after a store match it applies a separate NID64 selector-133 gate."
            ),
            coverage="subset",
            evidence_refs=("trusted_publisher_consumer",),
            unknowns=(
                SemanticUnknown(
                    "runtime_consumer",
                    "Caller coverage and the enclosing trust-policy paths remain incomplete.",
                ),
            ),
        )
        predicate_claim = SemanticClaim(
            id="trusted_publisher_local_predicate",
            scope="detection_predicate",
            statement=(
                "At the analyzed CheckPublisher boundary, an exact normalized-key "
                "store match is accepted only when the subsequent NID64 gate does not match."
            ),
            coverage="subset",
            evidence_refs=("trusted_publisher_consumer",),
            unknowns=(
                SemanticUnknown(
                    "detection_predicate",
                    "The enclosing IsTrustedFile policy is unresolved.",
                ),
            ),
        )
    else:
        consumer_claim = SemanticClaim(
            id="trusted_publisher_lookup_consumer",
            scope="runtime_consumer",
            statement=(
                "No CheckPublisher query is confirmed for this loader-recognized "
                f"certificate key type ({parsed.key_type})."
            ),
            coverage="unknown",
            unknowns=(
                SemanticUnknown(
                    "runtime_consumer",
                    "The analyzed CheckPublisher path queries only key types 1, 3, 2, and 5.",
                ),
            ),
        )
        predicate_claim = SemanticClaim(
            id="trusted_publisher_local_predicate",
            scope="detection_predicate",
            statement="No CheckPublisher predicate is established for this key type.",
            coverage="unknown",
            unknowns=(
                SemanticUnknown(
                    "detection_predicate",
                    "Without a confirmed runtime consumer, no record-level match predicate is established.",
                ),
            ),
        )

    if parsed.key_type in {1, 2, 3, 5}:
        report_claim = SemanticClaim(
            id="trusted_publisher_matched_identity",
            scope="report_mapping",
            statement=(
                "After the separate NID64 gate accepts the match, CheckPublisher "
                "copies the matched signature ID and SHA-1 to caller outputs."
            ),
            coverage="subset",
            evidence_refs=("trusted_publisher_report",),
            unknowns=(
                SemanticUnknown(
                    "report_mapping",
                    "The complete IsTrustedFile attribute and report arbitration is unresolved.",
                ),
            ),
        )
    else:
        report_claim = SemanticClaim(
            id="trusted_publisher_matched_identity",
            scope="report_mapping",
            statement="No matched-identity output is established for an unconsumed key type.",
            coverage="unknown",
            unknowns=(
                SemanticUnknown(
                    "report_mapping",
                    "No confirmed CheckPublisher match exists to reach the output branch.",
                ),
            ),
        )

    return RuleSemantics(
        status="unsupported" if unsupported else "confirmed_subset",
        representation="trusted_publisher.normalized_lookup.ir.v1",
        data=JSONObject(
            (
                ("raw_hex", parsed.raw.hex()),
                (
                    "framing",
                    JSONArray(
                        (
                            JSONObject(
                                (
                                    ("kind", "key_len"),
                                    ("offset", 0),
                                    ("length", 2),
                                    ("raw_hex", parsed.raw[:2].hex()),
                                )
                            ),
                            JSONObject(
                                (
                                    ("kind", "key_data"),
                                    ("offset", 2),
                                    ("length", parsed.key_len),
                                    ("raw_hex", parsed.key_data.hex()),
                                )
                            ),
                            JSONObject(
                                (
                                    ("kind", "recid_tail"),
                                    ("offset", 2 + parsed.key_len),
                                    ("length", len(parsed.recid_tail_raw)),
                                    ("raw_hex", parsed.recid_tail_raw.hex()),
                                )
                            ),
                        )
                    ),
                ),
                ("key_descriptor", JSONObject(tuple(key_descriptor_items))),
                (
                    "normalization",
                    JSONObject(
                        (
                            ("engine_call", "GetKey"),
                            (
                                "recipe",
                                JSONObject(tuple(normalization_profile.items())),
                            ),
                            ("operation", normalization),
                            (
                                "normalized_key_hex",
                                None
                                if normalized_key is None
                                else normalized_key.hex(),
                            ),
                        )
                    ),
                ),
                ("match_operation", "exact_normalized_key_lookup"),
                (
                    "runtime_consumer",
                    JSONObject(
                        (
                            ("queried_key_types", JSONArray((1, 3, 2, 5))),
                            (
                                "type4_consumer",
                                "unknown" if parsed.key_type == 4 else "not_applicable",
                            ),
                            (
                                "post_lookup_gate",
                                "nid64searchrecid(selector=133, key=reply_matched_sig_id)",
                            ),
                            (
                                "tail_relationship",
                                "independent_receiver_metadata; not_the_nid64_gate_input",
                            ),
                        )
                    ),
                ),
                ("policy_effect", "unknown"),
            )
        ),
        evidence=(
            "TRUSTED_PUBLISHER parser bounds key_len and key_data",
            "mpengine 1.443.903.0 trustedpublisher_t::Load",
            "mpengine 1.443.903.0 GetKey overloads and key-type dispatch",
            "mpengine 1.443.903.0 CheckPublisher exact store lookup",
        ),
        profile="mpengine-1.443.903.0",
        issues=tuple(issues),
        claims=(
            SemanticClaim(
                id="certificate_key_successful_projection",
                scope="receiver_transform",
                statement="The shared raw-key normalizer projects binary GetKey and terminated wide strict-hex or CP_UTF8 flags0 success, including surrogate replacement; no Unicode canonicalization or trust decision is implied.",
                coverage="subset",
                evidence_refs=("certificate_key_native_projection",),
                unknowns=(
                    SemanticUnknown(
                        "final_verdict",
                        "API/allocation failure fallback, invalid-hex C++ catch, X509 field selection, lookup and final trust remain outside the projection.",
                    ),
                ),
            ),
            SemanticClaim(
                id="trusted_publisher_wire_layout",
                scope="wire_layout",
                statement=(
                    "TRUSTED_PUBLISHER contains a u16-bounded key descriptor and an "
                    "optional RecID metadata tail."
                ),
                coverage="complete",
                evidence_refs=("trusted_publisher_receiver",),
            ),
            SemanticClaim(
                id="trusted_publisher_loader_dispatch",
                scope="loader_dispatch",
                statement="The analyzed store registration binds type 0x70 to TRUSTED_PUBLISHER.",
                coverage="subset",
                evidence_refs=("trusted_publisher_dispatch",),
                unknowns=(
                    SemanticUnknown(
                        "loader_dispatch",
                        "Other database profiles and engine versions are not covered.",
                    ),
                ),
            ),
            SemanticClaim(
                id="trusted_publisher_receiver_projection",
                scope="receiver_transform",
                statement=(
                    "Load normalizes the bounded certificate key and, when present, "
                    "uses the independent tail to derive stored threat/signature IDs."
                ),
                coverage="subset",
                evidence_refs=("trusted_publisher_receiver",),
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
                id="trusted_publisher_final_verdict",
                scope="final_verdict",
                statement="A TRUSTED_PUBLISHER match does not establish a global allow or skip-scan verdict.",
                coverage="unknown",
                unknowns=(
                    SemanticUnknown(
                        "final_verdict",
                        "Revocation, exclusion, caller policy, and final scan arbitration remain unresolved.",
                    ),
                ),
            ),
        ),
        claim_evidence=(
            SemanticEvidence(
                id="certificate_key_native_projection",
                axis="receiver",
                kind="engine_equivalent_test",
                source_ref="Pinned mpengine 1.443.903.0 original receivers/GetKey/Win32 wrappers/SHA1; actual host CP_UTF8 flags0 and C-locale prefix oracles; allocations/copies are successful resource services.",
                locator="tests/local_certificate_key_native.py SHA256 4313d2706c50081c20d6223e2c09bbc0b38440302a325359ecb91f46fc463f11 (47 cases); current source bridge tests/local_certificate_key_differential.py SHA256 0f06417d212b9e20cab7e316f62571c19c54b4664ce5368f5e9c66478953d76e (35 cases); docs/mpengine.dll/1.443.903.0/certificate_key_native_private.md",
                supports=("certificate_key_successful_projection",),
            ),
            SemanticEvidence(
                id="trusted_publisher_dispatch",
                axis="dispatch",
                kind="engine_static",
                source_ref="mpengine 1.443.903.0",
                locator="TRUSTED_PUBLISHER store registration",
                supports=("trusted_publisher_loader_dispatch",),
            ),
            SemanticEvidence(
                id="trusted_publisher_receiver",
                axis="receiver",
                kind="engine_static",
                source_ref="mpengine 1.443.903.0",
                locator="trustedpublisher_t::Load @ 0x18032039C",
                supports=(
                    "trusted_publisher_wire_layout",
                    "trusted_publisher_receiver_projection",
                ),
            ),
            SemanticEvidence(
                id="trusted_publisher_consumer",
                axis="consumer",
                kind="engine_static",
                source_ref="mpengine 1.443.903.0",
                locator="CheckPublisher @ 0x180298E3C",
                supports=(
                    "trusted_publisher_lookup_consumer",
                    "trusted_publisher_local_predicate",
                ),
            ),
            SemanticEvidence(
                id="trusted_publisher_report",
                axis="report",
                kind="engine_static",
                source_ref="mpengine 1.443.903.0",
                locator="CheckPublisher @ 0x180298E3C accepted-match output branch",
                supports=("trusted_publisher_matched_identity",),
            ),
        ),
    )


def export_trusted_publisher(parsed: TrustedPublisher) -> ArtifactExport:
    """Export the key record and opaque post-key program losslessly."""
    key_end = 2 + parsed.key_len
    manifest = {
        "schema": "vdm.trusted_publisher.artifact.v1",
        "record_type": {"byte": TRUSTED_PUBLISHER_TYPE, "name": "TRUSTED_PUBLISHER"},
        "raw_hex": parsed.raw.hex(),
        "normalization_recipe": certificate_key_profile(
            parse_trusted_publisher(parsed.raw).key_data
        ),
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
        },
        "post_key_tail": {"raw_hex": parsed.recid_tail_raw.hex(), "offset": key_end},
        "matcher_boundary": {
            "confirmed_operation": "exact_normalized_key_lookup",
            "key_normalization": "GetKey_overload_depends_on_key_type_and_encoding",
            "x509_field_mapping": "unknown",
            "post_key_gate_input": "recid_pcode_bytes_preserved_not_executed",
            "final_trust_or_scan_verdict": "unknown",
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
            Artifact(f"70-{digest}.json", "trusted_publisher_json_manifest", data),
        ),
    )


SPEC = FamilySpec(
    TRUSTED_PUBLISHER_TYPE,
    "TRUSTED_PUBLISHER",
    parse_trusted_publisher,
    render_trusted_publisher,
    exporter=export_trusted_publisher,
    semantic_exporter=export_trusted_publisher_semantics,
)
