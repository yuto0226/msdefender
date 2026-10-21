import hashlib
import json
from collections.abc import Callable
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

NID_TYPE: Final = 0x55
SNID_TYPE: Final = 0x7E
NID64_TYPE: Final = 0xCE

_FAMILY_NAMES = MappingProxyType(
    {
        NID_TYPE: "NID",
        SNID_TYPE: "SNID",
        NID64_TYPE: "NID64",
    }
)

# These records have the same shape but use different identifier widths.
# Names intentionally describe only confirmed wire semantics.
_KEY_WIDTHS = MappingProxyType(
    {
        NID_TYPE: 4,
        SNID_TYPE: 20,
        NID64_TYPE: 8,
    }
)


@dataclass(frozen=True, slots=True)
class NidPayload:
    raw: bytes
    type_byte: int
    key_raw: bytes
    metadata_raw: int
    recid_input_raw: bytes
    identity_kind: Literal["none", "object", "unnamed", "raw"]
    object_raw: bytes | None
    ignored_trailing_raw: bytes

    @property
    def identity_text(self) -> str | None:
        """Return a display-only text view without asserting a wire encoding."""
        data = self.object_raw
        if data is None:
            return None
        if data.endswith(b"\0"):
            data = data[:-1]
        if not data or b"\0" in data:
            return None
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            return None
        return text if all(character.isprintable() for character in text) else None


def parse_nid(payload: bytes, *, type_byte: int) -> NidPayload:
    """Parse the fixed key prefix and preserve the following metadata byte."""
    try:
        key_width = _KEY_WIDTHS[type_byte]
    except KeyError as exc:
        raise ValueError(f"unsupported NID family type 0x{type_byte:02X}") from exc

    header_size = key_width + 1
    if len(payload) < header_size:
        raise ValueError(
            f"truncated {_FAMILY_NAMES[type_byte]} header: "
            f"need {header_size} bytes, have {len(payload)}"
        )

    recid_input_raw = payload[header_size:]
    object_raw: bytes | None = None
    ignored_trailing_raw = b""
    if not recid_input_raw:
        identity_kind: Literal["none", "object", "unnamed", "raw"] = "none"
    elif recid_input_raw[0] == 0:
        identity_kind = "unnamed"
        ignored_trailing_raw = recid_input_raw[1:]
    else:
        identity_kind = "object"
        nul = recid_input_raw.find(b"\0")
        if nul < 0:
            object_raw = recid_input_raw
        else:
            object_raw = recid_input_raw[: nul + 1]
            ignored_trailing_raw = recid_input_raw[nul + 1 :]

    return NidPayload(
        raw=payload,
        type_byte=type_byte,
        key_raw=payload[:key_width],
        metadata_raw=payload[key_width],
        recid_input_raw=recid_input_raw,
        identity_kind=identity_kind,
        object_raw=object_raw,
        ignored_trailing_raw=ignored_trailing_raw,
    )


def render_nid(parsed: NidPayload) -> FormatResult:
    if len(parsed.key_raw) in (4, 8):
        key_width = len(parsed.key_raw) * 2 + 2
        key = f"{int.from_bytes(parsed.key_raw, 'little'):#0{key_width}x}"
    else:
        key = parsed.key_raw.hex()

    fields = [
        ("key", key),
        ("key_raw", parsed.key_raw.hex(" ")),
        ("metadata_raw", f"0x{parsed.metadata_raw:02x}"),
    ]
    if parsed.type_byte == NID_TYPE:
        fields.append(("key_match", "exact 4-byte key; exact metadata byte"))
    elif parsed.type_byte == SNID_TYPE:
        fields.append(("key_match", "exact 20-byte key; exact metadata byte"))
    elif parsed.type_byte == NID64_TYPE:
        fields.append(("key_match", "exact 8-byte key; exact metadata byte"))
    fields.append(("record_identity", parsed.identity_kind))
    identity_text = parsed.identity_text
    if identity_text is not None:
        fields.extend(
            (
                ("identity_text", json.dumps(identity_text, ensure_ascii=False)),
                ("recid_input_raw", parsed.recid_input_raw.hex(" ")),
            )
        )
        if parsed.type_byte in (NID_TYPE, SNID_TYPE, NID64_TYPE):
            fields.append(
                (
                    "identity_role",
                    "interned RecID name; runtime checks IsAttribute()",
                )
            )
    elif parsed.recid_input_raw:
        fields.append(("recid_input_raw", parsed.recid_input_raw.hex(" ")))
    if parsed.object_raw is not None:
        fields.append(("interned_object_length", f"{len(parsed.object_raw)} B"))
    if parsed.ignored_trailing_raw:
        fields.append(("receiver_ignored_raw", parsed.ignored_trailing_raw.hex(" ")))
    return FormatResult(
        sections=(DisplaySection("Exact-Key Record", rows=tuple(fields)),)
    )


def _raw_field(kind: str, raw: bytes, offset: int) -> JSONObject:
    return JSONObject(
        (
            ("kind", kind),
            (
                "raw_span",
                JSONObject((("offset", offset), ("length", len(raw)))),
            ),
            ("raw_hex", raw.hex()),
        )
    )


def export_nid_semantics(parsed: NidPayload) -> RuleSemantics:
    """Export the receiver-confirmed exact lookup tuple and lossless framing."""
    key_width = _KEY_WIDTHS[parsed.type_byte]
    identity_offset = key_width + 1
    identity_length = len(parsed.recid_input_raw) - len(parsed.ignored_trailing_raw)
    identity_raw = parsed.recid_input_raw[:identity_length]

    framing = JSONArray(
        (
            _raw_field("key", parsed.key_raw, 0),
            _raw_field("metadata", parsed.raw[key_width : key_width + 1], key_width),
            _raw_field("record_identity", identity_raw, identity_offset),
            _raw_field(
                "receiver_ignored_trailing",
                parsed.ignored_trailing_raw,
                identity_offset + identity_length,
            ),
        )
    )

    if parsed.type_byte == NID_TYPE:
        provider_inputs = JSONArray(
            (
                JSONObject(
                    (
                        ("caller", "swf_scan_nid@0x180A5BF1C"),
                        ("query_selector", 6),
                        ("key_source", "context DWORDs at +0x60, +0x64, +0x68"),
                        ("operation", "caller passes each present DWORD unchanged"),
                        ("upstream_producer", "unknown"),
                    )
                ),
            )
        )
    elif parsed.type_byte == SNID_TYPE:
        provider_inputs = JSONArray(
            (
                JSONObject(
                    (
                        ("caller", "scan_imphash@0x1804A6370"),
                        ("query_selector", 98),
                        (
                            "key_source",
                            "context +0xAA018 (16 bytes) || context +0xAA028 (4 bytes)",
                        ),
                        ("operation", "copied unchanged to snidsearchrecidex"),
                        ("upstream_producer", "unknown"),
                    )
                ),
            )
        )
    else:
        provider_inputs = JSONArray(
            (
                JSONObject(
                    (
                        ("caller", "IsHighlyTrustedPublisher@0x1805179D8"),
                        ("query_selector", 132),
                        ("key_source", "sigseqfromrecid(recid)"),
                        ("operation", "existing signature sequence passed as uint64"),
                    )
                ),
                JSONObject(
                    (
                        ("caller", "CheckPublisher@0x180298E3C"),
                        ("query_selector", 133),
                        (
                            "key_source",
                            "SCAN_REPLY +0x90 after trustedpublisher lookup",
                        ),
                        ("operation", "existing QWORD passed as uint64"),
                    )
                ),
            )
        )

    family_id = _FAMILY_NAMES[parsed.type_byte].lower()
    if parsed.type_byte == NID_TYPE:
        receiver_locator = "RecordPush @ 0x180447AE4"
        dispatch_locator = "Register @ 0x18048A610"
        lookup_locator = "Lookup<NidProvider> @ 0x1800AF540"
        lookup_statement = (
            "The local NID lookup narrows candidates with its index and then requires "
            "the 4-byte scalar key and metadata selector to compare equal."
        )
    elif parsed.type_byte == SNID_TYPE:
        receiver_locator = "RecordPush @ 0x1800FA5F0"
        dispatch_locator = "Register @ 0x180566440"
        lookup_locator = "Lookup<SnidProvider> @ 0x180145874"
        lookup_statement = (
            "The local SNID lookup uses the first key DWORD for prefiltering and "
            "then requires the full 20-byte key and selector byte to compare equal."
        )
    else:
        receiver_locator = "RecordPush @ 0x180497874"
        dispatch_locator = "Register @ 0x180566040"
        lookup_locator = "Lookup<Nid64Provider> @ 0x1800AE800"
        lookup_statement = (
            "The local NID64 lookup requires the 8-byte scalar key to compare equal "
            "and compares the zero-extended entry selector byte with the full "
            "32-bit query selector; query values above 0xFF cannot match."
        )

    wire_claim_id = f"{family_id}_wire_layout"
    dispatch_claim_id = f"{family_id}_loader_dispatch"
    receiver_claim_id = f"{family_id}_receiver_projection"
    consumer_claim_id = f"{family_id}_lookup_consumer"
    predicate_claim_id = f"{family_id}_local_lookup_predicate"
    report_claim_id = f"{family_id}_matched_entry_reporting"
    final_claim_id = f"{family_id}_final_verdict"
    receiver_evidence_id = f"{family_id}_receiver"
    dispatch_evidence_id = f"{family_id}_dispatch"
    consumer_evidence_id = f"{family_id}_consumer"
    report_evidence_id = f"{family_id}_report"

    issues: list[SemanticIssue] = [
        SemanticIssue(
            "upstream_key_generation_unknown",
            "Provider-level caller inputs are recorded per family, but upstream "
            "generation remains unknown: NID/SNID context-field producers are "
            "unlocated; NID64 accepts RecID signature-sequence or existing reply "
            "QWORD sources without establishing their common derivation.",
        ),
        SemanticIssue(
            "outer_verdict_unknown",
            "A successful table lookup is not exported as a final detection verdict.",
        ),
    ]
    unsupported = False
    if parsed.identity_kind == "raw":
        unsupported = True
        issues.append(
            SemanticIssue(
                "unknown_identity_kind",
                "The record identity bytes have no confirmed receiver semantics.",
            )
        )
    if parsed.ignored_trailing_raw:
        issues.append(
            SemanticIssue(
                "receiver_ignored_trailing",
                "Bytes after the first NUL are passed to createrecidz but excluded "
                "from the interned name/object span.",
                (("length", len(parsed.ignored_trailing_raw)),),
            )
        )

    return RuleSemantics(
        status="unsupported" if unsupported else "confirmed_subset",
        representation="nid.exact_lookup.ir.v2",
        data=JSONObject(
            (
                ("raw_hex", parsed.raw.hex()),
                ("framing", framing),
                ("type_byte", parsed.type_byte),
                ("family", _FAMILY_NAMES[parsed.type_byte]),
                ("key_width", key_width),
                (
                    "metadata_source",
                    JSONObject(
                        (
                            ("wire_payload_offset", key_width),
                            ("raw_value", parsed.metadata_raw),
                            (
                                "lookup_role",
                                "compared exactly with provider query_selector",
                            ),
                            ("normalization", "none confirmed at receiver/lookup"),
                        )
                    ),
                ),
                (
                    "lookup",
                    JSONObject(
                        (
                            ("kind", "exact"),
                            ("key_raw_hex", parsed.key_raw.hex()),
                            ("metadata_raw", parsed.metadata_raw),
                        )
                    ),
                ),
                ("provider_specific_key_inputs_confirmed_subset", provider_inputs),
                (
                    "record_identity",
                    JSONObject(
                        (
                            ("kind", parsed.identity_kind),
                            ("raw_hex", identity_raw.hex()),
                        )
                    ),
                ),
                (
                    "receiver_ignored_trailing_raw_hex",
                    parsed.ignored_trailing_raw.hex(),
                ),
            )
        ),
        evidence=(
            f"{_FAMILY_NAMES[parsed.type_byte]} receiver: {receiver_locator}",
            f"{_FAMILY_NAMES[parsed.type_byte]} registration: {dispatch_locator}",
            f"{_FAMILY_NAMES[parsed.type_byte]} local lookup: {lookup_locator}",
        ),
        profile="mpengine-1.443.903.0",
        issues=tuple(issues),
        claims=(
            SemanticClaim(
                id=wire_claim_id,
                scope="wire_layout",
                statement=(
                    f"{_FAMILY_NAMES[parsed.type_byte]} has a {key_width}-byte key, "
                    "one metadata byte, and an optional bounded RecID-name input."
                ),
                coverage="complete",
                evidence_refs=(receiver_evidence_id,),
            ),
            SemanticClaim(
                id=dispatch_claim_id,
                scope="loader_dispatch",
                statement=(
                    f"The analyzed registration path binds type "
                    f"0x{parsed.type_byte:02X} to its NID-family receiver."
                ),
                coverage="subset",
                evidence_refs=(dispatch_evidence_id,),
                unknowns=(
                    SemanticUnknown(
                        "loader_dispatch",
                        "The registration site does not close every database/profile dispatch path.",
                    ),
                ),
            ),
            SemanticClaim(
                id=receiver_claim_id,
                scope="receiver_transform",
                statement=(
                    f"The receiver copies the {key_width}-byte key and metadata byte "
                    "without normalization, resolves an optional bounded RecID name, "
                    "and excludes bytes after its first NUL from the interned object."
                ),
                coverage="complete",
                evidence_refs=(receiver_evidence_id,),
            ),
            SemanticClaim(
                id=consumer_claim_id,
                scope="runtime_consumer",
                statement=lookup_statement,
                coverage="subset",
                evidence_refs=(consumer_evidence_id,),
                unknowns=(
                    SemanticUnknown(
                        "runtime_consumer",
                        "Caller coverage and the general query-key producer remain incomplete.",
                    ),
                ),
            ),
            SemanticClaim(
                id=predicate_claim_id,
                scope="detection_predicate",
                statement=(
                    "At the analyzed local lookup boundary, a candidate matches only "
                    "when both its exact key and selector comparisons succeed."
                ),
                coverage="subset",
                evidence_refs=(consumer_evidence_id,),
                unknowns=(
                    SemanticUnknown(
                        "detection_predicate",
                        "The outer caller gates and scan-level predicate are not closed.",
                    ),
                ),
            ),
            SemanticClaim(
                id=report_claim_id,
                scope="report_mapping",
                statement=(
                    "The analyzed matched-entry path resolves signature details and "
                    "can route ordinary or attribute names into scan-result handling."
                ),
                coverage="subset",
                evidence_refs=(report_evidence_id,),
                unknowns=(
                    SemanticUnknown(
                        "report_mapping",
                        "Outer policy, caller-specific reply state, and arbitration remain unresolved.",
                    ),
                ),
            ),
            SemanticClaim(
                id=final_claim_id,
                scope="final_verdict",
                statement=(
                    f"A local {_FAMILY_NAMES[parsed.type_byte]} match does not by "
                    "itself establish the final scan verdict."
                ),
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
                id=receiver_evidence_id,
                axis="receiver",
                kind="engine_static",
                source_ref="mpengine 1.443.903.0",
                locator=receiver_locator,
                supports=(wire_claim_id, receiver_claim_id),
            ),
            SemanticEvidence(
                id=dispatch_evidence_id,
                axis="dispatch",
                kind="engine_static",
                source_ref="mpengine 1.443.903.0",
                locator=dispatch_locator,
                supports=(dispatch_claim_id,),
            ),
            SemanticEvidence(
                id=consumer_evidence_id,
                axis="consumer",
                kind="engine_static",
                source_ref="mpengine 1.443.903.0",
                locator=lookup_locator,
                supports=(consumer_claim_id, predicate_claim_id),
            ),
            SemanticEvidence(
                id=report_evidence_id,
                axis="report",
                kind="engine_static",
                source_ref="mpengine 1.443.903.0",
                locator=lookup_locator,
                supports=(report_claim_id,),
            ),
        ),
    )


def export_nid_artifact(parsed: NidPayload) -> ArtifactExport:
    """Export the exact-key record and all following bytes losslessly."""
    key_width = _KEY_WIDTHS[parsed.type_byte]
    manifest = {
        "schema": "vdm.nid.artifact.v1",
        "record_type": {
            "byte": parsed.type_byte,
            "name": _FAMILY_NAMES[parsed.type_byte],
        },
        "raw_hex": parsed.raw.hex(),
        "key": {"offset": 0, "length": key_width, "raw_hex": parsed.key_raw.hex()},
        "metadata": {
            "offset": key_width,
            "raw_hex": parsed.raw[key_width : key_width + 1].hex(),
            "value": parsed.metadata_raw,
        },
        "recid_input": {
            "offset": key_width + 1,
            "raw_hex": parsed.recid_input_raw.hex(),
            "receiver_identity_kind": parsed.identity_kind,
            "bounded_object_raw_hex": (
                None if parsed.object_raw is None else parsed.object_raw.hex()
            ),
            "receiver_ignored_trailing_raw_hex": parsed.ignored_trailing_raw.hex(),
        },
        "matcher_boundary": {
            "confirmed_operation": "exact_key_and_metadata_byte_lookup",
            "key_generation": "unknown",
            "provider_selector": "unknown",
            "recid_or_pcode_effect": "unknown",
            "final_report_or_verdict": "unknown",
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
            Artifact(
                f"{parsed.type_byte:02x}-{digest}.json", "nid_json_manifest", data
            ),
        ),
    )


def _parser_for(type_byte: int) -> Callable[[bytes], NidPayload]:
    def parser(payload: bytes) -> NidPayload:
        return parse_nid(payload, type_byte=type_byte)

    return parser


NID_SPECS = tuple(
    FamilySpec(
        type_byte,
        name,
        _parser_for(type_byte),
        render_nid,
        exporter=export_nid_artifact,
        semantic_exporter=export_nid_semantics,
    )
    for type_byte, name in _FAMILY_NAMES.items()
)
