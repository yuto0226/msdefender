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
    semantic_json_to_data,
)

NID_TYPE: Final = 0x55
SNID_TYPE: Final = 0x7E
NID64_TYPE: Final = 0xCE
_SNID98_RESOLVER_CALLABLE: Final = "lib.vdm.snid_resolver.resolve_import_descriptor"
_SNID98_SNAPSHOT_TYPES: Final = (
    ("nid_snapshot", "lib.vdm.snid_resolver.NidLookupSnapshot"),
    ("virtual_dlls", "lib.vdm.snid_resolver.VirtualDllSnapshot"),
)
_NO_TAIL_NAME_BRIDGE: Final = JSONObject(
    (
        ("callable", "lib.vdm.nid_namespace.no_tail_nid_runtime_entry"),
        ("namespace_snapshot_type", "lib.vdm.nid_namespace.NoTailNameSnapshot"),
        ("initialization_profile_type", "lib.vdm.nid_namespace.NoTailNameProfile"),
        (
            "profile_kind",
            "mpengine-1.443.903.0.normal-copy.unique-direct-full.no-redirect.no-override",
        ),
        ("record_type", NID_TYPE),
        ("payload_length", 5),
        ("caller_threat_id_required", True),
        ("threats_loaded_required", True),
        ("threats_loaded_values", JSONArray((False, True))),
        ("source", "raw THREAT_BEGIN payload/name_raw; never display name"),
        (
            "runtime_entry_name_profile",
            (
                "ASCII C-string content only; non-ASCII raises UnsupportedNidNamespace; "
                "the separate raw runtime_name accessor preserves high-bit bytes without strip/decode"
            ),
        ),
        ("unsupported_error_type", "lib.vdm.nid_namespace.UnsupportedNidNamespace"),
        ("key_generation", "not derived; raw NID4 key/selector retained"),
        (
            "unknown_boundary",
            (
                "caller must select effective namespace/profile; dependencies, special/magic IDs, "
                "duplicates, alternate store, overlays and nonempty NID tails are unsupported; "
                "unresolved namespace is an error, not runtime NULL"
            ),
        ),
    )
)
_NAMED_TAIL_NAME_BRIDGE: Final = JSONObject(
    (
        ("callable", "lib.vdm.nid_named_namespace.named_tail_nid_runtime_entry"),
        (
            "initialization_profile_type",
            "lib.vdm.nid_named_namespace.NamedTailNameProfile",
        ),
        (
            "profile_kind",
            "mpengine-1.443.903.0.normal-copy.consistent-mini.immutable-no-shadow",
        ),
        ("optional_parent_namespace_type", "lib.vdm.nid_namespace.NoTailNameSnapshot"),
        ("unsupported_error_type", "lib.vdm.nid_namespace.UnsupportedNidNamespace"),
        ("record_type", NID_TYPE),
        ("payload_length", "greater than 5"),
        ("caller_threat_id_required", True),
        ("caller_sig_id_required", True),
        ("caller_sig_id_bits", 20),
        ("threats_loaded_required", True),
        ("threats_loaded_values", JSONArray((False, True))),
        ("source", "raw type55 payload tail; never identity_text or display name"),
        (
            "named_branch",
            "nonzero first byte and bounded NUL: exact raw bytes before first NUL; post-NUL suffix never reaches object storage",
        ),
        (
            "leading_nul_branch",
            "parent_namespace required; same threats_loaded; explicit caller ID lookup; proven NULL and empty remain distinct",
        ),
        (
            "runtime_entry_name_profile",
            "ASCII C-string content only; non-ASCII unsupported without strip/decode",
        ),
        (
            "storage_profile",
            "successful normal flags0 copy returning exact requested bounded span including NUL; immutable value-preserving OID; no unverified interner/dedup/casefold/collision state",
        ),
        (
            "mini_profile",
            "consistent InternalIdMap/mini name association, flags0x1F7, no mutation/full-fast shadow/counter collision; consistent cross-parent cache reuse allowed",
        ),
        (
            "output_boundary",
            "name-value projection only; generated mini IDs, signature counters and report identities not reconstructed",
        ),
        ("key_generation", "not derived; raw NID4 key/selector retained"),
        (
            "unknown_boundary",
            "unterminated storage, missing parent dependency, inconsistent initialization and namespace overrides are unsupported, never synthesized runtime NULL; no whole namespace loader",
        ),
    )
)

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
    snid98 = parsed.type_byte == SNID_TYPE and parsed.metadata_raw == 98
    no_tail_nid = parsed.type_byte == NID_TYPE and len(parsed.raw) == 5
    named_tail_nid = parsed.type_byte == NID_TYPE and len(parsed.raw) > 5

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
                        ("applies_to_record", snid98),
                        (
                            "key_source",
                            "context +0xAAA58 (16 bytes) || context +0xAAA68 (4 bytes)",
                        ),
                        ("operation", "copied unchanged to snidsearchrecidex"),
                        (
                            "upstream_producer",
                            "pe_parse_imports@0x1801385F4; MD5 prefix subset"
                            if snid98
                            else "not applicable to this record; producer unknown",
                        ),
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
            "upstream_key_generation_partial"
            if snid98
            else "upstream_key_generation_unknown",
            "Selector 98 has a confirmed effective-import MD5 prefix subset; "
            "locale, traversal/resource failures, all suffix alias writers and "
            "outer caller applicability remain unresolved."
            if snid98
            else "Provider-level caller inputs are recorded per family, but upstream "
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
        representation="nid.exact_lookup.ir.v3",
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
                    "no_tail_namespace_bridge",
                    _NO_TAIL_NAME_BRIDGE if no_tail_nid else None,
                ),
                (
                    "known_no_tail_namespace_role",
                    "selector97 runtime names can feed the selector98 ordinal resolver"
                    if no_tail_nid and parsed.metadata_raw == 97
                    else "generic name association only; key/selector purpose unknown"
                    if no_tail_nid
                    else "not applicable",
                ),
                (
                    "named_tail_namespace_bridge",
                    _NAMED_TAIL_NAME_BRIDGE if named_tail_nid else None,
                ),
                (
                    "known_named_tail_namespace_role",
                    "selector97 runtime names can feed the selector98 ordinal resolver"
                    if named_tail_nid and parsed.metadata_raw == 97
                    else "selector99 runtime names can feed the selector98 API-set resolver"
                    if named_tail_nid and parsed.metadata_raw == 99
                    else "generic name association only; key/selector purpose unknown"
                    if named_tail_nid
                    else "not applicable",
                ),
                (
                    "selector98_producer_profile",
                    JSONObject(
                        (
                            ("applies_to_record", snid98),
                            ("query_selector", 98),
                            (
                                "algorithm",
                                "MD5 of effective import token stream"
                                if snid98
                                else "not applicable",
                            ),
                            (
                                "input_boundary",
                                "successfully mapped/traversed effective descriptors and thunks; original order, duplicates retained",
                            ),
                            (
                                "normalization",
                                "ASCII success profile: lowercase DLL/function, last dll/sys/ocx extension removed, dot separator, comma tokens",
                            ),
                            (
                                "ordinal_resolution",
                                "explicit selector97 result: miss ordN; matched empty skip; nonempty drop first byte then lowercase",
                            ),
                            (
                                "runtime_dependency",
                                "virtual DLL ID and API-set selector99 can affect ordinal selector97 lookup",
                            ),
                            (
                                "resolver_contract",
                                "portable reply-NULL NID4 selector97/99 snapshot evaluation: "
                                "normalized delta/base order, resolved runtime names, shared selector108 sequence membership; "
                                "accept only status 1; wire no-tail is not runtime empty"
                                if snid98
                                else "not applicable",
                            ),
                            (
                                "resolver_callable",
                                _SNID98_RESOLVER_CALLABLE if snid98 else None,
                            ),
                            (
                                "resolver_snapshot_types",
                                JSONObject(_SNID98_SNAPSHOT_TYPES) if snid98 else None,
                            ),
                            (
                                "no_tail_namespace_dependency",
                                _NO_TAIL_NAME_BRIDGE if snid98 else None,
                            ),
                            ("namespace_dependency_selector", 97 if snid98 else None),
                            (
                                "named_tail_namespace_dependency",
                                _NAMED_TAIL_NAME_BRIDGE if snid98 else None,
                            ),
                            (
                                "named_tail_namespace_dependency_selectors",
                                JSONArray((97, 99)) if snid98 else None,
                            ),
                            (
                                "virtual_dll_contract",
                                "explicit selected-host lookup/stored-ID snapshot; index0 and ID0 valid; "
                                "MSVCRT canonical before path strip; dot presence before trim; "
                                "API99 accepted target uses raw target CRC even when virtual-known"
                                if snid98
                                else "not applicable",
                            ),
                            (
                                "suffix_source",
                                "context +0xAAA68 raw4; verified pefile_scan_mp reset writes zero; all alias writers unknown",
                            ),
                            (
                                "scope",
                                "caller-specific derivation subset; not a file-content hash or final verdict",
                            ),
                        )
                    ),
                ),
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
        )
        + (
            (
                SemanticClaim(
                    id="nid_no_tail_runtime_name_association",
                    scope="runtime_consumer",
                    statement=(
                        "For a five-byte type55 record, RecordPush retains the explicit "
                        "caller threat ID. In the fixed normal-copy unique direct-full "
                        "namespace profile, its name comes from raw THREAT_BEGIN bytes "
                        "up to the first NUL; zero name length yields runtime NULL. "
                        "The raw accessor preserves bytes, while the runtime-entry factory "
                        "supports ASCII names only. This associates a name without deriving "
                        "the NID key or selector role."
                    ),
                    coverage="subset",
                    evidence_refs=("nid_no_tail_name_bridge_native",),
                    unknowns=(
                        SemanticUnknown(
                            "runtime_consumer",
                            "Effective caller namespace and initialization profile must be "
                            "explicit; dependency redirects, overlays, special/magic IDs, "
                            "alternate store and nonempty-tail mini-threat loading remain outside. "
                            "Non-ASCII raw names are preserved by the accessor but unsupported "
                            "by the runtime-entry factory; they are not stripped or decoded.",
                        ),
                    ),
                ),
            )
            if no_tail_nid
            else ()
        )
        + (
            (
                SemanticClaim(
                    id="nid_named_tail_runtime_name_association",
                    scope="runtime_consumer",
                    statement=(
                        "For a type55 nonempty tail in the fixed successful value-preserving "
                        "normal-copy consistent immutable mini profile, a nonzero label with "
                        "bounded NUL supplies the exact raw name bytes before that NUL. "
                        "A leading NUL instead retains the explicit caller parent namespace. "
                        "The portable ASCII factory preserves key and selector without deriving "
                        "their role or reproducing generated numeric IDs."
                    ),
                    coverage="subset",
                    evidence_refs=("nid_named_tail_name_bridge_native",),
                    unknowns=(
                        SemanticUnknown(
                            "runtime_consumer",
                            "Initialization, OID-to-span equality, immutable consistent mini rows "
                            "and no shadows/collisions must be explicit. Leading NUL requires a "
                            "supported parent snapshot with matching loaded state; unresolved "
                            "parent, unterminated storage and non-ASCII runtime-entry names are "
                            "unsupported, not runtime NULL. Whole namespace loading, numeric "
                            "mini allocation and report identity remain outside this projection.",
                        ),
                    ),
                ),
            )
            if named_tail_nid
            else ()
        )
        + (
            (
                SemanticClaim(
                    id="snid98_effective_import_key_prefix",
                    scope="runtime_consumer",
                    statement=(
                        "For selector 98, pe_parse_imports produces the first 16 query "
                        "bytes with MD5 over ordered effective import tokens; the "
                        "consumer appends four unchanged context bytes. Portable "
                        "reproduction accepts explicit ordinal resolution or resolved "
                        "runtime snapshots within the ASCII success profile."
                    ),
                    coverage="subset",
                    evidence_refs=(
                        "snid98_producer_static",
                        "snid98_resolver_differential",
                        "nid_named_tail_name_bridge_native",
                    ),
                    unknowns=(
                        SemanticUnknown(
                            "runtime_consumer",
                            "Portable reproduction covers successful effective inputs "
                            "in an ASCII profile with explicit ordinal resolution or "
                            "resolved runtime NID4/virtual-host/suppression snapshots; "
                            "whole snapshot/namespace loading beyond the fixed named-tail bridge, "
                            "other locales, traversal failures, all suffix aliases "
                            "and outer caller gates remain unknown.",
                        ),
                    ),
                ),
            )
            if snid98
            else ()
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
        )
        + (
            (
                SemanticEvidence(
                    id="nid_no_tail_name_bridge_native",
                    axis="engine_equivalent_test",
                    kind="engine_equivalent_test",
                    source_ref="mpengine 1.443.903.0; DLL SHA256 928e171c60a44bb326776d2a356412ae98d78469bdf8c94ebfbfa09f8ec4b4b3",
                    locator=(
                        "tests/local_snid98_name_bridge_native.py (27 cases; SHA256 "
                        "adc6b01bc524964610be7d8ba7ed0bbafba128b3da96b379cc6ceb0395de9bc3); "
                        "tests/local_nid_namespace_differential.py (24 cases; SHA256 "
                        "835331b479d46e6b952cb169e8fc3dc911406fe469ef86f89b5be0bb592852d9); "
                        "threat_info_receiver@0x1809EB590 -> kpushobject@0x1800FBFDC -> "
                        "kstore_copy_buff@0x1800FC594 -> add_full_threat@0x180483A10; "
                        "RecordPush@0x180447AE4 -> get_threat_name@0x1800F7D10; "
                        "docs/mpengine.dll/1.443.903.0/snid98_name_bridge_private.md; "
                        "normal-copy unique direct-full no-redirect/no-override profile only"
                    ),
                    supports=("nid_no_tail_runtime_name_association",),
                ),
            )
            if no_tail_nid
            else ()
        )
        + (
            (
                SemanticEvidence(
                    id="nid_named_tail_name_bridge_native",
                    axis="engine_equivalent_test",
                    kind="engine_equivalent_test",
                    source_ref="mpengine 1.443.903.0; DLL SHA256 928e171c60a44bb326776d2a356412ae98d78469bdf8c94ebfbfa09f8ec4b4b3",
                    locator=(
                        "tests/local_nid_named_tail_native.py (31 cases; SHA256 "
                        "68d61185a6240620828e87f3bf8773ec331b307c3c4824361d8f8be4e3185ddc); "
                        "tests/local_nid_named_namespace_differential.py (35 cases; SHA256 "
                        "60102c8101a62aa53591abe8b3b8607ebdb9899edcc2947c4852ec9b88682521); "
                        "RecordPush@0x180447AE4 -> kpushobject@0x1800FBFDC -> "
                        "createrecid@0x1800FB5EC -> GenerateInternalId@0x1803C3030 -> "
                        "add_mini_threat@0x18046EC28 -> get_threat_name@0x1800F7D10; "
                        "docs/mpengine.dll/1.443.903.0/nid_named_tail_bridge_private.md; "
                        "generic type55 name-value projection; successful exact-span normal-copy "
                        "immutable consistent-mini no-shadow profile, ASCII runtime entries; "
                        "651 saved raw selector97/99 corpus records compared; whole loader and numeric IDs excluded"
                    ),
                    supports=("nid_named_tail_runtime_name_association",)
                    if named_tail_nid
                    else ("snid98_effective_import_key_prefix",),
                ),
            )
            if named_tail_nid or snid98
            else ()
        )
        + (
            (
                SemanticEvidence(
                    id="snid98_producer_static",
                    axis="consumer",
                    kind="engine_static",
                    source_ref="mpengine 1.443.903.0",
                    locator="pe_parse_imports@0x1801385F4; MD5 Result@0x180138836; reset@0x1803E9858; scan_imphash@0x1804A6370",
                    supports=("snid98_effective_import_key_prefix",),
                ),
                SemanticEvidence(
                    id="snid98_resolver_differential",
                    axis="engine_equivalent_test",
                    kind="engine_equivalent_test",
                    source_ref="mpengine 1.443.903.0; DLL SHA256 928e171c60a44bb326776d2a356412ae98d78469bdf8c94ebfbfa09f8ec4b4b3",
                    locator=(
                        "tests/local_snid98_resolver_native.py (43 cases; SHA256 "
                        "b67f5ec019b8c46eb5e9c70ab42a6d56c8f27fe6ec23d25edb46a8c7801ebf78); "
                        "tests/local_snid98_resolver_differential.py (23 cases; SHA256 "
                        "76a211f10d04f54493a280490756c57cf005fc575cdfa84c9508548f8f3b1da4); "
                        "docs/mpengine.dll/1.443.903.0/snid98_resolver_private.md; "
                        "lib.vdm.snid_resolver.resolve_import_descriptor; reply-NULL "
                        "NID4 selectors97/99, ASCII successful effective imports, "
                        "explicit resolved-name/selected-host/suppression snapshots; "
                        "namespace loading and outer scan gates excluded"
                    ),
                    supports=("snid98_effective_import_key_prefix",),
                ),
            )
            if snid98
            else ()
        ),
    )


def export_nid_artifact(parsed: NidPayload) -> ArtifactExport:
    """Export the exact-key record and all following bytes losslessly."""
    key_width = _KEY_WIDTHS[parsed.type_byte]
    snid98 = parsed.type_byte == SNID_TYPE and parsed.metadata_raw == 98
    no_tail_nid = parsed.type_byte == NID_TYPE and len(parsed.raw) == 5
    named_tail_nid = parsed.type_byte == NID_TYPE and len(parsed.raw) > 5
    manifest = {
        "schema": "vdm.nid.artifact.v2",
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
            "key_generation": "selector98_effective_import_md5_prefix_subset"
            if snid98
            else "unknown",
            "provider_selector": 98 if snid98 else "unknown",
            "selector98_profile_applies": snid98,
            "digest_prefix_raw_hex": parsed.key_raw[:16].hex() if snid98 else None,
            "context_suffix_raw_hex": parsed.key_raw[16:].hex() if snid98 else None,
            "derivation_boundary": (
                "effective mapped imports, ASCII profile, explicit ordinal resolver results; suffix supplied explicitly"
                if snid98
                else "unknown; selector98 derivation does not apply"
            ),
            "resolver_contract": (
                "NID4 selector97/99 reply-NULL subset with normalized delta/base "
                "runtime rows and resolved names, shared selector108 membership, "
                "explicit selected-host virtual table; accept status exactly1; "
                "wire tail is not a resolved-name backend"
                if snid98
                else "unknown; selector98 resolver does not apply"
            ),
            "resolver_callable": _SNID98_RESOLVER_CALLABLE if snid98 else None,
            "resolver_snapshot_types": dict(_SNID98_SNAPSHOT_TYPES) if snid98 else None,
            "no_tail_namespace_bridge": semantic_json_to_data(_NO_TAIL_NAME_BRIDGE)
            if no_tail_nid
            else None,
            "no_tail_namespace_dependency": semantic_json_to_data(_NO_TAIL_NAME_BRIDGE)
            if snid98
            else None,
            "namespace_dependency_selector": 97 if snid98 else None,
            "named_tail_namespace_bridge": semantic_json_to_data(
                _NAMED_TAIL_NAME_BRIDGE
            )
            if named_tail_nid
            else None,
            "named_tail_namespace_dependency": semantic_json_to_data(
                _NAMED_TAIL_NAME_BRIDGE
            )
            if snid98
            else None,
            "named_tail_namespace_dependency_selectors": [97, 99] if snid98 else None,
            "file_content_hash_ioc": False,
            "outer_caller_gates": "unknown",
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
