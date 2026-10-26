from dataclasses import dataclass
from types import MappingProxyType
from typing import Final

from ..core import (
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

THREAT_CATEGORIES = MappingProxyType(
    {
        0x01: "Adware",
        0x02: "Spyware",
        0x03: "PWS",
        0x04: "TrojanDownloader",
        0x05: "Worm",
        0x06: "Backdoor",
        0x08: "Trojan",
        0x09: "Spammer",
        0x0B: "Dialer",
        0x0C: "MonitoringTool",
        0x0D: "BrowserModifier",
        0x13: "Joke",
        0x15: "SoftwareBundler",
        0x16: "TrojanClicker",
        0x17: "SettingsModifier",
        0x1B: "PUA",
        0x1E: "Exploit",
        0x20: "VirTool",
        0x21: "RemoteAccess",
        0x22: "Tool",
        0x24: "DoS",
        0x25: "TrojanDropper",
        0x26: "Flooder",
        0x27: "TrojanSpy",
        0x28: "TrojanProxy",
        0x2A: "Virus",
        0x2B: "Known",
        0x2C: "Unknown",
        0x2D: "SPP",
        0x2E: "Behavior",
        0x2F: "Vulnerability",
        0x30: "Policy",
        0x31: "EUS",
        0x32: "Ransom",
        0x33: "HipsRule",
    }
)

# Sentinel IDs handled specially by threat_info_receiver/DispatchRecords. They
# are distinct from the 0x7FFE/0x7FFF magic-threat ranges.
MAGIC_THREAT_IDS = MappingProxyType(
    {
        0x00040E1A: "hosts_loaded",
        0x7FFFFFF0: "infrastructure",
        0x7FFFFFFA: "infrastructure",
        0x7FFFFFFE: "unknown_loaded",
        0x7FFFFFFF: "friendly_loaded",
        0xFFFFFFF0: "infrastructure",
        0xFFFFFFF9: "behaviordetection_loaded",
        0xFFFFFFFA: "infrastructure",
        0xFFFFFFFF: "avfriendly_loaded",
    }
)

THREAT_BEGIN_TYPE: Final = 0x5C
THREAT_END_TYPE: Final = 0x5D


@dataclass(frozen=True, slots=True)
class ThreatMetadata:
    """Receiver-built tail named by the engine getters that read it.

    Wire tail offsets +0..+5 map to metadata-object offsets +4..+9.
    """

    short_description_id: int
    threat_advice_id: int
    severity: int
    action: int


@dataclass(frozen=True, slots=True)
class ThreatBegin:
    raw: bytes
    threat_id: int
    dep_count: int
    ext_count: int
    category: int
    name_len: int
    name_raw: bytes
    post_name_zero: int
    dependencies: tuple[int, ...]
    ext_entries: tuple[int, ...]
    metadata: ThreatMetadata | None
    metadata_wire_size: int
    marker_raw: bytes
    display_name_raw: bytes
    name: str
    trailing_raw: bytes

    @property
    def effective_metadata(self) -> ThreatMetadata:
        """Return engine defaults for omitted or partially supplied metadata."""
        # Receiver defaults are two bytes at metadata-object +4/+5. The engine
        # getters read them together as a little-endian short-description ID.
        return self.metadata or ThreatMetadata(0x0301, 0, 0, 0)


@dataclass(frozen=True, slots=True)
class ThreatEnd:
    raw: bytes
    value: int
    trailing_raw: bytes


def threat_category_name(category: int) -> str | None:
    return THREAT_CATEGORIES.get(category)


def parse_threat_begin(payload: bytes) -> ThreatBegin:
    """Parse the THREAT_BEGIN header, name, arrays, and optional metadata."""
    if len(payload) < 0x0C:
        raise ValueError("truncated THREAT_BEGIN header")

    threat_id = int.from_bytes(payload[0:4], "little")
    dep_count = int.from_bytes(payload[4:6], "little")
    ext_count = int.from_bytes(payload[6:8], "little")
    if not 1 <= ext_count <= 507:
        raise ValueError(
            f"THREAT_BEGIN ext_count outside engine receiver range: {ext_count}"
        )
    category = int.from_bytes(payload[8:10], "little")
    name_len = int.from_bytes(payload[10:12], "little")
    name_end = 0x0C + name_len
    if name_end > len(payload):
        raise ValueError(
            f"truncated THREAT_BEGIN name: need {name_len} bytes, "
            f"have {len(payload) - 0x0C}"
        )

    name_raw = payload[0x0C:name_end]
    cursor = name_end

    if len(payload) - cursor < 2:
        raise ValueError("truncated THREAT_BEGIN post_name_zero")
    post_name_zero = int.from_bytes(payload[cursor : cursor + 2], "little")
    cursor += 2

    dependency_size = dep_count * 4
    if len(payload) - cursor < dependency_size:
        raise ValueError(
            f"truncated THREAT_BEGIN dependency_ids: need {dependency_size} bytes, "
            f"have {len(payload) - cursor}"
        )
    dependencies = tuple(
        int.from_bytes(payload[offset : offset + 4], "little")
        for offset in range(cursor, cursor + dependency_size, 4)
    )
    cursor += dependency_size

    ext_size = ext_count * 2
    if len(payload) - cursor < ext_size:
        raise ValueError(
            f"truncated THREAT_BEGIN ext_entries: need {ext_size} bytes, "
            f"have {len(payload) - cursor}"
        )
    ext_entries = tuple(
        int.from_bytes(payload[offset : offset + 2], "little")
        for offset in range(cursor, cursor + ext_size, 2)
    )
    cursor += ext_size

    remaining = len(payload) - cursor
    if 0 < remaining < 6 and remaining != 2:
        raise ValueError(
            f"truncated THREAT_BEGIN metadata tail: need 6 bytes, have {remaining}"
        )
    metadata = None
    metadata_wire_size = 0
    if remaining == 2:
        metadata = ThreatMetadata(
            short_description_id=int.from_bytes(payload[cursor : cursor + 2], "little"),
            threat_advice_id=0,
            severity=0,
            action=0,
        )
        metadata_wire_size = 2
        cursor += 2
    elif remaining >= 6:
        metadata = ThreatMetadata(
            short_description_id=int.from_bytes(payload[cursor : cursor + 2], "little"),
            threat_advice_id=int.from_bytes(payload[cursor + 2 : cursor + 4], "little"),
            severity=payload[cursor + 4],
            action=payload[cursor + 5],
        )
        metadata_wire_size = 6
        cursor += 6

    marker_len = 0
    while marker_len < len(name_raw) and name_raw[marker_len] >= 0x80:
        marker_len += 1
    marker_raw = name_raw[:marker_len]
    display_name_raw = name_raw[marker_len:]
    nul = display_name_raw.find(b"\0")
    if nul != -1:
        display_name_raw = display_name_raw[:nul]
    name = display_name_raw.decode("utf-8", errors="replace").strip()
    if not name:
        name = f"threat_{threat_id:08x}"

    return ThreatBegin(
        raw=payload,
        threat_id=threat_id,
        dep_count=dep_count,
        ext_count=ext_count,
        category=category,
        name_len=name_len,
        name_raw=name_raw,
        post_name_zero=post_name_zero,
        dependencies=dependencies,
        ext_entries=ext_entries,
        metadata=metadata,
        metadata_wire_size=metadata_wire_size,
        marker_raw=marker_raw,
        display_name_raw=display_name_raw,
        name=name,
        trailing_raw=payload[cursor:],
    )


def parse_threat_end(payload: bytes) -> ThreatEnd:
    if len(payload) < 4:
        raise ValueError("truncated THREAT_END value")
    return ThreatEnd(
        raw=payload,
        value=int.from_bytes(payload[:4], "little"),
        trailing_raw=payload[4:],
    )


def render_threat_begin(threat: ThreatBegin) -> FormatResult:
    category = threat_category_name(threat.category) or "?"
    category_display = f"{threat.category:#06x}  ({category})"
    threat_id_display = f"{threat.threat_id:#010x}"
    if magic := MAGIC_THREAT_IDS.get(threat.threat_id):
        threat_id_display += f"  [{magic}]"
    fields = [
        ("threat_id", threat_id_display),
        ("header_category", category_display),
        ("dep_count", str(threat.dep_count)),
        (
            "dependency_ids",
            f"[{', '.join(format(item, '#010x') for item in threat.dependencies)}]",
        ),
        ("ext_count", str(threat.ext_count)),
        (
            "ext_entries",
            f"[{', '.join(format(item, '#06x') for item in threat.ext_entries)}]",
        ),
        ("post_name_zero", f"{threat.post_name_zero:#06x}"),
        ("name_len", str(threat.name_len)),
        ("name", threat.name),
    ]
    if threat.metadata is not None:
        metadata = threat.metadata
        fields.append(
            (
                (
                    "wire_metadata"
                    if threat.metadata_wire_size == 6
                    else "wire_metadata_partial (2 bytes; remaining words defaulted)"
                ),
                (
                    f"short_description_id={metadata.short_description_id:#06x}, "
                    f"threat_advice_id={metadata.threat_advice_id:#06x}, "
                    f"severity={metadata.severity:#04x}, action={metadata.action:#04x}"
                ),
            )
        )
    else:
        metadata = threat.effective_metadata
        fields.append(
            (
                "effective_metadata (wire tail absent)",
                (
                    f"short_description_id={metadata.short_description_id:#06x}, "
                    f"threat_advice_id={metadata.threat_advice_id:#06x}, "
                    f"severity={metadata.severity:#04x}, action={metadata.action:#04x}"
                ),
            )
        )
    if threat.marker_raw:
        fields.append(("name_marker_raw", threat.marker_raw.hex(" ")))
    if threat.trailing_raw:
        fields.append(("trailing_raw", threat.trailing_raw.hex(" ")))
    return FormatResult(fields=tuple(fields))


def render_threat_end(threat: ThreatEnd) -> FormatResult:
    fields = [("value", f"{threat.value:#010x}")]
    if threat.trailing_raw:
        fields.append(("trailing_raw", threat.trailing_raw.hex(" ")))
    return FormatResult(fields=tuple(fields))


def _raw_span(offset: int, raw: bytes) -> JSONObject:
    return JSONObject(
        (("offset", offset), ("length", len(raw)), ("raw_hex", raw.hex()))
    )


def export_threat_begin_semantics(threat: ThreatBegin) -> RuleSemantics:
    """Export THREAT_BEGIN as an association anchor and metadata record."""
    category_name = threat_category_name(threat.category)
    issues = [
        SemanticIssue(
            "threat_container_not_detection_predicate",
            "THREAT_BEGIN identifies and groups a threat namespace; it does not "
            "describe a scan-time detection predicate or verdict.",
        ),
        SemanticIssue(
            "extension_entry_semantics_unknown",
            "The ext_entries values are preserved as raw numeric entries; their "
            "individual platform or flag meanings are unresolved.",
            (("count", len(threat.ext_entries)),),
        ),
        SemanticIssue(
            "post_name_word_producer_semantics_unknown",
            "The current receiver skips post_name_zero without using it as a "
            "condition; its producer-side format purpose remains unknown.",
            (("raw_value", threat.post_name_zero),),
        ),
    ]
    if threat.trailing_raw:
        issues.append(
            SemanticIssue(
                "trailing_bytes_uninterpreted",
                "Bytes after the confirmed optional metadata are retained without "
                "receiver semantics.",
                (("length", len(threat.trailing_raw)),),
            )
        )
    metadata = None
    if threat.metadata is not None:
        metadata = JSONObject(
            (
                ("short_description_id", threat.metadata.short_description_id),
                ("threat_advice_id", threat.metadata.threat_advice_id),
                ("severity", threat.metadata.severity),
                ("action", threat.metadata.action),
                ("wire_size", threat.metadata_wire_size),
            )
        )
    return RuleSemantics(
        status="unsupported" if threat.trailing_raw else "confirmed_subset",
        representation="threat-association.anchor.v1",
        data=JSONObject(
            (
                ("record_type", "THREAT_BEGIN"),
                ("container_role", "establishes_active_threat_association"),
                ("raw_hex", threat.raw.hex()),
                (
                    "threat_id",
                    JSONObject(
                        (
                            ("value", threat.threat_id),
                            ("wire", _raw_span(0, threat.raw[:4])),
                            ("sentinel_kind", MAGIC_THREAT_IDS.get(threat.threat_id)),
                        )
                    ),
                ),
                (
                    "category",
                    JSONObject(
                        (
                            ("value", threat.category),
                            ("name", category_name),
                            ("wire", _raw_span(8, threat.raw[8:10])),
                        )
                    ),
                ),
                (
                    "name",
                    JSONObject(
                        (
                            ("display_decoded_utf8_lossy", threat.name),
                            ("raw_hex", threat.name_raw.hex()),
                            ("display_bytes_hex", threat.display_name_raw.hex()),
                            ("marker_hex", threat.marker_raw.hex()),
                        )
                    ),
                ),
                (
                    "dependencies",
                    JSONObject(
                        (
                            ("count", threat.dep_count),
                            ("threat_ids", JSONArray(threat.dependencies)),
                        )
                    ),
                ),
                (
                    "extension_entries",
                    JSONObject(
                        (
                            ("count", threat.ext_count),
                            ("raw_values", JSONArray(threat.ext_entries)),
                        )
                    ),
                ),
                ("post_name_zero", threat.post_name_zero),
                ("metadata", metadata),
                ("trailing_raw_hex", threat.trailing_raw.hex()),
            )
        ),
        evidence=(
            "mpengine 1.443.903.0 threat_info_receiver @ 0x1809EB590",
            "mpengine 1.443.903.0 DispatchRecords @ 0x1800F99A8",
        ),
        profile="mpengine-1.443.903.0",
        issues=tuple(issues),
        claims=(
            SemanticClaim(
                id="threat_begin_association",
                scope="loader_dispatch",
                statement=(
                    "THREAT_BEGIN supplies the active threat or namespace association "
                    "used while subsequent records are received."
                ),
                coverage="subset",
                evidence_refs=("threat_begin_receiver",),
                unknowns=(
                    SemanticUnknown(
                        "loader_dispatch",
                        "Special sentinel handling and every loader mode are not closed.",
                    ),
                ),
            ),
            SemanticClaim(
                id="threat_begin_detection_predicate",
                scope="detection_predicate",
                statement="THREAT_BEGIN does not establish a detection predicate.",
                coverage="unknown",
                unknowns=(
                    SemanticUnknown(
                        "detection_predicate",
                        "The record is metadata and association state; no matcher "
                        "predicate dataflow was followed.",
                    ),
                ),
            ),
            SemanticClaim(
                id="threat_begin_report_mapping",
                scope="report_mapping",
                statement=(
                    "The receiver-built threat index and metadata are consumed by "
                    "the runtime resource-report chain, which remaps selectors, "
                    "updates resource state, constructs a threat callback record, "
                    "and forwards its SCANSTRUCT pointer through the callback pair "
                    "preserved in the current thread's scan request."
                ),
                coverage="subset",
                evidence_refs=("threat_begin_report_chain",),
                unknowns=(
                    SemanticUnknown(
                        "report_mapping",
                        "The concrete callback target for each runtime scan, complete "
                        "action/severity policy, and externally visible outcome are "
                        "not established.",
                    ),
                ),
            ),
            SemanticClaim(
                id="threat_begin_final_verdict",
                scope="final_verdict",
                statement="THREAT_BEGIN does not establish a final verdict.",
                coverage="unknown",
                unknowns=(
                    SemanticUnknown(
                        "final_verdict",
                        "The report chain reaches FireProgressCallback, but its host "
                        "consumer and final malicious/benign disposition are unknown.",
                    ),
                ),
            ),
        ),
        claim_evidence=(
            SemanticEvidence(
                id="threat_begin_receiver",
                axis="dispatch",
                kind="engine_static",
                source_ref="mpengine 1.443.903.0",
                locator=(
                    "threat_info_receiver @ 0x1809EB590; DispatchRecords @ 0x1800F99A8"
                ),
                supports=("threat_begin_association",),
            ),
            SemanticEvidence(
                id="threat_begin_report_chain",
                axis="report",
                kind="engine_static",
                source_ref="mpengine 1.443.903.0",
                locator=(
                    "report_threat_component @ 0x18012FA84; "
                    "get_threat_index_ex @ 0x18012FF74; "
                    "store_object_name @ 0x18012EE94; "
                    "FireThreatReportCallback @ 0x18012E24C; "
                    "FireProgressCallback @ 0x180226020; "
                    "ScanOpenWithContext @ 0x180214764; "
                    "CResmgrPlugin::CResmgrPlugin @ 0x18004C850"
                ),
                supports=("threat_begin_report_mapping",),
            ),
        ),
    )


def export_threat_end_semantics(threat: ThreatEnd) -> RuleSemantics:
    """Export 0x5D dispatch/cache observations without inventing value semantics."""
    return RuleSemantics(
        status="unsupported" if threat.trailing_raw else "confirmed_subset",
        representation="threat-end.container-observation.v3",
        data=JSONObject(
            (
                ("record_type", "THREAT_END"),
                ("container_role", None),
                (
                    "raw_dispatch_observation",
                    (
                        "DispatchRecords(mode!=0) sends non-0x5C records, including "
                        "0x5D, through DispatchRecord and the shared ordinal epilogue; "
                        "no 0x5D-specific close/finalize branch was observed."
                    ),
                ),
                ("raw_hex", threat.raw.hex()),
                (
                    "observed_value",
                    JSONObject(
                        (
                            ("value", threat.value),
                            ("wire", _raw_span(0, threat.raw[:4])),
                            (
                                "cache_writer_storage",
                                "dword_181289CB8 when payload size is four",
                            ),
                        )
                    ),
                ),
                (
                    "cache_writer_observation",
                    JSONObject(
                        (
                            ("global", "dword_181289CB8"),
                            ("source", "DispatchRecords @ 0x1800F99A8"),
                            (
                                "behavior",
                                (
                                    "For payload size 4, save the DWORD. A nonzero "
                                    "value defers the current raw-record write. Before "
                                    "the next record, emit {DWORD 1117, DWORD value} "
                                    "unless that next type is 0x5C, then clear pending "
                                    "state. Zero does not take the deferred-write path."
                                ),
                            ),
                            (
                                "global_xrefs",
                                JSONArray(
                                    ("0x1800F9CD2", "0x1800F9CE0", "0x1800F9E4E")
                                ),
                            ),
                            (
                                "cache_replay",
                                (
                                    "DWORD 1117 is bytes 5D 04 00 00; the cache "
                                    "reader reframes the pair as type 0x5D, size 4, "
                                    "and DispatchRecords(mode=1) uses ordinary "
                                    "DispatchRecord."
                                ),
                            ),
                        )
                    ),
                ),
                (
                    "threat_manager_registration",
                    (
                        "threat_mgr_init_module @ 0x1809EBA10 registers "
                        "threat_info_receiver and threat_info_end for type 0x5C "
                        "only; threat_info_end @ 0x1809EB100 finalizes staged threat "
                        "rows and dependencies but does not read the 0x5D DWORD."
                    ),
                ),
                (
                    "registration_census",
                    JSONObject(
                        (
                            (
                                "scope",
                                "direct_and_data_xrefs_to_two_registration_writers",
                            ),
                            ("direct_callsites", 171),
                            ("classified_callsites", 171),
                            ("unresolved_callsites", 0),
                            ("unprocessed_direct_callsites", 0),
                            ("data_xrefs", 2),
                            ("classified_data_xrefs", 2),
                            ("to_entry_xrefs", 0),
                            (
                                "pdata_metadata_xrefs",
                                JSONArray(("0x1812B96A0", "0x1812B0958")),
                            ),
                            ("unresolved_static_xrefs", 0),
                            ("recovered_type_0x5d_registrations", 0),
                            (
                                "classified_direct_constructor_examples",
                                JSONArray(
                                    (
                                        "0x1802C60F7: kcrce_t, type 0x80",
                                        "0x1805A23D7: pestaticex_t, type 0xCB",
                                        "0x1805C10B7: snidex_entry_t, type 0xE5",
                                        "0x1805DF966: revokedcert_t, type 0x6C",
                                    )
                                ),
                            ),
                            (
                                "constructor_examples_exhaustive",
                                False,
                            ),
                            (
                                "conclusion",
                                (
                                    "All 171 direct callsites and both data xrefs were "
                                    "classified. The data xrefs at 0x1812B96A0 and "
                                    "0x1812B0958 are PE .pdata RUNTIME_FUNCTION metadata, "
                                    "not function pointers; to-entry xrefs are zero and "
                                    "unresolved static xrefs are zero. This static census "
                                    "does not exclude computed or runtime-dynamic calls, "
                                    "so it is not a global absence claim."
                                ),
                            ),
                        )
                    ),
                ),
                (
                    "corpus_invariant",
                    JSONObject(
                        (
                            ("scope", "current_mpas_mpav_corpus"),
                            ("evidence_tier", "corpus_invariant"),
                            ("coverage", "subset"),
                            ("mpas_begin_end", JSONArray((17989, 17989))),
                            ("mpav_begin_end", JSONArray((342609, 342609))),
                            ("all_end_payloads_length", 4),
                            ("end_value_matches_paired_begin_threat_id", True),
                            ("nested", 0),
                            ("orphan", 0),
                            ("unmatched", 0),
                            ("dangling", 0),
                            ("end_value_matches_inner_record_count_count", 0),
                            (
                                "value_interpretation",
                                "unassigned; not identified as checksum",
                            ),
                        )
                    ),
                ),
                (
                    "error_boundary",
                    (
                        "Malformed framing returns 40964; receiver errors propagate; "
                        "load cancellation returns 36868; unresolved dependency in "
                        "threat_info_end returns 32780. These are not 0x5D value "
                        "semantics."
                    ),
                ),
                ("trailing_raw_hex", threat.trailing_raw.hex()),
            )
        ),
        evidence=(
            "mpengine 1.443.903.0 DispatchRecords @ 0x1800F99A8",
            "mpengine 1.443.903.0 DispatchRecord @ 0x1800FAF18",
            "mpengine 1.443.903.0 threat_mgr_init_module @ 0x1809EBA10",
            "mpengine 1.443.903.0 threat_info_end @ 0x1809EB100",
            (
                "mpengine 1.443.903.0 bounded static-xref census: 171 direct callsites "
                "and 2 data xrefs classified; both data xrefs are PE .pdata "
                "RUNTIME_FUNCTION metadata, with zero to-entry xrefs and zero "
                "unresolved static xrefs; computed/runtime dynamic calls are not excluded"
            ),
            (
                "Current mpas/mpav corpus invariant (subset): mpas BEGIN/END "
                "17989/17989; mpav 342609/342609; every END has a four-byte payload "
                "matching its paired BEGIN threat_id; nested/orphan/unmatched/dangling "
                "counts are zero; END values do not equal inner-record counts. This "
                "does not identify a checksum or establish engine semantics."
            ),
        ),
        profile="mpengine-1.443.903.0",
        issues=(
            SemanticIssue(
                "threat_end_value_semantics_unknown",
                "No inspected current-binary path proves that this value is a "
                "threat ID, checksum, namespace, or group terminator.",
            ),
            SemanticIssue(
                "threat_container_not_detection_predicate",
                "No inspected current-binary path establishes type 0x5D as a "
                "scan-time detection predicate or verdict; a threat-group "
                "closing role is also not established.",
            ),
            SemanticIssue(
                "threat_end_dynamic_registration_boundary",
                "The bounded static census classifies all 171 direct callsites and "
                "both data xrefs; both data xrefs are PE .pdata RUNTIME_FUNCTION "
                "metadata, not function pointers, and unresolved_static_xrefs is zero. "
                "Computed or runtime-dynamic calls remain outside this census.",
                (
                    ("direct_callsites", 171),
                    ("classified_callsites", 171),
                    ("unresolved_callsites", 0),
                    ("data_xrefs", 2),
                    ("classified_data_xrefs", 2),
                    ("to_entry_xrefs", 0),
                    ("unresolved_static_xrefs", 0),
                    ("computed_runtime_dynamic_calls_ruled_out", False),
                ),
            ),
            *(
                (
                    SemanticIssue(
                        "trailing_bytes_uninterpreted",
                        "Only the first DWORD has an observed cache-writer role.",
                        (("length", len(threat.trailing_raw)),),
                    ),
                )
                if threat.trailing_raw
                else ()
            ),
        ),
        claims=(
            SemanticClaim(
                id="threat_end_dispatch_cache",
                scope="loader_dispatch",
                statement=(
                    "A four-byte 0x5D payload can be staged by DispatchRecords and "
                    "reframed through the cache path."
                ),
                coverage="subset",
                evidence_refs=("threat_end_dispatch",),
                unknowns=(
                    SemanticUnknown(
                        "loader_dispatch",
                        "The DWORD meaning remains unresolved; computed or runtime-dynamic "
                        "registration paths are outside the static-xref census.",
                    ),
                ),
            ),
            SemanticClaim(
                id="threat_end_detection_predicate",
                scope="detection_predicate",
                statement="No 0x5D detection predicate is established.",
                coverage="unknown",
                unknowns=(
                    SemanticUnknown(
                        "detection_predicate",
                        "Dispatch and cache behavior do not establish matching semantics.",
                    ),
                ),
            ),
            SemanticClaim(
                id="threat_end_final_verdict",
                scope="final_verdict",
                statement="No 0x5D final verdict role is established.",
                coverage="unknown",
                unknowns=(
                    SemanticUnknown(
                        "final_verdict",
                        "No close, report, or final-verdict branch tied to the DWORD "
                        "was observed.",
                    ),
                ),
            ),
        ),
        claim_evidence=(
            SemanticEvidence(
                id="threat_end_dispatch",
                axis="dispatch",
                kind="engine_static",
                source_ref="mpengine 1.443.903.0",
                locator=("DispatchRecords @ 0x1800F99A8; DispatchRecord @ 0x1800FAF18"),
                supports=("threat_end_dispatch_cache",),
            ),
        ),
    )


THREAT_BEGIN_SPEC = FamilySpec(
    THREAT_BEGIN_TYPE,
    "THREAT_BEGIN",
    parse_threat_begin,
    render_threat_begin,
    semantic_exporter=export_threat_begin_semantics,
)
THREAT_END_SPEC = FamilySpec(
    THREAT_END_TYPE,
    "THREAT_END",
    parse_threat_end,
    render_threat_end,
    semantic_exporter=export_threat_end_semantics,
)
THREAT_SPECS = (THREAT_BEGIN_SPEC, THREAT_END_SPEC)
