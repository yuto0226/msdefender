"""Lossless parser and bounded renderer for DELTA_BLOB_RECINFO (0x74)."""

from dataclasses import dataclass
from typing import Final

from ..core import (
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

DELTA_BLOB_RECINFO_TYPE: Final = 0x74
ENTRY_SIZE: Final = 4
ENTRY_PREVIEW_LIMIT: Final = 32
RAW_PREVIEW_SIZE: Final = 32


@dataclass(frozen=True, slots=True)
class DeltaBlobRecInfoEntry:
    """Observed entry bytes, with no assigned meaning for either field."""

    type: int
    value: int


@dataclass(frozen=True, slots=True)
class DeltaBlobRecInfo:
    """Observed count-prefixed DELTA_BLOB_RECINFO payload."""

    raw: bytes
    entry_count: int
    entries: tuple[DeltaBlobRecInfoEntry, ...]


def parse_delta_blob_recinfo(payload: bytes) -> DeltaBlobRecInfo:
    """Parse ``u32le count`` followed by exactly ``count`` four-byte entries."""
    if len(payload) < 4:
        raise ValueError("truncated DELTA_BLOB_RECINFO header")

    entry_count = int.from_bytes(payload[:4], "little")
    remaining_size = len(payload) - 4
    if entry_count > remaining_size // ENTRY_SIZE:
        raise ValueError("DELTA_BLOB_RECINFO entry count exceeds available size")
    expected_size = 4 + entry_count * ENTRY_SIZE
    if len(payload) != expected_size:
        raise ValueError("DELTA_BLOB_RECINFO size does not match entry count")

    entries = tuple(
        DeltaBlobRecInfoEntry(
            type=payload[offset],
            value=int.from_bytes(payload[offset + 1 : offset + 4], "little"),
        )
        for offset in range(4, expected_size, ENTRY_SIZE)
    )
    return DeltaBlobRecInfo(raw=payload, entry_count=entry_count, entries=entries)


def _raw_preview(raw: bytes) -> str:
    preview = raw[:RAW_PREVIEW_SIZE].hex(" ") or "(empty)"
    return preview + (" ..." if len(raw) > RAW_PREVIEW_SIZE else "")


def render_delta_blob_recinfo(parsed: DeltaBlobRecInfo) -> FormatResult:
    """Display observed fields with a fixed entry and raw-byte preview bound."""
    rows: list[tuple[str, str]] = [
        ("entry_count", str(parsed.entry_count)),
        ("entry_value_semantics", "semantics unresolved; values shown as raw values"),
    ]
    for index, entry in enumerate(parsed.entries[:ENTRY_PREVIEW_LIMIT]):
        rows.append(
            (
                f"entry[{index}]",
                f"type=0x{entry.type:02X}, value=0x{entry.value:06X}",
            )
        )
    if parsed.entry_count > ENTRY_PREVIEW_LIMIT:
        rows.append(
            (
                "entries_omitted",
                str(parsed.entry_count - ENTRY_PREVIEW_LIMIT),
            )
        )

    return FormatResult(
        sections=(
            DisplaySection("DELTA_BLOB_RECINFO", rows=tuple(rows)),
            DisplaySection(
                "Raw Payload Preview",
                rows=(("raw_preview", _raw_preview(parsed.raw)),),
            ),
        )
    )


def export_delta_blob_recinfo_semantics(parsed: DeltaBlobRecInfo) -> RuleSemantics:
    """Export the exact observed entry bytes without assigning field meanings."""
    entries = JSONArray(
        tuple(
            JSONObject(
                (
                    ("index", index),
                    ("wire_offset", 4 + index * ENTRY_SIZE),
                    ("type_raw", entry.type),
                    ("value_raw_u24le", entry.value),
                    (
                        "raw_hex",
                        parsed.raw[
                            4 + index * ENTRY_SIZE : 8 + index * ENTRY_SIZE
                        ].hex(),
                    ),
                )
            )
            for index, entry in enumerate(parsed.entries)
        )
    )
    return RuleSemantics(
        status="observed_only",
        representation="delta_blob_recinfo.framing_dispatch_observation.v2",
        data=JSONObject(
            (
                ("record_type", "DELTA_BLOB_RECINFO"),
                ("raw_hex", parsed.raw.hex()),
                ("entry_count", parsed.entry_count),
                ("entry_size", ENTRY_SIZE),
                ("entries", entries),
                (
                    "wire_entry_layout",
                    (
                        "The local parser represents each four-byte unit as a one-byte "
                        "raw type plus a three-byte little-endian raw value; no "
                        "engine receiver was found that confirms those field semantics."
                    ),
                ),
                (
                    "engine_disposition",
                    JSONObject(
                        (
                            (
                                "mode0_gate_true",
                                (
                                    "After framing, the 0x74 switch arm at "
                                    "DispatchRecords+0x147 is an empty break; no "
                                    "payload fields are consumed and DispatchRecord "
                                    "is not called."
                                ),
                            ),
                            (
                                "mode0_gate_false",
                                "Falls through to the shared DispatchRecord route.",
                            ),
                            (
                                "mode1",
                                "Calls DispatchRecord(0x74, payload, size).",
                            ),
                            ("receiver_registration", "unconfirmed"),
                        )
                    ),
                ),
                (
                    "delta_blob_linkage",
                    (
                        "No direct linkage from 0x74 entry fields to 0x73 commands, "
                        "compressed input, or reconstructed output was established. "
                        "Both types share a version-gated switch, but use separate arms."
                    ),
                ),
                (
                    "loader_purpose",
                    (
                        "Unknown: the mode0 gate behavior and mode1 generic dispatch "
                        "are observed, but runtime registration, storage, and "
                        "consumer are not identified."
                    ),
                ),
                (
                    "detection_relevance",
                    "metadata observation; no detection predicate established",
                ),
            )
        ),
        evidence=(
            (
                "mpengine 1.443.903.0 DispatchRecords @ 0x1800F99A8: "
                "framing and mode split"
            ),
            (
                "mpengine 1.443.903.0 DispatchRecords @ 0x1800F9AEF: "
                "switch 0x74 empty arm"
            ),
            ("mpengine 1.443.903.0 DispatchRecords @ 0x1800F9AE5: version-gate switch"),
            (
                "mpengine 1.443.903.0 DispatchRecords @ 0x1800F9C90: "
                "mode1 generic dispatch call"
            ),
            (
                "mpengine 1.443.903.0 DispatchRecords @ 0x1800FA010: "
                "mode0 gate-false shared dispatch call"
            ),
            ("mpengine 1.443.903.0 DispatchRecord @ 0x1800FAF18: runtime gktab slots"),
            (
                "mpengine 1.443.903.0 load_database_cache @ 0x1800DBE50 "
                "calls DispatchRecords(mode=1)"
            ),
            (
                "mpengine 1.443.903.0 DispatchProxy::ConsumeInputCompressed "
                "@ 0x1800D9ED0 consumes compressed blocks; no 0x74 entry-field "
                "dataflow to this function was established"
            ),
        ),
        profile="mpengine-1.443.903.0",
        issues=(
            SemanticIssue(
                "entry_field_semantics_unknown",
                (
                    "The one-byte type and three-byte value fields are preserved "
                    "as raw numeric values; their meanings are unresolved."
                ),
                (("entry_count", parsed.entry_count),),
            ),
            SemanticIssue(
                "record_linkage_unconfirmed",
                (
                    "Adjacency to DELTA_BLOB does not prove that entries identify "
                    "its commands or reconstructed output."
                ),
            ),
            SemanticIssue(
                "not_detection_rule",
                (
                    "No evidence establishes that this metadata record is a "
                    "scan-time detection predicate or verdict."
                ),
            ),
            SemanticIssue(
                "runtime_receiver_unconfirmed",
                (
                    "Static IDA data does not establish the initialized 0x74 "
                    "template or handler slot; the type is not proven globally "
                    "ignored."
                ),
            ),
        ),
        claims=(
            SemanticClaim(
                id="delta_recinfo_corpus_presence",
                scope="corpus_observation",
                statement="The current mpas/mpav corpus snapshot contains two type 0x74 records.",
                coverage="subset",
                evidence_refs=("delta_recinfo_corpus",),
                unknowns=(
                    SemanticUnknown(
                        "corpus_observation",
                        "This count does not cover other databases or engine versions.",
                    ),
                ),
            ),
            SemanticClaim(
                id="delta_recinfo_loader_dispatch",
                scope="loader_dispatch",
                statement=(
                    "DispatchRecords has a mode- and gate-dependent 0x74 path: an "
                    "empty break in one mode-0 branch and generic DispatchRecord in "
                    "the other observed branches."
                ),
                coverage="subset",
                evidence_refs=("delta_recinfo_dispatch",),
                unknowns=(
                    SemanticUnknown(
                        "loader_dispatch",
                        "The conclusion is limited to the documented 1.443.903.0 branches.",
                    ),
                ),
            ),
            SemanticClaim(
                id="delta_recinfo_receiver",
                scope="receiver_transform",
                statement="The runtime receiver and normalized storage are unresolved.",
                coverage="unknown",
                unknowns=(
                    SemanticUnknown(
                        "receiver_transform",
                        "No registration-complete 0x74 gktab slot or receiver trace exists.",
                    ),
                ),
            ),
            SemanticClaim(
                id="delta_recinfo_runtime_consumer",
                scope="runtime_consumer",
                statement="A runtime consumer for the projected entries is unresolved.",
                coverage="unknown",
                unknowns=(
                    SemanticUnknown(
                        "runtime_consumer",
                        "No entry-field-to-storage-or-consumer dataflow is established.",
                    ),
                ),
            ),
            SemanticClaim(
                id="delta_recinfo_detection_predicate",
                scope="detection_predicate",
                statement="No type 0x74 detection predicate is established.",
                coverage="unknown",
                unknowns=(
                    SemanticUnknown(
                        "detection_predicate",
                        "The current evidence stops at loader dispatch.",
                    ),
                ),
            ),
            SemanticClaim(
                id="delta_recinfo_final_verdict",
                scope="final_verdict",
                statement="No type 0x74 final-verdict role is established.",
                coverage="unknown",
                unknowns=(
                    SemanticUnknown(
                        "final_verdict",
                        "No consumer, report, or verdict path has been identified.",
                    ),
                ),
            ),
        ),
        claim_evidence=(
            SemanticEvidence(
                id="delta_recinfo_corpus",
                axis="corpus",
                kind="corpus",
                source_ref="mpas.sig + mpav.sig",
                locator="semantic inventory corpus count for type 0x74: 2",
                supports=("delta_recinfo_corpus_presence",),
            ),
            SemanticEvidence(
                id="delta_recinfo_dispatch",
                axis="dispatch",
                kind="engine_static",
                source_ref="mpengine 1.443.903.0",
                locator=(
                    "DispatchRecords @ 0x1800F99A8; branches at "
                    "0x1800F9AE5/0x1800F9AEF; dispatch calls at "
                    "0x1800FA010/0x1800F9C90"
                ),
                supports=("delta_recinfo_loader_dispatch",),
            ),
        ),
    )


SPEC = FamilySpec(
    DELTA_BLOB_RECINFO_TYPE,
    "DELTA_BLOB_RECINFO",
    parse_delta_blob_recinfo,
    render_delta_blob_recinfo,
    semantic_exporter=export_delta_blob_recinfo_semantics,
)
