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
    SemanticIssue,
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
        representation="delta_blob_recinfo.observed_metadata.v1",
        data=JSONObject(
            (
                ("record_type", "DELTA_BLOB_RECINFO"),
                ("raw_hex", parsed.raw.hex()),
                ("entry_count", parsed.entry_count),
                ("entry_size", ENTRY_SIZE),
                ("entries", entries),
                (
                    "association",
                    "adjacent DELTA_BLOB record observed; exact linkage unresolved",
                ),
                (
                    "detection_relevance",
                    "metadata observation; no detection predicate established",
                ),
            )
        ),
        evidence=(
            "mpengine 1.443.903.0 DispatchRecords @ 0x1800F99A8",
            "The alternate-mode 0x74 skip branch does not inspect payload fields",
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
        ),
    )


SPEC = FamilySpec(
    DELTA_BLOB_RECINFO_TYPE,
    "DELTA_BLOB_RECINFO",
    parse_delta_blob_recinfo,
    render_delta_blob_recinfo,
    semantic_exporter=export_delta_blob_recinfo_semantics,
)
