"""Lossless structural parser for TARGET_SCRIPT_PCODE (0x90) payloads.

Pattern tokens are retained as integers and are not presented as decompiled
bytecode.  The signature-table control fields use names confirmed from the
native ``TargSig`` consumer; unresolved Match-vector fields remain raw.
"""

import json
from dataclasses import dataclass
from typing import Final

from ..core import (
    Artifact,
    ArtifactExport,
    DisplaySection,
    FamilySpec,
    FormatResult,
)

TARGET_SCRIPT_PCODE_TYPE: Final = 0x90
FAMILY_COUNT: Final = 6
SUBTYPE_COUNT: Final = 2
_SECTION_HEADER_SIZE: Final = 6
_SIGNATURE_ENTRY_HEADER_SIZE: Final = 11
_MATCH_SIZE: Final = 6
_RENDER_SECTION_LIMIT: Final = 12
_RENDER_ARRAY_LIMIT: Final = 2
_RENDER_TOKEN_LIMIT: Final = 4
_RENDER_ENTRY_LIMIT: Final = 4
_PREVIEW_BYTES: Final = 16
_RENDER_VALUE_LIMIT: Final = 512


@dataclass(frozen=True, slots=True)
class TargetScriptTokenArray:
    token_count: int
    tokens: tuple[int, ...]
    offset: int
    end_offset: int
    raw: bytes


@dataclass(frozen=True, slots=True)
class TargetScriptPatternSection:
    family: int
    subtype: int
    count: int
    token_arrays: tuple[TargetScriptTokenArray, ...]
    offset: int
    end_offset: int
    raw: bytes


@dataclass(frozen=True, slots=True)
class TargetScriptMatch:
    base: int
    selector_raw: int
    value_raw: int
    offset: int
    end_offset: int
    raw: bytes


@dataclass(frozen=True, slots=True)
class TargetScriptSignatureEntry:
    nid_value: int
    nid_value_raw: bytes
    outcome_control: int
    context_filter: int
    target_type: int
    match_count: int
    matches: tuple[TargetScriptMatch, ...]
    offset: int
    end_offset: int
    raw: bytes


@dataclass(frozen=True, slots=True)
class TargetScriptSignatureTable:
    family: int
    subtype: int
    count: int
    entry_count: int
    entries: tuple[TargetScriptSignatureEntry, ...]
    offset: int
    end_offset: int
    header_raw: bytes
    raw: bytes


@dataclass(frozen=True, slots=True)
class TargetScriptPcodePayload:
    raw: bytes
    pattern_sections: tuple[TargetScriptPatternSection, ...]
    signature_table: TargetScriptSignatureTable

    def to_bytes(self) -> bytes:
        """Return the original wire payload without normalization."""
        return self.raw


class _Cursor:
    __slots__ = ("data", "offset")

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.offset = 0

    def read(self, size: int, field: str) -> bytes:
        remaining = len(self.data) - self.offset
        if size < 0 or size > remaining:
            raise ValueError(
                f"truncated TARGET_SCRIPT_PCODE {field}: need {size} bytes, "
                f"have {remaining} at offset 0x{self.offset:X}"
            )
        start = self.offset
        self.offset += size
        return self.data[start : self.offset]

    def u8(self, field: str) -> int:
        return self.read(1, field)[0]

    def u16(self, field: str) -> int:
        return int.from_bytes(self.read(2, field), "little")

    def u32(self, field: str) -> tuple[int, bytes]:
        raw = self.read(4, field)
        return int.from_bytes(raw, "little"), raw


def parse_target_script_pcode(payload: bytes) -> TargetScriptPcodePayload:
    """Parse complete family/subtype token sections and the final sig table.

    The `(family=0, subtype=0, count=0)` section header is the signature-table
    marker. Its table must consume the rest of the payload exactly.
    """
    if not isinstance(payload, bytes):
        raise TypeError("TARGET_SCRIPT_PCODE payload must be bytes")

    cursor = _Cursor(payload)
    pattern_sections: list[TargetScriptPatternSection] = []

    while cursor.offset < len(payload):
        section_start = cursor.offset
        header_raw = cursor.read(_SECTION_HEADER_SIZE, "section header")
        family = header_raw[0]
        subtype = header_raw[1]
        count = int.from_bytes(header_raw[2:6], "little")
        if family >= FAMILY_COUNT:
            raise ValueError(
                f"invalid TARGET_SCRIPT_PCODE family {family} "
                f"at offset 0x{section_start:X}"
            )
        if subtype >= SUBTYPE_COUNT:
            raise ValueError(
                f"invalid TARGET_SCRIPT_PCODE subtype {subtype} "
                f"at offset 0x{section_start:X}"
            )

        if family == 0 and subtype == 0 and count == 0:
            table_start = section_start
            entry_count, _ = cursor.u32("signature entry count")
            remaining = len(payload) - cursor.offset
            if entry_count > remaining // _SIGNATURE_ENTRY_HEADER_SIZE:
                raise ValueError(
                    "invalid TARGET_SCRIPT_PCODE signature entry count: "
                    f"{entry_count} entries cannot fit in {remaining} bytes"
                )

            entries: list[TargetScriptSignatureEntry] = []
            for entry_index in range(entry_count):
                entry_start = cursor.offset
                nid_value, nid_value_raw = cursor.u32(
                    f"signature entry {entry_index} NID value"
                )
                controls_raw = cursor.read(
                    3, f"signature entry {entry_index} control fields"
                )
                match_count, _ = cursor.u32(
                    f"signature entry {entry_index} match count"
                )
                remaining = len(payload) - cursor.offset
                if match_count > remaining // _MATCH_SIZE:
                    raise ValueError(
                        "invalid TARGET_SCRIPT_PCODE match count: "
                        f"{match_count} matches cannot fit in {remaining} bytes "
                        f"at offset 0x{entry_start:X}"
                    )

                matches: list[TargetScriptMatch] = []
                for match_index in range(match_count):
                    match_start = cursor.offset
                    base, _ = cursor.u32(
                        f"entry {entry_index} match {match_index} base"
                    )
                    selector = cursor.u8(
                        f"entry {entry_index} match {match_index} selector"
                    )
                    if selector >= 2:
                        raise ValueError(
                            "invalid TARGET_SCRIPT_PCODE match selector "
                            f"{selector} at offset 0x{match_start + 4:X}"
                        )
                    value = cursor.u8(f"entry {entry_index} match {match_index} value")
                    matches.append(
                        TargetScriptMatch(
                            base=base,
                            selector_raw=selector,
                            value_raw=value,
                            offset=match_start,
                            end_offset=cursor.offset,
                            raw=payload[match_start : cursor.offset],
                        )
                    )

                entries.append(
                    TargetScriptSignatureEntry(
                        nid_value=nid_value,
                        nid_value_raw=nid_value_raw,
                        outcome_control=controls_raw[0],
                        context_filter=controls_raw[1],
                        target_type=controls_raw[2],
                        match_count=match_count,
                        matches=tuple(matches),
                        offset=entry_start,
                        end_offset=cursor.offset,
                        raw=payload[entry_start : cursor.offset],
                    )
                )

            if cursor.offset != len(payload):
                raise ValueError(
                    "trailing bytes after TARGET_SCRIPT_PCODE signature table: "
                    f"{len(payload) - cursor.offset} bytes at "
                    f"offset 0x{cursor.offset:X}"
                )

            table = TargetScriptSignatureTable(
                family=family,
                subtype=subtype,
                count=count,
                entry_count=entry_count,
                entries=tuple(entries),
                offset=table_start,
                end_offset=cursor.offset,
                header_raw=header_raw,
                raw=payload[table_start : cursor.offset],
            )
            return TargetScriptPcodePayload(
                raw=payload,
                pattern_sections=tuple(pattern_sections),
                signature_table=table,
            )

        section_arrays: list[TargetScriptTokenArray] = []
        for array_index in range(count):
            array_start = cursor.offset
            token_count = cursor.u16(f"section token array {array_index} count")
            token_bytes = cursor.read(
                token_count * 4, f"section token array {array_index} tokens"
            )
            tokens = tuple(
                int.from_bytes(token_bytes[offset : offset + 4], "little")
                for offset in range(0, len(token_bytes), 4)
            )
            section_arrays.append(
                TargetScriptTokenArray(
                    token_count=token_count,
                    tokens=tokens,
                    offset=array_start,
                    end_offset=cursor.offset,
                    raw=payload[array_start : cursor.offset],
                )
            )

        pattern_sections.append(
            TargetScriptPatternSection(
                family=family,
                subtype=subtype,
                count=count,
                token_arrays=tuple(section_arrays),
                offset=section_start,
                end_offset=cursor.offset,
                raw=payload[section_start : cursor.offset],
            )
        )

    raise ValueError("missing TARGET_SCRIPT_PCODE signature table")


def _hex_preview(data: bytes, limit: int = _PREVIEW_BYTES) -> str:
    preview = data[:limit].hex(" ")
    return preview + (" ..." if len(data) > limit else "")


def render_target_script_pcode(
    parsed: TargetScriptPcodePayload,
) -> FormatResult:
    """Render counts and short previews; never dump complete token arrays."""
    rows: list[tuple[str, str]] = [
        ("payload_length", f"{len(parsed.raw)} B"),
        ("pattern_section_count", str(len(parsed.pattern_sections))),
        ("signature_entry_count", str(parsed.signature_table.entry_count)),
        (
            "signature_match_count",
            str(sum(entry.match_count for entry in parsed.signature_table.entries)),
        ),
        (
            "interpretation",
            "compiled-token candidates and targeted NID checks; not bytecode",
        ),
    ]

    for section_index, section in enumerate(
        parsed.pattern_sections[:_RENDER_SECTION_LIMIT]
    ):
        rows.append(
            (
                f"section_{section_index}",
                (
                    f"family={section.family}, subtype={section.subtype}, "
                    f"count={section.count}, offset=0x{section.offset:X}.."
                    f"0x{section.end_offset:X}"
                ),
            )
        )
        for array_index, token_array in enumerate(
            section.token_arrays[:_RENDER_ARRAY_LIMIT]
        ):
            token_preview = ", ".join(
                f"0x{token:08X}" for token in token_array.tokens[:_RENDER_TOKEN_LIMIT]
            )
            suffix = " ..." if token_array.token_count > _RENDER_TOKEN_LIMIT else ""
            rows.append(
                (
                    f"section_{section_index}_array_{array_index}",
                    f"token_count={token_array.token_count}; {token_preview}{suffix}",
                )
            )

    if len(parsed.pattern_sections) > _RENDER_SECTION_LIMIT:
        rows.append(
            (
                "pattern_sections_omitted",
                str(len(parsed.pattern_sections) - _RENDER_SECTION_LIMIT),
            )
        )

    table = parsed.signature_table
    for entry_index, entry in enumerate(table.entries[:_RENDER_ENTRY_LIMIT]):
        rows.append(
            (
                f"signature_entry_{entry_index}",
                (
                    f"nid_value=0x{entry.nid_value:08X}, "
                    f"outcome={entry.outcome_control}, "
                    f"context_filter=0x{entry.context_filter:02X}, "
                    f"target_type=0x{entry.target_type:02X}, "
                    f"match_count={entry.match_count}, "
                    f"offset=0x{entry.offset:X}..0x{entry.end_offset:X}"
                ),
            )
        )
    if table.entry_count > _RENDER_ENTRY_LIMIT:
        rows.append(
            (
                "signature_entries_omitted",
                str(table.entry_count - _RENDER_ENTRY_LIMIT),
            )
        )

    bounded_rows = tuple((key, value[:_RENDER_VALUE_LIMIT]) for key, value in rows)
    return FormatResult(
        sections=(DisplaySection("TARGET_SCRIPT_PCODE", rows=bounded_rows),)
    )


def _manifest(parsed: TargetScriptPcodePayload) -> dict[str, object]:
    return {
        "format": "TARGET_SCRIPT_PCODE",
        "type_byte": TARGET_SCRIPT_PCODE_TYPE,
        "interpretation": (
            "compiled-token candidates and targeted NID checks; not bytecode"
        ),
        "payload_length": len(parsed.raw),
        "payload_raw_hex": parsed.raw.hex(),
        "pattern_sections": [
            {
                "family": section.family,
                "subtype": section.subtype,
                "count": section.count,
                "offset": section.offset,
                "end_offset": section.end_offset,
                "raw_hex": section.raw.hex(),
                "token_arrays": [
                    {
                        "token_count": token_array.token_count,
                        "offset": token_array.offset,
                        "end_offset": token_array.end_offset,
                        "tokens": list(token_array.tokens),
                        "raw_hex": token_array.raw.hex(),
                    }
                    for token_array in section.token_arrays
                ],
            }
            for section in parsed.pattern_sections
        ],
        "signature_table": {
            "family": parsed.signature_table.family,
            "subtype": parsed.signature_table.subtype,
            "count": parsed.signature_table.count,
            "entry_count": parsed.signature_table.entry_count,
            "offset": parsed.signature_table.offset,
            "end_offset": parsed.signature_table.end_offset,
            "header_raw_hex": parsed.signature_table.header_raw.hex(),
            "raw_hex": parsed.signature_table.raw.hex(),
            "entries": [
                {
                    "nid_value": entry.nid_value,
                    "nid_value_raw_hex": entry.nid_value_raw.hex(),
                    "outcome_control": entry.outcome_control,
                    "context_filter": entry.context_filter,
                    "target_type": entry.target_type,
                    "match_count": entry.match_count,
                    "offset": entry.offset,
                    "end_offset": entry.end_offset,
                    "raw_hex": entry.raw.hex(),
                    "matches": [
                        {
                            "base": match.base,
                            "selector_raw": match.selector_raw,
                            "value_raw": match.value_raw,
                            "offset": match.offset,
                            "end_offset": match.end_offset,
                            "raw_hex": match.raw.hex(),
                        }
                        for match in entry.matches
                    ],
                }
                for entry in parsed.signature_table.entries
            ],
        },
    }


def export_target_script_pcode_json(parsed: TargetScriptPcodePayload) -> str:
    """Export a complete JSON manifest without assigning code semantics."""
    return json.dumps(_manifest(parsed), separators=(",", ":"))


def export_target_script_pcode(parsed: TargetScriptPcodePayload) -> ArtifactExport:
    """Export the complete wire-level structure without claiming decompilation."""
    manifest = export_target_script_pcode_json(parsed).encode("utf-8")
    return ArtifactExport(
        "ready",
        artifacts=(
            Artifact(
                "target_script_pcode.json",
                "target_script_pcode_manifest",
                manifest,
            ),
        ),
    )


SPEC = FamilySpec(
    TARGET_SCRIPT_PCODE_TYPE,
    "TARGET_SCRIPT_PCODE",
    parse_target_script_pcode,
    render_target_script_pcode,
    exporter=export_target_script_pcode,
)
