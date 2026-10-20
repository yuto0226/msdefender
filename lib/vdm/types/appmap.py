"""Lossless parser and bounded renderer for PUA_APPMAP (0xE8)."""

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
    SemanticJSONValue,
)

APPMAP_TYPE: Final = 0xE8
MAX_SECTIONS: Final = 16
_FIXED_ITEM_SIZES: Final = {0x02: 8, 0x03: 20}
_STRING_SECTION_TYPES: Final = frozenset((*range(0x04, 0x0C), *range(0x0D, 0x11)))
_PREVIEW_BYTES: Final = 32
_SECTION_ROLES: Final = {
    0x01: "path_id_to_current_record_ordinal_mapping",
    0x02: "file_hash_or_key_matcher_input",
    0x03: "three_field_metadata_matcher_input",
    0x04: "version_or_certificate_metadata_matcher_input",
    0x05: "app_file_path_matcher_input",
    0x06: "app_folder_path_matcher_input",
    0x07: "path_from_key_matcher_input",
    0x08: "uninstall_path_matcher_input",
    0x09: "resource_string_input",
    0x0A: "resource_string_input",
    0x0B: "resource_string_input",
    0x0C: "receiver_skips_section_body",
    0x0D: "version_or_certificate_metadata_matcher_input",
    0x0E: "version_or_certificate_metadata_matcher_input",
    0x0F: "version_or_certificate_metadata_matcher_input",
    0x10: "version_or_certificate_metadata_matcher_input",
}


@dataclass(frozen=True, slots=True)
class AppMapSection:
    """One non-terminator section, retaining its exact wire representation."""

    type_byte: int
    subtype: int
    offset: int
    raw: bytes
    data_raw: bytes
    u32_values: tuple[int, ...] = ()
    items_raw: tuple[bytes, ...] = ()


@dataclass(frozen=True, slots=True)
class AppMapTerminator:
    """Terminator header and the payload bytes following it."""

    type_byte: int
    subtype: int
    offset: int
    raw: bytes


@dataclass(frozen=True, slots=True)
class AppMapPayload:
    """Parsed PUA app-map sections with complete lossless source bytes."""

    raw: bytes
    sections: tuple[AppMapSection, ...]
    terminator: AppMapTerminator | None
    trailing_raw: bytes


def _need(payload: bytes, cursor: int, size: int, label: str) -> int:
    end = cursor + size
    if end > len(payload):
        raise ValueError(
            f"truncated {label}: need {size} bytes, have {len(payload) - cursor}"
        )
    return end


def _read_c_strings(
    payload: bytes, cursor: int, count: int, section_type: int
) -> tuple[tuple[bytes, ...], int]:
    items: list[bytes] = []
    for index in range(count):
        end = payload.find(b"\0", cursor)
        if end < 0:
            raise ValueError(
                f"type 0x{section_type:02X} item {index + 1} is missing NUL"
            )
        items.append(payload[cursor:end])
        cursor = end + 1
    return tuple(items), cursor


def parse_appmap(payload: bytes) -> AppMapPayload:
    """Parse section headers and preserve opaque/string bytes without decoding."""
    cursor = 0
    sections: list[AppMapSection] = []
    terminator: AppMapTerminator | None = None

    while cursor < len(payload):
        section_offset = cursor
        header_end = _need(payload, cursor, 2, "section header")
        section_type, subtype = payload[cursor], payload[cursor + 1]
        cursor = header_end

        if section_type >= 0x11:
            terminator = AppMapTerminator(
                type_byte=section_type,
                subtype=subtype,
                offset=section_offset,
                raw=payload[section_offset:cursor],
            )
            break
        if section_type == 0:
            raise ValueError(f"invalid section type 0x00 at offset {section_offset}")
        if len(sections) >= MAX_SECTIONS:
            raise ValueError(f"more than {MAX_SECTIONS} non-terminator sections")

        data_start = cursor
        u32_values: tuple[int, ...] = ()
        items_raw: tuple[bytes, ...] = ()

        if section_type == 0x01:
            data_end = _need(payload, cursor, subtype * 4, "type 0x01 DWORD array")
            data_raw = payload[cursor:data_end]
            u32_values = tuple(
                int.from_bytes(data_raw[index : index + 4], "little")
                for index in range(0, len(data_raw), 4)
            )
            cursor = data_end
        elif section_type in _FIXED_ITEM_SIZES:
            item_size = _FIXED_ITEM_SIZES[section_type]
            data_end = _need(
                payload,
                cursor,
                subtype * item_size,
                f"type 0x{section_type:02X} items",
            )
            data_raw = payload[cursor:data_end]
            items_raw = tuple(
                data_raw[index : index + item_size]
                for index in range(0, len(data_raw), item_size)
            )
            cursor = data_end
        elif section_type in _STRING_SECTION_TYPES:
            items_raw, cursor = _read_c_strings(payload, cursor, subtype, section_type)
            data_raw = payload[data_start:cursor]
        elif section_type == 0x0C:
            data_raw = b""
        else:  # All non-terminator types 0x01-0x10 are covered above.
            raise ValueError(
                f"unsupported section type 0x{section_type:02X} at offset "
                f"{section_offset}"
            )

        sections.append(
            AppMapSection(
                type_byte=section_type,
                subtype=subtype,
                offset=section_offset,
                raw=payload[section_offset:cursor],
                data_raw=data_raw,
                u32_values=u32_values,
                items_raw=items_raw,
            )
        )

    return AppMapPayload(
        raw=payload,
        sections=tuple(sections),
        terminator=terminator,
        trailing_raw=payload[cursor:],
    )


def _hex_preview(data: bytes, limit: int = _PREVIEW_BYTES) -> str:
    preview = data[:limit].hex(" ").upper()
    if len(data) > limit:
        preview += f" … ({len(data) - limit} more bytes)"
    return preview or "(empty)"


def _json_object(**values: SemanticJSONValue) -> JSONObject:
    return JSONObject(tuple(values.items()))


def export_appmap_semantics(parsed: AppMapPayload) -> RuleSemantics:
    """Export receiver and consumer observations without guessing field names."""
    issues: list[SemanticIssue] = []
    sections: list[JSONObject] = []

    for index, section in enumerate(parsed.sections):
        opcode = section.type_byte
        role = _SECTION_ROLES[opcode]
        section_issues: list[str] = []
        item_values: list[JSONObject] = []
        section_data: list[tuple[str, SemanticJSONValue]] = []

        if opcode == 0x01:
            section_data.append(("path_ids", JSONArray(tuple(section.u32_values))))
            section_data.append(("mapping_target", "current_record_ordinal"))
            section_issues.append("path_id_namespace_and_runtime_mapping_not_resolved")
        elif opcode in _FIXED_ITEM_SIZES:
            for item_index, raw in enumerate(section.items_raw):
                item_values.append(
                    _json_object(
                        index=item_index,
                        raw_hex=raw.hex(),
                        raw_length=len(raw),
                        semantic_status="unsupported",
                    )
                )
            section_data.append(("stride", _FIXED_ITEM_SIZES[opcode]))
            section_data.append(("items", JSONArray(tuple(item_values))))
            section_issues.append("fixed_item_field_semantics_unresolved")
        elif opcode in _STRING_SECTION_TYPES:
            for item_index, raw in enumerate(section.items_raw):
                item_value: list[tuple[str, SemanticJSONValue]] = [
                    ("index", item_index),
                    ("raw_hex", raw.hex()),
                    ("raw_length", len(raw)),
                ]
                try:
                    item_value.append(("utf8", raw.decode("utf-8")))
                except UnicodeDecodeError:
                    section_issues.append("string_is_not_valid_utf8")
                item_values.append(_json_object(**dict(item_value)))
            section_data.append(("items", JSONArray(tuple(item_values))))
            section_issues.append("per_item_business_name_unconfirmed")

        section_status = "observed_only" if section_issues else "confirmed_subset"
        sections.append(
            _json_object(
                index=index,
                type=opcode,
                subtype=section.subtype,
                offset=section.offset,
                raw_hex=section.raw.hex(),
                data_raw_hex=section.data_raw.hex(),
                receiver_role=role,
                semantic_status=section_status,
                data=_json_object(**dict(section_data)),
                issues=JSONArray(tuple(section_issues)),
            )
        )
        for issue in section_issues:
            issues.append(
                SemanticIssue(
                    issue,
                    "Section bytes are preserved; full semantics are not confirmed.",
                    (("section_index", index), ("type", opcode)),
                )
            )

    terminator = None
    if parsed.terminator is not None:
        terminator = _json_object(
            type=parsed.terminator.type_byte,
            subtype=parsed.terminator.subtype,
            offset=parsed.terminator.offset,
            raw_hex=parsed.terminator.raw.hex(),
            role="stream_terminator",
        )
    if parsed.trailing_raw:
        issues.append(
            SemanticIssue(
                "bytes_after_terminator_ignored_by_receiver",
                "The receiver returns at the terminator; following bytes remain uninterpreted.",
                (("length", len(parsed.trailing_raw)),),
            )
        )

    return RuleSemantics(
        status="observed_only",
        representation="pua_appmap.manifest.v1",
        data=_json_object(
            raw_hex=parsed.raw.hex(),
            sections=JSONArray(tuple(sections)),
            terminator=terminator,
            trailing_raw_hex=parsed.trailing_raw.hex(),
        ),
        evidence=(
            "mpengine 1.443.903.0 PUA_appmap_receiver",
            "mpengine 1.443.903.0 LoadAppmapSection",
            "mpengine 1.443.903.0 isAppmapRecMatch",
            "mpengine 1.443.903.0 GetAppmapInfo",
        ),
        profile="mpengine-1.443.903.0",
        issues=tuple(issues),
    )


def render_appmap(parsed: AppMapPayload) -> FormatResult:
    """Render section metadata and bounded hex previews, never full payloads."""
    terminator = (
        f"0x{parsed.terminator.type_byte:02X}/{parsed.terminator.subtype}"
        if parsed.terminator is not None
        else "(none; reached EOF)"
    )
    rows = []
    for index, section in enumerate(parsed.sections[:MAX_SECTIONS], start=1):
        value = (
            f"type=0x{section.type_byte:02X} subtype={section.subtype} "
            f"offset=0x{section.offset:X} data_len={len(section.data_raw)} "
            f"data={_hex_preview(section.data_raw)}"
        )
        rows.append((f"section_{index:02d}", value))
    return FormatResult(
        fields=(
            ("section_count", str(len(parsed.sections))),
            ("terminator", terminator),
            ("trailing_len", f"{len(parsed.trailing_raw)} B"),
            ("trailing_raw", _hex_preview(parsed.trailing_raw)),
            ("raw_len", f"{len(parsed.raw)} B"),
        ),
        sections=(DisplaySection("PUA App Map", rows=tuple(rows)),),
    )


APPMAP_SPEC = FamilySpec(
    APPMAP_TYPE,
    "PUA_APPMAP",
    parse_appmap,
    render_appmap,
    semantic_exporter=export_appmap_semantics,
)
SPEC = APPMAP_SPEC
