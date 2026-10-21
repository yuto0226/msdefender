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
    0x02: "threat_info_u64_matcher_input",
    0x03: "pua_file_info_triplet_matcher_input",
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
    """Export the confirmed runtime candidate-matching operations."""
    issues: list[SemanticIssue] = []
    sections: list[JSONObject] = []
    unsupported = bool(parsed.trailing_raw)

    for index, section in enumerate(parsed.sections):
        opcode = section.type_byte
        role = _SECTION_ROLES[opcode]
        section_issues: list[str] = []
        item_values: list[JSONObject] = []
        section_data: list[tuple[str, SemanticJSONValue]] = []
        runtime_operation: JSONObject
        aggregation: str

        if opcode == 0x01:
            section_data.append(("path_ids", JSONArray(tuple(section.u32_values))))
            section_data.append(("mapping_target", "current_record_ordinal"))
            runtime_operation = _json_object(
                operation="index_candidate_ordinals_by_path_key",
                key_width=4,
                value="current_record_ordinal",
                namespace=None,
            )
            aggregation = "candidate_ordinal_range_lookup"
            section_issues.append("path_id_namespace_not_resolved")
        elif opcode in _FIXED_ITEM_SIZES:
            for item_index, raw in enumerate(section.items_raw):
                values: dict[str, SemanticJSONValue] = {
                    "index": item_index,
                    "raw_hex": raw.hex(),
                    "raw_length": len(raw),
                }
                if opcode == 0x02:
                    values["u64_value"] = int.from_bytes(raw, "little")
                elif opcode == 0x03:
                    values["tuple_values"] = JSONArray(
                        (
                            int.from_bytes(raw[0:8], "little"),
                            int.from_bytes(raw[8:16], "little"),
                            int.from_bytes(raw[16:20], "little"),
                        )
                    )
                item_values.append(_json_object(**values))
            section_data.append(("stride", _FIXED_ITEM_SIZES[opcode]))
            section_data.append(("items", JSONArray(tuple(item_values))))
            if opcode == 0x02:
                section_data.append(("runtime_compare_source", "ThreatInfo+0x10 u64"))
                runtime_operation = _json_object(
                    operation="exact_u64_equality",
                    compare_source="ThreatInfo+0x10",
                    activation="runtime_call_mode_bit_0_set",
                    condition="any_item_equals_source",
                )
                aggregation = "any_item_match"
            elif opcode == 0x03:
                section_data.append(
                    (
                        "runtime_compare_sources",
                        JSONArray(
                            (
                                "PUAFileInfo+0x30 u64",
                                "PUAFileInfo+0x38 u64",
                                "PUAFileInfo+0x40 u32",
                            )
                        ),
                    )
                )
                runtime_operation = _json_object(
                    operation="exact_tuple_equality",
                    compare_sources=JSONArray(
                        (
                            "PUAFileInfo+0x30 u64",
                            "PUAFileInfo+0x38 u64",
                            "PUAFileInfo+0x40 u32",
                        )
                    ),
                    activation="runtime_call_mode_bit_0_set",
                    condition="any_item_tuple_equals_sources",
                )
                aggregation = "any_item_match"
            section_issues.append("fixed_item_business_field_names_unresolved")
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
                    unsupported = True
                item_values.append(_json_object(**dict(item_value)))
            section_data.append(("items", JSONArray(tuple(item_values))))
            if opcode == 0x04:
                runtime_operation = _json_object(
                    operation="version_string_match",
                    compare_source="PUAFileInfo+0x08",
                    activation="runtime_call_mode_bit_0_set",
                    matching="wildcard_name_match",
                )
                aggregation = "any_item_match_when_condition_true"
            elif opcode in (0x05, 0x06, 0x07):
                runtime_operation = _json_object(
                    operation={
                        0x05: "add_app_file",
                        0x06: "add_app_folder",
                        0x07: "add_app_path_from_key",
                    }[opcode],
                    compare_source="PUAFileInfo+0x00 path context",
                    activation="runtime_call_mode_bit_1_set",
                    final_operation="CPathExclusionCtx::isPathExcluded",
                    when_inactive=("set_out_parameter_a7_to_1_without_path_evaluation"),
                )
                aggregation = "collect_rules_then_evaluate_path_exclusion"
            elif opcode == 0x08:
                runtime_operation = _json_object(
                    operation="add_app_uninstall_paths",
                    compare_source="PUAFileInfo+0x00 path context",
                    activation="runtime_call_mode_bit_1_set",
                    final_operation="CPathExclusionCtx::isPathExcluded",
                    when_inactive=("set_out_parameter_a7_to_1_without_path_evaluation"),
                )
                aggregation = "collect_rules_then_evaluate_path_exclusion"
            elif opcode in (0x09, 0x0A, 0x0B):
                runtime_operation = _json_object(
                    operation="no_direct_match_predicate",
                    consumer="GetAppmapInfo resource metadata extraction",
                )
                aggregation = "resource_metadata_only"
            elif opcode in (0x0D, 0x0E):
                runtime_operation = _json_object(
                    operation="version_string_match",
                    compare_source=(
                        "PUAFileInfo+0x10" if opcode == 0x0D else "PUAFileInfo+0x18"
                    ),
                    activation="runtime_call_mode_bit_0_set",
                    matching="wildcard_name_match",
                )
                aggregation = "any_item_match_when_condition_true"
            else:  # 0x0F, 0x10
                runtime_operation = _json_object(
                    operation="certificate_string_match",
                    compare_source=(
                        "PUAFileInfo+0x20" if opcode == 0x0F else "PUAFileInfo+0x28"
                    ),
                    activation="runtime_call_mode_bit_0_set",
                    matching="semicolon_tokens_then_wildcard_name_match",
                )
                aggregation = "any_item_match_when_condition_true"
            section_issues.append("per_item_business_name_unconfirmed")
        elif opcode == 0x0C:
            runtime_operation = _json_object(
                operation="receiver_skips_section_body",
                matcher_operation="none",
            )
            aggregation = "no_match_contribution"
        else:  # pragma: no cover - parser constrains supported opcodes
            runtime_operation = _json_object(operation="unknown")
            aggregation = "unknown"

        section_status = (
            "unsupported"
            if "string_is_not_valid_utf8" in section_issues
            else "confirmed_subset"
        )
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
                runtime_operation=runtime_operation,
                aggregation=aggregation,
                data=_json_object(**dict(section_data)),
                issues=JSONArray(tuple(section_issues)),
            )
        )
        for issue in section_issues:
            issues.append(
                SemanticIssue(
                    issue,
                    "Runtime operation is confirmed; namespace or business field "
                    "naming remains unresolved.",
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
    issues.append(
        SemanticIssue(
            "appmap_final_report_policy_unknown",
            "Record matching feeds PUA ignore/policy and latent/resource report paths; "
            "a matcher hit is not established as a final external verdict.",
        )
    )

    return RuleSemantics(
        status="unsupported" if unsupported else "confirmed_subset",
        representation="pua_appmap.candidate_ir.v4",
        data=_json_object(
            raw_hex=parsed.raw.hex(),
            sections=JSONArray(tuple(sections)),
            terminator=terminator,
            trailing_raw_hex=parsed.trailing_raw.hex(),
            runtime_lookup=_json_object(
                type_01_storage=(
                    "FNV1a-keyed path-key map to current record ordinals; "
                    "reorganized into path-key to RecID ordinal ranges"
                ),
                query_key_flow=("SCAN_REPLY/SCANSTRUCT+0x84 to ThreatInfo+0x04"),
                query_key_namespace=None,
            ),
            report_boundary=_json_object(
                match_is_final_verdict=False,
                process_path=(
                    "ProcessPUADetection applies ignore/policy and trace/latent handling"
                ),
                resource_path=(
                    "ResfileReportPUA checks ignored state before threat/resource report"
                ),
            ),
            candidate_matching=_json_object(
                candidate_source="type_0x01_path_key_to_current_record_ordinals",
                query_key_source="ThreatInfo+0x04 (copied from SCAN_REPLY/SCANSTRUCT+0x84)",
                matching="any_confirmed_section_predicate_or_path_exclusion_result",
                output="matching_candidate_ordinals",
                verdict="not_decided_by_candidate_ir",
            ),
            opcode_coverage=_json_object(
                engine_dispatch_function="isAppmapRecMatch",
                engine_dispatch_address="0x180B33CC4",
                engine_dispatch_size="0x7A2",
                receiver_function="PUA_appmap_receiver",
                receiver_address="0x1800E48F0",
                receiver_size="0x5E5",
                corpus_scope="mpas.sig + mpav.sig",
                corpus_record_count=8,
                corpus_section_counts=_json_object(
                    **{
                        f"0x{opcode:02X}": count
                        for opcode, count in (
                            (0x01, 8),
                            (0x02, 1),
                            (0x04, 1),
                            (0x06, 1),
                            (0x07, 1),
                            (0x08, 3),
                            (0x0A, 5),
                            (0x0B, 5),
                            (0x0C, 8),
                            (0x0D, 1),
                        )
                    }
                ),
                corpus_unobserved_dispatch_opcodes=JSONArray(
                    (0x03, 0x05, 0x09, 0x0E, 0x0F, 0x10)
                ),
                no_match_predicate_opcodes=JSONArray((0x09, 0x0A, 0x0B)),
                candidate_predicates_not_final_verdict=True,
            ),
        ),
        evidence=(
            "mpengine 1.443.903.0 PUA_appmap_receiver (0x1800E48F0)",
            "mpengine 1.443.903.0 LoadAppmapSection (0x1800E4ED8)",
            "mpengine 1.443.903.0 isAppmapRecMatch (0x180B33CC4)",
            "mpengine 1.443.903.0 GetAppmapInfo (0x180B331AC)",
            "mpengine 1.443.903.0 ReorgThreat2Appmap (0x1800E56B0)",
            "mpengine 1.443.903.0 AppmapPUAFile (0x18054D36C)",
            "mpengine 1.443.903.0 ProcessPUADetection (0x18054CB00)",
            "mpengine 1.443.903.0 ResfileReportPUA (0x180A90950)",
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
