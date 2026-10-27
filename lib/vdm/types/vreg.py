"""Lossless parser and concise renderer for VREG (0xB0) payloads."""

import json
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
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

VREG_TYPE: Final = 0xB0
MAX_KEY_UNITS: Final = 0x100
MAX_NAME_UNITS: Final = 0x108

_HIVE_LABELS = MappingProxyType(
    {
        0: "HKCR (HKEY_CLASSES_ROOT)",
        1: "HKCU (HKEY_CURRENT_USER)",
        2: "HKLM (HKEY_LOCAL_MACHINE)",
        3: "HKU (HKEY_USERS)",
        4: "HKEY_PERFORMANCE_DATA",
        5: "HKCC (HKEY_CURRENT_CONFIG)",
    }
)
_HIVE_IDENTITIES = MappingProxyType(
    {
        0: "HKEY_CLASSES_ROOT",
        1: "HKEY_CURRENT_USER",
        2: "HKEY_LOCAL_MACHINE",
        3: "HKEY_USERS",
        4: "HKEY_PERFORMANCE_DATA",
        5: "HKEY_CURRENT_CONFIG",
    }
)

# WinNT.h REG_* constants.  Values are presentation labels only: the engine
# accepts unknown values and does not validate the data size against the type.
_VALUE_TYPE_LABELS = MappingProxyType(
    {
        0: "REG_NONE",
        1: "REG_SZ",
        2: "REG_EXPAND_SZ",
        3: "REG_BINARY",
        4: "REG_DWORD",
        5: "REG_DWORD_BIG_ENDIAN",
        6: "REG_LINK",
        7: "REG_MULTI_SZ",
        8: "REG_RESOURCE_LIST",
        9: "REG_FULL_RESOURCE_DESCRIPTOR",
        10: "REG_RESOURCE_REQUIREMENTS_LIST",
        11: "REG_QWORD",
    }
)


@dataclass(frozen=True, slots=True)
class VregPayload:
    raw: bytes
    hive: int
    key_units: int
    key_raw: bytes
    key_wire: str
    key: str
    value_type: int
    name_units: int
    name_raw: bytes
    name_wire: str
    name: str
    data_size: int
    data_raw: bytes
    trailing_raw: bytes

    @property
    def creates_key_only(self) -> bool:
        return self.data_size == 0


def _effective_string(wire: str) -> str:
    return wire.partition("\0")[0]


def parse_vreg(payload: bytes) -> VregPayload:
    """Parse the engine's length-prefixed VREG wire layout."""
    if len(payload) < 8:
        raise ValueError(f"truncated VREG header: need 8 bytes, have {len(payload)}")

    hive = payload[0]
    key_units = int.from_bytes(payload[1:3], "little")
    if key_units >= MAX_KEY_UNITS:
        raise ValueError(
            f"invalid VREG key_units: need < {MAX_KEY_UNITS}, have {key_units}"
        )

    key_end = 3 + 2 * key_units
    if len(payload) < key_end:
        raise ValueError(
            "truncated VREG key: "
            f"need {2 * key_units} bytes, have {max(0, len(payload) - 3)}"
        )

    name_header_end = key_end + 3
    if len(payload) < name_header_end:
        raise ValueError(
            "truncated VREG value header: "
            f"need 3 bytes, have {max(0, len(payload) - key_end)}"
        )

    value_type = payload[key_end]
    name_units = int.from_bytes(payload[key_end + 1 : name_header_end], "little")
    if name_units >= MAX_NAME_UNITS:
        raise ValueError(
            f"invalid VREG name_units: need < {MAX_NAME_UNITS}, have {name_units}"
        )

    name_offset = name_header_end
    name_end = name_offset + 2 * name_units
    data_size_end = name_end + 2
    if len(payload) < data_size_end:
        raise ValueError(
            "truncated VREG name/data_size: "
            f"need {2 * name_units + 2} bytes, "
            f"have {max(0, len(payload) - name_offset)}"
        )

    data_size = int.from_bytes(payload[name_end:data_size_end], "little")
    data_end = data_size_end + data_size
    if len(payload) < data_end:
        raise ValueError(
            f"truncated VREG data: need {data_size} bytes, "
            f"have {max(0, len(payload) - data_size_end)}"
        )

    key_raw = payload[3:key_end]
    name_raw = payload[name_offset:name_end]
    key_wire = key_raw.decode("utf-16le", errors="surrogatepass")
    name_wire = name_raw.decode("utf-16le", errors="surrogatepass")
    return VregPayload(
        raw=payload,
        hive=hive,
        key_units=key_units,
        key_raw=key_raw,
        key_wire=key_wire,
        key=_effective_string(key_wire),
        value_type=value_type,
        name_units=name_units,
        name_raw=name_raw,
        name_wire=name_wire,
        name=_effective_string(name_wire),
        data_size=data_size,
        data_raw=payload[data_size_end:data_end],
        trailing_raw=payload[data_end:],
    )


def _quoted(text: str) -> str:
    # ensure_ascii keeps lone UTF-16 surrogates safe for terminal encoders.
    return json.dumps(text, ensure_ascii=True)


def _enum_value(value: int, labels: Mapping[int, str]) -> str:
    label = labels.get(value)
    return (
        f"{label} (0x{value:02X})" if label is not None else f"unknown (0x{value:02X})"
    )


def _string_rows(
    label: str,
    units: int,
    wire: str,
    effective: str,
) -> list[tuple[str, str]]:
    rows = [(f"{label}_units", str(units)), (label, _quoted(effective))]
    if wire not in {effective, effective + "\0"}:
        rows.append((f"{label}_wire", _quoted(wire)))
    return rows


def _hex_preview(data: bytes, limit: int = 32) -> str:
    preview = data[:limit].hex(" ") or "(empty)"
    if len(data) > limit:
        return f"{preview} … (+{len(data) - limit} B)"
    return preview


def _reg_sz_preview(data: bytes) -> str | None:
    if len(data) % 2:
        return None
    text = data.decode("utf-16le", errors="surrogatepass")
    effective = _effective_string(text)
    if any(not (char.isprintable() or char in "\t\r\n") for char in effective):
        return None
    return _quoted(effective)


def render_vreg(parsed: VregPayload) -> FormatResult:
    key_rows = [
        ("hive", _enum_value(parsed.hive, _HIVE_LABELS)),
        *_string_rows("key", parsed.key_units, parsed.key_wire, parsed.key),
    ]

    value_rows = [
        ("name_units", str(parsed.name_units)),
        ("name", "(default)" if not parsed.name else _quoted(parsed.name)),
    ]
    if parsed.name_wire not in {parsed.name, parsed.name + "\0"}:
        value_rows.append(("name_wire", _quoted(parsed.name_wire)))
    value_rows.extend(
        (
            ("value_type", _enum_value(parsed.value_type, _VALUE_TYPE_LABELS)),
            ("data_size", f"{parsed.data_size} B"),
        )
    )
    if parsed.creates_key_only:
        value_rows.append(("operation", "create key only (engine skips SetValue)"))
    else:
        if parsed.value_type == 1:
            preview = _reg_sz_preview(parsed.data_raw)
            if preview is not None:
                value_rows.append(("text", preview))
        elif parsed.value_type == 4 and parsed.data_size == 4:
            value_rows.append(
                ("dword", f"0x{int.from_bytes(parsed.data_raw, 'little'):08X}")
            )
        value_rows.append(("data_raw", _hex_preview(parsed.data_raw)))

    sections = [
        DisplaySection("Target Key", rows=tuple(key_rows)),
        DisplaySection("Value Data", rows=tuple(value_rows)),
    ]
    if parsed.trailing_raw:
        sections.append(
            DisplaySection(
                "Ignored Trailing Bytes",
                rows=(
                    ("trailing_len", f"{len(parsed.trailing_raw)} B"),
                    ("trailing_raw", _hex_preview(parsed.trailing_raw)),
                    ("engine_behavior", "ignored"),
                ),
            )
        )
    return FormatResult(sections=tuple(sections))


def _wire_field(kind: str, raw: bytes, offset: int) -> JSONObject:
    return JSONObject(
        (
            ("kind", kind),
            ("raw_span", JSONObject((("offset", offset), ("length", len(raw))))),
            ("raw_hex", raw.hex()),
        )
    )


def _semantic_utf16_string(
    raw: bytes,
    units: int,
    offset: int,
    field: str,
    issues: list[SemanticIssue],
) -> JSONObject:
    terminator_at = next(
        (index for index in range(0, len(raw), 2) if raw[index : index + 2] == b"\0\0"),
        len(raw),
    )
    effective_raw = raw[:terminator_at]
    texts: list[str | None] = []
    for stage, content in (("wire", raw), ("effective_c_string", effective_raw)):
        try:
            text = content.decode("utf-16le")
        except UnicodeDecodeError:
            text = None
            issues.append(
                SemanticIssue(
                    "utf16_text_projection_unavailable",
                    "Raw UTF-16 units are retained, but this string has no "
                    "well-formed Unicode text projection; this is not engine rejection.",
                    (("field", field), ("stage", stage)),
                )
            )
        texts.append(text)
    wire_text, effective_text = texts
    return JSONObject(
        (
            ("wire", _wire_field("utf16le_code_units", raw, offset)),
            ("unit_count", units),
            ("wire_text", wire_text),
            ("wire_utf16_well_formed", wire_text is not None),
            ("effective_c_string", effective_text),
            ("effective_c_string_raw_hex", effective_raw.hex()),
            ("effective_utf16_well_formed", effective_text is not None),
        )
    )


def _key_info_contract() -> JSONObject:
    fields = (
        ("subkey_count", 0x200, "count", 4),
        ("max_subkey_name", 0x208, "UTF-16 code units excluding NUL", 5),
        ("value_count", 0x210, "count", 7),
        ("max_value_name", 0x218, "UTF-16 code units excluding NUL", 8),
        ("max_value_data", 0x220, "bytes", 9),
    )
    return JSONObject(
        (
            ("missing_key_error", 2),
            (
                "layout",
                JSONObject(
                    (
                        ("name", "VREG_KeyInfo"),
                        ("size_bytes", 0x228),
                        (
                            "name_buffer",
                            JSONObject(
                                (
                                    ("offset", 0),
                                    ("capacity_utf16_units", 256),
                                    ("code_unit_bytes", 2),
                                    ("unused_capacity_initialized", False),
                                )
                            ),
                        ),
                        (
                            "statistics",
                            JSONArray(
                                tuple(
                                    JSONObject(
                                        (
                                            ("name", name),
                                            ("offset", offset),
                                            ("storage_bytes", 8),
                                            ("unsigned", True),
                                            ("unit", unit),
                                            ("guest_output_argument_index", argument),
                                        )
                                    )
                                    for name, offset, unit, argument in fields
                                )
                            ),
                        ),
                    )
                ),
            ),
            (
                "count_scope",
                "direct children only; no recursive or synthesized default-value count",
            ),
            (
                "name_length_rule",
                "UTF-16 code units excluding NUL; a non-BMP surrogate pair counts as two",
            ),
            (
                "data_length_rule",
                "raw value-vector bytes, including any stored NUL; independent of value_type",
            ),
            ("empty_statistics", "zero when no applicable children exist"),
            (
                "guest_output_patch",
                JSONObject(
                    (
                        ("argument_index_base", 0),
                        ("argument_slot_bytes", 8),
                        ("output_bytes", 4),
                        ("value_projection", "low DWORD of each uint64 statistic"),
                        ("null_output_pointer", "skip that write"),
                        ("write_helper_boolean_checked", False),
                        (
                            "untouched_pointed_buffer_arguments",
                            JSONArray((1, 2, 3, 6, 10, 11)),
                        ),
                        ("argument_slots_still_fetched", True),
                        ("memory_helper_fault_effect", None),
                    )
                ),
            ),
            (
                "wrapper_return",
                JSONObject(
                    (
                        ("hkey_projection", "low DWORD, zero-extended"),
                        ("zero_hkey_error", 6),
                        ("query_failure_error", 2),
                        ("success", 0),
                        ("delivery", "pe_set_return_value; host wrapper returns void"),
                    )
                ),
            ),
            ("full_windows_api_equivalence", None),
        )
    )


def export_vreg_semantics(parsed: VregPayload) -> RuleSemantics:
    """Export only VREG behavior confirmed in the selected engine profile."""
    key_end = 3 + len(parsed.key_raw)
    name_offset = key_end + 3
    data_size_offset = name_offset + len(parsed.name_raw)
    data_offset = data_size_offset + 2
    issues = [
        SemanticIssue(
            "caller_interpretation_unknown",
            "The modeled Win32-emulation API contract ends at return values and "
            "output buffers; how PE/P-code callers interpret those results and "
            "whether they influence scan/report policy remain unknown.",
        ),
        SemanticIssue(
            "value_type_is_raw",
            "The receiver forwards value_type and data without validating their "
            "relationship; Windows REG_* names are not treated as enforcement "
            "semantics.",
            (("value_type", parsed.value_type),),
        ),
    ]
    unknown_hive = parsed.hive > 5
    if unknown_hive:
        issues.append(
            SemanticIssue(
                "hive_slot_unrecognized",
                "The receiver preserves this hive byte, but the virtual-registry "
                "handle normalization only confirms slots 0 through 5.",
                (("hive", parsed.hive),),
            )
        )
    if parsed.trailing_raw:
        issues.append(
            SemanticIssue(
                "trailing_bytes_ignored_by_receiver",
                "The receiver stops after data_size bytes; trailing bytes do not "
                "participate in key creation or value setting.",
                (("length", len(parsed.trailing_raw)),),
            )
        )
    key_projection = _semantic_utf16_string(
        parsed.key_raw, parsed.key_units, 3, "key", issues
    )
    name_projection = _semantic_utf16_string(
        parsed.name_raw, parsed.name_units, name_offset, "value_name", issues
    )

    return RuleSemantics(
        status="confirmed_subset",
        representation="vreg.virtual_registry_write.ir.v6",
        data=JSONObject(
            (
                ("type", "VREG"),
                ("raw_hex", parsed.raw.hex()),
                (
                    "hive",
                    JSONObject(
                        (
                            ("raw_u8", parsed.hive),
                            (
                                "virtual_registry_slot",
                                parsed.hive if parsed.hive <= 5 else None,
                            ),
                            (
                                "windows_hive_identity",
                                _HIVE_IDENTITIES.get(parsed.hive),
                            ),
                        )
                    ),
                ),
                ("key", key_projection),
                ("value_name", name_projection),
                (
                    "write",
                    JSONObject(
                        (
                            ("create_key_attempt", True),
                            ("set_value_attempt", parsed.data_size != 0),
                            ("value_type_raw_u8", parsed.value_type),
                            ("data_size", parsed.data_size),
                            (
                                "data",
                                _wire_field(
                                    "opaque_value_bytes", parsed.data_raw, data_offset
                                ),
                            ),
                            ("type_to_data_validation", False),
                        )
                    ),
                ),
                (
                    "confirmed_query_consumers",
                    JSONArray(
                        (
                            "query_value",
                            "query_key",
                            "enumerate_subkey",
                            "enumerate_value",
                        )
                    ),
                ),
                (
                    "query_policy",
                    JSONObject(
                        (
                            (
                                "hive_roots",
                                JSONObject(
                                    (
                                        (
                                            "selector_0",
                                            "Registry\\Machine\\SOFTWARE\\Classes",
                                        ),
                                        (
                                            "selector_1",
                                            "Registry\\Users\\Charlie",
                                        ),
                                        ("selector_2", "Registry\\Machine"),
                                        ("selector_3", "Registry\\Users"),
                                        (
                                            "selector_4",
                                            "Registry\\PerformanceData",
                                        ),
                                        (
                                            "selector_5",
                                            "Registry\\Machine\\SYSTEM\\CurrentControlSet\\Hardware Profiles\\Current",
                                        ),
                                    )
                                ),
                            ),
                            (
                                "open_key",
                                JSONObject(
                                    (
                                        ("mode", "open_only; no key creation"),
                                        ("missing_key_error", 2),
                                        ("null_root_error", 6),
                                        ("null_output_handle_error", 87),
                                    )
                                ),
                            ),
                            (
                                "query_value",
                                JSONObject(
                                    (
                                        (
                                            "missing_key_or_named_value_error",
                                            2,
                                        ),
                                        (
                                            "missing_default_value",
                                            "existing key + empty value name returns type 1 and two zero bytes",
                                        ),
                                        (
                                            "buffer_too_small",
                                            "required size is reported; no bytes copied; ERROR_MORE_DATA (234) when data buffer is supplied",
                                        ),
                                        (
                                            "value_type_and_data",
                                            "returned without type-specific validation",
                                        ),
                                    )
                                ),
                            ),
                            (
                                "enumeration",
                                JSONObject(
                                    (
                                        ("index_base", "zero-based"),
                                        ("index_miss_error", 259),
                                        ("name_or_data_buffer_too_small_error", 234),
                                    )
                                ),
                            ),
                            ("key_info", _key_info_contract()),
                            (
                                "boundary",
                                "These are emulated PE Win32 registry API results, not direct threat reports or final scan verdicts.",
                            ),
                        )
                    ),
                ),
                (
                    "trailing",
                    _wire_field(
                        "ignored_trailing_bytes",
                        parsed.trailing_raw,
                        data_offset + len(parsed.data_raw),
                    ),
                ),
                (
                    "consumer_boundary",
                    JSONObject(
                        (
                            ("api_layer", "confirmed virtual-registry behavior"),
                            ("pe_or_pcode_caller_interpretation", None),
                            ("direct_threat_report", None),
                            ("final_scan_verdict", None),
                        )
                    ),
                ),
            )
        ),
        evidence=(
            "vregReceiver@0x180270110 creates key and conditionally writes value",
            "vemulib_init_module@0x18048B450 initializes six hive roots and registers receiver",
            "VirtualReg::translateHiveRoots@0x1804F4A28 maps pseudo selectors 0..5",
            "ADVAPI32_DLL_RegOpenKeyExW@0x1801A15D0 uses open_only=true",
            "VirtualReg::queryValue@0x1801A0FEC; ADVAPI32_DLL_RegQueryValueExW@0x1801A1380",
            "VirtualReg::enumerateSubKey@0x18019DC58; ADVAPI32_DLL_RegEnumKeyExW@0x1801A0610",
            "VirtualReg::enumerateValue@0x18034BA10; ADVAPI32_DLL_RegEnumValueW@0x180CB5640",
            "VirtualReg::queryKey@0x18019E03C; ADVAPI32_DLL_RegQueryInfoKeyW@0x180568760",
        ),
        profile="mpengine-1.443.903.0",
        issues=tuple(issues),
        claims=(
            SemanticClaim(
                id="vreg_wire_layout",
                scope="wire_layout",
                statement=(
                    "The receiver reads the hive byte, bounded UTF-16LE key and value "
                    "name fields, raw value type, u16 data size, and ignores bytes "
                    "after the declared value data."
                ),
                coverage="complete",
                evidence_refs=("vreg_receiver",),
            ),
            SemanticClaim(
                id="vreg_dispatch_path",
                scope="loader_dispatch",
                statement="vemulib initialization registers type 0xB0 to vregReceiver.",
                coverage="subset",
                evidence_refs=("vreg_dispatch",),
                unknowns=(
                    SemanticUnknown(
                        "loader_dispatch",
                        "Outer database selection and virtual-emulation enablement "
                        "gates are not modeled.",
                    ),
                ),
            ),
            SemanticClaim(
                id="vreg_receiver_write",
                scope="receiver_transform",
                statement=(
                    "vregReceiver preserves the hive byte, attempts key creation, and "
                    "calls SetValue only when data_size is nonzero; an unrecognized "
                    "hive byte is not itself a receiver rejection."
                ),
                coverage="subset",
                evidence_refs=("vreg_receiver",),
                unknowns=(
                    SemanticUnknown(
                        "receiver_transform",
                        "Allocation failures, mutation failure handling, and downstream "
                        "normalization of hive values outside 0 through 5 are unresolved.",
                    ),
                ),
            ),
            SemanticClaim(
                id="vreg_runtime_query_surface",
                scope="runtime_consumer",
                statement=(
                    "The confirmed emulated Win32 surface can open keys, query values "
                    "and key information, and enumerate subkeys and values in the "
                    "VirtualReg tree."
                ),
                coverage="subset",
                evidence_refs=("vreg_query_consumer",),
                unknowns=(
                    SemanticUnknown(
                        "runtime_consumer",
                        "Other VirtualReg consumers and PE/P-code interpretation of API "
                        "results are not traced.",
                    ),
                ),
            ),
            SemanticClaim(
                id="vreg_key_info_contract",
                scope="runtime_consumer",
                statement=(
                    "VREG_KeyInfo has a 0x200-byte UTF-16 name buffer followed by "
                    "five uint64 statistics at 0x200/0x208/0x210/0x218/0x220. "
                    "Counts cover direct children, name maxima count UTF-16 code "
                    "units without NUL, and data maxima count raw bytes. QueryInfoW "
                    "writes low DWORDs to optional zero-based guest arguments "
                    "4/5/7/8/9, skips null pointers and ignores the write helper's "
                    "bool. Handle projection, error returns and untouched buffers "
                    "are the bounded static wrapper contract, not Windows equivalence."
                ),
                coverage="subset",
                evidence_refs=("vreg_key_info_static", "vreg_key_info_native"),
                unknowns=(
                    SemanticUnknown(
                        "runtime_consumer",
                        "PE memory-helper fault effects, complete Windows API "
                        "compatibility and PE/P-code caller interpretation remain "
                        "unmodeled. Native coverage is limited to the declared "
                        "producer loops, queryKey/Tree::info with synthetic providers "
                        "and success output block; full wrapper/Parameters/handle "
                        "validation and error paths are static-only evidence.",
                    ),
                ),
            ),
            SemanticClaim(
                id="vreg_detection_predicate",
                scope="detection_predicate",
                statement=(
                    "No threat-detection predicate is established by the registry API "
                    "surface."
                ),
                coverage="unknown",
                unknowns=(
                    SemanticUnknown(
                        "detection_predicate",
                        "PE/P-code caller logic that may turn registry results into a "
                        "candidate remains unresolved.",
                    ),
                ),
            ),
            SemanticClaim(
                id="vreg_report_mapping",
                scope="report_mapping",
                statement=(
                    "VirtualReg API results have no confirmed threat-report mapping."
                ),
                coverage="unknown",
                unknowns=(
                    SemanticUnknown(
                        "report_mapping",
                        "No caller was followed from a VirtualReg result into report policy.",
                    ),
                ),
            ),
            SemanticClaim(
                id="vreg_final_verdict",
                scope="final_verdict",
                statement=(
                    "A virtual-registry write or query result is not a confirmed final "
                    "verdict."
                ),
                coverage="unknown",
                unknowns=(
                    SemanticUnknown(
                        "final_verdict",
                        "Outer emulation arbitration and final report policy remain unresolved.",
                    ),
                ),
            ),
        ),
        claim_evidence=(
            SemanticEvidence(
                id="vreg_receiver",
                axis="receiver",
                kind="engine_static",
                source_ref="mpengine 1.443.903.0",
                locator="vregReceiver @ 0x180270110",
                supports=("vreg_wire_layout", "vreg_receiver_write"),
            ),
            SemanticEvidence(
                id="vreg_dispatch",
                axis="dispatch",
                kind="engine_static",
                source_ref="mpengine 1.443.903.0",
                locator="vemulib_init_module @ 0x18048B450",
                supports=("vreg_dispatch_path",),
            ),
            SemanticEvidence(
                id="vreg_key_info_static",
                axis="consumer",
                kind="engine_static",
                source_ref="mpengine 1.443.903.0",
                locator=(
                    "VirtualReg::queryKey 0x18019E03C/0x319 full 0x228-byte copy "
                    "0x18019E23A..0x18019E293; Tree::info 0x18019E358/0x115; "
                    "name length loops 0x18019DE1F..0x18019DE3A and "
                    "0x180270368..0x180270372; QueryInfoW 0x180568760/0x1AB "
                    "output calls 0x18056884F/0x18056886A/0x180568885/"
                    "0x1805688A0/0x1805688BB; handle-validation overload "
                    "0x18019F29C/0x9C"
                ),
                supports=("vreg_key_info_contract",),
            ),
            SemanticEvidence(
                id="vreg_key_info_native",
                axis="engine_equivalent_test",
                kind="engine_equivalent_test",
                source_ref=(
                    "Pinned DLL SHA256 "
                    "928e171c60a44bb326776d2a356412ae98d78469bdf8c94ebfbfa09f8ec4b4b3; "
                    "local_vreg_keyinfo_differential: 15 cases, comprising 4 original "
                    "setValue WORD-loop slices, 6 createKey component-loop slices, "
                    "2 complete queryKey/Tree::info executions with synthetic node/"
                    "iterator/value-storage providers and 3 original success output "
                    "blocks with a PE DWORD-write seam returning false; no complete "
                    "wrapper, handle-validation/error-path or PE memory mapper execution"
                ),
                locator=(
                    "0x180270368..0x180270372; 0x18019DE1F..0x18019DE3A; "
                    "0x18019E03C/0x319 and 0x18019E358/0x115; "
                    "success output block 0x180568839..0x1805688C2"
                ),
                supports=("vreg_key_info_contract",),
            ),
            SemanticEvidence(
                id="vreg_query_consumer",
                axis="consumer",
                kind="engine_static",
                source_ref="mpengine 1.443.903.0",
                locator=(
                    "VirtualReg::queryValue @ 0x1801A0FEC; "
                    "VirtualReg::enumerateSubKey @ 0x18019DC58; "
                    "VirtualReg::enumerateValue @ 0x18034BA10; "
                    "VirtualReg::queryKey @ 0x18019E03C"
                ),
                supports=("vreg_runtime_query_surface",),
            ),
        ),
    )


SPEC = FamilySpec(
    VREG_TYPE,
    "VREG",
    parse_vreg,
    render_vreg,
    semantic_exporter=export_vreg_semantics,
)
