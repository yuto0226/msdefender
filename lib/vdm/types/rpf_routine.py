"""Lossless structural parser for RPFROUTINE (0x53) RPFM payloads."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from ..core import (
    Artifact,
    ArtifactExport,
    DisplaySection,
    FamilySpec,
    FormatResult,
    JSONArray,
    JSONObject,
    RuleSemantics,
    SemanticIssue,
)

RPF_ROUTINE_TYPE: Final = 0x53
_HEADER_SIZE: Final = 32
_ROUTINE_PREVIEW: Final = 12
_SECTION_PREVIEW: Final = 16
_NAME_PREVIEW_CHARS: Final = 64
_CRC_POLYNOMIAL: Final = 0xEDB88320


@dataclass(frozen=True, slots=True)
class RpfRoutineEntry:
    offset: int
    size: int
    kind: int
    fields_raw: bytes
    name_raw: bytes
    second_name_raw: bytes | None
    trailing_raw: bytes

    @property
    def name(self) -> str:
        return self.name_raw.decode("ascii", errors="replace")

    @property
    def second_name(self) -> str | None:
        if self.second_name_raw is None:
            return None
        return self.second_name_raw.decode("ascii", errors="replace")


@dataclass(frozen=True, slots=True)
class RpfRoutineSection:
    kind: int
    offset: int
    size: int
    raw: bytes


@dataclass(frozen=True, slots=True)
class RpfRoutinePayload:
    raw: bytes
    declared_size: int
    reserved: int
    routine_count: int
    routine_table_offset: int
    index_data_offset: int
    descriptor_table_offset: int
    version: int
    state: int
    flags: int
    routines: tuple[RpfRoutineEntry, ...]
    sections: tuple[RpfRoutineSection, ...]
    crc_marker_offset: int | None
    stored_crc: int | None
    computed_crc: int | None
    crc_valid: bool | None
    tail_raw: bytes


def _u16(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 2], "little")


def _u32(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 4], "little")


def _require_range(start: int, size: int, limit: int, label: str) -> int:
    end = start + size
    if start < 0 or size < 0 or end < start or end > limit:
        raise ValueError(
            f"RPFROUTINE {label} out of bounds: range {start:#x}..{end:#x}, "
            f"limit {limit:#x}"
        )
    return end


def _cstring(data: bytes, start: int, end: int, label: str) -> tuple[bytes, int]:
    terminator = data.find(b"\0", start, end)
    if terminator < 0:
        raise ValueError(f"RPFROUTINE {label} is not NUL-terminated within its entry")
    return data[start:terminator], terminator + 1


def _engine_crc(data: bytes) -> int:
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (_CRC_POLYNOMIAL if crc & 1 else 0)
    return crc


def parse_rpf_routine(payload: bytes) -> RpfRoutinePayload:
    """Parse engine-validated RPFM structure; retain opaque metadata and sections."""
    if len(payload) < _HEADER_SIZE:
        raise ValueError(
            f"truncated RPFROUTINE header: need 32 bytes, have {len(payload)}"
        )
    if payload[:4] != b"RPFM":
        raise ValueError("invalid RPFROUTINE magic; expected RPFM")

    declared_size = _u32(payload, 4)
    if declared_size < _HEADER_SIZE or declared_size > len(payload):
        raise ValueError(
            f"invalid RPFROUTINE declared size {declared_size}: input has {len(payload)} bytes"
        )
    data = payload[:declared_size]
    reserved = _u32(data, 8)
    routine_count = _u32(data, 12)
    routine_table_offset = _u32(data, 16)
    index_data_offset = _u32(data, 20)
    descriptor_table_offset = _u32(data, 24)
    version = int.from_bytes(data[28:30], "big")
    state = data[30]
    flags = data[31]
    if flags & 0x06 != 0x06:
        raise ValueError(
            f"invalid RPFROUTINE flags: required mask 0x06, got {flags:#04x}"
        )
    if version > 0x200:
        raise ValueError(f"unsupported RPFROUTINE version {version:#x}")
    if descriptor_table_offset == 0:
        raise ValueError("RPFROUTINE descriptor table offset is zero")

    if routine_table_offset < _HEADER_SIZE or routine_table_offset > index_data_offset:
        raise ValueError("RPFROUTINE routine table offsets are invalid")
    _require_range(routine_table_offset, 0, declared_size, "routine table")
    _require_range(index_data_offset, 0, declared_size, "index data")
    if descriptor_table_offset < _HEADER_SIZE:
        raise ValueError("RPFROUTINE descriptor table starts inside the header")

    routines: list[RpfRoutineEntry] = []
    cursor = routine_table_offset
    for index in range(routine_count):
        _require_range(cursor, 4, index_data_offset, f"routine {index} size")
        entry_size = _u32(data, cursor)
        if entry_size < 19:
            raise ValueError(
                f"RPFROUTINE routine {index} size is too small: {entry_size}"
            )
        end = _require_range(cursor, entry_size, index_data_offset, f"routine {index}")
        kind = _u16(data, cursor + 4)
        name_raw, after_name = _cstring(data, cursor + 18, end, f"routine {index} name")
        second_name_raw = None
        trailing_raw = b""
        if after_name < end:
            second_name_raw, after_second_name = _cstring(
                data, after_name, end, f"routine {index} optional name"
            )
            trailing_raw = data[after_second_name:end]
        routines.append(
            RpfRoutineEntry(
                offset=cursor,
                size=entry_size,
                kind=kind,
                fields_raw=data[cursor + 6 : cursor + 18],
                name_raw=name_raw,
                second_name_raw=second_name_raw,
                trailing_raw=trailing_raw,
            )
        )
        cursor = end
    if cursor != index_data_offset:
        raise ValueError(
            f"RPFROUTINE routine table ends at {cursor:#x}, "
            f"index data begins at {index_data_offset:#x}"
        )

    sections: list[RpfRoutineSection] = []
    descriptor_cursor = descriptor_table_offset
    body_start = _HEADER_SIZE
    crc_marker_offset = None
    stored_crc = computed_crc = None
    crc_valid = None
    while True:
        _require_range(descriptor_cursor, 12, declared_size, "section descriptor")
        kind = _u32(data, descriptor_cursor)
        if kind == 0:
            break
        section_offset = _u32(data, descriptor_cursor + 4)
        section_size = _u32(data, descriptor_cursor + 8)
        absolute_start = body_start + section_offset
        absolute_end = _require_range(
            absolute_start, section_size, declared_size, "section"
        )
        raw = data[absolute_start:absolute_end]
        sections.append(RpfRoutineSection(kind, section_offset, section_size, raw))
        if kind == 5:
            marker = section_offset + body_start
            _require_range(marker, 4, declared_size, "CRC marker")
            crc_marker_offset = marker
            stored_crc = _u32(data, marker)
            computed_crc = _engine_crc(data[:marker] + data[marker + 4 :])
            crc_valid = stored_crc == computed_crc
        descriptor_cursor += 12

    return RpfRoutinePayload(
        raw=payload,
        declared_size=declared_size,
        reserved=reserved,
        routine_count=routine_count,
        routine_table_offset=routine_table_offset,
        index_data_offset=index_data_offset,
        descriptor_table_offset=descriptor_table_offset,
        version=version,
        state=state,
        flags=flags,
        routines=tuple(routines),
        sections=tuple(sections),
        crc_marker_offset=crc_marker_offset,
        stored_crc=stored_crc,
        computed_crc=computed_crc,
        crc_valid=crc_valid,
        tail_raw=payload[declared_size:],
    )


def _hex_preview(data: bytes, limit: int) -> str:
    value = data[:limit].hex(" ").upper() or "(empty)"
    if len(data) > limit:
        value += f" … (+{len(data) - limit} B)"
    return value


def render_rpf_routine(parsed: RpfRoutinePayload) -> FormatResult:
    """Render summary and bounded previews, never recursively dump opaque data."""
    rows: list[tuple[str, str]] = [
        ("version", f"0x{parsed.version:04X}"),
        ("state", f"0x{parsed.state:02X}"),
        ("flags", f"0x{parsed.flags:02X}"),
        ("routine_count", str(parsed.routine_count)),
        ("section_count", str(len(parsed.sections))),
        ("declared_size", f"{parsed.declared_size} B"),
        ("tail_size", f"{len(parsed.tail_raw)} B"),
        ("crc_valid", str(parsed.crc_valid)),
    ]
    routine_rows = []
    for index, routine in enumerate(parsed.routines[:_ROUTINE_PREVIEW]):
        name = routine.name[:_NAME_PREVIEW_CHARS]
        if len(routine.name) > _NAME_PREVIEW_CHARS:
            name += f"… (+{len(routine.name) - _NAME_PREVIEW_CHARS} chars)"
        routine_rows.append((f"routine_{index}", f"kind={routine.kind:#x}, {name!r}"))
    if len(parsed.routines) > _ROUTINE_PREVIEW:
        routine_rows.append(
            ("routines_omitted", str(len(parsed.routines) - _ROUTINE_PREVIEW))
        )
    section_rows = tuple(
        (
            f"section_{index}",
            (
                f"kind={section.kind}, offset={section.offset:#x}, "
                f"size={section.size} B, "
                f"raw={_hex_preview(section.raw, _SECTION_PREVIEW)}"
            ),
        )
        for index, section in enumerate(parsed.sections[:16])
    )
    return FormatResult(
        fields=tuple(rows),
        sections=(
            DisplaySection("RPF Routine", tuple(routine_rows)),
            DisplaySection("Opaque sections", section_rows),
        ),
    )


def export_rpf_routine(parsed: RpfRoutinePayload) -> ArtifactExport:
    """Export the original container only; no metadata or routine decompilation."""
    return ArtifactExport(
        status="ready",
        artifacts=(Artifact("routine.rpfm", "RPFM", parsed.raw),),
    )


def export_rpf_routine_semantics(parsed: RpfRoutinePayload) -> RuleSemantics:
    """Export RPFM wire and runtime facts without interpreting managed code."""
    known_section_kinds = {1, 2, 3, 4, 5, 7}
    unknown_sections = tuple(
        section.kind
        for section in parsed.sections
        if section.kind not in known_section_kinds
    )
    has_entry_tails = any(routine.trailing_raw for routine in parsed.routines)
    issues = [
        SemanticIssue(
            "rpf_sections_opaque",
            "Section bytes are preserved verbatim; their internal formats are "
            "not established.",
        ),
        SemanticIssue(
            "rpf_managed_code_uninterpreted",
            "CLR metadata and routine method bodies are not decoded or executed "
            "by this exporter.",
        ),
        SemanticIssue(
            "rpf_detection_semantics_unconfirmed",
            "RPFROUTINE registration and runtime loading do not establish a "
            "detection rule or final verdict.",
        ),
    ]
    if parsed.crc_valid is False:
        issues.append(
            SemanticIssue(
                "rpf_crc_invalid",
                "The receiver-compatible payload CRC does not match.",
                (
                    ("stored_crc", parsed.stored_crc),
                    ("computed_crc", parsed.computed_crc),
                ),
            )
        )
    if unknown_sections:
        issues.append(
            SemanticIssue(
                "rpf_unknown_section_kind",
                "Unrecognized section kinds are retained as raw bytes and are "
                "not assigned semantics.",
                (("kinds", JSONArray(unknown_sections)),),
            )
        )
    if has_entry_tails:
        issues.append(
            SemanticIssue(
                "rpf_entry_tail_uninterpreted",
                "Bytes after the optional second NUL-terminated name are "
                "preserved without interpretation.",
            )
        )
    if parsed.tail_raw:
        issues.append(
            SemanticIssue(
                "rpf_payload_tail_uninterpreted",
                "Bytes after the declared RPFM size are preserved without "
                "interpretation.",
                (("length", len(parsed.tail_raw)),),
            )
        )

    wire_routines = JSONArray(
        tuple(
            JSONObject(
                (
                    ("index", index),
                    ("offset", routine.offset),
                    ("size", routine.size),
                    ("kind", routine.kind),
                    ("receiver_candidate", routine.kind <= 0x200),
                    ("fields_raw_hex", routine.fields_raw.hex()),
                    ("name_raw_hex", routine.name_raw.hex()),
                    ("name_ascii", routine.name),
                    (
                        "second_name_raw_hex",
                        routine.second_name_raw.hex()
                        if routine.second_name_raw is not None
                        else None,
                    ),
                    ("second_name_ascii", routine.second_name),
                    ("trailing_raw_hex", routine.trailing_raw.hex()),
                )
            )
            for index, routine in enumerate(parsed.routines)
        )
    )
    wire_sections = JSONArray(
        tuple(
            JSONObject(
                (
                    ("index", index),
                    ("kind", section.kind),
                    ("offset_from_body", section.offset),
                    ("size", section.size),
                    ("raw_hex", section.raw.hex()),
                )
            )
            for index, section in enumerate(parsed.sections)
        )
    )
    fail_closed = bool(
        parsed.crc_valid is False
        or unknown_sections
        or has_entry_tails
        or parsed.tail_raw
    )
    return RuleSemantics(
        status="unsupported" if fail_closed else "observed_only",
        representation="rpf_routine.receiver_and_runtime_inventory.v1",
        data=JSONObject(
            (
                ("type", "RPFROUTINE"),
                ("raw_hex", parsed.raw.hex()),
                (
                    "wire_container",
                    JSONObject(
                        (
                            ("magic", "RPFM"),
                            ("declared_size", parsed.declared_size),
                            ("reserved", parsed.reserved),
                            ("routine_count", parsed.routine_count),
                            ("routine_table_offset", parsed.routine_table_offset),
                            ("index_data_offset", parsed.index_data_offset),
                            (
                                "descriptor_table_offset",
                                parsed.descriptor_table_offset,
                            ),
                            ("version", parsed.version),
                            ("state", parsed.state),
                            ("flags", parsed.flags),
                            ("routines", wire_routines),
                            ("sections", wire_sections),
                            ("crc_marker_offset", parsed.crc_marker_offset),
                            ("stored_crc", parsed.stored_crc),
                            ("computed_crc", parsed.computed_crc),
                            ("crc_valid", parsed.crc_valid),
                            ("tail_raw_hex", parsed.tail_raw.hex()),
                        )
                    ),
                ),
                (
                    "receiver_storage",
                    JSONObject(
                        (
                            ("registration", "netvm_init_module"),
                            ("registration_address", "0x180BE9030"),
                            ("record_type", RPF_ROUTINE_TYPE),
                            ("receiver", "nvsig_push"),
                            ("receiver_address", "0x18032C230"),
                            ("end_callback", "nvsig_pushend"),
                            ("end_callback_address", "0x18032E850"),
                            ("runtime_entry_stride", 160),
                            ("internal_table_is_wire_layout", False),
                        )
                    ),
                ),
                (
                    "runtime",
                    JSONObject(
                        (
                            ("managed_module", "DynamicModule"),
                            ("managed_module_name", "RPF-Emu"),
                            ("metadata_cache", "nvmcache_data"),
                            ("metadata_cache_address", "0x180259344"),
                            ("native_module_loader", "init_native_rpf_routines"),
                            ("native_module_loader_address", "0x180BEB244"),
                            ("routine_interpreter", None),
                            ("routine_call_sites", None),
                            ("method_body_semantics", "unknown"),
                        )
                    ),
                ),
                (
                    "detection_relevance",
                    JSONObject(
                        (
                            ("detection_role", "unknown"),
                            ("rule_semantics_established", False),
                            ("final_verdict_established", False),
                            ("basis", "receiver and runtime loading evidence only"),
                        )
                    ),
                ),
            )
        ),
        evidence=(
            "mpengine 1.443.903.0 netvm_init_module registers type 0x53",
            "mpengine 1.443.903.0 nvsig_push validates and stores RPFM payloads",
            "mpengine 1.443.903.0 nvsig_pushend publishes the DynamicModule",
            "mpengine 1.443.903.0 nvmcache_data links CLR metadata and routines",
            "mpengine 1.443.903.0 init_native_rpf_routines loads native RPF DLLs",
        ),
        profile="mpengine-1.443.903.0",
        issues=tuple(issues),
    )


SPEC = FamilySpec(
    RPF_ROUTINE_TYPE,
    "RPFROUTINE",
    parse_rpf_routine,
    render_rpf_routine,
    export_rpf_routine,
    semantic_exporter=export_rpf_routine_semantics,
)

__all__ = [
    "RPF_ROUTINE_TYPE",
    "SPEC",
    "RpfRoutineEntry",
    "RpfRoutinePayload",
    "RpfRoutineSection",
    "export_rpf_routine",
    "export_rpf_routine_semantics",
    "parse_rpf_routine",
    "render_rpf_routine",
]
