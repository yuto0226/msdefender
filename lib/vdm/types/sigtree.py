from dataclasses import dataclass

from ..core import DisplaySection, FamilySpec, FormatResult


@dataclass(frozen=True, slots=True)
class SigtreeParam:
    kind: str
    raw: bytes
    subtype: int | None = None


@dataclass(frozen=True, slots=True)
class SigtreeEntry:
    fixed_raw: bytes
    level_extra_raw: bytes
    param_a: SigtreeParam | None
    param_b: SigtreeParam | None


@dataclass(frozen=True, slots=True)
class SigtreePayload:
    raw: bytes
    entry_count: int
    format_level: int
    raw_header_2: int
    handler_index: int
    name_raw: bytes
    record_extra_raw: bytes
    entries: tuple[SigtreeEntry, ...]
    trailing_raw: bytes


def _take(payload: bytes, cursor: int, size: int, label: str) -> tuple[bytes, int]:
    end = cursor + size
    if end > len(payload):
        raise ValueError(f"truncated {label}")
    return payload[cursor:end], end


def _parse_param(
    payload: bytes,
    cursor: int,
    *,
    size_hint: int,
    flags: int,
    hash_enabled: bool,
    label: str,
) -> tuple[SigtreeParam | None, int]:
    if flags & 0x10:
        raw, cursor = _take(payload, cursor, size_hint, f"{label} BM data")
        kind = "special_extended" if flags & 0x04 else "bm_pattern"
        return SigtreeParam(kind=kind, raw=raw), cursor
    if not hash_enabled:
        return None, cursor

    subtype_raw, cursor = _take(payload, cursor, 1, f"{label} hash subtype")
    subtype = subtype_raw[0]
    if subtype == 1:
        data_size = size_hint * (2 if flags & 0x40 else 1)
    else:
        fixed_sizes = {2: 16, 3: 20, 4: 32}
        try:
            data_size = fixed_sizes[subtype]
        except KeyError as exc:
            raise ValueError(f"unsupported {label} hash subtype {subtype}") from exc
    data, cursor = _take(payload, cursor, data_size, f"{label} hash data")
    return SigtreeParam(
        kind="typed_hash", raw=subtype_raw + data, subtype=subtype
    ), cursor


def parse_sigtree(payload: bytes) -> SigtreePayload:
    if len(payload) < 5:
        raise ValueError("truncated SIGTREE header")

    entry_count, format_level, raw_header_2, handler_index = payload[:4]
    if format_level > 4:
        raise ValueError(f"unsupported SIGTREE format level {format_level}")
    if handler_index >= 7:
        raise ValueError(f"invalid SIGTREE handler index {handler_index}")

    name_end = payload.find(b"\0", 4, min(len(payload), 68))
    if name_end < 0:
        raise ValueError("unterminated SIGTREE name")
    name_raw = payload[4:name_end]
    cursor = name_end + 1

    record_extra_raw = b""
    if format_level >= 3:
        record_extra_raw, cursor = _take(payload, cursor, 4, "SIGTREE record extension")

    entries: list[SigtreeEntry] = []
    level_extra_size = 4 * min(format_level, 2)
    for index in range(entry_count):
        fixed_raw, cursor = _take(payload, cursor, 16, f"SIGTREE entry {index}")
        level_extra_raw, cursor = _take(
            payload,
            cursor,
            level_extra_size,
            f"SIGTREE entry {index} extension",
        )
        hash_gate_a = len(level_extra_raw) >= 3 and bool(level_extra_raw[2] & 1)
        hash_gate_b = len(level_extra_raw) >= 2 and bool(level_extra_raw[1] & 1)
        param_a, cursor = _parse_param(
            payload,
            cursor,
            size_hint=fixed_raw[7],
            flags=fixed_raw[1],
            hash_enabled=hash_gate_a,
            label=f"SIGTREE entry {index} param 1",
        )
        param_b, cursor = _parse_param(
            payload,
            cursor,
            size_hint=fixed_raw[6],
            flags=fixed_raw[0],
            hash_enabled=hash_gate_b,
            label=f"SIGTREE entry {index} param 2",
        )
        entries.append(
            SigtreeEntry(
                fixed_raw=fixed_raw,
                level_extra_raw=level_extra_raw,
                param_a=param_a,
                param_b=param_b,
            )
        )

    return SigtreePayload(
        raw=payload,
        entry_count=entry_count,
        format_level=format_level,
        raw_header_2=raw_header_2,
        handler_index=handler_index,
        name_raw=name_raw,
        record_extra_raw=record_extra_raw,
        entries=tuple(entries),
        trailing_raw=payload[cursor:],
    )


def render_sigtree(parsed: SigtreePayload) -> FormatResult:
    def preview(raw: bytes) -> str:
        if not raw:
            return "(empty)"
        shown = raw[:32].hex(" ")
        ellipsis = " …" if len(raw) > 32 else ""
        return f"{len(raw)} B [{shown}{ellipsis}]"

    def render_param(param: SigtreeParam) -> str:
        subtype = f" subtype={param.subtype}" if param.subtype is not None else ""
        return f"{param.kind}{subtype}, {preview(param.raw)}"

    sections: list[DisplaySection] = []
    for index, entry in enumerate(parsed.entries, 1):
        rows = [
            ("fixed_raw", entry.fixed_raw.hex(" ")),
            ("level_extra_raw", entry.level_extra_raw.hex(" ") or "(empty)"),
        ]
        if entry.param_a is not None:
            rows.append(("param_1", render_param(entry.param_a)))
        if entry.param_b is not None:
            rows.append(("param_2", render_param(entry.param_b)))
        sections.append(DisplaySection(title=f"> Entry #{index}", rows=tuple(rows)))
    return FormatResult(
        fields=(
            ("entry_count", str(parsed.entry_count)),
            ("format_level", str(parsed.format_level)),
            ("raw_header_2", f"{parsed.raw_header_2:#04x}"),
            ("handler_index", str(parsed.handler_index)),
            ("name_raw", parsed.name_raw.hex(" ") or "(empty)"),
            ("name", parsed.name_raw.decode("latin-1")),
            ("record_extra_raw", parsed.record_extra_raw.hex(" ") or "(empty)"),
            ("trailing_raw", preview(parsed.trailing_raw)),
        ),
        sections=tuple(sections),
    )


SIGTREE_SPEC = FamilySpec(0x40, "SIGTREE", parse_sigtree, render_sigtree)
SIGTREE_EXT_SPEC = FamilySpec(0x41, "SIGTREE_EXT", parse_sigtree, render_sigtree)
SIGTREE_BM_SPEC = FamilySpec(0xB3, "SIGTREE_BM", parse_sigtree, render_sigtree)
