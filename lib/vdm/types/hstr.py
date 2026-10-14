from collections.abc import Callable
from dataclasses import dataclass
from types import MappingProxyType

from ..catalog import type_name
from ..core import DisplaySection, FamilySpec, FormatResult


@dataclass(frozen=True, slots=True)
class HstrFlags:
    value: int
    raw: bytes


@dataclass(frozen=True, slots=True)
class HstrSubsignature:
    raw: bytes
    tag: int
    flags: HstrFlags | None
    data: bytes


@dataclass(frozen=True, slots=True)
class HstrPayload:
    raw: bytes
    type_byte: int
    header_word0: int
    header_word1: int
    name_raw: bytes
    subsignatures: tuple[HstrSubsignature, ...]
    tail_word0: int | None
    tail_word1: int | None
    trailing_raw: bytes


_FAMILY_NAMES = MappingProxyType(
    {
        0x61: "PEHSTR",
        0x78: "PEHSTR_EXT",
        0x85: "PEHSTR_EXT2",
        0x8C: "ELFHSTR_EXT",
        0x8D: "MACHOHSTR_EXT",
        0x8E: "DOSHSTR_EXT",
        0x8F: "MACROHSTR_EXT",
        0x92: "ASCRIPTHSTR_EXT",
        0xBE: "DEXHSTR_EXT",
        0xBF: "JAVAHSTR_EXT",
        0xC5: "ARHSTR_EXT",
        0xEF: "ARHSTR_POSIX_EXT",
    }
)


def _read_u16(payload: bytes, cursor: int, label: str) -> tuple[int, int]:
    end = cursor + 2
    if end > len(payload):
        raise ValueError(f"truncated {label}")
    return int.from_bytes(payload[cursor:end], "little"), end


def _read_flags(payload: bytes, cursor: int) -> tuple[HstrFlags, int]:
    start = cursor
    if cursor >= len(payload):
        raise ValueError("truncated subsignature flags")

    value = payload[cursor]
    cursor += 1
    if value & 0x80:
        if cursor >= len(payload):
            raise ValueError("truncated extended subsignature flags")
        value |= payload[cursor] << 8
        cursor += 1
    if value & 0x8000:
        end = cursor + 2
        if end > len(payload):
            raise ValueError("truncated long subsignature flags")
        value |= int.from_bytes(payload[cursor:end], "little") << 16
        cursor = end

    return HstrFlags(value=value, raw=payload[start:cursor]), cursor


def parse_hstr(payload: bytes, *, type_byte: int) -> HstrPayload:
    """Parse one HSTR family payload, retaining every unclassified byte."""
    if type_byte not in _FAMILY_NAMES:
        raise ValueError(f"unsupported HSTR type 0x{type_byte:02X}")
    if len(payload) < 6:
        raise ValueError("truncated HSTR header")

    header_word0 = int.from_bytes(payload[0:2], "little")
    header_word1 = int.from_bytes(payload[2:4], "little")
    subsignature_count = int.from_bytes(payload[4:6], "little")

    name_start = 6
    name_end = payload.find(b"\0", name_start, min(len(payload), name_start + 65))
    if name_end < 0:
        raise ValueError("unterminated HSTR name (maximum 64 bytes)")
    name_raw = payload[name_start:name_end]
    cursor = name_end + 1

    subsignatures: list[HstrSubsignature] = []
    for index in range(subsignature_count):
        start = cursor
        tag, cursor = _read_u16(payload, cursor, f"subsignature {index} tag")
        if cursor >= len(payload):
            raise ValueError(f"truncated subsignature {index} data length")
        data_len = payload[cursor]
        cursor += 1

        flags = None
        if type_byte != 0x61:
            flags, cursor = _read_flags(payload, cursor)

        data_end = cursor + data_len
        if data_end > len(payload):
            raise ValueError(f"truncated subsignature {index} data")
        data = payload[cursor:data_end]
        cursor = data_end
        subsignatures.append(
            HstrSubsignature(
                raw=payload[start:cursor],
                tag=tag,
                flags=flags,
                data=data,
            )
        )

    tail_word0 = None
    tail_word1 = None
    if len(payload) - cursor >= 2:
        tail_word0, cursor = _read_u16(payload, cursor, "tail_word0")
    if len(payload) - cursor >= 2:
        tail_word1, cursor = _read_u16(payload, cursor, "tail_word1")

    return HstrPayload(
        raw=payload,
        type_byte=type_byte,
        header_word0=header_word0,
        header_word1=header_word1,
        name_raw=name_raw,
        subsignatures=tuple(subsignatures),
        tail_word0=tail_word0,
        tail_word1=tail_word1,
        trailing_raw=payload[cursor:],
    )


def render_hstr(parsed: HstrPayload) -> FormatResult:
    def preview(raw: bytes) -> str:
        shown = raw[:32].hex(" ")
        ellipsis = " …" if len(raw) > 32 else ""
        return f"{len(raw)} B [{shown}{ellipsis}]" if raw else "0 B [(empty)]"

    sections: list[DisplaySection] = []
    for index, subsig in enumerate(parsed.subsignatures, 1):
        rows = [
            ("tag", f"{subsig.tag:#06x}"),
            ("data_len", str(len(subsig.data))),
            ("data_preview", preview(subsig.data)),
        ]
        if subsig.flags is not None:
            flags = subsig.flags
            known = (
                ("preserve_case", 0x001),
                ("bm_pattern", 0x002),
                ("emit_wide_copy", 0x100),
            )
            enabled = [name for name, mask in known if flags.value & mask]
            rows.extend(
                (
                    ("flags_value", f"{flags.value:#x}"),
                    ("flags_raw", flags.raw.hex(" ")),
                    ("known_flags", ", ".join(enabled) or "(none)"),
                )
            )
        sections.append(
            DisplaySection(title=f"> Subsignature #{index}", rows=tuple(rows))
        )

    return FormatResult(
        fields=(
            ("family", _FAMILY_NAMES[parsed.type_byte]),
            (
                "type_byte",
                f"{parsed.type_byte:#04x} ({type_name(parsed.type_byte)})",
            ),
            ("header_word0", f"{parsed.header_word0:#06x}"),
            ("header_word1", f"{parsed.header_word1:#06x}"),
            ("name_raw", parsed.name_raw.hex(" ") or "(empty)"),
            ("name", parsed.name_raw.decode("latin-1")),
            ("subsignature_count", str(len(parsed.subsignatures))),
            (
                "tail_word0",
                f"{parsed.tail_word0:#06x}"
                if parsed.tail_word0 is not None
                else "(absent)",
            ),
            (
                "tail_word1",
                f"{parsed.tail_word1:#06x}"
                if parsed.tail_word1 is not None
                else "(absent)",
            ),
            ("trailing_raw", preview(parsed.trailing_raw)),
        ),
        sections=tuple(sections),
    )


def _parser_for(type_byte: int) -> Callable[[bytes], HstrPayload]:
    def parser(payload: bytes) -> HstrPayload:
        return parse_hstr(payload, type_byte=type_byte)

    return parser


HSTR_SPECS = tuple(
    FamilySpec(type_byte, name, _parser_for(type_byte), render_hstr)
    for type_byte, name in _FAMILY_NAMES.items()
)
