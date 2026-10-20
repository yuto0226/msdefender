"""Lossless parsers for the FOP scanner signature payload family."""

from collections.abc import Callable
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final

from ..core import DisplaySection, FamilySpec, FormatResult

FOP_TYPES: Final = MappingProxyType(
    {
        0x7F: "FOP",
        0x89: "FOPEX",
        0xB4: "VBFOP",
        0xBA: "MSILFOP",
        0xC6: "MSILFOPEX",
        0xC7: "VBFOPEX",
        0xC8: "FOP64",
        0xC9: "FOPEX64",
    }
)
FOP_PLAIN_TYPES: Final = frozenset({0x7F, 0xB4, 0xBA, 0xC8})
FOP_EXTENDED_TYPES: Final = frozenset(FOP_TYPES) - FOP_PLAIN_TYPES
FOP_PLAIN_HEADER_SIZE: Final = 4
FOP_EXTENDED_HEADER_SIZE: Final = 10
FOP_PREVIEW_SIZE: Final = 64


@dataclass(frozen=True, slots=True)
class FopPayload:
    """Parsed FOP fields; section labels are neutral pending semantic analysis."""

    raw: bytes
    type_byte: int
    flags: int
    prefix: bytes
    pattern: bytes
    section1: bytes | None
    section2: bytes | None
    pattern_options: int | None


def parse_fop(payload: bytes, *, type_byte: int) -> FopPayload:
    """Parse a strict plain or extended FOP envelope and preserve all fields."""
    try:
        FOP_TYPES[type_byte]
    except KeyError as exc:
        raise ValueError(f"unsupported FOP family type 0x{type_byte:02X}") from exc

    header_size = (
        FOP_PLAIN_HEADER_SIZE
        if type_byte in FOP_PLAIN_TYPES
        else FOP_EXTENDED_HEADER_SIZE
    )
    if len(payload) < header_size:
        raise ValueError(
            f"truncated FOP header: need {header_size} bytes, have {len(payload)}"
        )
    if len(payload) == header_size:
        raise ValueError("invalid FOP header-only payload: no sections are present")

    flags = payload[0]
    if flags & 0xFE:
        raise ValueError(f"invalid FOP flags 0x{flags:02X}: reserved bits must be zero")

    prefix_len = payload[1]
    pattern_len = int.from_bytes(payload[2:4], "little")
    if type_byte in FOP_PLAIN_TYPES:
        expected_size = FOP_PLAIN_HEADER_SIZE + prefix_len + pattern_len
        if len(payload) != expected_size:
            raise ValueError(
                f"invalid FOP payload length: expected {expected_size}, got {len(payload)}"
            )
        prefix_start = FOP_PLAIN_HEADER_SIZE
        pattern_start = prefix_start + prefix_len
        return FopPayload(
            raw=payload,
            type_byte=type_byte,
            flags=flags,
            prefix=payload[prefix_start:pattern_start],
            pattern=payload[pattern_start:],
            section1=None,
            section2=None,
            pattern_options=None,
        )

    section1_len = int.from_bytes(payload[4:6], "little")
    section2_len = int.from_bytes(payload[6:8], "little")
    pattern_options = int.from_bytes(payload[8:10], "little")
    expected_size = (
        FOP_EXTENDED_HEADER_SIZE
        + prefix_len
        + pattern_len
        + section1_len
        + section2_len
    )
    if len(payload) != expected_size:
        raise ValueError(
            f"invalid FOP payload length: expected {expected_size}, got {len(payload)}"
        )

    cursor = FOP_EXTENDED_HEADER_SIZE
    prefix = payload[cursor : cursor + prefix_len]
    cursor += prefix_len
    pattern = payload[cursor : cursor + pattern_len]
    cursor += pattern_len
    section1 = payload[cursor : cursor + section1_len]
    cursor += section1_len
    section2 = payload[cursor : cursor + section2_len]
    return FopPayload(
        raw=payload,
        type_byte=type_byte,
        flags=flags,
        prefix=prefix,
        pattern=pattern,
        section1=section1,
        section2=section2,
        pattern_options=pattern_options,
    )


def _preview(raw: bytes) -> str:
    value = raw[:FOP_PREVIEW_SIZE].hex(" ") or "(empty)"
    if len(raw) > FOP_PREVIEW_SIZE:
        value += f" … (+{len(raw) - FOP_PREVIEW_SIZE} B)"
    return value


def _section_rows(name: str, raw: bytes) -> tuple[tuple[str, str], ...]:
    return ((f"{name}_length", f"{len(raw)} B"), (f"{name}_preview", _preview(raw)))


def render_fop(parsed: FopPayload) -> FormatResult:
    """Render normalized fields and byte-limited previews for each byte section."""
    name = FOP_TYPES[parsed.type_byte]
    rows = [
        ("type", f"{name} (0x{parsed.type_byte:02X})"),
        ("flags", f"0x{parsed.flags:02X}"),
        ("flag_bit0", str(bool(parsed.flags & 1))),
        *_section_rows("prefix", parsed.prefix),
        *_section_rows("pattern", parsed.pattern),
    ]
    if parsed.pattern_options is not None:
        rows.append(("pattern_options", f"0x{parsed.pattern_options:04X}"))
        assert parsed.section1 is not None and parsed.section2 is not None
        rows.extend(_section_rows("section1", parsed.section1))
        rows.extend(_section_rows("section2", parsed.section2))
    return FormatResult(sections=(DisplaySection("FOP", rows=tuple(rows)),))


def _parser_for(type_byte: int) -> Callable[[bytes], FopPayload]:
    def parser(payload: bytes) -> FopPayload:
        return parse_fop(payload, type_byte=type_byte)

    return parser


FOP_SPECS = tuple(
    FamilySpec(type_byte, name, _parser_for(type_byte), render_fop)
    for type_byte, name in FOP_TYPES.items()
)
