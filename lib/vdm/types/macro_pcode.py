"""Lossless parsers for the MACRO_PCODE record families."""

from dataclasses import dataclass
from typing import Final

from ..core import DisplaySection, FamilySpec, FormatResult

MACRO_PCODE_TYPE: Final = 0x42
MACRO_PCODE64_TYPE: Final = 0xCF
MACRO_PCODE_NAME_PREVIEW_LIMIT: Final = 32
MACRO_PCODE_TAIL_PREVIEW_LIMIT: Final = 32


@dataclass(frozen=True, slots=True)
class MacroPcodePayload:
    """Three normalized header values and the complete NUL-delimited tail."""

    fields: tuple[int, int, int]
    wire_width: int
    tail: bytes
    name_bytes: bytes
    suffix: bytes


def _parse_macro_pcode(payload: bytes, type_byte: int) -> MacroPcodePayload:
    if type_byte == MACRO_PCODE_TYPE:
        width = 4
    elif type_byte == MACRO_PCODE64_TYPE:
        width = 8
    else:
        raise ValueError(f"unsupported MACRO_PCODE type 0x{type_byte:02X}")

    header_size = width * 3
    if len(payload) < header_size:
        raise ValueError(
            "truncated MACRO_PCODE header: "
            f"need {header_size} bytes, have {len(payload)}"
        )

    fields = tuple(
        int.from_bytes(payload[offset : offset + width], "little")
        for offset in range(0, header_size, width)
    )
    tail = payload[header_size:]
    if tail:
        nul_offset = tail.find(b"\0")
        if nul_offset < 0:
            raise ValueError("invalid MACRO_PCODE tail: missing NUL terminator")
        name_bytes = tail[:nul_offset]
        suffix = tail[nul_offset + 1 :]
    else:
        name_bytes = b""
        suffix = b""

    return MacroPcodePayload(
        fields=(fields[0], fields[1], fields[2]),
        wire_width=width,
        tail=tail,
        name_bytes=name_bytes,
        suffix=suffix,
    )


def parse_macro_pcode(payload: bytes) -> MacroPcodePayload:
    """Parse the 32-bit MACRO_PCODE (0x42) record."""
    return _parse_macro_pcode(payload, MACRO_PCODE_TYPE)


def parse_macro_pcode64(payload: bytes) -> MacroPcodePayload:
    """Parse the 64-bit MACRO_PCODE64 (0xCF) record."""
    return _parse_macro_pcode(payload, MACRO_PCODE64_TYPE)


def render_macro_pcode(parsed: MacroPcodePayload) -> FormatResult:
    """Render fixed-width normalized fields and bounded tail previews."""
    rows = [
        (f"field{index}", f"0x{value:0{parsed.wire_width * 2}x}")
        for index, value in enumerate(parsed.fields)
    ]
    name_preview = parsed.name_bytes[:MACRO_PCODE_NAME_PREVIEW_LIMIT]
    rows.extend(
        (
            ("wire_width", str(parsed.wire_width)),
            ("tail_length", str(len(parsed.tail))),
            ("name_preview", name_preview.hex(" ")),
            (
                "name_omitted_bytes",
                str(len(parsed.name_bytes) - len(name_preview)),
            ),
            ("suffix_length", str(len(parsed.suffix))),
        )
    )
    if parsed.tail:
        rows.append(
            (
                "tail_preview",
                parsed.tail[:MACRO_PCODE_TAIL_PREVIEW_LIMIT].hex(" "),
            )
        )
    return FormatResult(sections=(DisplaySection("MACRO_PCODE", rows=tuple(rows)),))


MACRO_PCODE_SPEC = FamilySpec(
    MACRO_PCODE_TYPE,
    "MACRO_PCODE",
    parse_macro_pcode,
    render_macro_pcode,
)
MACRO_PCODE64_SPEC = FamilySpec(
    MACRO_PCODE64_TYPE,
    "MACRO_PCODE64",
    parse_macro_pcode64,
    render_macro_pcode,
)
MACRO_PCODE_SPECS = (MACRO_PCODE_SPEC, MACRO_PCODE64_SPEC)
