"""Lossless wire parser for MACRO_SOURCE (0x43) payloads."""

from dataclasses import dataclass
from typing import Final

from ..core import DisplaySection, FamilySpec, FormatResult

MACRO_SOURCE_TYPE: Final = 0x43
PRIMARY_PREVIEW_LIMIT: Final = 16
WORD_SIZE: Final = 4


@dataclass(frozen=True, slots=True)
class MacroSourcePayload:
    """Raw MACRO_SOURCE fields and normalized safecrc candidate pairs."""

    name_bytes: bytes
    name_preview: str
    packed_header: int
    metadata_raw: int
    count: int
    primary: tuple[int, ...]
    secondary: tuple[int, ...] | None
    pairs: tuple[tuple[int, int], ...]
    trailing: bytes


def parse_macro_source(payload: bytes) -> MacroSourcePayload:
    """Parse wire fields; retain name bytes and incomplete optional data raw."""
    if not payload:
        raise ValueError("truncated MACRO_SOURCE payload: missing name length")

    name_len = payload[0]
    header_offset = 1 + name_len
    if len(payload) < header_offset + WORD_SIZE:
        raise ValueError(
            "truncated MACRO_SOURCE payload: "
            f"need at least {header_offset + WORD_SIZE} bytes, have {len(payload)}"
        )

    name_bytes = payload[1:header_offset]
    packed_header = int.from_bytes(
        payload[header_offset : header_offset + WORD_SIZE], "little"
    )
    count = packed_header & 0x3F
    metadata_raw = packed_header >> 6
    primary_offset = header_offset + WORD_SIZE
    primary_end = primary_offset + count * WORD_SIZE
    if len(payload) < primary_end:
        raise ValueError(
            "truncated MACRO_SOURCE primary values: "
            f"need {count * WORD_SIZE} bytes, have {len(payload) - primary_offset}"
        )

    primary = tuple(
        int.from_bytes(payload[offset : offset + WORD_SIZE], "little")
        for offset in range(primary_offset, primary_end, WORD_SIZE)
    )
    remaining = len(payload) - primary_end
    if remaining >= count * WORD_SIZE:
        secondary_end = primary_end + count * WORD_SIZE
        secondary = tuple(
            int.from_bytes(payload[offset : offset + WORD_SIZE], "little")
            for offset in range(primary_end, secondary_end, WORD_SIZE)
        )
        trailing = payload[secondary_end:]
    else:
        secondary = None
        trailing = payload[primary_end:]

    effective_secondary = secondary if secondary is not None else (0,) * count
    pairs = tuple(zip(primary, effective_secondary, strict=True))
    return MacroSourcePayload(
        name_bytes=name_bytes,
        name_preview=name_bytes.decode("utf-8", errors="replace"),
        packed_header=packed_header,
        metadata_raw=metadata_raw,
        count=count,
        primary=primary,
        secondary=secondary,
        pairs=pairs,
        trailing=trailing,
    )


def render_macro_source(parsed: MacroSourcePayload) -> FormatResult:
    """Render stable summary fields and a bounded preview of identifier pairs."""
    rows = [
        ("name_bytes", parsed.name_bytes.hex(" ")),
        ("name_preview_utf8_lossy_unvalidated", repr(parsed.name_preview)),
        ("packed_header", f"0x{parsed.packed_header:08x}"),
        ("metadata_raw", f"0x{parsed.metadata_raw:x}"),
        ("count", str(parsed.count)),
        (
            "secondary",
            "present" if parsed.secondary is not None else "absent (effective zero)",
        ),
        ("trailing_length", str(len(parsed.trailing))),
    ]
    if parsed.trailing:
        rows.append(("trailing_preview", parsed.trailing[:16].hex(" ")))

    preview = parsed.pairs[:PRIMARY_PREVIEW_LIMIT]
    pair_rows = tuple(
        (f"pair[{index}]", f"0x{primary:08x}, 0x{secondary:08x}")
        for index, (primary, secondary) in enumerate(preview)
    )
    if len(parsed.pairs) > len(preview):
        pair_rows += (("remaining", str(len(parsed.pairs) - len(preview))),)

    return FormatResult(
        sections=(
            DisplaySection("MACRO_SOURCE", rows=tuple(rows)),
            DisplaySection("Pairs", rows=pair_rows),
        )
    )


SPEC = FamilySpec(
    MACRO_SOURCE_TYPE,
    "MACRO_SOURCE",
    parse_macro_source,
    render_macro_source,
)
