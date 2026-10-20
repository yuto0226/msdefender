"""Lossless typed parser for IL2_PATTERN (0xA6)."""

from dataclasses import dataclass
from typing import Final

from ..core import DisplaySection, FamilySpec, FormatResult

IL2_PATTERN_TYPE: Final = 0xA6
_HEADER_SIZE: Final = 28
_ARRAY_PREVIEW: Final = 16
_RAW_PREVIEW: Final = 64


@dataclass(frozen=True, slots=True)
class IL2Pattern:
    """Observed IL2_PATTERN fields; array semantics remain unresolved."""

    raw: bytes
    count_a: int
    count_b: int
    opaque_prefix: bytes
    lookup_key: bytes
    array_a: tuple[int, ...]
    array_b: tuple[tuple[int, int], ...]
    trailing: bytes


def parse_il2_pattern(payload: bytes) -> IL2Pattern:
    """Parse observed offsets, retaining opaque bytes and accepted trailing data."""
    if len(payload) < 12:
        raise ValueError(
            "IL2_PATTERN receiver error 0xA004: payload shorter than 12 bytes"
        )

    count_a = int.from_bytes(payload[0:2], "little")
    count_b = int.from_bytes(payload[2:4], "little")
    if count_a > 0xFFF or count_b > 0xFF:
        raise ValueError("IL2_PATTERN receiver error 0x8002: count out of range")

    required_size = _HEADER_SIZE + 4 * (count_a + 2 * count_b)
    if required_size < _HEADER_SIZE or required_size > len(payload):
        raise ValueError(
            "IL2_PATTERN receiver error 0x8002: required size exceeds payload"
        )

    array_a_start = _HEADER_SIZE
    array_a_end = array_a_start + count_a * 4
    array_a = tuple(
        int.from_bytes(payload[offset : offset + 4], "little")
        for offset in range(array_a_start, array_a_end, 4)
    )
    array_b_end = array_a_end + count_b * 8
    array_b = tuple(
        (
            int.from_bytes(payload[offset : offset + 4], "little"),
            int.from_bytes(payload[offset + 4 : offset + 8], "little"),
        )
        for offset in range(array_a_end, array_b_end, 8)
    )
    return IL2Pattern(
        raw=payload,
        count_a=count_a,
        count_b=count_b,
        opaque_prefix=payload[4:8],
        lookup_key=payload[8:28],
        array_a=array_a,
        array_b=array_b,
        trailing=payload[required_size:],
    )


def _preview(raw: bytes) -> str:
    return raw[:_RAW_PREVIEW].hex(" ") + (" ..." if len(raw) > _RAW_PREVIEW else "")


def render_il2_pattern(parsed: IL2Pattern) -> FormatResult:
    """Render bounded previews and observed structure without interpreting arrays."""
    array_a_preview = ", ".join(
        f"0x{value:08X}" for value in parsed.array_a[:_ARRAY_PREVIEW]
    )
    array_b_preview = ", ".join(
        f"(0x{first:08X}, 0x{second:08X})"
        for first, second in parsed.array_b[:_ARRAY_PREVIEW]
    )
    rows = (
        ("count_A", str(parsed.count_a)),
        ("count_B", str(parsed.count_b)),
        ("opaque_prefix", parsed.opaque_prefix.hex(" ")),
        ("lookup_key_length", str(len(parsed.lookup_key))),
        ("lookup_key", parsed.lookup_key.hex(" ")),
        ("array_A_count", str(len(parsed.array_a))),
        ("array_A_preview", array_a_preview or "(empty)"),
        ("array_A_remaining", str(max(0, len(parsed.array_a) - _ARRAY_PREVIEW))),
        ("array_B_count", str(len(parsed.array_b))),
        ("array_B_preview", array_b_preview or "(empty)"),
        ("array_B_remaining", str(max(0, len(parsed.array_b) - _ARRAY_PREVIEW))),
        ("arrays_interpretation", "opaque values; semantics unresolved"),
        ("trailing_length", str(len(parsed.trailing))),
        ("trailing_preview", _preview(parsed.trailing) or "(empty)"),
    )
    return FormatResult(sections=(DisplaySection("IL2_PATTERN", rows=rows),))


SPEC = FamilySpec(
    IL2_PATTERN_TYPE, "IL2_PATTERN", parse_il2_pattern, render_il2_pattern
)
