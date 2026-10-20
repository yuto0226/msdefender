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
    """IL2_PATTERN receiver fields and operand arrays."""

    raw: bytes
    v1_count: int
    tag_count: int
    unknown_04: bytes
    lookup_key: bytes
    v1_operands: tuple[int, ...]
    tag_operands: tuple[tuple[int, int], ...]
    trailing: bytes

    @property
    def lookup_hash_words(self) -> tuple[int, int]:
        """Return the two key DWORDs used by the lookup bucket hash."""
        return (
            int.from_bytes(self.lookup_key[0:4], "little"),
            int.from_bytes(self.lookup_key[4:8], "little"),
        )


def parse_il2_pattern(payload: bytes) -> IL2Pattern:
    """Parse observed offsets, retaining opaque bytes and accepted trailing data."""
    if len(payload) < 12:
        raise ValueError(
            "IL2_PATTERN receiver error 0xA004: payload shorter than 12 bytes"
        )

    v1_count = int.from_bytes(payload[0:2], "little")
    tag_count = int.from_bytes(payload[2:4], "little")
    if v1_count > 0xFFF or tag_count > 0xFF:
        raise ValueError("IL2_PATTERN receiver error 0x8002: count out of range")

    required_size = _HEADER_SIZE + 4 * (v1_count + 2 * tag_count)
    if required_size < _HEADER_SIZE or required_size > len(payload):
        raise ValueError(
            "IL2_PATTERN receiver error 0x8002: required size exceeds payload"
        )

    v1_start = _HEADER_SIZE
    v1_end = v1_start + v1_count * 4
    v1_operands = tuple(
        int.from_bytes(payload[offset : offset + 4], "little")
        for offset in range(v1_start, v1_end, 4)
    )
    tag_end = v1_end + tag_count * 8
    tag_operands = tuple(
        (
            int.from_bytes(payload[offset : offset + 4], "little"),
            int.from_bytes(payload[offset + 4 : offset + 8], "little"),
        )
        for offset in range(v1_end, tag_end, 8)
    )
    return IL2Pattern(
        raw=payload,
        v1_count=v1_count,
        tag_count=tag_count,
        unknown_04=payload[4:8],
        lookup_key=payload[8:28],
        v1_operands=v1_operands,
        tag_operands=tag_operands,
        trailing=payload[required_size:],
    )


def _preview(raw: bytes) -> str:
    return raw[:_RAW_PREVIEW].hex(" ") + (" ..." if len(raw) > _RAW_PREVIEW else "")


def render_il2_pattern(parsed: IL2Pattern) -> FormatResult:
    """Render bounded previews and observed structure without interpreting arrays."""
    v1_preview = ", ".join(
        f"0x{value:08X}" for value in parsed.v1_operands[:_ARRAY_PREVIEW]
    )
    tag_preview = ", ".join(
        f"(0x{first:08X}, 0x{second:08X})"
        for first, second in parsed.tag_operands[:_ARRAY_PREVIEW]
    )
    hash_word0, hash_word1 = parsed.lookup_hash_words
    rows = (
        ("v1_count", str(parsed.v1_count)),
        ("tag_count", str(parsed.tag_count)),
        ("unknown_04", parsed.unknown_04.hex(" ")),
        ("lookup_key_length", str(len(parsed.lookup_key))),
        ("lookup_key", parsed.lookup_key.hex(" ")),
        ("lookup_hash_words", f"0x{hash_word0:08X}, 0x{hash_word1:08X}"),
        ("key_match", "exact 20-byte key; first two DWORDs select bucket"),
        ("v1_operand_count", str(len(parsed.v1_operands))),
        ("v1_operand_preview", v1_preview or "(empty)"),
        (
            "v1_operand_remaining",
            str(max(0, len(parsed.v1_operands) - _ARRAY_PREVIEW)),
        ),
        ("tag_operand_count", str(len(parsed.tag_operands))),
        ("tag_operand_preview", tag_preview or "(empty)"),
        (
            "tag_operand_remaining",
            str(max(0, len(parsed.tag_operands) - _ARRAY_PREVIEW)),
        ),
        (
            "operand_semantics",
            "IL execution operands; individual operations unresolved",
        ),
        ("trailing_length", str(len(parsed.trailing))),
        ("trailing_preview", _preview(parsed.trailing) or "(empty)"),
    )
    return FormatResult(sections=(DisplaySection("IL2_PATTERN", rows=rows),))


SPEC = FamilySpec(
    IL2_PATTERN_TYPE, "IL2_PATTERN", parse_il2_pattern, render_il2_pattern
)
