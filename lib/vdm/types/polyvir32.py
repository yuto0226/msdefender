"""Corpus-profile model for observed POLYVIR32 records (type 0x21)."""

from dataclasses import dataclass
from typing import Final

from ..core import DisplaySection, FamilySpec, FormatResult

POLYVIR32_TYPE: Final = 0x21
POLYVIR32_SIZE: Final = 34
_PREFIX_SIZE: Final = 16
_TERMINATOR_OFFSET: Final = 0x20


@dataclass(frozen=True, slots=True)
class Polyvir32Payload:
    """Preserve offset-grouped corpus fields without assigning semantics."""

    raw: bytes
    bytes_00_0f: bytes
    word_10: int
    word_12: int
    dword_14: int
    word_18: int
    word_1a: int
    dword_1c: int

    def to_bytes(self) -> bytes:
        """Rebuild the observed 34-byte layout exactly."""
        return b"".join(
            (
                self.bytes_00_0f,
                self.word_10.to_bytes(2, "little"),
                self.word_12.to_bytes(2, "little"),
                self.dword_14.to_bytes(4, "little"),
                self.word_18.to_bytes(2, "little"),
                self.word_1a.to_bytes(2, "little"),
                self.dword_1c.to_bytes(4, "little"),
                bytes(2),
            )
        )


def parse_polyvir32(payload: bytes) -> Polyvir32Payload:
    """Parse the validated corpus profile: 16 bytes, two groups, zero word."""
    if len(payload) != POLYVIR32_SIZE:
        raise ValueError(
            f"POLYVIR32 payload must be exactly {POLYVIR32_SIZE} bytes, "
            f"have {len(payload)}"
        )
    terminator = int.from_bytes(payload[_TERMINATOR_OFFSET:], "little")
    if terminator != 0:
        raise ValueError("POLYVIR32 terminator at offset 0x20 must be zero")

    return Polyvir32Payload(
        raw=payload,
        bytes_00_0f=payload[:_PREFIX_SIZE],
        word_10=int.from_bytes(payload[0x10:0x12], "little"),
        word_12=int.from_bytes(payload[0x12:0x14], "little"),
        dword_14=int.from_bytes(payload[0x14:0x18], "little"),
        word_18=int.from_bytes(payload[0x18:0x1A], "little"),
        word_1a=int.from_bytes(payload[0x1A:0x1C], "little"),
        dword_1c=int.from_bytes(payload[0x1C:0x20], "little"),
    )


def render_polyvir32(parsed: Polyvir32Payload) -> FormatResult:
    rows = (
        ("bytes_00_0f", parsed.bytes_00_0f.hex(" ")),
        ("word_10", f"0x{parsed.word_10:04X}"),
        ("word_12", f"0x{parsed.word_12:04X}"),
        ("dword_14", f"0x{parsed.dword_14:08X}"),
        ("word_18", f"0x{parsed.word_18:04X}"),
        ("word_1a", f"0x{parsed.word_1a:04X}"),
        ("dword_1c", f"0x{parsed.dword_1c:08X}"),
        ("terminator_20", "0x0000"),
    )
    return FormatResult(sections=(DisplaySection("POLYVIR32", rows=rows),))


SPEC: Final = FamilySpec(POLYVIR32_TYPE, "POLYVIR32", parse_polyvir32, render_polyvir32)
