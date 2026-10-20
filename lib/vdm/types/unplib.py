"""Corpus-validated wire parser for UNPLIB (0x57)."""

from dataclasses import dataclass
from typing import Final

from ..core import DisplaySection, FamilySpec, FormatResult

UNPLIB_TYPE: Final = 0x57
PAYLOAD_SIZE: Final = 24


@dataclass(frozen=True, slots=True)
class UnpLibPayload:
    """Observed fixed-size UNPLIB record with neutral field names."""

    raw: bytes
    prefix: bytes
    prefix_word: int
    word_08: int
    word_0c: int
    word_10: int
    word_14: int


def parse_unplib(payload: bytes) -> UnpLibPayload:
    """Parse the 24-byte layout shared by every supplied corpus record."""
    if len(payload) != PAYLOAD_SIZE:
        raise ValueError(
            f"UNPLIB corpus layout requires {PAYLOAD_SIZE} bytes, have {len(payload)}"
        )

    return UnpLibPayload(
        raw=payload,
        prefix=payload[:8],
        prefix_word=int.from_bytes(payload[:2], "little"),
        word_08=int.from_bytes(payload[0x08:0x0C], "little"),
        word_0c=int.from_bytes(payload[0x0C:0x10], "little"),
        word_10=int.from_bytes(payload[0x10:0x14], "little"),
        word_14=int.from_bytes(payload[0x14:0x18], "little"),
    )


def render_unplib(parsed: UnpLibPayload) -> FormatResult:
    """Render stable wire slices without guessing their consumer semantics."""
    return FormatResult(
        sections=(
            DisplaySection(
                "UNPLIB",
                rows=(
                    ("prefix", parsed.prefix.hex(" ")),
                    ("prefix_word", f"0x{parsed.prefix_word:04X}"),
                    ("word_08", f"0x{parsed.word_08:08X}"),
                    ("word_0c", f"0x{parsed.word_0c:08X}"),
                    ("word_10", f"0x{parsed.word_10:08X}"),
                    ("word_14", f"0x{parsed.word_14:08X}"),
                    ("field_semantics", "unresolved"),
                ),
            ),
        )
    )


SPEC = FamilySpec(UNPLIB_TYPE, "UNPLIB", parse_unplib, render_unplib)
