"""Corpus-validated fixed wire view for PEMAIN_LOCATOR (0x86)."""

from dataclasses import dataclass
from typing import Final

from ..core import DisplaySection, FamilySpec, FormatResult

PEMAIN_LOCATOR_TYPE: Final = 0x86
PAYLOAD_SIZE: Final = 8


@dataclass(frozen=True, slots=True)
class PeMainLocatorPayload:
    """Two observed little-endian words with unresolved semantics."""

    raw: bytes
    word_00: int
    word_04: int


def parse_pemain_locator(payload: bytes) -> PeMainLocatorPayload:
    """Parse the exact eight-byte layout shared by all supplied records."""
    if len(payload) != PAYLOAD_SIZE:
        raise ValueError(
            "PEMAIN_LOCATOR corpus layout requires "
            f"{PAYLOAD_SIZE} bytes, have {len(payload)}"
        )
    return PeMainLocatorPayload(
        raw=payload,
        word_00=int.from_bytes(payload[:4], "little"),
        word_04=int.from_bytes(payload[4:], "little"),
    )


def render_pemain_locator(parsed: PeMainLocatorPayload) -> FormatResult:
    """Render neutral word names without assigning unverified PE semantics."""
    return FormatResult(
        sections=(
            DisplaySection(
                "PEMAIN_LOCATOR",
                rows=(
                    ("word_00", f"0x{parsed.word_00:08X}"),
                    ("word_04", f"0x{parsed.word_04:08X}"),
                    ("field_semantics", "unresolved"),
                    ("validation_profile", "current corpus: exactly 8 bytes"),
                ),
            ),
        )
    )


SPEC = FamilySpec(
    PEMAIN_LOCATOR_TYPE,
    "PEMAIN_LOCATOR",
    parse_pemain_locator,
    render_pemain_locator,
)
