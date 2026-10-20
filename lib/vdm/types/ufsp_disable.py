"""Corpus-validated DWORD view for UFSP_DISABLE (0x88)."""

from dataclasses import dataclass
from typing import Final

from ..core import DisplaySection, FamilySpec, FormatResult

UFSP_DISABLE_TYPE: Final = 0x88
PAYLOAD_SIZE: Final = 4


@dataclass(frozen=True, slots=True)
class UfspDisablePayload:
    """Observed single little-endian value; its engine effect is unresolved."""

    raw: bytes
    value: int


def parse_ufsp_disable(payload: bytes) -> UfspDisablePayload:
    """Parse the four-byte layout shared by all supplied corpus records."""
    if len(payload) != PAYLOAD_SIZE:
        raise ValueError(
            f"UFSP_DISABLE corpus layout requires {PAYLOAD_SIZE} bytes, "
            f"have {len(payload)}"
        )
    return UfspDisablePayload(
        raw=payload,
        value=int.from_bytes(payload, "little"),
    )


def render_ufsp_disable(parsed: UfspDisablePayload) -> FormatResult:
    """Render the wire value while keeping its selector semantics unresolved."""
    return FormatResult(
        sections=(
            DisplaySection(
                "UFSP_DISABLE",
                rows=(
                    ("value", f"0x{parsed.value:08X}"),
                    ("value_semantics", "unresolved"),
                    ("validation_profile", "current corpus: exactly 4 bytes"),
                ),
            ),
        )
    )


SPEC = FamilySpec(
    UFSP_DISABLE_TYPE,
    "UFSP_DISABLE",
    parse_ufsp_disable,
    render_ufsp_disable,
)
