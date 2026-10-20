"""Lossless wire parser for LATENT_THREAT (0x69) payloads."""

from dataclasses import dataclass
from typing import Final

from ..core import DisplaySection, FamilySpec, FormatResult

LATENT_THREAT_TYPE: Final = 0x69
PAYLOAD_SIZE: Final = 8
WORD_SIZE: Final = 4


@dataclass(frozen=True, slots=True)
class LatentThreat:
    """Two raw 32-bit words whose precise domain is not established."""

    raw: bytes
    word_0: int
    word_1: int


def parse_latent_threat(payload: bytes) -> LatentThreat:
    """Parse the exact 8-byte payload accepted by latent_info_receiver."""
    if len(payload) < PAYLOAD_SIZE:
        raise ValueError(
            "truncated LATENT_THREAT payload: "
            f"need {PAYLOAD_SIZE} bytes, have {len(payload)}"
        )
    if len(payload) > PAYLOAD_SIZE:
        raise ValueError(
            "LATENT_THREAT payload must be exactly "
            f"{PAYLOAD_SIZE} bytes, have {len(payload)}"
        )

    return LatentThreat(
        raw=payload,
        word_0=int.from_bytes(payload[0:WORD_SIZE], "little"),
        word_1=int.from_bytes(payload[WORD_SIZE:PAYLOAD_SIZE], "little"),
    )


def render_latent_threat(parsed: LatentThreat) -> FormatResult:
    """Render both words without assigning unconfirmed ID roles."""
    return FormatResult(
        sections=(
            DisplaySection(
                "LATENT_THREAT",
                rows=(
                    ("word_0_raw", f"0x{parsed.word_0:08x}"),
                    ("word_1_raw", f"0x{parsed.word_1:08x}"),
                ),
            ),
        )
    )


SPEC = FamilySpec(
    LATENT_THREAT_TYPE,
    "LATENT_THREAT",
    parse_latent_threat,
    render_latent_threat,
)
