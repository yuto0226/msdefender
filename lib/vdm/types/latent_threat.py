"""Lossless wire parser for LATENT_THREAT (0x69) payloads."""

from dataclasses import dataclass
from typing import Final

from ..core import DisplaySection, FamilySpec, FormatResult

LATENT_THREAT_TYPE: Final = 0x69
PAYLOAD_SIZE: Final = 8
WORD_SIZE: Final = 4


@dataclass(frozen=True, slots=True)
class LatentThreat:
    """A lookup threat ID and its associated threat ID, as stored on wire."""

    raw: bytes
    lookup_threat_id: int
    related_threat_id: int


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
        lookup_threat_id=int.from_bytes(payload[0:WORD_SIZE], "little"),
        related_threat_id=int.from_bytes(payload[WORD_SIZE:PAYLOAD_SIZE], "little"),
    )


def render_latent_threat(parsed: LatentThreat) -> FormatResult:
    """Render the confirmed threat-ID roles."""
    return FormatResult(
        sections=(
            DisplaySection(
                "LATENT_THREAT",
                rows=(
                    ("lookup_threat_id", f"0x{parsed.lookup_threat_id:08x}"),
                    ("related_threat_id", f"0x{parsed.related_threat_id:08x}"),
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
