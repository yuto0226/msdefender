"""Engine-validated parser for UFSP_DISABLE (0x88)."""

from dataclasses import dataclass
from typing import Final

from ..core import DisplaySection, FamilySpec, FormatResult

UFSP_DISABLE_TYPE: Final = 0x88
PAYLOAD_SIZE: Final = 4


@dataclass(frozen=True, slots=True)
class UfspDisablePayload:
    """Plugin ID removed from the registered-plugin collection."""

    raw: bytes
    plugin_id: int
    trailing_raw: bytes


def parse_ufsp_disable(payload: bytes) -> UfspDisablePayload:
    """Parse the engine template's DWORD and preserve accepted suffix bytes."""
    if len(payload) < PAYLOAD_SIZE:
        raise ValueError(
            f"truncated UFSP_DISABLE plugin ID: need {PAYLOAD_SIZE} bytes, "
            f"have {len(payload)}"
        )
    return UfspDisablePayload(
        raw=payload,
        plugin_id=int.from_bytes(payload[:PAYLOAD_SIZE], "little"),
        trailing_raw=payload[PAYLOAD_SIZE:],
    )


def render_ufsp_disable(parsed: UfspDisablePayload) -> FormatResult:
    """Render the exact-ID removal semantics confirmed in the engine."""
    rows = [
        ("plugin_id", f"0x{parsed.plugin_id:08X}"),
        ("effect", "remove exact ID from registered plugins"),
    ]
    if parsed.trailing_raw:
        rows.append(("trailing_raw", parsed.trailing_raw.hex(" ")))
    return FormatResult(
        sections=(
            DisplaySection(
                "UFSP_DISABLE",
                rows=tuple(rows),
            ),
        )
    )


SPEC = FamilySpec(
    UFSP_DISABLE_TYPE,
    "UFSP_DISABLE",
    parse_ufsp_disable,
    render_ufsp_disable,
)
