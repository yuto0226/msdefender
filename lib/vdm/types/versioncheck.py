"""Parser and renderer for VERSIONCHECK (0x7A) payloads."""

from dataclasses import dataclass
from typing import Final

from ..core import DisplaySection, FamilySpec, FormatResult

VERSIONCHECK_TYPE: Final = 0x7A
BASE_SIZE: Final = 8


@dataclass(frozen=True, slots=True)
class VersionCheckPayload:
    raw: bytes
    field_00: int
    field_04: int
    trailing_raw: bytes


def parse_versioncheck(payload: bytes) -> VersionCheckPayload:
    """Parse the observed two-DWORD prefix and preserve any trailing bytes."""
    if len(payload) < BASE_SIZE:
        raise ValueError(
            f"truncated VERSIONCHECK header: need {BASE_SIZE} bytes, "
            f"have {len(payload)}"
        )

    return VersionCheckPayload(
        raw=payload,
        field_00=int.from_bytes(payload[0:4], "little"),
        field_04=int.from_bytes(payload[4:8], "little"),
        trailing_raw=payload[BASE_SIZE:],
    )


def render_versioncheck(parsed: VersionCheckPayload) -> FormatResult:
    """Render confirmed DWORD ordering and conservative evaluator roles."""
    sections = [
        DisplaySection(
            "Version Check",
            rows=(
                (
                    "field_00",
                    f"0x{parsed.field_00:08x} (evaluator selector; mapping unresolved)",
                ),
                ("field_04", f"0x{parsed.field_04:08x} (selector-dependent operand)"),
            ),
        )
    ]
    if parsed.trailing_raw:
        sections.append(
            DisplaySection(
                "Trailing Data",
                rows=(("trailing_len", f"{len(parsed.trailing_raw)} B"),),
            )
        )
    return FormatResult(sections=tuple(sections))


SPEC = FamilySpec(
    VERSIONCHECK_TYPE,
    "VERSIONCHECK",
    parse_versioncheck,
    render_versioncheck,
)
