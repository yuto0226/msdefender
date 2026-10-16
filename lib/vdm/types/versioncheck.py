"""Parser and renderer for VERSIONCHECK (0x7A) payloads."""

from dataclasses import dataclass
from typing import Final

from ..core import DisplaySection, FamilySpec, FormatResult

VERSIONCHECK_TYPE: Final = 0x7A
BASE_SIZE: Final = 8


@dataclass(frozen=True, slots=True)
class VersionCheckPayload:
    raw: bytes
    operator_value: int
    comparison_value: int
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
        operator_value=int.from_bytes(payload[0:4], "little"),
        comparison_value=int.from_bytes(payload[4:8], "little"),
        trailing_raw=payload[BASE_SIZE:],
    )


def render_versioncheck(parsed: VersionCheckPayload) -> FormatResult:
    """Render the two observed DWORDs without assigning unknown flag meanings."""
    sections = [
        DisplaySection(
            "Version Check",
            rows=(
                ("operator_value", f"0x{parsed.operator_value:08x}"),
                ("comparison_value", f"0x{parsed.comparison_value:08x}"),
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
