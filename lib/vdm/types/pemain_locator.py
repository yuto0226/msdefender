"""Template-backed prefix view for PEMAIN_LOCATOR (0x86)."""

from dataclasses import dataclass
from typing import Final

from ..core import DisplaySection, FamilySpec, FormatResult

PEMAIN_LOCATOR_TYPE: Final = 0x86
PAYLOAD_SIZE: Final = 8
_TRAILING_PREVIEW_BYTES: Final = 64


@dataclass(frozen=True, slots=True)
class PeMainLocatorPayload:
    """Lookup key, relative read offset, and any unconsumed tail."""

    raw: bytes
    lookup_key: int
    relative_offset: int
    trailing_raw: bytes


def parse_pemain_locator(payload: bytes) -> PeMainLocatorPayload:
    """Parse the two DWORD template fields and preserve any trailing bytes."""
    if len(payload) < PAYLOAD_SIZE:
        raise ValueError(
            "PEMAIN_LOCATOR template requires at least "
            f"{PAYLOAD_SIZE} bytes, have {len(payload)}"
        )
    return PeMainLocatorPayload(
        raw=payload,
        lookup_key=int.from_bytes(payload[:4], "little"),
        relative_offset=int.from_bytes(payload[4:8], "little"),
        trailing_raw=payload[8:],
    )


def render_pemain_locator(parsed: PeMainLocatorPayload) -> FormatResult:
    """Render consumer-backed roles without assigning broader PE semantics."""
    trailing_preview = parsed.trailing_raw[:_TRAILING_PREVIEW_BYTES].hex(" ")
    if len(parsed.trailing_raw) > _TRAILING_PREVIEW_BYTES:
        omitted = len(parsed.trailing_raw) - _TRAILING_PREVIEW_BYTES
        trailing_preview += f" … ({omitted} more bytes)"
    return FormatResult(
        sections=(
            DisplaySection(
                "PEMAIN_LOCATOR",
                rows=(
                    ("lookup_key", f"0x{parsed.lookup_key:08X}"),
                    ("relative_offset", f"0x{parsed.relative_offset:08X}"),
                    ("trailing_raw", trailing_preview or "(empty)"),
                    (
                        "runtime_use",
                        (
                            "exact bsearch_s(Base_3) match by pattern_info_t[0]; if "
                            "relative_offset < 0x3FC, read u32le at current search "
                            "offset + relative_offset"
                        ),
                    ),
                    (
                        "relative_base",
                        (
                            "current search offset in scan_compiler_worker (input plus "
                            "fallback candidate adjustment when used)"
                        ),
                    ),
                    ("engine_template", "2 × u32le; trailing bytes are not checked"),
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
