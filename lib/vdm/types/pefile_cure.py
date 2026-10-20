"""Typed parser and bounded renderer for PEFILE_CURE (0x3D)."""

from dataclasses import dataclass
from typing import Final

from ..core import DisplaySection, FamilySpec, FormatResult

PEFILE_CURE_TYPE: Final = 0x3D
BASE_SIZE: Final = 12
TRAILING_PREVIEW: Final = 16


@dataclass(frozen=True, slots=True)
class PeFileCure:
    """Lossless observed PEFILE_CURE prefix and neutral method fields."""

    raw: bytes
    name_crc: int
    method_spec: int
    arg: int
    selector: int
    method_data: int
    trailing_raw: bytes


def parse_pefile_cure(payload: bytes) -> PeFileCure:
    """Parse the three-DWORD prefix, retaining any bytes after it."""
    if len(payload) < BASE_SIZE:
        raise ValueError(
            f"truncated PEFILE_CURE header: need {BASE_SIZE} bytes, have {len(payload)}"
        )

    method_spec = int.from_bytes(payload[4:8], "little")
    return PeFileCure(
        raw=payload,
        name_crc=int.from_bytes(payload[0:4], "little"),
        method_spec=method_spec,
        arg=int.from_bytes(payload[8:12], "little"),
        selector=method_spec >> 24,
        method_data=method_spec & 0x00FFFFFF,
        trailing_raw=payload[BASE_SIZE:],
    )


def _method_description(selector: int) -> str:
    if selector <= 6:
        return f"cm{selector}"
    if selector == 7:
        return "special (consumer returns 253)"
    return "fallback clean_rpf_alg32"


def render_pefile_cure(parsed: PeFileCure) -> FormatResult:
    """Render interpreted selector behavior and bounded trailing bytes."""
    sections = [
        DisplaySection(
            "PEFILE_CURE",
            rows=(
                ("name_crc", f"0x{parsed.name_crc:08X}"),
                ("name_crc_note", "engine CRC_1 output"),
                ("method_spec", f"0x{parsed.method_spec:08X}"),
                ("selector", str(parsed.selector)),
                ("method_data", f"0x{parsed.method_data:06X}"),
                ("method_dispatch", _method_description(parsed.selector)),
                ("arg", f"0x{parsed.arg:08X}"),
            ),
        )
    ]
    if parsed.trailing_raw:
        preview = parsed.trailing_raw[:TRAILING_PREVIEW].hex(" ")
        if len(parsed.trailing_raw) > TRAILING_PREVIEW:
            preview += " ..."
        sections.append(
            DisplaySection(
                "Trailing Data",
                rows=(
                    ("trailing_length", str(len(parsed.trailing_raw))),
                    ("trailing_preview", preview),
                ),
            )
        )
    return FormatResult(sections=tuple(sections))


SPEC = FamilySpec(
    PEFILE_CURE_TYPE,
    "PEFILE_CURE",
    parse_pefile_cure,
    render_pefile_cure,
)
