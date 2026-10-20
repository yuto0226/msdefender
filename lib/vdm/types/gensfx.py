"""Corpus-validated wire parser for GENSFX (0x56)."""

from dataclasses import dataclass
from typing import Final

from ..core import DisplaySection, FamilySpec, FormatResult

GENSFX_TYPE: Final = 0x56
PAYLOAD_SIZE: Final = 84
NAME_SIZE: Final = 64


@dataclass(frozen=True, slots=True)
class GenSfxPayload:
    """Observed fixed-size GENSFX record with neutral field names."""

    raw: bytes
    name_bytes: bytes
    word_40: int
    word_44: int
    word_48: int
    format_tag: bytes

    @property
    def name(self) -> str:
        """Return the observed NUL-terminated ASCII name view."""
        return self.name_bytes.split(b"\0", 1)[0].decode("ascii", errors="replace")


def parse_gensfx(payload: bytes) -> GenSfxPayload:
    """Parse the fixed 84-byte layout observed in both supplied corpora."""
    if len(payload) != PAYLOAD_SIZE:
        raise ValueError(
            f"GENSFX corpus layout requires {PAYLOAD_SIZE} bytes, have {len(payload)}"
        )

    return GenSfxPayload(
        raw=payload,
        name_bytes=payload[:NAME_SIZE],
        word_40=int.from_bytes(payload[0x40:0x44], "little"),
        word_44=int.from_bytes(payload[0x44:0x48], "little"),
        word_48=int.from_bytes(payload[0x48:0x4C], "little"),
        format_tag=payload[0x4C:0x54],
    )


def _format_tag(tag: bytes) -> str:
    printable = tag.rstrip(b"\0")
    if printable and all(0x20 <= byte <= 0x7E for byte in printable):
        return f"{printable.decode('ascii')} ({tag.hex(' ')})"
    return tag.hex(" ")


def render_gensfx(parsed: GenSfxPayload) -> FormatResult:
    """Render confirmed wire fields without assigning unknown DWORD semantics."""
    return FormatResult(
        sections=(
            DisplaySection(
                "GENSFX",
                rows=(
                    ("name", parsed.name or "(empty)"),
                    ("word_40", f"0x{parsed.word_40:08X}"),
                    ("word_44", f"0x{parsed.word_44:08X}"),
                    ("word_48", f"0x{parsed.word_48:08X}"),
                    ("format_tag", _format_tag(parsed.format_tag)),
                    ("word_semantics", "unresolved"),
                ),
            ),
        )
    )


SPEC = FamilySpec(GENSFX_TYPE, "GENSFX", parse_gensfx, render_gensfx)
