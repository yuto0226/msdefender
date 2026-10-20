"""Corpus-validated wire parser for GENSFX (0x56)."""

from dataclasses import dataclass
from typing import Final

from ..core import DisplaySection, FamilySpec, FormatResult

GENSFX_TYPE: Final = 0x56
PAYLOAD_SIZE: Final = 84
NAME_SIZE: Final = 64


@dataclass(frozen=True, slots=True)
class GenSfxPayload:
    """GENSFX fields whose offsets have consumer-side evidence."""

    raw: bytes
    name_bytes: bytes
    lookup_key: int
    scan_start: int
    scan_end: int
    match_bytes: bytes
    match_offset_delta: int

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
        lookup_key=int.from_bytes(payload[0x40:0x44], "little"),
        scan_start=int.from_bytes(payload[0x44:0x48], "little"),
        scan_end=int.from_bytes(payload[0x48:0x4C], "little"),
        match_bytes=payload[0x4C:0x50],
        match_offset_delta=int.from_bytes(payload[0x50:0x54], "little"),
    )


def render_gensfx(parsed: GenSfxPayload) -> FormatResult:
    """Render scan semantics established by the registered receiver/consumer."""
    return FormatResult(
        sections=(
            DisplaySection(
                "GENSFX",
                rows=(
                    ("name", parsed.name or "(empty)"),
                    ("lookup_key", f"0x{parsed.lookup_key:08X}"),
                    ("scan_start", f"0x{parsed.scan_start:08X}"),
                    ("scan_end", f"0x{parsed.scan_end:08X}"),
                    ("match_bytes", parsed.match_bytes.hex(" ")),
                    (
                        "match_offset_delta",
                        f"0x{parsed.match_offset_delta:08X}",
                    ),
                    (
                        "semantics_note",
                        (
                            "scan interval and 4-byte search pattern confirmed; "
                            "lookup-key domain and delta purpose unresolved"
                        ),
                    ),
                ),
            ),
        )
    )


SPEC = FamilySpec(GENSFX_TYPE, "GENSFX", parse_gensfx, render_gensfx)
