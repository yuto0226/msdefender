"""Lossless parser and renderer for COMMON_CODE (0xAF) payloads."""

from dataclasses import dataclass
from typing import Final

from ..core import DisplaySection, FamilySpec, FormatResult

COMMON_CODE_TYPE: Final = 0xAF
HEADER_SIZE: Final = 4
MIN_CODE_SIZE: Final = 1
MAX_CODE_SIZE: Final = 0x100
FLAGS_LOOKUP_MASK: Final = 0x0003


@dataclass(frozen=True, slots=True)
class CommonCodePayload:
    """A validated COMMON_CODE header and opaque body, preserving raw bytes."""

    raw: bytes
    header_raw: bytes
    flags: int
    code_size: int
    body_raw: bytes

    @property
    def lookup_mode(self) -> int | None:
        """Return the loader's selected lookup mode for recognized low bits."""
        value = self.flags & FLAGS_LOOKUP_MASK
        if value == 0:
            return 1
        if value == 1:
            return 2
        return None


def parse_common_code(payload: bytes) -> CommonCodePayload:
    """Parse the receiver-validated 4-byte header and exact-length code body."""
    if len(payload) < HEADER_SIZE:
        raise ValueError(
            f"truncated COMMON_CODE header: need {HEADER_SIZE} bytes, "
            f"have {len(payload)}"
        )

    flags = int.from_bytes(payload[0:2], "little")
    code_size = int.from_bytes(payload[2:4], "little")
    if code_size < MIN_CODE_SIZE:
        raise ValueError("COMMON_CODE code_size must be at least 1 byte")
    if code_size > MAX_CODE_SIZE:
        raise ValueError(
            f"COMMON_CODE code_size exceeds {MAX_CODE_SIZE} bytes: {code_size}"
        )

    body_end = HEADER_SIZE + code_size
    if len(payload) < body_end:
        raise ValueError(
            f"truncated COMMON_CODE body: need {code_size} bytes, "
            f"have {len(payload) - HEADER_SIZE}"
        )
    if len(payload) > body_end:
        raise ValueError(
            f"COMMON_CODE has {len(payload) - body_end} trailing bytes; "
            "receiver requires an exact payload size"
        )

    return CommonCodePayload(
        raw=payload,
        header_raw=payload[:HEADER_SIZE],
        flags=flags,
        code_size=code_size,
        body_raw=payload[HEADER_SIZE:body_end],
    )


def render_common_code(parsed: CommonCodePayload) -> FormatResult:
    """Render confirmed header metadata without interpreting code bytes."""
    lookup_mode = (
        str(parsed.lookup_mode)
        if parsed.lookup_mode is not None
        else "skipped by loader (low flag bits 2 or 3)"
    )
    sections = (
        DisplaySection(
            "COMMON_CODE Header",
            rows=(
                ("flags", f"0x{parsed.flags:04x}"),
                ("code_size", f"{parsed.code_size} B"),
                ("loader_lookup_mode", lookup_mode),
            ),
        ),
        DisplaySection(
            "Opaque Code Bytes",
            rows=(
                ("body_length", f"{len(parsed.body_raw)} B"),
                ("body_raw", parsed.body_raw.hex(" ")),
            ),
        ),
    )
    return FormatResult(sections=sections)


SPEC = FamilySpec(
    COMMON_CODE_TYPE,
    "COMMON_CODE",
    parse_common_code,
    render_common_code,
)
