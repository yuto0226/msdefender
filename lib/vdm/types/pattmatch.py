"""Lossless parser and bounded renderer for PATTMATCH (0x51)."""

from dataclasses import dataclass
from typing import Final

from ..core import DisplaySection, FamilySpec, FormatResult

PATTMATCH_TYPE: Final = 0x51
_CODE_PREFIX_SIZE: Final = 8
_PREVIEW_SIZE: Final = 64
_NAME_PREVIEW_SIZE: Final = 256


@dataclass(frozen=True, slots=True)
class PattMatchPayload:
    """PATTMATCH metadata, opcode key, and encoded chunk stream."""

    raw: bytes
    expected_crc: int
    metadata_raw: int
    requested_callback_size: int
    metadata_high16: int
    name_raw: bytes
    opcode_key: bytes
    nibble_stream_raw: bytes

    @property
    def name_text(self) -> str | None:
        """Return a display-only UTF-8 view without asserting engine encoding."""
        try:
            text = self.name_raw.decode("utf-8")
        except UnicodeDecodeError:
            return None
        return (
            text
            if text and all(character.isprintable() for character in text)
            else None
        )


def parse_pattmatch(payload: bytes) -> PattMatchPayload:
    """Parse the observed PATTMATCH grammar and require its terminal marker."""
    if len(payload) < 10:
        raise ValueError("truncated PATTMATCH header or code blob")

    expected_crc = int.from_bytes(payload[0:4], "little")
    metadata_raw = int.from_bytes(payload[4:8], "little")
    name_end = payload.find(b"\0", 8)
    if name_end < 0:
        raise ValueError("PATTMATCH name is not NUL-terminated")
    if name_end == 8:
        raise ValueError("PATTMATCH name must be nonempty")

    code_blob = payload[name_end + 1 :]
    if len(code_blob) < _CODE_PREFIX_SIZE:
        raise ValueError("truncated PATTMATCH code prefix")

    marker_offset = code_blob.find(b"\x90\x00", _CODE_PREFIX_SIZE)
    if marker_offset < 0:
        raise ValueError("PATTMATCH code blob has no 90 00 marker")
    if marker_offset + 2 != len(code_blob):
        raise ValueError("PATTMATCH code blob has bytes after its first 90 00 marker")

    return PattMatchPayload(
        raw=payload,
        expected_crc=expected_crc,
        metadata_raw=metadata_raw,
        requested_callback_size=metadata_raw & 0xFFFF,
        metadata_high16=metadata_raw >> 16,
        name_raw=payload[8:name_end],
        opcode_key=code_blob[:_CODE_PREFIX_SIZE],
        nibble_stream_raw=code_blob[_CODE_PREFIX_SIZE:],
    )


def _preview(raw: bytes, size: int = _PREVIEW_SIZE) -> str:
    preview = raw[:size].hex(" ")
    return preview + (" ..." if len(raw) > size else "")


def render_pattmatch(parsed: PattMatchPayload) -> FormatResult:
    """Show observed values and bounded raw previews without guessed semantics."""
    rows = (
        ("expected_crc", f"0x{parsed.expected_crc:08X}"),
        ("metadata_raw", f"0x{parsed.metadata_raw:08X}"),
        ("requested_callback_size", str(parsed.requested_callback_size)),
        ("metadata_high16_raw", f"0x{parsed.metadata_high16:04X}"),
        ("name_length", str(len(parsed.name_raw))),
        (
            "name_text_preview",
            repr(parsed.name_text[:_NAME_PREVIEW_SIZE])
            if parsed.name_text is not None
            else "unavailable",
        ),
        ("name_raw", _preview(parsed.name_raw)),
        ("opcode_key_length", str(len(parsed.opcode_key))),
        ("opcode_key", _preview(parsed.opcode_key)),
        ("nibble_stream_length", str(len(parsed.nibble_stream_raw))),
        ("nibble_stream_preview", _preview(parsed.nibble_stream_raw)),
        ("terminal_marker", "90 00"),
        (
            "matching",
            "8 opcode-byte prefilter; decoded chunk lengths feed CRC_0 comparison",
        ),
        ("operand_semantics", "nibble length codec details unresolved"),
    )
    return FormatResult(sections=(DisplaySection("PATTMATCH", rows=rows),))


SPEC = FamilySpec(PATTMATCH_TYPE, "PATTMATCH", parse_pattmatch, render_pattmatch)
