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
    """Observed PATTMATCH fields, retaining raw metadata and opaque code bytes."""

    raw: bytes
    expected_crc: int
    metadata_raw: int
    requested_callback_size: int
    metadata_high16: int
    name_raw: bytes
    name: str
    code_prefix: bytes
    code_body_raw: bytes


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
        name=payload[8:name_end].decode("utf-8", errors="replace"),
        code_prefix=code_blob[:_CODE_PREFIX_SIZE],
        code_body_raw=code_blob[_CODE_PREFIX_SIZE:],
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
        ("name", repr(parsed.name[:_NAME_PREVIEW_SIZE])),
        ("name_raw", _preview(parsed.name_raw)),
        ("code_prefix_length", str(len(parsed.code_prefix))),
        ("code_prefix", _preview(parsed.code_prefix)),
        ("code_body_length", str(len(parsed.code_body_raw))),
        ("code_body_preview", _preview(parsed.code_body_raw)),
        ("terminal_marker", "90 00"),
        ("interpretation", "opaque code bytes; matching semantics unresolved"),
    )
    return FormatResult(sections=(DisplaySection("PATTMATCH", rows=rows),))


SPEC = FamilySpec(PATTMATCH_TYPE, "PATTMATCH", parse_pattmatch, render_pattmatch)
