"""Corpus-profile decoder for the unloadable MAGICCODE record 0xC0."""

from dataclasses import dataclass

from ..core import DisplaySection, FamilySpec, FormatResult

_BYTE_PREVIEW = 64
_TEXT_PREVIEW = 256


@dataclass(frozen=True, slots=True)
class MagicCodePayload:
    raw: bytes
    field_00_raw: bytes
    field_01_raw: bytes
    field_02_raw: bytes
    trailing_raw: bytes

    @property
    def field_00_c_string(self) -> bytes:
        """Return a display-only C-string view of the first observed field."""
        return self.field_00_raw.split(b"\0", 1)[0]

    @property
    def field_02_c_string(self) -> bytes:
        """Return a display-only C-string view of the third observed field."""
        return self.field_02_raw.split(b"\0", 1)[0]


def _take(payload: bytes, cursor: int, size: int, label: str) -> tuple[bytes, int]:
    end = cursor + size
    if end > len(payload):
        raise ValueError(f"truncated MAGICCODE {label}")
    return payload[cursor:end], end


def parse_magiccode(payload: bytes) -> MagicCodePayload:
    """Decode the three length-prefixed fields observed in the local corpus.

    This framing is a corpus profile, not the registered engine receiver
    grammar. Static analysis of that receiver reaches 0xA004 before an entry is
    built for this type in the documented engine version.
    """
    if not payload:
        raise ValueError("truncated MAGICCODE field 00 length")

    field_00_length = payload[0]
    field_00_raw, cursor = _take(payload, 1, field_00_length, "field 00")

    field_01_length_raw, cursor = _take(payload, cursor, 4, "field 01 length")
    field_01_length = int.from_bytes(field_01_length_raw, "little")
    field_01_raw, cursor = _take(payload, cursor, field_01_length, "field 01")

    field_02_length_raw, cursor = _take(payload, cursor, 2, "field 02 length")
    field_02_length = int.from_bytes(field_02_length_raw, "little")
    field_02_raw, cursor = _take(payload, cursor, field_02_length, "field 02")

    return MagicCodePayload(
        raw=payload,
        field_00_raw=field_00_raw,
        field_01_raw=field_01_raw,
        field_02_raw=field_02_raw,
        trailing_raw=payload[cursor:],
    )


def _hex_preview(data: bytes) -> str:
    return data[:_BYTE_PREVIEW].hex(" ") + (" ..." if len(data) > _BYTE_PREVIEW else "")


def _text_preview(data: bytes) -> str:
    text = data[:_TEXT_PREVIEW].decode("ascii", errors="backslashreplace")
    return repr(text) + (" ..." if len(data) > _TEXT_PREVIEW else "")


def render_magiccode(parsed: MagicCodePayload) -> FormatResult:
    rows = (
        ("semantic_status", "corpus profile; registered receiver returns 0xA004"),
        ("profile", "u8-length field, u32-length field, u16-length field"),
        ("field_00_length", str(len(parsed.field_00_raw))),
        ("field_00_text", _text_preview(parsed.field_00_c_string)),
        ("field_00_raw", _hex_preview(parsed.field_00_raw)),
        ("field_01_length", str(len(parsed.field_01_raw))),
        ("field_01_raw", _hex_preview(parsed.field_01_raw)),
        ("field_02_length", str(len(parsed.field_02_raw))),
        ("field_02_text", _text_preview(parsed.field_02_c_string)),
        ("field_02_raw", _hex_preview(parsed.field_02_raw)),
        ("trailing_length", str(len(parsed.trailing_raw))),
        ("trailing_preview", _hex_preview(parsed.trailing_raw)),
    )
    return FormatResult(sections=(DisplaySection("MAGICCODE", rows=rows),))


SPEC = FamilySpec(0xC0, "MAGICCODE", parse_magiccode, render_magiccode)
