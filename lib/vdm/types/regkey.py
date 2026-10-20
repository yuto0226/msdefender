"""Lossless parser for REGKEY (0x63) records."""

from dataclasses import dataclass
from typing import Final

from ..core import DisplaySection, FamilySpec, FormatResult

REGKEY_TYPE: Final = 0x63


@dataclass(frozen=True, slots=True)
class RegKeyPayload:
    """Decoded boundaries and raw byte slices for a REGKEY payload."""

    raw: bytes
    key_type: int
    key_path_len: int
    key_path_raw: bytes
    key_path: str | None
    value_len: int
    value_raw: bytes
    value_utf8_preview: str | None
    tail_raw: bytes


def _decode_utf8(data: bytes) -> str | None:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _decode_printable_utf8_preview(data: bytes) -> str | None:
    if not data:
        return None
    decoded = _decode_utf8(data)
    if decoded is None or not decoded.isprintable():
        return None
    return decoded


def parse_regkey(payload: bytes) -> RegKeyPayload:
    """Parse REGKEY's two length-prefixed fields and retain all trailing bytes."""
    if len(payload) < 4:
        raise ValueError(f"truncated REGKEY header: need 4 bytes, have {len(payload)}")

    key_type = int.from_bytes(payload[0:2], "little")
    key_path_len = int.from_bytes(payload[2:4], "little")
    key_path_end = 4 + key_path_len
    if key_path_end > len(payload):
        raise ValueError(
            "truncated REGKEY key_path: "
            f"need {key_path_len} bytes, have {len(payload) - 4}"
        )

    value_len_offset = key_path_end
    if value_len_offset + 2 > len(payload):
        available = len(payload) - value_len_offset
        raise ValueError(f"truncated REGKEY value_len: need 2 bytes, have {available}")

    value_len = int.from_bytes(
        payload[value_len_offset : value_len_offset + 2], "little"
    )
    value_offset = value_len_offset + 2
    value_end = value_offset + value_len
    if value_end > len(payload):
        raise ValueError(
            f"truncated REGKEY value: need {value_len} bytes, "
            f"have {len(payload) - value_offset}"
        )

    key_path_raw = payload[4:key_path_end]
    key_path = _decode_utf8(key_path_raw)
    value_raw = payload[value_offset:value_end]
    return RegKeyPayload(
        raw=payload,
        key_type=key_type,
        key_path_len=key_path_len,
        key_path_raw=key_path_raw,
        key_path=key_path,
        value_len=value_len,
        value_raw=value_raw,
        value_utf8_preview=_decode_printable_utf8_preview(value_raw),
        tail_raw=payload[value_end:],
    )


def render_regkey(parsed: RegKeyPayload) -> FormatResult:
    key_type = f"0x{parsed.key_type:04x}"

    rows: list[tuple[str, str]] = [
        ("key_type", key_type),
        ("key_path_len", str(parsed.key_path_len)),
    ]
    if parsed.key_path is not None:
        rows.append(("key_path", parsed.key_path or "(empty)"))
    else:
        rows.append(("key_path_raw", parsed.key_path_raw.hex(" ") or "(empty)"))
        rows.append(("key_path_text", "invalid UTF-8; raw bytes preserved"))
    rows.extend((("value_len", str(parsed.value_len)),))
    if parsed.value_utf8_preview is not None:
        rows.append(("value_utf8_preview", parsed.value_utf8_preview))
    elif parsed.value_raw:
        rows.append(("value_raw", parsed.value_raw.hex(" ")))

    sections = [DisplaySection("Registry key", rows=tuple(rows))]
    if parsed.tail_raw:
        sections.append(
            DisplaySection(
                "Unclassified trailing bytes",
                rows=(("tail_len", str(len(parsed.tail_raw))),),
            )
        )
    return FormatResult(sections=tuple(sections))


SPEC = FamilySpec(REGKEY_TYPE, "REGKEY", parse_regkey, render_regkey)
