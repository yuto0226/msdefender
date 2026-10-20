"""Parser and renderer for NDAT (0xA9) payloads."""

from dataclasses import dataclass
from typing import Final

from ..core import DisplaySection, FamilySpec, FormatResult

NDAT_TYPE: Final = 0xA9
PREVIEW_SIZE: Final = 16


@dataclass(frozen=True, slots=True)
class NdatPayload:
    """NDAT wire fields consumed by ``ReceiveNewTemplate``."""

    raw: bytes
    data_length: int
    data_raw: bytes
    callback_index: int
    record_id_suffix_raw: bytes | None
    trailing_raw: bytes


def parse_ndat(payload: bytes) -> NdatPayload:
    """Parse the counted data, callback index, and optional record-ID suffix."""
    if len(payload) < 4:
        raise ValueError(
            f"truncated NDAT payload: need 4-byte data length, have {len(payload)}"
        )

    data_length = int.from_bytes(payload[:4], "little")
    callback_offset = 4 + data_length
    if callback_offset >= len(payload):
        available = max(0, len(payload) - 4)
        raise ValueError(
            "truncated NDAT payload: "
            f"declared {data_length} data bytes and callback byte, have {available}"
        )

    suffix_and_trailing = payload[callback_offset + 1 :]
    record_id_suffix_raw: bytes | None = None
    trailing_raw = b""
    if suffix_and_trailing:
        terminator = suffix_and_trailing.find(b"\0")
        if terminator < 0:
            raise ValueError("unterminated NDAT record-ID suffix")
        record_id_suffix_raw = suffix_and_trailing[: terminator + 1]
        trailing_raw = suffix_and_trailing[terminator + 1 :]

    return NdatPayload(
        raw=payload,
        data_length=data_length,
        data_raw=payload[4:callback_offset],
        callback_index=payload[callback_offset],
        record_id_suffix_raw=record_id_suffix_raw,
        trailing_raw=trailing_raw,
    )


def _text_preview(data: bytes) -> str:
    preview = data[:PREVIEW_SIZE]
    text = "".join(chr(byte) if 0x20 <= byte <= 0x7E else "." for byte in preview)
    if len(data) > PREVIEW_SIZE:
        text += "..."
    return text or "(empty)"


def _preview_rows(data: bytes) -> tuple[tuple[str, str], ...]:
    return (
        ("hex_preview", data[:PREVIEW_SIZE].hex(" ") or "(empty)"),
        ("text_preview", _text_preview(data)),
    )


def render_ndat(parsed: NdatPayload) -> FormatResult:
    suffix = parsed.record_id_suffix_raw
    rows = [
        ("data_length", f"{parsed.data_length} B"),
        ("callback_index", f"{parsed.callback_index} (0x{parsed.callback_index:02x})"),
        ("record_id_suffix", _text_preview(suffix[:-1]) if suffix else "not present"),
    ]
    if parsed.trailing_raw:
        rows.append(("ignored_trailing_length", f"{len(parsed.trailing_raw)} B"))

    return FormatResult(
        sections=(
            DisplaySection("NDAT Metadata", rows=tuple(rows)),
            DisplaySection("NDAT Data", rows=_preview_rows(parsed.data_raw)),
        )
    )


NDAT_SPEC = FamilySpec(NDAT_TYPE, "NDAT", parse_ndat, render_ndat)
