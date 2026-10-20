"""Typed parser for THREAT_UPDATE_STATUS (0xC3) records."""

from dataclasses import dataclass
from typing import Final

from ..core import FamilySpec, FormatResult

_NAME_PREVIEW_BYTES = 64
_NAME_PREVIEW_CHARS = 96
_TAIL_PREVIEW_BYTES = 32
THREAT_UPDATE_STATUS_TYPE: Final = 0xC3


@dataclass(frozen=True, slots=True)
class ThreatUpdateStatusPayload:
    """Lossless bytes plus safely decoded view of a 0xC3 payload."""

    raw: bytes
    name_len: int
    name_raw: bytes
    name: str
    word_08: int
    word_0c: int
    trailing_raw: bytes


def _safe_name(raw: bytes) -> str:
    decoded = raw.decode("utf-8", errors="replace")
    safe: list[str] = []
    for char in decoded:
        codepoint = ord(char)
        if char == "\\":
            safe.append("\\\\")
        elif char.isprintable():
            safe.append(char)
        elif codepoint <= 0xFF:
            safe.append(f"\\x{codepoint:02x}")
        else:
            safe.append(f"\\u{codepoint:04x}")
    return "".join(safe)


def _take(payload: bytes, cursor: int, size: int, label: str) -> tuple[bytes, int]:
    end = cursor + size
    if end > len(payload):
        raise ValueError(f"truncated {label}")
    return payload[cursor:end], end


def parse_threat_update_status(payload: bytes) -> ThreatUpdateStatusPayload:
    """Parse the engine template: u8-length bytes followed by two u32 words.

    The engine stops after its three template instructions and does not require
    the cursor to equal the payload end, so remaining bytes are preserved.
    """
    length_raw, cursor = _take(payload, 0, 1, "name length")
    name_len = length_raw[0]
    name_raw, cursor = _take(payload, cursor, name_len, "name")
    word_08_raw, cursor = _take(payload, cursor, 4, "word_08")
    word_0c_raw, cursor = _take(payload, cursor, 4, "word_0c")

    return ThreatUpdateStatusPayload(
        raw=payload,
        name_len=name_len,
        name_raw=name_raw,
        name=_safe_name(name_raw),
        word_08=int.from_bytes(word_08_raw, "little"),
        word_0c=int.from_bytes(word_0c_raw, "little"),
        trailing_raw=payload[cursor:],
    )


def render_threat_update_status(
    parsed: ThreatUpdateStatusPayload,
) -> FormatResult:
    """Render bounded previews and leave both status words explicitly unknown."""
    name_hex = parsed.name_raw[:_NAME_PREVIEW_BYTES].hex(" ")
    if len(parsed.name_raw) > _NAME_PREVIEW_BYTES:
        name_hex += f" … ({len(parsed.name_raw) - _NAME_PREVIEW_BYTES} more bytes)"

    name_preview = parsed.name[:_NAME_PREVIEW_CHARS]
    if len(parsed.name) > _NAME_PREVIEW_CHARS:
        name_preview += f" … ({len(parsed.name) - _NAME_PREVIEW_CHARS} more chars)"

    tail_hex = parsed.trailing_raw[:_TAIL_PREVIEW_BYTES].hex(" ")
    if len(parsed.trailing_raw) > _TAIL_PREVIEW_BYTES:
        tail_hex += f" … ({len(parsed.trailing_raw) - _TAIL_PREVIEW_BYTES} more bytes)"

    return FormatResult(
        fields=(
            ("name_len", str(parsed.name_len)),
            ("name_raw", name_hex or "(empty)"),
            ("name_safe", name_preview or "(empty)"),
            ("word_08", f"{parsed.word_08:#010x} (semantics unknown)"),
            ("word_0c", f"{parsed.word_0c:#010x} (semantics unknown)"),
            ("trailing_len", f"{len(parsed.trailing_raw)} B"),
            ("trailing_raw", tail_hex or "(empty)"),
            ("raw_len", f"{len(parsed.raw)} B"),
        )
    )


SPEC = FamilySpec(
    THREAT_UPDATE_STATUS_TYPE,
    "THREAT_UPDATE_STATUS",
    parse_threat_update_status,
    render_threat_update_status,
)
