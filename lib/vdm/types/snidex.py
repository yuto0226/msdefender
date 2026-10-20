"""Typed models for extended SNID hash records 0xE5 and 0xE6."""

from dataclasses import dataclass
from typing import Final

from ..core import DisplaySection, FamilySpec, FormatResult

SNIDEX_TYPE: Final = 0xE5
SNIDEX2_TYPE: Final = 0xE6
_TEXT_PREVIEW: Final = 256


@dataclass(frozen=True, slots=True)
class SnidExPayload:
    type: int
    raw: bytes
    hashes: tuple[bytes, ...]
    category: int
    label_raw: bytes

    @property
    def label(self) -> bytes:
        """Return the bounded C-string view without requiring a terminator."""
        return self.label_raw.split(b"\0", 1)[0]

    @property
    def bytes_after_nul(self) -> bytes:
        """Expose bytes ignored by the C-string view, if a NUL is present."""
        _, separator, tail = self.label_raw.partition(b"\0")
        return tail if separator else b""


def parse_snidex(payload: bytes, type_byte: int = SNIDEX_TYPE) -> SnidExPayload:
    """Parse fixed opaque hash chunks, category, and optional label bytes."""
    if type_byte not in {SNIDEX_TYPE, SNIDEX2_TYPE}:
        raise ValueError(f"unsupported SNIDEX type 0x{type_byte:02X}")
    hash_count = 2 if type_byte == SNIDEX_TYPE else 4
    prefix_size = hash_count * 16 + 1
    if len(payload) < prefix_size:
        raise ValueError(
            f"truncated SNIDEX fixed prefix: need {prefix_size} bytes, "
            f"have {len(payload)}"
        )
    hashes = tuple(
        payload[offset : offset + 16] for offset in range(0, hash_count * 16, 16)
    )
    return SnidExPayload(
        type=type_byte,
        raw=payload,
        hashes=hashes,
        category=payload[hash_count * 16],
        label_raw=payload[prefix_size:],
    )


def _parser_for(type_byte: int):
    return lambda payload: parse_snidex(payload, type_byte)


def _text_preview(raw: bytes) -> str:
    text = raw[:_TEXT_PREVIEW].decode("utf-8", errors="backslashreplace")
    return repr(text) + (" ..." if len(raw) > _TEXT_PREVIEW else "")


def render_snidex(parsed: SnidExPayload) -> FormatResult:
    rows = [
        ("type", f"0x{parsed.type:02X}"),
        ("hash_chunks", str(len(parsed.hashes))),
    ]
    rows.extend(
        (f"hash[{index}]", value.hex(" ")) for index, value in enumerate(parsed.hashes)
    )
    rows.extend(
        (
            ("category", f"0x{parsed.category:02X}"),
            ("label_length", str(len(parsed.label_raw))),
            ("label", _text_preview(parsed.label)),
            ("bytes_after_nul", str(len(parsed.bytes_after_nul))),
        )
    )
    title = "SNIDEX2" if parsed.type == SNIDEX2_TYPE else "SNIDEX"
    return FormatResult(sections=(DisplaySection(title, rows=tuple(rows)),))


SNIDEX_SPEC = FamilySpec(SNIDEX_TYPE, "SNIDEX", _parser_for(SNIDEX_TYPE), render_snidex)
SNIDEX2_SPEC = FamilySpec(
    SNIDEX2_TYPE, "SNIDEX2", _parser_for(SNIDEX2_TYPE), render_snidex
)
SNIDEX_SPECS: Final = (SNIDEX_SPEC, SNIDEX2_SPEC)
