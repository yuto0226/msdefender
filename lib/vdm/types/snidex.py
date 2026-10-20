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
    key_blocks: tuple[bytes, ...]
    category_value: int
    recid_input_raw: bytes

    @property
    def object_raw(self) -> bytes | None:
        """Return the exact bytes interned by ``createrecidz``, when present."""
        if not self.recid_input_raw or self.recid_input_raw[0] == 0:
            return None
        nul = self.recid_input_raw.find(b"\0")
        return self.recid_input_raw if nul < 0 else self.recid_input_raw[: nul + 1]

    @property
    def ignored_trailing_raw(self) -> bytes:
        """Return bytes after the first NUL that the receiver does not intern."""
        if not self.recid_input_raw:
            return b""
        nul = self.recid_input_raw.find(b"\0")
        return b"" if nul < 0 else self.recid_input_raw[nul + 1 :]


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
    key_blocks = tuple(
        payload[offset : offset + 16] for offset in range(0, hash_count * 16, 16)
    )
    return SnidExPayload(
        type=type_byte,
        raw=payload,
        key_blocks=key_blocks,
        category_value=payload[hash_count * 16],
        recid_input_raw=payload[prefix_size:],
    )


def _parser_for(type_byte: int):
    return lambda payload: parse_snidex(payload, type_byte)


def _text_preview(raw: bytes) -> str | None:
    if raw.endswith(b"\0"):
        raw = raw[:-1]
    try:
        text = raw[:_TEXT_PREVIEW].decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not text or not all(character.isprintable() for character in text):
        return None
    return repr(text) + (" ..." if len(raw) > _TEXT_PREVIEW else "")


def render_snidex(parsed: SnidExPayload) -> FormatResult:
    rows = [
        ("type", f"0x{parsed.type:02X}"),
        ("key_blocks", str(len(parsed.key_blocks))),
    ]
    rows.extend(
        (f"key_block[{index}]", value.hex(" "))
        for index, value in enumerate(parsed.key_blocks)
    )
    object_raw = parsed.object_raw
    identity_preview = _text_preview(object_raw) if object_raw is not None else None
    rows.extend(
        (
            ("category_value", f"0x{parsed.category_value:02X} (semantics unresolved)"),
            ("recid_input_length", str(len(parsed.recid_input_raw))),
            (
                "interned_object_length",
                "none" if object_raw is None else f"{len(object_raw)} B",
            ),
            (
                "identity_text_preview",
                identity_preview if identity_preview is not None else "unavailable",
            ),
            ("receiver_ignored_length", str(len(parsed.ignored_trailing_raw))),
        )
    )
    title = "SNIDEX2" if parsed.type == SNIDEX2_TYPE else "SNIDEX"
    return FormatResult(sections=(DisplaySection(title, rows=tuple(rows)),))


SNIDEX_SPEC = FamilySpec(SNIDEX_TYPE, "SNIDEX", _parser_for(SNIDEX_TYPE), render_snidex)
SNIDEX2_SPEC = FamilySpec(
    SNIDEX2_TYPE, "SNIDEX2", _parser_for(SNIDEX2_TYPE), render_snidex
)
SNIDEX_SPECS: Final = (SNIDEX_SPEC, SNIDEX2_SPEC)
