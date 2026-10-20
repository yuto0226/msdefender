"""Corpus-profile parser and bounded renderer for TITANFLT (0x30)."""

from dataclasses import dataclass
from typing import Final

from ..core import FamilySpec, FormatResult

TITANFLT_TYPE: Final = 0x30
_ENTRY_PREVIEW_COUNT: Final = 12
_ENTRY_PREVIEW_BYTES: Final = 40


@dataclass(frozen=True, slots=True)
class TitanFltPayload:
    """Lossless TITANFLT payload and its corpus-profile ASCII entries."""

    raw: bytes
    entries: tuple[bytes, ...]

    @property
    def entries_ascii(self) -> tuple[str, ...]:
        """Return entries as ASCII text while retaining their original bytes."""
        return tuple(entry.decode("ascii") for entry in self.entries)


def parse_titanflt(payload: bytes) -> TitanFltPayload:
    """Parse only the observed corpus profile; this is not an engine validator."""
    if not payload or payload[-1] != 0:
        raise ValueError("TITANFLT corpus profile requires exactly one terminal NUL")

    body = payload[:-1]
    if b"\x00" in body:
        raise ValueError("TITANFLT corpus profile does not allow embedded NUL")
    if not body:
        raise ValueError("TITANFLT corpus profile requires at least one entry")

    entries = tuple(body.split(b"|"))
    if any(not entry for entry in entries):
        raise ValueError("TITANFLT corpus profile does not allow an empty entry")
    if any(byte < 0x20 or byte > 0x7E for entry in entries for byte in entry):
        raise ValueError("TITANFLT corpus profile entries must use printable ASCII")

    return TitanFltPayload(raw=payload, entries=entries)


def render_titanflt(parsed: TitanFltPayload) -> FormatResult:
    """Render a bounded entry preview while preserving the complete raw model."""
    preview_entries: list[str] = []
    for entry in parsed.entries[:_ENTRY_PREVIEW_COUNT]:
        text = entry[:_ENTRY_PREVIEW_BYTES].decode("ascii")
        if len(entry) > _ENTRY_PREVIEW_BYTES:
            text += f"… ({len(entry) - _ENTRY_PREVIEW_BYTES} more bytes)"
        preview_entries.append(text)

    if len(parsed.entries) > _ENTRY_PREVIEW_COUNT:
        preview_entries.append(
            f"… ({len(parsed.entries) - _ENTRY_PREVIEW_COUNT} more entries)"
        )

    return FormatResult(
        fields=(
            ("entry_count", str(len(parsed.entries))),
            ("entries_preview", " | ".join(preview_entries)),
            ("raw_len", str(len(parsed.raw))),
        )
    )


SPEC = FamilySpec(
    TITANFLT_TYPE,
    "TITANFLT",
    parse_titanflt,
    render_titanflt,
)
