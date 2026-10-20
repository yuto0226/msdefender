"""Parser and bounded renderer for FTRIE_POS (0xCD) payloads."""

from dataclasses import dataclass
from typing import Final

from ..core import DisplaySection, FamilySpec, FormatResult

FTRIE_POS_TYPE: Final = 0xCD
_DWORD_SIZE: Final = 4
_MAX_DWORD_TAIL_BYTES: Final = 0xFFFFFFFF
_VALUES_PREVIEW_COUNT: Final = 16
_OPAQUE_PREVIEW_BYTES: Final = 24


@dataclass(frozen=True, slots=True)
class FTriePosPayload:
    """Lossless parsed representation of a FTRIE_POS payload."""

    raw: bytes
    set_id: int
    bank: int
    reserved_raw: bytes
    values_raw: bytes
    values: tuple[int, ...] | None

    @property
    def engine_noop(self) -> bool:
        """Whether the engine ignores this selector and its payload tail."""
        return self.set_id >= 3

    @property
    def slot_index(self) -> int | None:
        """Return the engine's six-slot index, or None for its no-op selector."""
        if self.engine_noop:
            return None
        return self.bank + 2 * self.set_id


def _invalid(reason: str) -> ValueError:
    return ValueError(f"invalid FTRIE_POS payload (engine error 0x800C): {reason}")


def parse_ftrie_pos(payload: bytes) -> FTriePosPayload:
    """Parse receiver-validated fields while preserving every input byte.

    The receiver first requires a four-byte header. Selectors >= 3 are accepted
    as no-ops and bypass bank and DWORD-alignment validation, so their tail is
    retained as opaque bytes rather than interpreted as values.
    """
    if len(payload) < _DWORD_SIZE:
        raise _invalid("payload smaller than 4 bytes")

    set_id = payload[0]
    bank = payload[1]
    reserved_raw = payload[2:4]
    values_raw = payload[4:]

    if set_id >= 3:
        return FTriePosPayload(
            raw=payload,
            set_id=set_id,
            bank=bank,
            reserved_raw=reserved_raw,
            values_raw=values_raw,
            values=None,
        )

    if bank > 1:
        raise _invalid("bank must be 0 or 1")
    if len(values_raw) % _DWORD_SIZE:
        raise _invalid("values length is not DWORD aligned")
    if len(values_raw) > _MAX_DWORD_TAIL_BYTES:
        raise _invalid("values length exceeds UINT32_MAX bytes")

    values = tuple(
        int.from_bytes(values_raw[offset : offset + _DWORD_SIZE], "little")
        for offset in range(0, len(values_raw), _DWORD_SIZE)
    )
    return FTriePosPayload(
        raw=payload,
        set_id=set_id,
        bank=bank,
        reserved_raw=reserved_raw,
        values_raw=values_raw,
        values=values,
    )


def _hex_preview(data: bytes, limit: int) -> str:
    preview = data[:limit].hex(" ").upper()
    if len(data) > limit:
        preview += f" … ({len(data) - limit} more bytes)"
    return preview or "(empty)"


def render_ftrie_pos(parsed: FTriePosPayload) -> FormatResult:
    """Render bounded header/value previews without expanding large arrays."""
    if parsed.values is None:
        values_preview = _hex_preview(parsed.values_raw, _OPAQUE_PREVIEW_BYTES)
        values_count = "not decoded (engine no-op)"
    else:
        shown = parsed.values[:_VALUES_PREVIEW_COUNT]
        values_preview = ", ".join(str(value) for value in shown) or "(empty)"
        remaining = len(parsed.values) - len(shown)
        if remaining:
            values_preview += f" … ({remaining} more DWORDs)"
        values_count = str(len(parsed.values))

    return FormatResult(
        fields=(
            ("set_id", str(parsed.set_id)),
            ("bank", str(parsed.bank)),
            (
                "slot_index",
                str(parsed.slot_index) if parsed.slot_index is not None else "(no-op)",
            ),
            ("reserved_raw", parsed.reserved_raw.hex(" ").upper()),
            ("values_count", values_count),
            ("values_bytes", f"{len(parsed.values_raw)} B"),
            ("raw_len", f"{len(parsed.raw)} B"),
        ),
        sections=(
            DisplaySection(
                "FTRIE_POS values",
                rows=(("values_preview", values_preview),),
            ),
        ),
    )


SPEC = FamilySpec(FTRIE_POS_TYPE, "FTRIE_POS", parse_ftrie_pos, render_ftrie_pos)
FTRIE_POS_SPEC = SPEC


__all__ = [
    "FTRIE_POS_SPEC",
    "FTRIE_POS_TYPE",
    "SPEC",
    "FTriePosPayload",
    "parse_ftrie_pos",
    "render_ftrie_pos",
]
