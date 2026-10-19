from dataclasses import dataclass

from ..core import FamilySpec, FormatResult

ITEM_PREVIEW_LIMIT = 16
TRAILING_PREVIEW_LIMIT = 32


@dataclass(frozen=True, slots=True)
class VdllMetaPayload:
    """Lossless fields shared by the known VDLL_META record families."""

    field0: int
    hash_key: int
    control: int
    count_flags: int
    field10: int
    items: tuple[int, ...]
    optional_value: int | None
    trailing: bytes

    @property
    def item_count(self) -> int:
        return len(self.items)


def parse_vdll_meta(payload: bytes) -> VdllMetaPayload:
    """Parse the common VDLL_META header, u16 items, and optional dword."""
    if len(payload) < 12:
        raise ValueError("truncated VDLL_META header")

    field0 = int.from_bytes(payload[0:4], "little")
    hash_key = int.from_bytes(payload[4:8], "little")
    control = payload[8]
    count_flags = payload[9]
    field10 = int.from_bytes(payload[10:12], "little")
    item_count = count_flags >> 3 if count_flags >= 8 else 0
    cursor = 12
    items_end = cursor + item_count * 2
    if items_end > len(payload):
        raise ValueError("truncated VDLL_META items")
    items = tuple(
        int.from_bytes(payload[offset : offset + 2], "little")
        for offset in range(cursor, items_end, 2)
    )
    cursor = items_end

    optional_value = None
    if len(payload) - cursor >= 4:
        optional_value = int.from_bytes(payload[cursor : cursor + 4], "little")
        cursor += 4
    elif cursor != len(payload):
        raise ValueError("truncated VDLL_META optional value")

    return VdllMetaPayload(
        field0=field0,
        hash_key=hash_key,
        control=control,
        count_flags=count_flags,
        field10=field10,
        items=items,
        optional_value=optional_value,
        trailing=payload[cursor:],
    )


def render_vdll_meta(parsed: VdllMetaPayload) -> FormatResult:
    preview_items = parsed.items[:ITEM_PREVIEW_LIMIT]
    items_preview = ", ".join(f"{item:#06x}" for item in preview_items)
    if len(parsed.items) > ITEM_PREVIEW_LIMIT:
        items_preview += f", … ({len(parsed.items) - ITEM_PREVIEW_LIMIT} more)"
    trailing_preview = parsed.trailing[:TRAILING_PREVIEW_LIMIT].hex(" ") or "(empty)"
    if len(parsed.trailing) > TRAILING_PREVIEW_LIMIT:
        trailing_preview += f" … ({len(parsed.trailing) - TRAILING_PREVIEW_LIMIT} more)"
    return FormatResult(
        fields=(
            ("field0", f"{parsed.field0:#010x}"),
            ("hash_key", f"{parsed.hash_key:#010x}"),
            ("control", f"{parsed.control:#04x}"),
            ("count_flags", f"{parsed.count_flags:#04x}"),
            ("item_count", str(parsed.item_count)),
            ("field10", f"{parsed.field10:#06x}"),
            ("items_preview", items_preview or "(empty)"),
            (
                "optional_value",
                "None"
                if parsed.optional_value is None
                else f"{parsed.optional_value:#010x}",
            ),
            ("trailing_length", str(len(parsed.trailing))),
            ("trailing_preview", trailing_preview),
        )
    )


FAMILY_SPECS = (
    FamilySpec(0xB5, "VDLL_META", parse_vdll_meta, render_vdll_meta),
    FamilySpec(0xE1, "VDLL_META_X64", parse_vdll_meta, render_vdll_meta),
    FamilySpec(0xE2, "VDLL_META_ARM", parse_vdll_meta, render_vdll_meta),
    FamilySpec(0xE3, "VDLL_META_MSIL", parse_vdll_meta, render_vdll_meta),
)
