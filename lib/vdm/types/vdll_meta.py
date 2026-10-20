from dataclasses import dataclass

from ..core import (
    FamilySpec,
    FormatResult,
    JSONArray,
    JSONObject,
    RuleSemantics,
    SemanticIssue,
)

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
    raw: bytes

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
        raw=payload,
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


def export_vdll_meta(
    parsed: VdllMetaPayload,
    *,
    type_byte: int,
    variant: str,
) -> RuleSemantics:
    """Export observed VDLL metadata fields without inventing rule semantics."""
    data = JSONObject(
        (
            ("record_type", f"0x{type_byte:02X}"),
            ("variant", variant),
            (
                "wire_metadata",
                JSONObject(
                    (
                        ("field0", parsed.field0),
                        ("hash_key", parsed.hash_key),
                        ("control", parsed.control),
                        ("count_flags", parsed.count_flags),
                        ("item_count", parsed.item_count),
                        ("field10", parsed.field10),
                        ("items", JSONArray(tuple(parsed.items))),
                        ("optional_value", parsed.optional_value),
                        ("trailing_hex", parsed.trailing.hex()),
                    )
                ),
            ),
            (
                "receiver_storage",
                JSONObject(
                    (
                        ("table_scope", "type-specific VDLL metadata table"),
                        ("bucket_key", "hash_key modulo bucket_count"),
                        ("internal_entry", "receiver-converted; not a wire struct"),
                    )
                ),
            ),
            (
                "vdll_code_linkage",
                "No VDLL_CODE record linkage is established by this payload.",
            ),
            (
                "runtime_loader",
                (
                    "Metadata registration/storage does not establish code loading "
                    "or execution."
                ),
            ),
            ("raw_hex", parsed.raw.hex()),
            ("detection_expression", None),
        )
    )
    if parsed.trailing:
        return RuleSemantics(
            status="unsupported",
            representation="vdll_metadata_record.v1",
            data=data,
            evidence=(
                (
                    "vdll_metadata_receiver reads the fixed header, count-derived "
                    "u16 items, and optional dword."
                ),
                (
                    "Remaining bytes are ignored by the receiver and have unknown "
                    "semantics."
                ),
            ),
            profile="mpengine-1.443.903.0",
            issues=(
                SemanticIssue(
                    code="unknown_trailing_bytes",
                    message=(
                        "Semantic export is incomplete because payload tail "
                        "bytes are unknown."
                    ),
                    details=(("length", len(parsed.trailing)),),
                ),
            ),
        )
    return RuleSemantics(
        status="observed_only",
        representation="vdll_metadata_record.v1",
        data=data,
        evidence=(
            (
                "vdll_metadata_receiver inserts parsed fields into a type-specific "
                "metadata table using hash_key modulo bucket_count."
            ),
            (
                "The receiver does not establish that this record is a detection "
                "expression."
            ),
        ),
        profile="mpengine-1.443.903.0",
    )


def _semantic_exporter(type_byte: int, variant: str):
    def export(parsed: VdllMetaPayload) -> RuleSemantics:
        return export_vdll_meta(parsed, type_byte=type_byte, variant=variant)

    return export


FAMILY_SPECS = (
    FamilySpec(
        0xB5,
        "VDLL_META",
        parse_vdll_meta,
        render_vdll_meta,
        semantic_exporter=_semantic_exporter(0xB5, "unspecified architecture"),
    ),
    FamilySpec(
        0xE1,
        "VDLL_META_X64",
        parse_vdll_meta,
        render_vdll_meta,
        semantic_exporter=_semantic_exporter(0xE1, "x64"),
    ),
    FamilySpec(
        0xE2,
        "VDLL_META_ARM",
        parse_vdll_meta,
        render_vdll_meta,
        semantic_exporter=_semantic_exporter(0xE2, "ARM"),
    ),
    FamilySpec(
        0xE3,
        "VDLL_META_MSIL",
        parse_vdll_meta,
        render_vdll_meta,
        semantic_exporter=_semantic_exporter(0xE3, "MSIL / managed"),
    ),
)
