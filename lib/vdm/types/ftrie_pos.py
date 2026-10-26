"""Parser and bounded renderer for FTRIE_POS (0xCD) payloads."""

from dataclasses import dataclass
from typing import Final

from ..core import (
    DisplaySection,
    FamilySpec,
    FormatResult,
    JSONArray,
    JSONObject,
    RuleSemantics,
    SemanticIssue,
)
from ._semantic_claims import scoped_claim

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


def _wire_field(kind: str, raw: bytes, offset: int) -> JSONObject:
    return JSONObject(
        (
            ("kind", kind),
            ("raw_span", JSONObject((("offset", offset), ("length", len(raw))))),
            ("raw_hex", raw.hex()),
        )
    )


def export_ftrie_pos_semantics(parsed: FTriePosPayload) -> RuleSemantics:
    """Export the six-slot set update and its exact DWORD wire encoding."""
    claim, claim_evidence = scoped_claim(
        "ftrie_pos",
        "best_position_subset",
        "runtime_consumer",
        "The runtime consumer performs a DwordsSet-backed best-position lookup over four-byte windows.",
        "This does not establish a hash-table implementation, enum value meaning, linkage behavior, or final verdict.",
        "consumer",
        "FTBestPos::findBestPos data flow",
    )
    framing = JSONArray(
        (
            _wire_field("set_id", parsed.raw[0:1], 0),
            _wire_field("bank", parsed.raw[1:2], 1),
            _wire_field("reserved", parsed.reserved_raw, 2),
            _wire_field("values", parsed.values_raw, 4),
        )
    )
    issues = [
        SemanticIssue(
            "reserved_bytes_uninterpreted",
            "The receiver retains no meaning for the two reserved header bytes.",
            (("raw_hex", parsed.reserved_raw.hex()),),
        )
    ]
    if parsed.engine_noop:
        effect = JSONObject(
            (
                ("type", "receiver_noop"),
                ("reason", "set_id_outside_0_2"),
            )
        )
        issues.append(
            SemanticIssue(
                "receiver_ignored",
                "set_id values at least 3 are accepted without reading the tail.",
                (("set_id", parsed.set_id),),
            )
        )
        status = "ignored"
    else:
        effect = JSONObject(
            (
                ("type", "install_dword_set_if_slot_empty"),
                ("slot_index", parsed.slot_index),
                ("empty_values_effect", "no_set_created"),
                ("occupied_slot_effect", "keep_existing_set"),
                (
                    "values",
                    JSONObject(
                        (
                            ("encoding", "little_endian_u32"),
                            ("count", len(parsed.values or ())),
                            ("raw_hex", parsed.values_raw.hex()),
                        )
                    ),
                ),
                (
                    "runtime_consumer",
                    JSONObject(
                        (
                            ("type", "four_byte_window_membership"),
                            ("case_variants", "lowercase_and_uppercase_tables"),
                        )
                    ),
                ),
            )
        )
        issues.append(
            SemanticIssue(
                "slot_update_is_order_dependent",
                "A previously populated slot causes this record to be ignored.",
                (("slot_index", parsed.slot_index),),
            )
        )
        status = "confirmed_subset"

    return RuleSemantics(
        status=status,
        representation="ftrie_pos.state_update.ir.v1",
        data=JSONObject(
            (
                ("raw_hex", parsed.raw.hex()),
                ("framing", framing),
                ("set_id", parsed.set_id),
                ("bank", parsed.bank),
                ("effect", effect),
            )
        ),
        evidence=(
            "mpengine 1.443.903.0 FTBestPos::ftrie_push and findBestPos data flow",
        ),
        profile="mpengine-1.443.903.0",
        issues=tuple(issues),
        claims=(claim,),
        claim_evidence=(claim_evidence,),
    )


SPEC = FamilySpec(
    FTRIE_POS_TYPE,
    "FTRIE_POS",
    parse_ftrie_pos,
    render_ftrie_pos,
    semantic_exporter=export_ftrie_pos_semantics,
)
FTRIE_POS_SPEC = SPEC


__all__ = [
    "FTRIE_POS_SPEC",
    "FTRIE_POS_TYPE",
    "SPEC",
    "FTriePosPayload",
    "export_ftrie_pos_semantics",
    "parse_ftrie_pos",
    "render_ftrie_pos",
]
