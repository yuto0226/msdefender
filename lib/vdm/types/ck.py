"""Lossless CKOLDREC and CKSIMPLEREC wire models."""

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

CKOLDREC_TYPE: Final = 0x11
CKSIMPLEREC_TYPE: Final = 0x50
_BASE_SIZE: Final = 20
_PREVIEW_LIMIT: Final = 64
_KNOWN_FLAGS_MASK: Final = 0xBC000000


@dataclass(frozen=True, slots=True)
class CkOldPayload:
    first_word: int
    first_length: int
    first_crc32: int
    second_offset: int
    second_length: int
    second_crc32: int
    flags: int
    object_length: int | None
    object_data_raw: bytes | None
    object_wire_raw: bytes | None
    remaining_raw: bytes

    @property
    def ck_type(self) -> int:
        return (self.flags >> 26) & 0xF

    @property
    def callback_mode_index(self) -> int:
        return self.first_word & 0x3F


@dataclass(frozen=True, slots=True)
class CkSimplePayload:
    first_dword: int
    first16_crc32: int
    second_offset: int
    second_length: int
    second_crc32: int
    flags: int
    object_length: int | None
    object_data_raw: bytes | None
    object_wire_raw: bytes | None
    remaining_raw: bytes

    @property
    def ck_type(self) -> int:
        return (self.flags >> 26) & 0xF


def _u16(payload: bytes, offset: int) -> int:
    return int.from_bytes(payload[offset : offset + 2], "little")


def _u32(payload: bytes, offset: int) -> int:
    return int.from_bytes(payload[offset : offset + 4], "little")


def _parse_tail(
    payload: bytes, flags: int
) -> tuple[int | None, bytes | None, bytes | None, bytes]:
    """Project the conditional CK object while retaining every raw tail byte.

    ReceiveNewTemplate's 0x1006 descriptor only consumes an object when the
    preceding flags DWORD is negative. In that branch its wire prefix is a
    u16 byte length. The receiver does not require exact payload exhaustion.
    """
    tail = payload[_BASE_SIZE:]
    if flags & 0x80000000:
        if len(tail) < 2:
            raise ValueError("truncated CK conditional object")
        object_length = _u16(tail, 0)
        object_end = 2 + object_length
        if object_end > len(tail):
            raise ValueError("truncated CK conditional object")
        return object_length, tail[2:object_end], tail[:object_end], tail[object_end:]
    return None, None, None, tail


def parse_ckoldrec(payload: bytes) -> CkOldPayload:
    """Parse CKOLDREC's callback key/length fields and common tail."""
    if len(payload) < _BASE_SIZE:
        raise ValueError("truncated CKOLDREC header")
    flags = _u32(payload, 16)
    object_length, object_data_raw, object_wire_raw, remaining_raw = _parse_tail(
        payload, flags
    )
    return CkOldPayload(
        first_word=_u16(payload, 0),
        first_length=_u16(payload, 2),
        first_crc32=_u32(payload, 4),
        second_offset=_u16(payload, 8),
        second_length=_u16(payload, 10),
        second_crc32=_u32(payload, 12),
        flags=flags,
        object_length=object_length,
        object_data_raw=object_data_raw,
        object_wire_raw=object_wire_raw,
        remaining_raw=remaining_raw,
    )


def parse_cksimplerec(payload: bytes) -> CkSimplePayload:
    """Parse CKSIMPLEREC's prefix checks and second CRC descriptor."""
    if len(payload) < _BASE_SIZE:
        raise ValueError("truncated CKSIMPLEREC header")
    flags = _u32(payload, 16)
    object_length, object_data_raw, object_wire_raw, remaining_raw = _parse_tail(
        payload, flags
    )
    return CkSimplePayload(
        first_dword=_u32(payload, 0),
        first16_crc32=_u32(payload, 4),
        second_offset=_u16(payload, 8),
        second_length=_u16(payload, 10),
        second_crc32=_u32(payload, 12),
        flags=flags,
        object_length=object_length,
        object_data_raw=object_data_raw,
        object_wire_raw=object_wire_raw,
        remaining_raw=remaining_raw,
    )


def _preview(raw: bytes | None) -> str:
    if raw is None:
        return "absent"
    value = raw[:_PREVIEW_LIMIT].hex(" ") or "(empty)"
    if len(raw) > _PREVIEW_LIMIT:
        value += f" ... ({len(raw) - _PREVIEW_LIMIT} more)"
    return value


def _common_rows(
    *,
    second_offset: int,
    second_length: int,
    second_crc32: int,
    flags: int,
    ck_type: int,
    object_length: int | None,
    object_data_raw: bytes | None,
    object_wire_raw: bytes | None,
    remaining_raw: bytes,
) -> tuple[tuple[str, str], ...]:
    return (
        ("second_offset", str(second_offset)),
        ("second_length", str(second_length)),
        ("second_crc32", f"0x{second_crc32:08X}"),
        ("flags", f"0x{flags:08X}"),
        ("ck_type", str(ck_type)),
        (
            "object_length",
            "not projected" if object_length is None else str(object_length),
        ),
        ("object_data_preview", _preview(object_data_raw)),
        ("object_wire_preview", _preview(object_wire_raw)),
        (
            "remaining_length",
            str(len(remaining_raw)),
        ),
        ("remaining_preview", _preview(remaining_raw)),
    )


def render_ckoldrec(parsed: CkOldPayload) -> FormatResult:
    return FormatResult(
        sections=(
            DisplaySection(
                "CKOLDREC",
                rows=(
                    ("first_word", f"0x{parsed.first_word:04X}"),
                    ("callback_mode_index", str(parsed.callback_mode_index)),
                    ("first_length", str(parsed.first_length)),
                    ("first_crc32", f"0x{parsed.first_crc32:08X}"),
                    *_common_rows(
                        second_offset=parsed.second_offset,
                        second_length=parsed.second_length,
                        second_crc32=parsed.second_crc32,
                        flags=parsed.flags,
                        ck_type=parsed.ck_type,
                        object_length=parsed.object_length,
                        object_data_raw=parsed.object_data_raw,
                        object_wire_raw=parsed.object_wire_raw,
                        remaining_raw=parsed.remaining_raw,
                    ),
                ),
            ),
        )
    )


def render_cksimplerec(parsed: CkSimplePayload) -> FormatResult:
    return FormatResult(
        sections=(
            DisplaySection(
                "CKSIMPLEREC",
                rows=(
                    ("first_dword", f"0x{parsed.first_dword:08X}"),
                    ("first16_crc32", f"0x{parsed.first16_crc32:08X}"),
                    *_common_rows(
                        second_offset=parsed.second_offset,
                        second_length=parsed.second_length,
                        second_crc32=parsed.second_crc32,
                        flags=parsed.flags,
                        ck_type=parsed.ck_type,
                        object_length=parsed.object_length,
                        object_data_raw=parsed.object_data_raw,
                        object_wire_raw=parsed.object_wire_raw,
                        remaining_raw=parsed.remaining_raw,
                    ),
                ),
            ),
        )
    )


def _wire_span(kind: str, raw: bytes, offset: int) -> JSONObject:
    return JSONObject(
        (
            ("kind", kind),
            ("raw_span", JSONObject((("offset", offset), ("length", len(raw))))),
            ("raw_hex", raw.hex()),
        )
    )


def _raw_payload(parsed: CkOldPayload | CkSimplePayload) -> bytes:
    """Reassemble the exact wire payload from the lossless parsed fields."""
    if isinstance(parsed, CkOldPayload):
        prefix = (
            parsed.first_word.to_bytes(2, "little")
            + parsed.first_length.to_bytes(2, "little")
            + parsed.first_crc32.to_bytes(4, "little")
        )
    else:
        prefix = parsed.first_dword.to_bytes(
            4, "little"
        ) + parsed.first16_crc32.to_bytes(4, "little")
    prefix += (
        parsed.second_offset.to_bytes(2, "little")
        + parsed.second_length.to_bytes(2, "little")
        + parsed.second_crc32.to_bytes(4, "little")
        + parsed.flags.to_bytes(4, "little")
    )
    return prefix + (parsed.object_wire_raw or b"") + parsed.remaining_raw


def _ck_semantics(
    parsed: CkOldPayload | CkSimplePayload, *, old: bool
) -> RuleSemantics:
    raw = _raw_payload(parsed)
    issues: list[SemanticIssue] = [
        SemanticIssue(
            "final_verdict_unknown",
            "A CK callback match does not by itself establish a final detection verdict.",
        )
    ]
    unsupported = False
    framing = [
        _wire_span("fixed_prefix", raw[:_BASE_SIZE], 0),
        _wire_span(
            "conditional_object_wire",
            parsed.object_wire_raw or b"",
            _BASE_SIZE,
        ),
        _wire_span(
            "unconsumed_tail",
            parsed.remaining_raw,
            _BASE_SIZE + len(parsed.object_wire_raw or b""),
        ),
    ]
    if parsed.flags & ~_KNOWN_FLAGS_MASK:
        issues.append(
            SemanticIssue(
                "unknown_flag_bits",
                "CK flag bits outside the sign bit and ck_type are preserved; "
                "the verified receiver, index builder, and scanner path do "
                "not consume them.",
                (
                    ("unknown_bits", parsed.flags & ~_KNOWN_FLAGS_MASK),
                    ("status_scope", "confirmed CK callback subset"),
                ),
            )
        )
    if parsed.object_data_raw is not None:
        unsupported = True
        issues.append(
            SemanticIssue(
                "opaque_conditional_object",
                "The receiver stores these bytes as an object; their application semantics are unknown.",
                (("length", len(parsed.object_data_raw)),),
            )
        )
    if parsed.remaining_raw:
        issues.append(
            SemanticIssue(
                "unconsumed_tail",
                "The generic receiver accepts these suffix bytes without "
                "consuming or copying them into the fixed-stride CK entry.",
                (
                    ("length", len(parsed.remaining_raw)),
                    ("status_scope", "confirmed CK callback subset"),
                ),
            )
        )

    receiver = JSONObject(
        (
            ("fixed_prefix_length", _BASE_SIZE),
            ("conditional_object", "read_u16_length_and_store_if_flags_sign_bit_set"),
            ("trailing_bytes", "accepted_without_cursor_exhaustion"),
        )
    )
    storage = JSONObject(
        (
            ("entry_stride", 0x1C if old else 0x24),
            ("threat_id_field", "runtime_entry_plus_20"),
            ("conditional_object_slot", "runtime_entry_plus_24"),
        )
    )
    if old:
        assert isinstance(parsed, CkOldPayload)
        first = JSONObject(
            (
                ("callback_mode_index", parsed.callback_mode_index),
                ("callback_length", parsed.first_length),
                ("expected_callback_result", parsed.first_crc32),
            )
        )
        second = JSONObject(
            (
                ("callback_offset", parsed.second_offset),
                ("callback_length", parsed.second_length),
                ("expected_callback_result", parsed.second_crc32),
            )
        )
        comparison = "each callback result equals its stored DWORD"
        representation = "ckoldrec.callback_checks.ir.v2"
        callback_description = "caller_supplied_callback"
        callback_sequence = JSONArray((first, second))
        key = JSONObject(
            (
                ("kind", "callback_slot"),
                ("index", parsed.callback_mode_index),
                ("first_word_raw", parsed.first_word),
                ("uninterpreted_high_bits", parsed.first_word & ~0x3F),
            )
        )
        first_word_unknown = parsed.first_word & ~0x3F
        if first_word_unknown:
            issues.append(
                SemanticIssue(
                    "unknown_first_word_bits",
                    "CKOLDREC first_word bits outside the low six callback index bits are uninterpreted; raw row bytes are retained for identity hashes.",
                    (("unknown_bits", first_word_unknown),),
                )
            )
    else:
        assert isinstance(parsed, CkSimplePayload)
        first = JSONObject(
            (
                ("callback_kind", "knbuf_crc"),
                ("callback_length", 16),
                ("expected_callback_result", parsed.first16_crc32),
                ("crc_algorithm", "CRC_1"),
            )
        )
        second = JSONObject(
            (
                ("callback_offset", parsed.second_offset),
                ("callback_length", parsed.second_length),
                ("expected_callback_result", parsed.second_crc32),
            )
        )
        comparison = "callback CRC result equals stored DWORD"
        representation = "cksimplerec.callback_checks.ir.v1"
        callback_description = "caller_selected_callback_and_context"
        callback_sequence = JSONArray((first, second))
        key = JSONObject(
            (
                ("kind", "subject_first_dword"),
                ("value", parsed.first_dword),
            )
        )

    evidence = [
        "ReceiveNewTemplate 0x1000/0x1006 descriptor behavior",
        "CK scanner callback/key comparisons documented for this engine profile",
        "ShouldContinueScanning separates a scanner match from final reporting",
    ]
    if old:
        evidence.extend(
            (
                "krecpush_end @ 0x180474B20 and ksigsearch @ 0x18019428C",
                "SigseqFromDatabaseRecord @ 0x1805F7D84",
                "SigshaFromDatabaseRecord @ 0x1803CA9B4",
            )
        )

    return RuleSemantics(
        status="unsupported" if unsupported else "confirmed_subset",
        representation=representation,
        data=JSONObject(
            (
                ("raw_hex", raw.hex()),
                ("wire_framing", JSONArray(tuple(framing))),
                ("receiver", receiver),
                ("storage", storage),
                (
                    "runtime_matching",
                    JSONObject(
                        (
                            ("ck_type_filter", parsed.ck_type),
                            ("lookup_key", key),
                            ("callback_source", callback_description),
                            ("callback_checks", callback_sequence),
                            ("comparison", comparison),
                        )
                    ),
                ),
                (
                    "reporting",
                    JSONObject(
                        (
                            ("threat_id_source", "runtime_entry_plus_20"),
                            (
                                "final_verdict",
                                "unknown; policy/report continuation is separate",
                            ),
                        )
                    ),
                ),
            )
        ),
        evidence=tuple(evidence),
        profile="mpengine-1.443.903.0",
        issues=tuple(issues),
    )


def export_ckoldrec_semantics(parsed: CkOldPayload) -> RuleSemantics:
    """Export confirmed CKOLDREC callback fields without verdict inference."""
    return _ck_semantics(parsed, old=True)


def export_cksimplerec_semantics(parsed: CkSimplePayload) -> RuleSemantics:
    """Export confirmed CKSIMPLEREC checks without verdict inference."""
    return _ck_semantics(parsed, old=False)


CK_SPECS = (
    FamilySpec(
        CKOLDREC_TYPE,
        "CKOLDREC",
        parse_ckoldrec,
        render_ckoldrec,
        semantic_exporter=export_ckoldrec_semantics,
    ),
    FamilySpec(
        CKSIMPLEREC_TYPE,
        "CKSIMPLEREC",
        parse_cksimplerec,
        render_cksimplerec,
        semantic_exporter=export_cksimplerec_semantics,
    ),
)
