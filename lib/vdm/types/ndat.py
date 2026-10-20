"""Parser and renderer for NDAT (0xA9) payloads."""

from dataclasses import dataclass
from typing import Final

from ..core import (
    DisplaySection,
    FamilySpec,
    FormatResult,
    JSONObject,
    RuleSemantics,
    SemanticIssue,
)

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


def export_ndat_semantics(parsed: NdatPayload) -> RuleSemantics:
    """Export confirmed NDAT framing and callback dispatch without guessing use."""
    callback_targets = {
        5: "LogSkipNdatCallback",
        22: "CAsrNotAllowedNdatCallback",
    }
    callback_semantics = {
        5: "logskip_rule_ingest",
        22: "custom_asr_not_allowed_rule_ingest",
    }
    callback_target = callback_targets.get(parsed.callback_index)
    business_semantics = callback_semantics.get(parsed.callback_index, "unknown")
    issues = []
    if callback_target is None:
        issues.append(
            SemanticIssue(
                "ndat_callback_business_semantics_unknown",
                "No registration target or consumer semantics are confirmed "
                "for this callback index.",
                details=(("callback_index", parsed.callback_index),),
            )
        )
    if parsed.record_id_suffix_raw is not None:
        issues.append(
            SemanticIssue(
                "record_name_encoding_unknown",
                "The NUL-terminated bytes are passed to createrecidz as a name, "
                "but their text encoding is not established.",
            )
        )
    if parsed.trailing_raw:
        issues.append(
            SemanticIssue(
                "trailing_bytes_uninterpreted",
                "Bytes following the first record-name terminator are retained "
                "without confirmed receiver semantics.",
                details=(("length", len(parsed.trailing_raw)),),
            )
        )
    status = (
        "unsupported"
        if parsed.trailing_raw
        else "confirmed_subset"
        if callback_target is not None
        else "observed_only"
    )
    return RuleSemantics(
        status=status,
        representation="ndat.counted_data_callback_suffix.v2",
        data=JSONObject(
            (
                ("type", "NDAT"),
                ("raw_hex", parsed.raw.hex()),
                ("data_length", parsed.data_length),
                ("data_raw_hex", parsed.data_raw.hex()),
                (
                    "callback",
                    JSONObject(
                        (
                            ("index", parsed.callback_index),
                            ("index_hex", f"0x{parsed.callback_index:02x}"),
                            ("dispatch_target", callback_target),
                            ("dispatch_mechanism_confirmed", True),
                            ("dispatch_target_confirmed", callback_target is not None),
                            ("business_semantics", business_semantics),
                            (
                                "is_final_detection",
                                False if callback_target is not None else None,
                            ),
                        )
                    ),
                ),
                (
                    "record_name_raw_hex",
                    parsed.record_id_suffix_raw.hex()
                    if parsed.record_id_suffix_raw is not None
                    else None,
                ),
                ("trailing_raw_hex", parsed.trailing_raw.hex()),
                (
                    "record_name_role",
                    "absent"
                    if parsed.record_id_suffix_raw is None
                    else "nul_terminated_name_for_createrecidz",
                ),
            )
        ),
        evidence=(
            "mpengine 1.443.903.0 ReceiveNewTemplate 0x1803224D0/0xB70",
            "mpengine 1.443.903.0 NdatPostCallback 0x180464800/0x186",
            "mpengine 1.443.903.0 LogSkip::Initialize 0x180B53F80/0x41",
            "mpengine 1.443.903.0 logskip_init_module 0x180B54A70/0x12F",
            "mpengine 1.443.903.0 LogSkipNdatCallback 0x18005B7C0/0x68",
            "mpengine 1.443.903.0 CAsrNotAllowedNdatCallback 0x1805009C0/0x59",
            "mpengine 1.443.903.0 LogSkip::AddString 0x18005C630/0xE66",
            "mpengine 1.443.903.0 CustomAsrIsNotAllowed 0x180B53EF0/0x8E",
            "mpengine 1.443.903.0 LogSkip::Check 0x180287DE0/0x1104",
        ),
        profile="mpengine-1.443.903.0",
        issues=tuple(issues),
    )


NDAT_SPEC = FamilySpec(
    NDAT_TYPE,
    "NDAT",
    parse_ndat,
    render_ndat,
    semantic_exporter=export_ndat_semantics,
)
