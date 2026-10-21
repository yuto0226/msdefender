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
    """Export only NDAT callbacks tied to a static registration and consumer."""
    callback_targets = {
        1: "VbasicPathNdatCallback",
        3: "VdllNdatDontCountCallback",
        4: "VdllNdatFireEventCallback",
        5: "LogSkipNdatCallback",
        6: "VdllNdatVfsLinkCallback",
        7: "VdllNdatApiAttributeCallback",
        8: "RkpatCallback",
        10: "PdbPathNdatCallback",
        12: "DnsCacheInfoNdatCallback_0",
        13: "GenericRegExpNdatCallback",
        15: "HttpUrlNdatCallback",
        16: "HttpHeaderNdatCallback",
        17: "MsgBodyNdatCallback",
        18: "SSLCertNdatCallback",
        19: "RawBodyNdatCallback",
        20: "RawSSLCertNdatCallback",
        21: "AsrAutoEnableNdatCallback",
        22: "CAsrNotAllowedNdatCallback",
        23: "McpServersNdatCallback",
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
    elif business_semantics == "unknown":
        issues.append(
            SemanticIssue(
                "ndat_callback_business_semantics_unknown",
                "The callback table target is confirmed, but this exporter does "
                "not claim its input/output business effect without a direct "
                "handler and consumer dataflow trace.",
                details=(
                    ("callback_index", parsed.callback_index),
                    ("dispatch_target", callback_target),
                ),
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
                                False
                                if parsed.callback_index in callback_semantics
                                else None,
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
            "mpengine 1.443.903.0 cksig_init_module 0x1805648A0/0x31D",
            "mpengine 1.443.903.0 callback table base 0x181280FF0; NdatPostCallback table[index] read 0x180464883",
            "mpengine 1.443.903.0 dllsupp_init 0x180CA6240/0x6E0 writes indices 3,4,7 at 0x180CA67D1/0x180CA67E6/0x180CA67F4",
            "mpengine 1.443.903.0 fssupp_init 0x18048B180/0x1C7 writes index 6 at 0x18048B283",
            "mpengine 1.443.903.0 filepathscan_init 0x180CAC350/0x67 writes indices 1,2,10,11",
            "mpengine 1.443.903.0 cksig_init_module 0x1805648A0/0x31D initializes table and writes indices 8,12,14",
            "mpengine 1.443.903.0 vlib_init_module 0x180C50820/0x156 writes index 13",
            "mpengine 1.443.903.0 NetworkHips_init_module 0x180C75A60/0x1BB writes indices 15-20",
            "mpengine 1.443.903.0 hips_init_module 0x18048C8E0/0x7A2 writes index 21",
            "mpengine 1.443.903.0 retarget_init_module 0x180BDDF60/0x163 writes index 23",
            "mpengine 1.443.903.0 callback bodies lookup: VbasicPathNdatCallback 0x1805861F0/0x15; VdllNdatDontCountCallback 0x180CA5640/0x201; VdllNdatFireEventCallback 0x180CA5850/0x48C; VdllNdatVfsLinkCallback 0x180429B00/0x287; VdllNdatApiAttributeCallback 0x180CA53F0/0x247",
            "mpengine 1.443.903.0 callback bodies lookup: RkpatCallback 0x18055BBD0/0xC3; PdbPathNdatCallback 0x180573920/0x15; DnsCacheInfoNdatCallback 0x180BBAE20/0x10C; GenericRegExpNdatCallback 0x1804B3FA0/0x8A",
            "mpengine 1.443.903.0 callback bodies lookup: HttpUrlNdatCallback 0x180526C00/0xC8; HttpHeaderNdatCallback 0x1805BA660/0xC5; MsgBodyNdatCallback 0x180C75990/0xC5; SSLCertNdatCallback 0x18055D720/0xC5; RawBodyNdatCallback 0x1804B4E70/0xBE; RawSSLCertNdatCallback 0x1804B4DA0/0xC8",
            "mpengine 1.443.903.0 callback bodies lookup: AsrAutoEnableNdatCallback 0x1805BC650/0x228; McpServersNdatCallback 0x180BDF100/0xA9",
            "mpengine 1.443.903.0 LogSkip::Initialize 0x180B53F80/0x41 writes indices 5 and 22",
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
