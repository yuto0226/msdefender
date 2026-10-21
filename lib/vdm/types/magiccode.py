"""Decoder for the unloadable MAGICCODE record 0xC0."""

from dataclasses import dataclass

from ..core import (
    DisplaySection,
    FamilySpec,
    FormatResult,
    JSONArray,
    JSONObject,
    RuleSemantics,
    SemanticIssue,
)

_BYTE_PREVIEW = 64
_TEXT_PREVIEW = 256


@dataclass(frozen=True, slots=True)
class MagicCodePayload:
    raw: bytes
    field_00_raw: bytes
    field_01_raw: bytes
    field_02_raw: bytes
    trailing_raw: bytes

    @property
    def field_00_c_string(self) -> bytes:
        """Return a display-only C-string view of the first observed field."""
        return self.field_00_raw.split(b"\0", 1)[0]

    @property
    def field_02_c_string(self) -> bytes:
        """Return a display-only C-string view of the third observed field."""
        return self.field_02_raw.split(b"\0", 1)[0]


def _take(payload: bytes, cursor: int, size: int, label: str) -> tuple[bytes, int]:
    end = cursor + size
    if end > len(payload):
        raise ValueError(f"truncated MAGICCODE {label}")
    return payload[cursor:end], end


def parse_magiccode(payload: bytes) -> MagicCodePayload:
    """Decode the four descriptor operations used by the C0 template.

    The engine reads a u8-length byte string, a u32le value, that many raw
    bytes, then a u16-length byte string. It stops after those fields and
    does not require the payload cursor to reach the record end.
    """
    if not payload:
        raise ValueError("truncated MAGICCODE field 00 length")

    field_00_length = payload[0]
    field_00_raw, cursor = _take(payload, 1, field_00_length, "field 00")

    field_01_length_raw, cursor = _take(payload, cursor, 4, "field 01 length")
    field_01_length = int.from_bytes(field_01_length_raw, "little")
    field_01_raw, cursor = _take(payload, cursor, field_01_length, "field 01")

    field_02_length_raw, cursor = _take(payload, cursor, 2, "field 02 length")
    field_02_length = int.from_bytes(field_02_length_raw, "little")
    field_02_raw, cursor = _take(payload, cursor, field_02_length, "field 02")

    return MagicCodePayload(
        raw=payload,
        field_00_raw=field_00_raw,
        field_01_raw=field_01_raw,
        field_02_raw=field_02_raw,
        trailing_raw=payload[cursor:],
    )


def _hex_preview(data: bytes) -> str:
    return data[:_BYTE_PREVIEW].hex(" ") + (" ..." if len(data) > _BYTE_PREVIEW else "")


def _text_preview(data: bytes) -> str:
    text = data[:_TEXT_PREVIEW].decode("ascii", errors="backslashreplace")
    return repr(text) + (" ..." if len(data) > _TEXT_PREVIEW else "")


def render_magiccode(parsed: MagicCodePayload) -> FormatResult:
    rows = (
        ("semantic_status", "engine-confirmed generic template receiver"),
        ("profile", "u8-length bytes, u32le length, length bytes, u16-length bytes"),
        ("registered_storage_stride", "32 bytes (current engine registration)"),
        (
            "registered_field_projection",
            "+0 pointer, +8 u32 length, +16 bytes pointer, +24 pointer",
        ),
        ("confirmed_lookup_consumer", "GetMagicCodeSignatures: fixed UpxEP prefix"),
        ("field_00_length", str(len(parsed.field_00_raw))),
        ("field_00_text", _text_preview(parsed.field_00_c_string)),
        ("field_00_raw", _hex_preview(parsed.field_00_raw)),
        ("field_01_length", str(len(parsed.field_01_raw))),
        ("field_01_raw", _hex_preview(parsed.field_01_raw)),
        ("field_02_length", str(len(parsed.field_02_raw))),
        ("field_02_text", _text_preview(parsed.field_02_c_string)),
        ("field_02_raw", _hex_preview(parsed.field_02_raw)),
        ("trailing_length", str(len(parsed.trailing_raw))),
        ("trailing_preview", _hex_preview(parsed.trailing_raw)),
    )
    return FormatResult(sections=(DisplaySection("MAGICCODE", rows=rows),))


def export_magiccode_semantics(parsed: MagicCodePayload) -> RuleSemantics:
    """Export receiver framing, projected row fields, and runtime consumer."""
    fields = (
        ("field_00", parsed.field_00_raw),
        ("field_01", parsed.field_01_raw),
        ("field_02", parsed.field_02_raw),
        ("trailing", parsed.trailing_raw),
    )
    return RuleSemantics(
        status="confirmed_subset",
        representation="magiccode.receiver_matcher_subset.v2",
        data=JSONObject(
            (
                ("type", "MAGICCODE"),
                ("raw_hex", parsed.raw.hex()),
                (
                    "corpus_manifest",
                    JSONObject(
                        (
                            (
                                "profile",
                                "u8-length bytes, u32le length + bytes, u16-length bytes",
                            ),
                            (
                                "engine_receiver",
                                JSONObject(
                                    (
                                        ("function", "ReceiveNewTemplate"),
                                        (
                                            "descriptor_tags",
                                            JSONArray((0x100C, 0x1000, 0x100F, 0x100D)),
                                        ),
                                        (
                                            "descriptor_row_offsets",
                                            JSONArray((0, 8, 16, 24)),
                                        ),
                                        (
                                            "trailing_bytes",
                                            "not checked after descriptors",
                                        ),
                                    )
                                ),
                            ),
                            (
                                "fields",
                                JSONArray(
                                    tuple(
                                        JSONObject(
                                            (
                                                ("name", name),
                                                ("length", len(raw)),
                                                ("raw_hex", raw.hex()),
                                            )
                                        )
                                        for name, raw in fields
                                    )
                                ),
                            ),
                            (
                                "field_00_text_preview",
                                _text_preview(parsed.field_00_c_string),
                            ),
                            (
                                "field_02_text_preview",
                                _text_preview(parsed.field_02_c_string),
                            ),
                        )
                    ),
                ),
                (
                    "confirmed_engine_consumer",
                    JSONObject(
                        (
                            ("engine_version", "1.443.903.0"),
                            ("registration", "32-byte records; 8 descriptor words"),
                            ("registered_stride", 32),
                            ("lookup_function", "GetMagicCodeSignatures"),
                            ("lookup_key", "UpxEP"),
                            ("lookup_behavior", "fixed-prefix range lookup"),
                            (
                                "unpacker_consumer",
                                JSONObject(
                                    (
                                        (
                                            "function",
                                            "Upxw60Unpacker::ResolveEntryPoint",
                                        ),
                                        ("address", "0x180269D10"),
                                        ("pattern_length_offset", 8),
                                        ("pattern_bytes_offset", 16),
                                        ("pattern_matcher", "MatchNopSignature"),
                                        ("expression_offset", 24),
                                        ("expression_evaluator", "EvaluateExpression"),
                                        (
                                            "behavior",
                                            "match pattern then evaluate expression",
                                        ),
                                    )
                                ),
                            ),
                        )
                    ),
                ),
            )
        ),
        evidence=(
            "mpas.sig contains 9 MAGICCODE records; mpav.sig contains none",
            "magiccode_init_module registers 32-byte storage and MagicCodeSort",
            "ReceiveNewTemplate consumes the four registered C0 descriptors",
            "GetMagicCodeSignatures performs a fixed UpxEP prefix range lookup",
        ),
        profile="mpengine-1.443.903.0",
        issues=(
            SemanticIssue(
                "magiccode_expression_grammar_unknown",
                "The expression bytes are passed to EvaluateExpression, but their "
                "portable grammar and evaluation semantics are not established.",
            ),
            SemanticIssue(
                "magiccode_final_effect_unknown",
                "The pattern/evaluation path is confirmed locally, but the complete "
                "unpacker state change and any final detection effect are unresolved.",
            ),
        ),
    )


SPEC = FamilySpec(
    0xC0,
    "MAGICCODE",
    parse_magiccode,
    render_magiccode,
    semantic_exporter=export_magiccode_semantics,
)
