"""Corpus-profile decoder for the unloadable MAGICCODE record 0xC0."""

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
    """Decode the three length-prefixed fields observed in the local corpus.

    This framing is a corpus profile, not an engine-confirmed receiver
    grammar. The current binary's module initializer registers database
    storage for this signature family, but this audit did not identify a
    C0-specific receiver acceptance path.
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
        ("semantic_status", "corpus profile; engine receiver acceptance unresolved"),
        ("profile", "u8-length field, u32-length field, u16-length field"),
        ("registered_storage_stride", "32 bytes (current engine registration)"),
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
    """Export observed framing separately from the confirmed runtime consumer."""
    fields = (
        ("field_00", parsed.field_00_raw),
        ("field_01", parsed.field_01_raw),
        ("field_02", parsed.field_02_raw),
        ("trailing", parsed.trailing_raw),
    )
    return RuleSemantics(
        status="observed_only",
        representation="magiccode.corpus_manifest.ir.v1",
        data=JSONObject(
            (
                ("type", "MAGICCODE"),
                ("raw_hex", parsed.raw.hex()),
                (
                    "corpus_manifest",
                    JSONObject(
                        (
                            ("profile", "u8-length, u32le-length, u16le-length"),
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
                        )
                    ),
                ),
            )
        ),
        evidence=(
            "mpas.sig contains 9 MAGICCODE records; mpav.sig contains none",
            "magiccode_init_module registers 32-byte storage and MagicCodeSort",
            "GetMagicCodeSignatures performs a fixed UpxEP prefix range lookup",
        ),
        profile="mpengine-1.443.903.0",
        issues=(
            SemanticIssue(
                "receiver_grammar_unresolved",
                "The u8/u32/u16 field framing is a corpus profile; the C0-specific "
                "receiver acceptance grammar is not identified.",
            ),
            SemanticIssue(
                "registered_record_field_semantics_unknown",
                "The registered 32-byte MagicCode storage fields have no confirmed "
                "field-level semantics.",
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
