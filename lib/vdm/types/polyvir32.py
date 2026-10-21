"""Observed zero-length-string POLYVIR32 subset (type 0x21)."""

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

POLYVIR32_TYPE: Final = 0x21
POLYVIR32_SIZE: Final = 34
_PREFIX_SIZE: Final = 16
_STRING_LENGTH_OFFSET: Final = 0x20


def _projection_entry(
    wire_offset: int | None,
    wire_width: int,
    row_offset: int,
    row_width: int,
    operation: str,
    row_value: int | None = None,
) -> JSONObject:
    fields = [
        ("wire_offset", wire_offset),
        ("wire_width", wire_width),
        ("row_offset", row_offset),
        ("row_width", row_width),
        ("operation", operation),
    ]
    if row_value is not None:
        fields.append(("row_value", row_value))
    return JSONObject(tuple(fields))


@dataclass(frozen=True, slots=True)
class Polyvir32Payload:
    """Preserve raw bytes and neutral wire offset/width groups."""

    raw: bytes
    bytes_00_0f: bytes
    word_10: int
    word_12: int
    dword_14: int
    word_18: int
    word_1a: int
    dword_1c: int
    string_length_20: int

    def to_bytes(self) -> bytes:
        """Rebuild the observed zero-length-string subset exactly."""
        return b"".join(
            (
                self.bytes_00_0f,
                self.word_10.to_bytes(2, "little"),
                self.word_12.to_bytes(2, "little"),
                self.dword_14.to_bytes(4, "little"),
                self.word_18.to_bytes(2, "little"),
                self.word_1a.to_bytes(2, "little"),
                self.dword_1c.to_bytes(4, "little"),
                self.string_length_20.to_bytes(2, "little"),
            )
        )


def parse_polyvir32(payload: bytes) -> Polyvir32Payload:
    """Parse the observed 34-byte subset with an empty string at wire +0x20.

    This narrow corpus profile is not the complete receiver grammar: the
    engine template accepts a length-prefixed string at this position.
    """
    if len(payload) != POLYVIR32_SIZE:
        raise ValueError(
            f"POLYVIR32 payload must be exactly {POLYVIR32_SIZE} bytes, "
            f"have {len(payload)}"
        )
    string_length = int.from_bytes(payload[_STRING_LENGTH_OFFSET:], "little")
    if string_length != 0:
        raise ValueError(
            "POLYVIR32 corpus subset requires zero string length at offset 0x20"
        )

    return Polyvir32Payload(
        raw=payload,
        bytes_00_0f=payload[:_PREFIX_SIZE],
        word_10=int.from_bytes(payload[0x10:0x12], "little"),
        word_12=int.from_bytes(payload[0x12:0x14], "little"),
        dword_14=int.from_bytes(payload[0x14:0x18], "little"),
        word_18=int.from_bytes(payload[0x18:0x1A], "little"),
        word_1a=int.from_bytes(payload[0x1A:0x1C], "little"),
        dword_1c=int.from_bytes(payload[0x1C:0x20], "little"),
        string_length_20=string_length,
    )


def render_polyvir32(parsed: Polyvir32Payload) -> FormatResult:
    rows = (
        ("bytes_00_0f", parsed.bytes_00_0f.hex(" ")),
        ("word_10", f"0x{parsed.word_10:04X}"),
        ("word_12", f"0x{parsed.word_12:04X}"),
        ("dword_14", f"0x{parsed.dword_14:08X}"),
        ("word_18", f"0x{parsed.word_18:04X}"),
        ("word_1a", f"0x{parsed.word_1a:04X}"),
        ("dword_1c", f"0x{parsed.dword_1c:08X}"),
        ("u16_20_string_length", "0x0000"),
    )
    return FormatResult(sections=(DisplaySection("POLYVIR32", rows=rows),))


def export_polyvir32_semantics(parsed: Polyvir32Payload) -> RuleSemantics:
    """Export the engine-confirmed wire-to-row projection for this subset."""
    return RuleSemantics(
        status="confirmed_subset",
        representation="polyvir32.template_projection.v1",
        data=JSONObject(
            (
                ("record_type", "POLYVIR32"),
                ("raw_hex", parsed.raw.hex()),
                ("profile_size", len(parsed.raw)),
                ("bytes_00_0f_hex", parsed.bytes_00_0f.hex()),
                ("u16_10_raw_le", parsed.word_10),
                ("u16_12_raw_le", parsed.word_12),
                ("u32_14_raw_le", parsed.dword_14),
                ("u16_18_raw_le", parsed.word_18),
                ("u16_1a_raw_le", parsed.word_1a),
                ("u32_1c_raw_le", parsed.dword_1c),
                ("u16_20_string_length", parsed.string_length_20),
                ("template_row_size", 0x28),
                (
                    "wire_to_row_projection",
                    JSONArray(
                        (
                            _projection_entry(0x00, 16, 0x00, 16, "copy"),
                            _projection_entry(0x10, 2, 0x10, 2, "u16"),
                            _projection_entry(0x12, 2, 0x12, 2, "u16"),
                            _projection_entry(0x14, 4, 0x14, 4, "u32"),
                            _projection_entry(0x18, 2, 0x18, 2, "u16"),
                            _projection_entry(0x1A, 2, 0x1A, 2, "u16"),
                            _projection_entry(0x1C, 4, 0x1C, 4, "u32"),
                            _projection_entry(
                                0x20,
                                2,
                                0x24,
                                4,
                                "zero_length_string_to_u32",
                                0xFFFFFFFF,
                            ),
                            _projection_entry(None, 0, 0x20, 4, "engine_generated_u32"),
                        )
                    ),
                ),
            )
        ),
        evidence=(
            (
                "pattsearch_init at 0x18056551F registers encoded type 0x421, "
                "normalized to type 0x21, with row size 0x28 and 0x12 "
                "template instructions."
            ),
            (
                "Descriptors at 0x180F670C0 map the observed zero-length-string "
                "wire subset to neutral row offsets and widths."
            ),
            (
                "Local corpus sweep: mpav.sig has 151 records of 34 bytes; "
                "mpas.sig has no type 0x21 records."
            ),
        ),
        profile="mpengine-1.443.903.0",
        issues=(
            SemanticIssue(
                "receiver_grammar_incomplete",
                "The parser supports only the observed 34-byte subset with a "
                "zero-length string at wire +0x20; it is not the complete "
                "template receiver grammar.",
            ),
            SemanticIssue(
                "consumer_and_final_verdict_unknown",
                "Runtime consumer field semantics, match conditions, and final "
                "verdict behavior are not established by this wire-to-row "
                "projection.",
            ),
        ),
    )


SPEC: Final = FamilySpec(
    POLYVIR32_TYPE,
    "POLYVIR32",
    parse_polyvir32,
    render_polyvir32,
    semantic_exporter=export_polyvir32_semantics,
)
