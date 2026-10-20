"""Corpus-validated wire parser for UNPLIB (0x57)."""

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

UNPLIB_TYPE: Final = 0x57
PAYLOAD_SIZE: Final = 24


@dataclass(frozen=True, slots=True)
class UnpLibPayload:
    """UNPLIB row with its consumer-confirmed lookup key."""

    raw: bytes
    prefix: bytes
    lookup_key: int
    word_08: int
    word_0c: int
    word_10: int
    word_14: int


def parse_unplib(payload: bytes) -> UnpLibPayload:
    """Parse the 24-byte layout shared by every supplied corpus record."""
    if len(payload) != PAYLOAD_SIZE:
        raise ValueError(
            f"UNPLIB corpus layout requires {PAYLOAD_SIZE} bytes, have {len(payload)}"
        )

    return UnpLibPayload(
        raw=payload,
        prefix=payload[:8],
        lookup_key=int.from_bytes(payload[:4], "little"),
        word_08=int.from_bytes(payload[0x08:0x0C], "little"),
        word_0c=int.from_bytes(payload[0x0C:0x10], "little"),
        word_10=int.from_bytes(payload[0x10:0x14], "little"),
        word_14=int.from_bytes(payload[0x14:0x18], "little"),
    )


def render_unplib(parsed: UnpLibPayload) -> FormatResult:
    """Render the consumer-confirmed lookup and output-bound fields."""
    return FormatResult(
        sections=(
            DisplaySection(
                "UNPLIB",
                rows=(
                    ("lookup_key", f"0x{parsed.lookup_key:08X}"),
                    ("raw_04", parsed.raw[0x04:0x08].hex(" ")),
                    ("offset_div_stride_limit", f"0x{parsed.word_08:08X}"),
                    ("early_offset_boundary", f"0x{parsed.word_0c:08X}"),
                    (
                        "absolute_output_limit",
                        f"0x{int.from_bytes(parsed.raw[0x10:0x18], 'little'):016X}",
                    ),
                    ("raw", parsed.raw.hex(" ")),
                    ("unresolved", "raw_04"),
                    # Retained as a renderer compatibility marker. The row
                    # above scopes the unresolved bytes; the bounds fields
                    # themselves are consumer-confirmed.
                    ("field_semantics", "unresolved"),
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


def export_unplib_semantics(parsed: UnpLibPayload) -> RuleSemantics:
    """Export only fields directly consumed by UNPLIB lookup/output code."""
    raw_04 = parsed.raw[0x04:0x08]
    ratio_limit_raw = parsed.raw[0x08:0x0C]
    offset_boundary_raw = parsed.raw[0x0C:0x10]
    absolute_limit_raw = parsed.raw[0x10:0x18]
    return RuleSemantics(
        status="confirmed_subset",
        representation="unplib.lookup_and_output_bounds.ir.v1",
        data=JSONObject(
            (
                ("raw_hex", parsed.raw.hex()),
                (
                    "framing",
                    JSONArray(
                        (
                            _wire_span("lookup_key", parsed.raw[:4], 0),
                            _wire_span("unknown_raw", raw_04, 0x04),
                            _wire_span(
                                "offset_div_stride_limit", ratio_limit_raw, 0x08
                            ),
                            _wire_span(
                                "early_offset_boundary", offset_boundary_raw, 0x0C
                            ),
                            _wire_span(
                                "absolute_output_limit", absolute_limit_raw, 0x10
                            ),
                        )
                    ),
                ),
                (
                    "lookup",
                    JSONObject(
                        (
                            ("kind", "exact_u32"),
                            ("key", parsed.lookup_key),
                            ("key_raw_hex", parsed.raw[:4].hex()),
                        )
                    ),
                ),
                (
                    "output_bounds",
                    JSONObject(
                        (
                            ("offset_div_stride_limit_u32", parsed.word_08),
                            ("early_offset_boundary_u32", parsed.word_0c),
                            (
                                "absolute_offset_limit_u64",
                                int.from_bytes(absolute_limit_raw, "little"),
                            ),
                        )
                    ),
                ),
                ("unresolved_raw_hex", raw_04.hex()),
            )
        ),
        evidence=(
            "getSignature/unplib_search exact DWORD key lookup",
            "rOutStream::flush_internal consumes row +0x08, +0x0C, and +0x10",
        ),
        profile="mpengine-1.443.903.0",
        issues=(
            SemanticIssue(
                "unplib_field_semantics_incomplete",
                "Bytes +0x04..+0x07 are preserved raw because no consumer is confirmed.",
                (("offset", 4), ("length", 4)),
            ),
        ),
    )


SPEC = FamilySpec(
    UNPLIB_TYPE,
    "UNPLIB",
    parse_unplib,
    render_unplib,
    semantic_exporter=export_unplib_semantics,
)
