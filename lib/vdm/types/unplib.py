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
    SemanticClaim,
    SemanticEvidence,
    SemanticIssue,
    SemanticUnknown,
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
                    (
                        "sort_tiebreak",
                        f"0x{int.from_bytes(parsed.raw[0x04:0x08], 'little'):08X}",
                    ),
                    ("offset_div_stride_limit", f"0x{parsed.word_08:08X}"),
                    ("early_offset_boundary", f"0x{parsed.word_0c:08X}"),
                    (
                        "absolute_output_limit",
                        f"0x{int.from_bytes(parsed.raw[0x10:0x18], 'little'):016X}",
                    ),
                    ("raw", parsed.raw.hex(" ")),
                    ("unresolved", "sort_tiebreak business meaning"),
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
        representation="unplib.lookup_and_output_bounds.ir.v2",
        data=JSONObject(
            (
                ("raw_hex", parsed.raw.hex()),
                (
                    "framing",
                    JSONArray(
                        (
                            _wire_span("lookup_key", parsed.raw[:4], 0),
                            _wire_span("sort_tiebreak_u32le", raw_04, 0x04),
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
                (
                    "storage_normalization",
                    JSONObject(
                        (
                            (
                                "sort_order_tiebreak_u32",
                                int.from_bytes(raw_04, "little"),
                            ),
                            (
                                "sort_order",
                                JSONArray(
                                    (
                                        "+0x00:u32",
                                        "+0x10:u64",
                                        "+0x08:u32",
                                        "+0x0C:u32",
                                        "+0x04:u32",
                                    )
                                ),
                            ),
                            (
                                "deduplicate_by",
                                "+0x00:u32; retain first sorted row per key",
                            ),
                        )
                    ),
                ),
            )
        ),
        evidence=(
            "unplib_init_module@0x180CE4390 registers type 0x157 with 24-byte rows",
            "unplib_sort@0x180CE4620 compares +0x04:u32 as final sort field",
            "unplib_removeDuplicates@0x1805B8EF0 deduplicates on +0x00 and retains first sorted row",
            "getSignature@0x1803D210C/unplib_search@0x1804F02B0 exact DWORD key lookup",
            "rOutStream::flush_internal@0x18023ED04 consumes +0x08/+0x0C/+0x10, not +0x04",
        ),
        profile="mpengine-1.443.903.0",
        issues=(
            SemanticIssue(
                "unplib_field_semantics_incomplete",
                (
                    "+0x04..+0x07 affects storage sort order; its field purpose "
                    "and any direct runtime consumer remain unknown."
                ),
                (("offset", 4), ("length", 4)),
            ),
        ),
        claims=(
            SemanticClaim(
                "unplib-row-layout",
                "wire_layout",
                "UNPLIB rows are 0x18 bytes; bytes +0x10..+0x17 are parsed as one u64le field.",
                "subset",
                ("unplib-wire",),
                (
                    SemanticUnknown(
                        "wire_layout", "The role of +0x04..+0x07 is unknown."
                    ),
                ),
            ),
            SemanticClaim(
                "unplib-key-lookup",
                "runtime_consumer",
                "UNPLIB lookup compares the first DWORD exactly; +0x08, +0x0C, and the u64le field at +0x10 participate in bounded output handling.",
                "subset",
                ("unplib-consumer",),
                (
                    SemanticUnknown(
                        "runtime_consumer",
                        "The broader business meaning of bounded output handling is unknown.",
                    ),
                ),
            ),
            SemanticClaim(
                "unplib-business",
                "final_verdict",
                "UNPLIB lookup and output handling do not establish a final verdict.",
                "unknown",
                (),
                (
                    SemanticUnknown(
                        "final_verdict",
                        "No report or verdict consumer has been established.",
                    ),
                ),
            ),
        ),
        claim_evidence=(
            SemanticEvidence(
                "unplib-wire",
                "wire_parser",
                "engine_static",
                "unplib_init_module / UNPLIB 24-byte row receiver",
                ("unplib-row-layout",),
            ),
            SemanticEvidence(
                "unplib-consumer",
                "consumer",
                "engine_static",
                "getSignature / unplib_search / rOutStream::flush_internal",
                ("unplib-key-lookup",),
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
