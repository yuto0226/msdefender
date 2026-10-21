"""Corpus-validated wire parser for GENSFX (0x56)."""

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

GENSFX_TYPE: Final = 0x56
PAYLOAD_SIZE: Final = 84
NAME_SIZE: Final = 64


@dataclass(frozen=True, slots=True)
class GenSfxPayload:
    """GENSFX fields whose offsets have consumer-side evidence."""

    raw: bytes
    name_bytes: bytes
    lookup_key: int
    scan_start: int
    scan_end: int
    match_bytes: bytes
    match_offset_delta: int

    @property
    def name(self) -> str:
        """Return the NUL-terminated byte-string view as lossy ASCII display."""
        return self.name_bytes.split(b"\0", 1)[0].decode("ascii", errors="replace")


def parse_gensfx(payload: bytes) -> GenSfxPayload:
    """Parse the fixed 84-byte layout observed in both supplied corpora."""
    if len(payload) != PAYLOAD_SIZE:
        raise ValueError(
            f"GENSFX corpus layout requires {PAYLOAD_SIZE} bytes, have {len(payload)}"
        )

    return GenSfxPayload(
        raw=payload,
        name_bytes=payload[:NAME_SIZE],
        lookup_key=int.from_bytes(payload[0x40:0x44], "little"),
        scan_start=int.from_bytes(payload[0x44:0x48], "little"),
        scan_end=int.from_bytes(payload[0x48:0x4C], "little"),
        match_bytes=payload[0x4C:0x50],
        match_offset_delta=int.from_bytes(payload[0x50:0x54], "little"),
    )


def render_gensfx(parsed: GenSfxPayload) -> FormatResult:
    """Render scan semantics established by the registered receiver/consumer."""
    return FormatResult(
        sections=(
            DisplaySection(
                "GENSFX",
                rows=(
                    ("name", parsed.name or "(empty)"),
                    ("lookup_key", f"0x{parsed.lookup_key:08X}"),
                    ("scan_start", f"0x{parsed.scan_start:08X}"),
                    ("scan_end", f"0x{parsed.scan_end:08X}"),
                    ("match_bytes", parsed.match_bytes.hex(" ")),
                    (
                        "match_offset_delta",
                        f"0x{parsed.match_offset_delta:08X}",
                    ),
                    (
                        "semantics_note",
                        (
                            "scan interval and 4-byte search pattern confirmed; "
                            "signed delta arithmetic confirmed, key domain and "
                            "high-level delta purpose unresolved"
                        ),
                    ),
                ),
            ),
        )
    )


def _raw_span(offset: int, length: int) -> JSONObject:
    return JSONObject((("offset", offset), ("length", length)))


def _raw_field(kind: str, raw: bytes, offset: int) -> JSONObject:
    return JSONObject(
        (
            ("kind", kind),
            ("raw_span", _raw_span(offset, len(raw))),
            ("raw_hex", raw.hex()),
        )
    )


def _signed_i32(value: int) -> int:
    """Interpret a raw DWORD as the signed offset used by the consumer."""
    return value - (1 << 32) if value & 0x80000000 else value


def export_gensfx_semantics(parsed: GenSfxPayload) -> RuleSemantics:
    """Export the confirmed GENSFX search fields without inventing a verdict."""
    name_prefix = parsed.name_bytes.split(b"\0", 1)[0]
    issues = (
        SemanticIssue(
            "name_encoding_unknown",
            "The scanner passes the NUL-terminated name bytes to a %s format; "
            "the text encoding is not established.",
        ),
        SemanticIssue(
            "lookup_key_derivation_unknown",
            "The runtime lookup key is retained as a 32-bit value; its generation "
            "is not established.",
        ),
        SemanticIssue(
            "outer_verdict_unknown",
            "A GENSFX lookup or byte-pattern match does not establish the final "
            "scan report.",
        ),
    )

    framing = JSONArray(
        (
            _raw_field("name_field", parsed.name_bytes, 0),
            _raw_field("lookup_key", parsed.raw[0x40:0x44], 0x40),
            _raw_field("scan_start", parsed.raw[0x44:0x48], 0x44),
            _raw_field("scan_end", parsed.raw[0x48:0x4C], 0x48),
            _raw_field("match_bytes", parsed.match_bytes, 0x4C),
            _raw_field("match_offset_delta", parsed.raw[0x50:0x54], 0x50),
        )
    )
    return RuleSemantics(
        status="confirmed_subset",
        representation="gensfx.byte_search.ir.v2",
        data=JSONObject(
            (
                ("type", "gensfx_byte_search"),
                ("raw_hex", parsed.raw.hex()),
                ("framing", framing),
                (
                    "name",
                    JSONObject(
                        (
                            ("raw_hex", parsed.name_bytes.hex()),
                            ("c_string_prefix_raw_hex", name_prefix.hex()),
                            ("raw_span", _raw_span(0, NAME_SIZE)),
                            ("encoding", "unknown"),
                            (
                                "runtime_interpretation",
                                "NUL-terminated byte string passed to (%s)",
                            ),
                            ("runtime_role", "result_label"),
                        )
                    ),
                ),
                (
                    "lookup",
                    JSONObject(
                        (
                            ("kind", "exact_sorted_key_lookup"),
                            ("key_u32", parsed.lookup_key),
                            ("key_raw_hex", parsed.raw[0x40:0x44].hex()),
                            ("key_span", _raw_span(0x40, 4)),
                        )
                    ),
                ),
                (
                    "runtime_search",
                    JSONObject(
                        (
                            ("role", "bounded_byte_pattern_search"),
                            ("scan_start", parsed.scan_start),
                            ("scan_end", parsed.scan_end),
                            ("scan_span", _raw_span(0x44, 8)),
                            ("pattern_hex", parsed.match_bytes.hex()),
                            ("pattern_comparison", "exact_4_bytes"),
                            ("pattern_span", _raw_span(0x4C, 4)),
                            (
                                "result_offset",
                                JSONObject(
                                    (
                                        (
                                            "expression",
                                            "hit_position + sign_extend_i32(delta)",
                                        ),
                                        ("delta", parsed.match_offset_delta),
                                        (
                                            "delta_signed_i32",
                                            _signed_i32(parsed.match_offset_delta),
                                        ),
                                        (
                                            "delta_raw_hex",
                                            parsed.raw[0x50:0x54].hex(),
                                        ),
                                        ("delta_span", _raw_span(0x50, 4)),
                                    )
                                ),
                            ),
                        )
                    ),
                ),
                (
                    "candidate_acceptance",
                    JSONObject(
                        (
                            (
                                "result_prepared_as",
                                "label, result_offset, and file_size - result_offset",
                            ),
                            (
                                "bounds_gate",
                                "result_offset must be less than file_size",
                            ),
                            (
                                "duplicate_interval_gate",
                                (
                                    "[result_offset, file_size) must not be burnt; "
                                    "Burn(component_id=7) must succeed"
                                ),
                            ),
                            ("callback_nonzero_requires_gates", True),
                            (
                                "threat_attribution_or_final_verdict",
                                "unknown beyond this callback",
                            ),
                        )
                    ),
                ),
            )
        ),
        evidence=(
            (
                "expk_init_module (0x180C45070) registers internal type 0x156 "
                "with 0x54-byte rows and gsfxs_cmp (0x18058B6C0)"
            ),
            "gsfxs_keycmp (0x1806015E0) compares the runtime key with row +0x40",
            (
                "gsfx_ismine (0x180095070) reads the runtime key from file context "
                "+0x20E8 and scans [row +0x44, row +0x48) for the exact 4 bytes "
                "at row +0x4C"
            ),
            (
                "gsfx_ismine (0x180095070) sign-extends row +0x50 and gates "
                "callback success through UsedIntervals component 7"
            ),
        ),
        profile="mpengine-1.443.903.0",
        issues=issues,
    )


SPEC = FamilySpec(
    GENSFX_TYPE,
    "GENSFX",
    parse_gensfx,
    render_gensfx,
    semantic_exporter=export_gensfx_semantics,
)
