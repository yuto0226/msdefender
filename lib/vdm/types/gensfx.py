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
        """Return the observed NUL-terminated ASCII name view."""
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
                            "lookup-key domain and delta purpose unresolved"
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


def export_gensfx_semantics(parsed: GenSfxPayload) -> RuleSemantics:
    """Export the confirmed GENSFX search fields without inventing a verdict."""
    name_prefix = parsed.name_bytes.split(b"\0", 1)[0]
    issues = (
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
        representation="gensfx.byte_search.ir.v1",
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
                                        ("expression", "hit_position + delta"),
                                        ("delta", parsed.match_offset_delta),
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
            )
        ),
        evidence=(
            "GENSFX 0x56 wire layout and registered runtime lookup/search consumer",
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
