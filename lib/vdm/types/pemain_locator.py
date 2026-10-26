"""Template-backed prefix view for PEMAIN_LOCATOR (0x86)."""

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
from ._semantic_claims import scoped_claim

PEMAIN_LOCATOR_TYPE: Final = 0x86
PAYLOAD_SIZE: Final = 8
_TRAILING_PREVIEW_BYTES: Final = 64
_RELATIVE_OFFSET_LIMIT: Final = 0x3FC


@dataclass(frozen=True, slots=True)
class PeMainLocatorPayload:
    """Lookup key, relative read offset, and any unconsumed tail."""

    raw: bytes
    lookup_key: int
    relative_offset: int
    trailing_raw: bytes


def parse_pemain_locator(payload: bytes) -> PeMainLocatorPayload:
    """Parse the two DWORD template fields and preserve any trailing bytes."""
    if len(payload) < PAYLOAD_SIZE:
        raise ValueError(
            "PEMAIN_LOCATOR template requires at least "
            f"{PAYLOAD_SIZE} bytes, have {len(payload)}"
        )
    return PeMainLocatorPayload(
        raw=payload,
        lookup_key=int.from_bytes(payload[:4], "little"),
        relative_offset=int.from_bytes(payload[4:8], "little"),
        trailing_raw=payload[8:],
    )


def render_pemain_locator(parsed: PeMainLocatorPayload) -> FormatResult:
    """Render consumer-backed roles without assigning broader PE semantics."""
    trailing_preview = parsed.trailing_raw[:_TRAILING_PREVIEW_BYTES].hex(" ")
    if len(parsed.trailing_raw) > _TRAILING_PREVIEW_BYTES:
        omitted = len(parsed.trailing_raw) - _TRAILING_PREVIEW_BYTES
        trailing_preview += f" … ({omitted} more bytes)"
    return FormatResult(
        sections=(
            DisplaySection(
                "PEMAIN_LOCATOR",
                rows=(
                    ("lookup_key", f"0x{parsed.lookup_key:08X}"),
                    ("relative_offset", f"0x{parsed.relative_offset:08X}"),
                    ("trailing_raw", trailing_preview or "(empty)"),
                    (
                        "runtime_use",
                        (
                            "exact bsearch_s(Base_3) match by pattern_info_t[0]; if "
                            "relative_offset < 0x3FC, read u32le at current search "
                            "offset + relative_offset"
                        ),
                    ),
                    (
                        "relative_base",
                        (
                            "current search offset in scan_compiler_worker (input plus "
                            "fallback candidate adjustment when used)"
                        ),
                    ),
                    ("engine_template", "2 × u32le; trailing bytes are not checked"),
                ),
            ),
        )
    )


def _wire_field(kind: str, raw: bytes, offset: int) -> JSONObject:
    return JSONObject(
        (
            ("kind", kind),
            ("raw_span", JSONObject((("offset", offset), ("length", len(raw))))),
            ("raw_hex", raw.hex()),
        )
    )


def export_pemain_locator_semantics(parsed: PeMainLocatorPayload) -> RuleSemantics:
    """Export the confirmed lookup/read subset and retain exact wire spans."""
    claim, claim_evidence = scoped_claim(
        "pemain_locator",
        "lookup_relative_read",
        "runtime_consumer",
        "The consumer performs an exact key comparison, then a bounded relative DWORD read when the key matches.",
        "The relative value is not established as an RVA, and downstream/final meaning remains unknown.",
        "consumer",
        "ComparePeMainLocators; scan_compiler_worker; ReceiveNewTemplate",
    )
    issues = [
        SemanticIssue(
            "final_verdict_unknown",
            "The final verdict or threat result produced after the DWORD read is unknown.",
        ),
        SemanticIssue(
            "consumer_policy_unknown",
            "The wider consumer policy for this locator, including downstream handling, is unknown.",
        ),
    ]
    if parsed.trailing_raw:
        issues.append(
            SemanticIssue(
                "trailing_bytes_unconsumed",
                "The template receiver consumes two DWORD instructions and leaves trailing bytes unused.",
                (("length", len(parsed.trailing_raw)),),
            )
        )
    return RuleSemantics(
        status="confirmed_subset",
        representation="pe_main_locator.lookup.ir.v1",
        data=JSONObject(
            (
                ("type", "exact_key_lookup_with_relative_read"),
                ("raw_hex", parsed.raw.hex()),
                (
                    "lookup_key",
                    JSONObject(
                        (
                            ("value", parsed.lookup_key),
                            ("wire", _wire_field("lookup_key", parsed.raw[:4], 0)),
                            ("lookup", "exact_bsearch_s_key_match"),
                        )
                    ),
                ),
                (
                    "relative_offset",
                    JSONObject(
                        (
                            ("value", parsed.relative_offset),
                            (
                                "wire",
                                _wire_field("relative_offset", parsed.raw[4:8], 4),
                            ),
                            ("relative_base", "current_search_offset"),
                            (
                                "read_guard",
                                JSONObject(
                                    (
                                        ("operator", "<"),
                                        ("limit", _RELATIVE_OFFSET_LIMIT),
                                    )
                                ),
                            ),
                            (
                                "read",
                                JSONObject(
                                    (
                                        ("type", "u32le"),
                                        (
                                            "condition",
                                            "exact_key_match and relative_offset < limit",
                                        ),
                                        (
                                            "offset_expression",
                                            "current_search_offset + relative_offset",
                                        ),
                                    )
                                ),
                            ),
                        )
                    ),
                ),
                ("trailing", _wire_field("trailing", parsed.trailing_raw, 8)),
            )
        ),
        evidence=(
            "mpengine 1.443.903.0 init_compiler template registration",
            "mpengine 1.443.903.0 ComparePeMainLocators exact first-DWORD comparison",
            "mpengine 1.443.903.0 scan_compiler_worker exact lookup and guarded DWORD read",
            "mpengine 1.443.903.0 ReceiveNewTemplate consumes two DWORD instructions",
        ),
        profile="mpengine-1.443.903.0",
        issues=tuple(issues),
        claims=(claim,),
        claim_evidence=(claim_evidence,),
    )


SPEC = FamilySpec(
    PEMAIN_LOCATOR_TYPE,
    "PEMAIN_LOCATOR",
    parse_pemain_locator,
    render_pemain_locator,
    semantic_exporter=export_pemain_locator_semantics,
)
