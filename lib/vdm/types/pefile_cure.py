"""Typed parser and bounded renderer for PEFILE_CURE (0x3D)."""

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

PEFILE_CURE_TYPE: Final = 0x3D
BASE_SIZE: Final = 12
TRAILING_PREVIEW: Final = 16


@dataclass(frozen=True, slots=True)
class PeFileCure:
    """Lossless observed PEFILE_CURE prefix and neutral method fields."""

    raw: bytes
    name_crc: int
    method_spec: int
    arg: int
    selector: int
    method_data: int
    trailing_raw: bytes


def parse_pefile_cure(payload: bytes) -> PeFileCure:
    """Parse the three-DWORD prefix, retaining any bytes after it."""
    if len(payload) < BASE_SIZE:
        raise ValueError(
            f"truncated PEFILE_CURE header: need {BASE_SIZE} bytes, have {len(payload)}"
        )

    method_spec = int.from_bytes(payload[4:8], "little")
    return PeFileCure(
        raw=payload,
        name_crc=int.from_bytes(payload[0:4], "little"),
        method_spec=method_spec,
        arg=int.from_bytes(payload[8:12], "little"),
        selector=method_spec >> 24,
        method_data=method_spec & 0x00FFFFFF,
        trailing_raw=payload[BASE_SIZE:],
    )


def _method_description(selector: int) -> str:
    if selector <= 6:
        return f"cm{selector}"
    if selector == 7:
        return "special (consumer returns 253)"
    return "fallback clean_rpf_alg32"


def render_pefile_cure(parsed: PeFileCure) -> FormatResult:
    """Render interpreted selector behavior and bounded trailing bytes."""
    sections = [
        DisplaySection(
            "PEFILE_CURE",
            rows=(
                ("name_crc", f"0x{parsed.name_crc:08X}"),
                ("name_crc_note", "engine CRC_1 output"),
                ("method_spec", f"0x{parsed.method_spec:08X}"),
                ("selector", str(parsed.selector)),
                ("method_data", f"0x{parsed.method_data:06X}"),
                ("method_dispatch", _method_description(parsed.selector)),
                ("arg", f"0x{parsed.arg:08X}"),
            ),
        )
    ]
    if parsed.trailing_raw:
        preview = parsed.trailing_raw[:TRAILING_PREVIEW].hex(" ")
        if len(parsed.trailing_raw) > TRAILING_PREVIEW:
            preview += " ..."
        sections.append(
            DisplaySection(
                "Trailing Data",
                rows=(
                    ("trailing_length", str(len(parsed.trailing_raw))),
                    ("trailing_preview", preview),
                ),
            )
        )
    return FormatResult(sections=tuple(sections))


def _wire_field(kind: str, raw: bytes, offset: int) -> JSONObject:
    return JSONObject(
        (
            ("kind", kind),
            ("raw_span", JSONObject((("offset", offset), ("length", len(raw))))),
            ("raw_hex", raw.hex()),
        )
    )


def _selector_dispatch(selector: int) -> JSONObject:
    if selector <= 6:
        target = f"pef_cm{selector}"
        branch = "cm_method"
        result = None
        fallback_target = "clean_rpf_alg32"
        fallback_on_result = 254
    elif selector == 7:
        target = None
        branch = "constant_return_253"
        result = 253
        fallback_target = None
        fallback_on_result = None
    else:
        target = "clean_rpf_alg32"
        branch = "fallback_method"
        result = None
        fallback_target = None
        fallback_on_result = None
    return JSONObject(
        (
            ("selector", selector),
            ("branch", branch),
            ("target", target),
            ("constant_result", result),
            ("fallback_target", fallback_target),
            ("fallback_on_result", fallback_on_result),
            ("action_semantics", "unknown"),
        )
    )


def export_pefile_cure_semantics(parsed: PeFileCure) -> RuleSemantics:
    """Export confirmed lookup/dispatch structure without cure meaning."""
    issues = [
        SemanticIssue(
            "cure_action_unknown",
            "The selected cure routine's action semantics are not established.",
        ),
        SemanticIssue(
            "final_verdict_unknown",
            "PEFILE_CURE lookup and dispatch do not establish a final scan verdict.",
        ),
    ]
    if parsed.selector > 7:
        issues.append(
            SemanticIssue(
                "selector_action_unknown",
                "Selectors above 7 enter the fallback routine; their action is "
                "unknown.",
                (("selector", parsed.selector),),
            )
        )
    if parsed.trailing_raw:
        issues.append(
            SemanticIssue(
                "trailing_bytes_uninterpreted",
                "Bytes after the three confirmed DWORDs are retained without "
                "semantics.",
                (("length", len(parsed.trailing_raw)),),
            )
        )

    framing = JSONArray(
        (
            _wire_field("name_crc_key", parsed.raw[0:4], 0),
            _wire_field("method_spec", parsed.raw[4:8], 4),
            _wire_field("arg", parsed.raw[8:12], 8),
            _wire_field("trailing", parsed.trailing_raw, BASE_SIZE),
        )
    )
    return RuleSemantics(
        status="unsupported" if parsed.trailing_raw else "confirmed_subset",
        representation="pefile_cure.lookup_dispatch.ir.v1",
        data=JSONObject(
            (
                ("type", "pefile_cure"),
                ("raw_hex", parsed.raw.hex()),
                ("framing", framing),
                (
                    "lookup",
                    JSONObject(
                        (
                            ("key", "name_crc"),
                            ("algorithm", "mpengine.CRC_1"),
                            ("source", "pe_name"),
                            (
                                "prefix_stops_at",
                                JSONArray(("nul", "ascii_space", "non_ascii_byte")),
                            ),
                            ("table", "sorted Base_1 entries"),
                        )
                    ),
                ),
                (
                    "method_spec",
                    JSONObject(
                        (
                            ("value", parsed.method_spec),
                            ("selector", parsed.selector),
                            (
                                "selector_raw_span",
                                JSONObject((("offset", 7), ("length", 1))),
                            ),
                            ("method_data", parsed.method_data),
                            (
                                "method_data_raw_span",
                                JSONObject((("offset", 4), ("length", 3))),
                            ),
                            ("method_data_semantics", "unknown"),
                        )
                    ),
                ),
                ("dispatch", _selector_dispatch(parsed.selector)),
                (
                    "arg",
                    JSONObject((("value", parsed.arg), ("semantics", "unknown"))),
                ),
                ("final_verdict", "unknown"),
            )
        ),
        evidence=("mpengine 1.443.903.0 pef_initmodule and pef_cleanfile",),
        profile="mpengine-1.443.903.0",
        issues=tuple(issues),
    )


SPEC = FamilySpec(
    PEFILE_CURE_TYPE,
    "PEFILE_CURE",
    parse_pefile_cure,
    render_pefile_cure,
    semantic_exporter=export_pefile_cure_semantics,
)
