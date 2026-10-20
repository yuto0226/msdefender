"""Lossless parsers for the FOP scanner signature payload family."""

from collections.abc import Callable
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final

from ..core import (
    DisplaySection,
    FamilySpec,
    FormatResult,
    JSONObject,
    RuleSemantics,
    SemanticIssue,
    SemanticJSONValue,
)

FOP_TYPES: Final = MappingProxyType(
    {
        0x7F: "FOP",
        0x89: "FOPEX",
        0xB4: "VBFOP",
        0xBA: "MSILFOP",
        0xC6: "MSILFOPEX",
        0xC7: "VBFOPEX",
        0xC8: "FOP64",
        0xC9: "FOPEX64",
    }
)
FOP_PLAIN_TYPES: Final = frozenset({0x7F, 0xB4, 0xBA, 0xC8})
FOP_EXTENDED_TYPES: Final = frozenset(FOP_TYPES) - FOP_PLAIN_TYPES
FOP_PLAIN_HEADER_SIZE: Final = 4
FOP_EXTENDED_HEADER_SIZE: Final = 10
FOP_PREVIEW_SIZE: Final = 64
_FOP_ROUTES: Final = MappingProxyType(
    {
        0x7F: "x86",
        0x89: "x86",
        0xB4: "vb",
        0xC7: "vb",
        0xBA: "msil",
        0xC6: "msil",
        0xC8: "x64",
        0xC9: "x64",
    }
)


@dataclass(frozen=True, slots=True)
class FopPayload:
    """Parsed FOP fields; section labels are neutral pending semantic analysis."""

    raw: bytes
    type_byte: int
    flags: int | None
    ignored_reason: str | None
    prefix: bytes
    pattern: bytes
    section1: bytes | None
    section2: bytes | None
    pattern_options: int | None


def parse_fop(payload: bytes, *, type_byte: int) -> FopPayload:
    """Mirror the FOP receiver's load/no-op/error disposition losslessly."""
    try:
        FOP_TYPES[type_byte]
    except KeyError as exc:
        raise ValueError(f"unsupported FOP family type 0x{type_byte:02X}") from exc

    header_size = (
        FOP_PLAIN_HEADER_SIZE
        if type_byte in FOP_PLAIN_TYPES
        else FOP_EXTENDED_HEADER_SIZE
    )
    if len(payload) <= header_size:
        return FopPayload(
            raw=payload,
            type_byte=type_byte,
            flags=payload[0] if payload else None,
            ignored_reason=f"payload size <= {header_size}-byte header",
            prefix=b"",
            pattern=b"",
            section1=None,
            section2=None,
            pattern_options=None,
        )

    flags = payload[0]
    if flags & 0xFE:
        return FopPayload(
            raw=payload,
            type_byte=type_byte,
            flags=flags,
            ignored_reason=f"reserved flag bits set (0x{flags & 0xFE:02X})",
            prefix=b"",
            pattern=b"",
            section1=None,
            section2=None,
            pattern_options=None,
        )

    prefix_len = payload[1]
    pattern_len = int.from_bytes(payload[2:4], "little")
    if type_byte in FOP_PLAIN_TYPES:
        expected_size = FOP_PLAIN_HEADER_SIZE + prefix_len + pattern_len
        if len(payload) != expected_size:
            raise ValueError(
                f"invalid FOP payload length: expected {expected_size}, got {len(payload)}"
            )
        prefix_start = FOP_PLAIN_HEADER_SIZE
        pattern_start = prefix_start + prefix_len
        return FopPayload(
            raw=payload,
            type_byte=type_byte,
            flags=flags,
            ignored_reason=None,
            prefix=payload[prefix_start:pattern_start],
            pattern=payload[pattern_start:],
            section1=None,
            section2=None,
            pattern_options=None,
        )

    section1_len = int.from_bytes(payload[4:6], "little")
    section2_len = int.from_bytes(payload[6:8], "little")
    pattern_options = int.from_bytes(payload[8:10], "little")
    expected_size = (
        FOP_EXTENDED_HEADER_SIZE
        + prefix_len
        + pattern_len
        + section1_len
        + section2_len
    )
    if len(payload) != expected_size:
        raise ValueError(
            f"invalid FOP payload length: expected {expected_size}, got {len(payload)}"
        )

    cursor = FOP_EXTENDED_HEADER_SIZE
    prefix = payload[cursor : cursor + prefix_len]
    cursor += prefix_len
    pattern = payload[cursor : cursor + pattern_len]
    cursor += pattern_len
    section1 = payload[cursor : cursor + section1_len]
    cursor += section1_len
    section2 = payload[cursor : cursor + section2_len]
    return FopPayload(
        raw=payload,
        type_byte=type_byte,
        flags=flags,
        ignored_reason=None,
        prefix=prefix,
        pattern=pattern,
        section1=section1,
        section2=section2,
        pattern_options=pattern_options,
    )


def _preview(raw: bytes) -> str:
    value = raw[:FOP_PREVIEW_SIZE].hex(" ") or "(empty)"
    if len(raw) > FOP_PREVIEW_SIZE:
        value += f" … (+{len(raw) - FOP_PREVIEW_SIZE} B)"
    return value


def _section_rows(name: str, raw: bytes) -> tuple[tuple[str, str], ...]:
    return ((f"{name}_length", f"{len(raw)} B"), (f"{name}_preview", _preview(raw)))


def render_fop(parsed: FopPayload) -> FormatResult:
    """Render normalized fields and byte-limited previews for each byte section."""
    name = FOP_TYPES[parsed.type_byte]
    rows = [
        ("type", f"{name} (0x{parsed.type_byte:02X})"),
        ("flags", "not read" if parsed.flags is None else f"0x{parsed.flags:02X}"),
    ]
    if parsed.ignored_reason is not None:
        rows.append(("receiver_disposition", f"ignored ({parsed.ignored_reason})"))
        return FormatResult(sections=(DisplaySection("FOP", rows=tuple(rows)),))

    assert parsed.flags is not None
    rows.extend(
        (
            ("receiver_disposition", "loaded"),
            ("flag_bit0", str(bool(parsed.flags & 1))),
            *_section_rows("prefix", parsed.prefix),
            *_section_rows("pattern", parsed.pattern),
        )
    )
    if parsed.pattern_options is not None:
        rows.append(("pattern_options", f"0x{parsed.pattern_options:04X}"))
        assert parsed.section1 is not None and parsed.section2 is not None
        rows.extend(_section_rows("section1", parsed.section1))
        rows.extend(_section_rows("section2", parsed.section2))
    return FormatResult(sections=(DisplaySection("FOP", rows=tuple(rows)),))


def export_fop_semantics(parsed: FopPayload) -> RuleSemantics:
    """Export the confirmed wire/route/matcher subset without verdict claims."""
    evidence = (
        "mpengine 1.443.903.0 FopScanner::Init @ 0x1805F0120",
        "mpengine 1.443.903.0 FopScanner::AddNewPatternCommon @ 0x18046F9AC",
        "mpengine 1.443.903.0 FopScanner::AddToResults @ 0x1802BC7BC",
        "mpengine 1.443.903.0 BMGetPatternFlags @ 0x1800FEBF4",
        "mpengine 1.443.903.0 BMMatchPEMapper @ 0x1803D5E44",
        "mpengine 1.443.903.0 FopScanner::ScanContext::GetChar @ 0x180250E5C",
        "mpengine 1.443.903.0 FopScanner::Scan @ 0x18040AF48",
        "mpengine 1.443.903.0 x86_fop_processor::GetCharAtAddr @ 0x180250F70",
        "mpengine 1.443.903.0 x64_fop_processor::GetCharAtAddr @ 0x180250500",
        "mpengine 1.443.903.0 vb_fop_processor::GetCharAtAddr @ 0x180555210",
    )
    if parsed.ignored_reason is not None:
        return RuleSemantics(
            status="ignored",
            representation="fop.trie_matcher_subset.ir.v2",
            data=JSONObject(
                (
                    ("raw_hex", parsed.raw.hex()),
                    ("type_byte", parsed.type_byte),
                    ("ignored_reason", parsed.ignored_reason),
                )
            ),
            evidence=evidence,
            profile="mpengine-1.443.903.0",
        )

    assert parsed.flags is not None
    data_items: list[tuple[str, SemanticJSONValue]] = [
        ("raw_hex", parsed.raw.hex()),
        ("type_byte", parsed.type_byte),
        ("semantic_scope", "wire_route_and_core_trie_matcher_shape"),
        ("route", _FOP_ROUTES[parsed.type_byte]),
        ("prefix_hex", parsed.prefix.hex()),
        ("pattern_hex", parsed.pattern.hex()),
        ("flag_bit0_raw", bool(parsed.flags & 1)),
        ("matcher", "processor_GetCharAtAddr_output_equals_trie_pattern_bytes"),
        ("engine_processor_required", True),
    ]
    issues = [
        SemanticIssue(
            "engine_processor_required",
            "The scanner trie is evaluated through the type-specific engine "
            "processor's GetCharAtAddr path; this export does not implement that "
            "processor.",
        ),
        SemanticIssue(
            "final_verdict_unknown",
            "This subset describes receiver routing and core trie matching only; "
            "result selection and final detection/report policy are not modeled.",
        ),
        SemanticIssue(
            "flag_bit0_semantics_unknown",
            "flag bit 0 is propagated into trie/result metadata, but its complete "
            "matching and reporting semantics are unresolved.",
        ),
    ]
    status = "confirmed_subset"
    representation = "fop.trie_matcher_subset.ir.v2"
    if parsed.pattern_options is not None:
        assert parsed.section1 is not None and parsed.section2 is not None
        data_items.extend(
            (
                ("section1_raw_hex", parsed.section1.hex()),
                ("section2_raw_hex", parsed.section2.hex()),
                ("pattern_options_raw", parsed.pattern_options),
                (
                    "runtime_effects_observed",
                    JSONObject(
                        (
                            (
                                "section1",
                                "BMGetPatternFlags validation; stored kernel object",
                            ),
                            (
                                "section2",
                                "optional kernel object; updates handle byte table",
                            ),
                            ("pattern_options", "copied to trie metadata low word"),
                            (
                                "candidate_gate",
                                "conditional BMMatchPEMapper; false rejects candidate",
                            ),
                        )
                    ),
                ),
            )
        )
        status = "observed_only"
        representation = "fop.trie_matcher_subset.ir.v3"
        issues.append(
            SemanticIssue(
                "extended_fields_uninterpreted",
                "Runtime effects are observed, but field domains, gate applicability, "
                "and complete subtype/report semantics are unresolved. Extended "
                "records are not represented as matching-equivalent rules.",
            )
        )
    return RuleSemantics(
        status=status,
        representation=representation,
        data=JSONObject(tuple(data_items)),
        evidence=evidence,
        profile="mpengine-1.443.903.0",
        issues=tuple(issues),
    )


def _parser_for(type_byte: int) -> Callable[[bytes], FopPayload]:
    def parser(payload: bytes) -> FopPayload:
        return parse_fop(payload, type_byte=type_byte)

    return parser


FOP_SPECS = tuple(
    FamilySpec(
        type_byte,
        name,
        _parser_for(type_byte),
        render_fop,
        semantic_exporter=export_fop_semantics,
    )
    for type_byte, name in FOP_TYPES.items()
)
