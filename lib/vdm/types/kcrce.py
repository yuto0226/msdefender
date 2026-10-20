"""Parser and concise renderer for KCRCE (0x80) payloads."""

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
from ..recid import RecIdTail, parse_recid_tail

KCRCE_TYPE: Final = 0x80
BASE_SIZE: Final = 16
UNRESOLVED_FLAGS_MASK: Final = 0x30000000
REQUIRE_FASTCRC_WHEN_PROVIDER_KEY_MISSING: Final = 0x40000000
SUPPRESS_WEAK_FASTCRC_FALLBACK: Final = 0x80000000


@dataclass(frozen=True, slots=True)
class KcrcePayload:
    raw: bytes
    fastcrc: int
    crc1: int
    crc2: int
    length_flags: int
    hash_length: int
    callback_relative_offset: int
    unresolved_flags: int
    require_fastcrc_when_provider_key_missing: bool
    suppress_weak_fastcrc_fallback: bool
    recid_tail: RecIdTail | None


def parse_kcrce(payload: bytes) -> KcrcePayload:
    """Parse the fixed KCRCE wire prefix and an optional shared RecID tail."""
    if len(payload) < BASE_SIZE:
        raise ValueError(
            f"truncated KCRCE header: need {BASE_SIZE} bytes, have {len(payload)}"
        )

    fastcrc = int.from_bytes(payload[0:4], "little")
    crc1 = int.from_bytes(payload[4:8], "little")
    crc2 = int.from_bytes(payload[8:12], "little")
    length_flags = int.from_bytes(payload[12:16], "little")
    return KcrcePayload(
        raw=payload,
        fastcrc=fastcrc,
        crc1=crc1,
        crc2=crc2,
        length_flags=length_flags,
        hash_length=length_flags & 0xFFFF,
        callback_relative_offset=(length_flags >> 16) & 0xFFF,
        unresolved_flags=length_flags & UNRESOLVED_FLAGS_MASK,
        require_fastcrc_when_provider_key_missing=bool(
            length_flags & REQUIRE_FASTCRC_WHEN_PROVIDER_KEY_MISSING
        ),
        suppress_weak_fastcrc_fallback=bool(
            length_flags & SUPPRESS_WEAK_FASTCRC_FALLBACK
        ),
        recid_tail=parse_recid_tail(payload[BASE_SIZE:]),
    )


def _printable_preview(data: bytes) -> str | None:
    try:
        preview = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return preview if preview and all(char.isprintable() for char in preview) else None


def _format_flags(parsed: KcrcePayload) -> str:
    states = []
    if parsed.require_fastcrc_when_provider_key_missing:
        states.append("require_fastcrc_when_provider_key_missing")
    if parsed.suppress_weak_fastcrc_fallback:
        states.append("suppress_weak_fastcrc_fallback")
    if parsed.unresolved_flags:
        states.append(f"unresolved=0x{parsed.unresolved_flags:08x}")
    if not states:
        return f"none (0x{parsed.length_flags:08x})"
    return f"{', '.join(states)} (0x{parsed.length_flags:08x})"


def render_kcrce(parsed: KcrcePayload) -> FormatResult:
    """Render confirmed matching inputs while keeping callback scope cautious."""
    sections = [
        DisplaySection(
            "Match Parameters",
            rows=(
                ("callback_domain", "scanner-supplied; not encoded in this record"),
                ("hash_length", f"{parsed.hash_length} B"),
                (
                    "callback_relative_offset",
                    f"{parsed.callback_relative_offset} B",
                ),
                ("flags", _format_flags(parsed)),
            ),
        ),
        DisplaySection(
            "CRC Fingerprints",
            rows=(
                ("fastcrc", f"0x{parsed.fastcrc:08x}"),
                ("crc1", f"0x{parsed.crc1:08x}"),
                ("crc2", f"0x{parsed.crc2:08x}"),
            ),
        ),
    ]

    if parsed.recid_tail is not None:
        tail = parsed.recid_tail
        alias_rows = [
            ("name_length_limit", f"{tail.length_limit} B"),
            ("effective_name_length", f"{len(tail.object_raw)} B"),
        ]
        if tail.has_object:
            preview = _printable_preview(tail.object_raw)
            if preview is not None:
                alias_rows.append(("name_preview", preview))
        alias_rows.extend(
            (
                ("attribute", str(tail.object_raw.startswith(b"!#")).lower()),
                ("trailing_length", f"{len(tail.trailing_raw)} B"),
            )
        )
        sections.append(DisplaySection("Threat Alias", rows=tuple(alias_rows)))

    return FormatResult(sections=tuple(sections))


def _raw_span(offset: int, length: int) -> JSONObject:
    return JSONObject((("offset", offset), ("length", length)))


def _raw_frame(kind: str, offset: int, raw: bytes) -> JSONObject:
    return JSONObject(
        (
            ("kind", kind),
            ("raw_span", _raw_span(offset, len(raw))),
            ("raw_hex", raw.hex()),
        )
    )


def export_kcrce_semantics(parsed: KcrcePayload) -> RuleSemantics:
    """Export the confirmed KCRCE comparison pipeline, not a final verdict."""
    tail = parsed.recid_tail
    tail_raw = b"" if tail is None else tail.raw
    framing = JSONArray(
        (
            _raw_frame("fastcrc", 0, parsed.raw[0:4]),
            _raw_frame("crc1", 4, parsed.raw[4:8]),
            _raw_frame("crc2", 8, parsed.raw[8:12]),
            _raw_frame("length_flags", 12, parsed.raw[12:16]),
            _raw_frame("recid_tail", BASE_SIZE, tail_raw),
        )
    )
    issues = [
        SemanticIssue(
            "callback_family_not_encoded",
            "The scanner supplies the callback family that interprets the packed "
            "range; the record does not identify that family.",
        ),
        SemanticIssue(
            "outer_verdict_unknown",
            "A KCRCE lookup result does not by itself define the final scan report.",
        ),
    ]
    unsupported = bool(parsed.unresolved_flags)
    if parsed.unresolved_flags:
        issues.append(
            SemanticIssue(
                "unresolved_flags_present",
                "Unresolved length_flags bits are retained without assigning behavior.",
                (("mask", parsed.unresolved_flags),),
            )
        )
    if tail is not None:
        if tail.length_limit > len(tail.raw) - 1:
            unsupported = True
            issues.append(
                SemanticIssue(
                    "recid_tail_truncated",
                    "The RecID tail is shorter than its declared bounded length.",
                    (
                        ("declared_length", tail.length_limit),
                        ("available_length", len(tail.raw) - 1),
                    ),
                )
            )
        if tail.trailing_raw:
            unsupported = True
            issues.append(
                SemanticIssue(
                    "recid_tail_trailing_bytes_uninterpreted",
                    "Bytes after the bounded RecID object are retained "
                    "without semantics.",
                    (("length", len(tail.trailing_raw)),),
                )
            )

    return RuleSemantics(
        status="unsupported" if unsupported else "confirmed_subset",
        representation="kcrce.match_pipeline.ir.v1",
        data=JSONObject(
            (
                ("type", "kcrce_match_pipeline"),
                ("raw_hex", parsed.raw.hex()),
                ("framing", framing),
                (
                    "matching_pipeline",
                    JSONArray(
                        (
                            JSONObject(
                                (
                                    ("stage", 0),
                                    ("field", "crc1"),
                                    ("expected", parsed.crc1),
                                    ("source", "callback_mode_1"),
                                    ("comparison", "exact"),
                                    ("index_role", "primary_equal_range"),
                                )
                            ),
                            JSONObject(
                                (
                                    ("stage", 1),
                                    ("field", "fastcrc"),
                                    ("expected", parsed.fastcrc),
                                    ("source", "provider_key_or_callback_mode_0"),
                                    (
                                        "comparison",
                                        "exact_if_provider_key_or_flag_0x40000000",
                                    ),
                                )
                            ),
                            JSONObject(
                                (
                                    ("stage", 2),
                                    ("field", "crc2"),
                                    ("expected", parsed.crc2),
                                    ("source", "callback_mode_2"),
                                    ("comparison", "exact"),
                                )
                            ),
                        )
                    ),
                ),
                (
                    "callback",
                    JSONObject(
                        (
                            ("family_source", "scanner_supplied"),
                            ("family_encoded_in_record", False),
                            ("range_interpretation", "callback_specific"),
                        )
                    ),
                ),
                (
                    "packed_range",
                    JSONObject(
                        (
                            ("raw_low28", parsed.length_flags & 0x0FFFFFFF),
                            ("low16", parsed.hash_length),
                            ("bits16_27", parsed.callback_relative_offset),
                        )
                    ),
                ),
                (
                    "flags",
                    JSONObject(
                        (
                            ("raw", parsed.length_flags),
                            ("unresolved_mask", parsed.unresolved_flags),
                            (
                                "require_fastcrc_when_provider_key_missing",
                                parsed.require_fastcrc_when_provider_key_missing,
                            ),
                            (
                                "suppress_weak_fastcrc_fallback",
                                parsed.suppress_weak_fastcrc_fallback,
                            ),
                        )
                    ),
                ),
                (
                    "crc2_mismatch_fallback",
                    JSONObject(
                        (
                            ("enabled_when_flag_0x80000000_clear", True),
                            ("requires_fastcrc_exact", True),
                            ("attribute_records_excluded", True),
                            ("result_policy", "not_represented"),
                        )
                    ),
                ),
                ("recid_tail_raw_hex", tail_raw.hex()),
            )
        ),
        evidence=(
            "mpengine 1.443.903.0 KCRCE RecordPush, CompareValues, and Lookup data flow",
        ),
        profile="mpengine-1.443.903.0",
        issues=tuple(issues),
    )


SPEC = FamilySpec(
    KCRCE_TYPE,
    "KCRCE",
    parse_kcrce,
    render_kcrce,
    semantic_exporter=export_kcrce_semantics,
)
