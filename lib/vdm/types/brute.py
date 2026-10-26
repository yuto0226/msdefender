"""Lossless model for the standalone 0xD0 BRUTE record."""

from dataclasses import dataclass

from ..bm import BmPattern, validate_bm_framing
from ..bm_semantic import serialize_bm_pattern
from ..bm_yara import render_bm_yara
from ..core import (
    DisplaySection,
    FamilySpec,
    FormatResult,
    JSONArray,
    JSONObject,
    RuleSemantics,
    SemanticIssue,
)
from ._semantic_claims import scoped_claim

_PREVIEW = 64
_TEXT_PREVIEW = 512


@dataclass(frozen=True, slots=True)
class BrutePayload:
    raw: bytes
    name_bytes: bytes
    script_type_flags: int
    direction_raw: int
    position_raw: int
    body: bytes
    pattern: BmPattern
    trailing: bytes

    @property
    def script_type_raw(self) -> int:
        return self.script_type_flags & 0x7F

    @property
    def lowfi(self) -> bool:
        return bool(self.script_type_flags & 0x80)

    @property
    def body_len(self) -> int:
        return len(self.body)


def _take(payload: bytes, offset: int, size: int, label: str) -> tuple[bytes, int]:
    end = offset + size
    if end > len(payload):
        raise ValueError(f"truncated BRUTE {label}: need {size} bytes")
    return payload[offset:end], end


def _u32(payload: bytes, offset: int, label: str) -> tuple[int, int]:
    raw, end = _take(payload, offset, 4, label)
    return int.from_bytes(raw, "little"), end


def parse_brute(payload: bytes) -> BrutePayload:
    """Parse 0xD0 BRUTE, checking all BM framing and preserving outer tail."""
    name_len, cursor = _take(payload, 0, 1, "name length")
    if name_len[0] >= 64:
        raise ValueError("BRUTE name length must be less than 64")
    name, cursor = _take(payload, cursor, name_len[0], "name")
    flags, cursor = _take(payload, cursor, 1, "script type")
    direction, cursor = _take(payload, cursor, 1, "direction")
    position, cursor = _u32(payload, cursor, "position")
    if position > 0xFFFF and position != 0xFFFFFFFF:
        raise ValueError("invalid BRUTE position")
    length, cursor = _u32(payload, cursor, "body length")
    if not 1 <= length <= 0xFFFF:
        raise ValueError("BRUTE body length must be in 1..65535")
    body, cursor = _take(payload, cursor, length, "body")
    pattern = validate_bm_framing(body, label="BRUTE")
    return BrutePayload(
        payload,
        name,
        flags[0],
        direction[0],
        position,
        body,
        pattern,
        payload[cursor:],
    )


def _preview(raw: bytes) -> str:
    return raw[:_PREVIEW].hex(" ") + (" ..." if len(raw) > _PREVIEW else "")


def render_brute(parsed: BrutePayload) -> FormatResult:
    yara = render_bm_yara(parsed.pattern)
    rows = [
        ("name_bytes", _preview(parsed.name_bytes)),
        ("name_preview", repr(parsed.name_bytes)),
        ("script_type_flags", f"0x{parsed.script_type_flags:02X}"),
        ("script_type_raw", str(parsed.script_type_raw)),
        ("lowfi", str(parsed.lowfi)),
        ("direction_raw", f"0x{parsed.direction_raw:02X}"),
        ("position_raw", f"0x{parsed.position_raw:08X}"),
        ("body_length", str(parsed.body_len)),
        ("body_preview", _preview(parsed.body)),
        ("bm_consumed", str(parsed.pattern.consumed)),
        ("bm_remaining_length", str(len(parsed.pattern.remaining_raw))),
        ("bm_remaining_preview", _preview(parsed.pattern.remaining_raw)),
        (
            "bm_issue",
            f"{parsed.pattern.issue.code}@{parsed.pattern.issue.offset}"
            if parsed.pattern.issue
            else "none",
        ),
        ("yara_fidelity", yara.fidelity.value),
    ]
    if yara.body:
        rows.append(("yara_like_preview", yara.body[:_TEXT_PREVIEW]))
    if yara.requirements:
        rows.append(("yara_requirements", "; ".join(yara.requirements)))
    rows.extend(
        (f"pattern_issue[{index}]", f"{issue.code}@{issue.offset}")
        for index, issue in enumerate(yara.diagnostics[:16])
    )
    if len(yara.diagnostics) > 16:
        rows.append(("remaining_issues", str(len(yara.diagnostics) - 16)))
    if yara.printable_preview:
        rows.append(("printable_preview", yara.printable_preview[:_TEXT_PREVIEW]))
    rows.extend(
        (
            ("trailing_length", str(len(parsed.trailing))),
            ("trailing_preview", _preview(parsed.trailing)),
        )
    )
    return FormatResult(sections=(DisplaySection("BRUTE", rows=tuple(rows)),))


def export_brute_semantics(parsed: BrutePayload) -> RuleSemantics:
    """Export the confirmed BM candidate subset without claiming a verdict."""
    claim, claim_evidence = scoped_claim(
        "brute",
        "candidate_bm_subset",
        "runtime_consumer",
        "Registration and receiver state feed a candidate subset to the observed Boyer–Moore matcher and validator path.",
        "Search direction, reported position semantics, and final verdict are unknown.",
        "consumer",
        "init_brute @ 0x180AFD578; kcrce_pushBrute @ 0x1800FEE80; Kcrce_SearchBrute",
    )
    pattern_data, pattern_issues = serialize_bm_pattern(parsed.pattern)
    name_length = len(parsed.name_bytes)
    body_offset = 1 + name_length + 1 + 1 + 4 + 4
    body_end = body_offset + parsed.body_len
    framing_fields = (
        ("name_length", 0, 1),
        ("name", 1, name_length),
        ("script_type_flags", 1 + name_length, 1),
        ("direction", 2 + name_length, 1),
        ("position", 3 + name_length, 4),
        ("body_length", 7 + name_length, 4),
        ("body", body_offset, parsed.body_len),
        ("trailing", body_end, len(parsed.trailing)),
    )
    framing = JSONArray(
        tuple(
            JSONObject(
                (
                    ("kind", name),
                    ("raw_span", JSONObject((("offset", offset), ("length", length)))),
                    ("raw_hex", parsed.raw[offset : offset + length].hex()),
                )
            )
            for name, offset, length in framing_fields
        )
    )
    outer = JSONObject(
        (
            ("raw_hex", parsed.raw.hex()),
            ("framing", framing),
            ("name_length", name_length),
            ("name_raw_hex", parsed.name_bytes.hex()),
            ("script_type_flags", parsed.script_type_flags),
            ("script_type_raw", parsed.script_type_raw),
            ("lowfi", parsed.lowfi),
            ("direction_raw", parsed.direction_raw),
            ("position_raw", parsed.position_raw),
            ("body_length", parsed.body_len),
            ("trailing_raw_hex", parsed.trailing.hex()),
            (
                "runtime_matcher_context",
                JSONObject(
                    (
                        (
                            "registration",
                            "init_brute -> kcrce_pushBrute -> Kcrce_SearchBrute",
                        ),
                        ("match_function", "BMMatchEx2"),
                        ("subject_reader", "BMSBufferReader"),
                        ("subject_base_argument", "subject buffer base"),
                        ("subject_size_argument", "subject buffer size"),
                        (
                            "start_argument",
                            "subject base + KCRCE loop candidate offset",
                        ),
                        (
                            "remaining_size_argument",
                            "subject size - KCRCE loop candidate offset",
                        ),
                        ("pattern_argument", "KCRCE entry +0x00 BM object"),
                        ("pattern_size_argument", "KCRCE entry +0x12 body length"),
                        ("translation_symbol", "BM_MAP_ALL"),
                        (
                            "translation_semantics",
                            "caller-selected table; exact byte mapping not reconstructed",
                        ),
                        ("flags_argument", "KCRCE entry +0x16 runtime control flags"),
                        ("capture_output", "caller_supplied_match_end_slot"),
                        ("offsets_vector_supplied", False),
                        (
                            "candidate_passes",
                            JSONArray(
                                (
                                    JSONObject(
                                        (
                                            ("pass_flag", 1),
                                            ("subject_base", "reply + 0xC0"),
                                            (
                                                "direction_filter",
                                                "skip raw direction 2",
                                            ),
                                            (
                                                "other_direction_values",
                                                "pass this filter",
                                            ),
                                            (
                                                "position_gate",
                                                "raw 0xFFFFFFFF bypasses fixed-position gate",
                                            ),
                                        )
                                    ),
                                    JSONObject(
                                        (
                                            ("pass_flag", 0),
                                            (
                                                "subject_base",
                                                "reply + 0x20C0 - window_size",
                                            ),
                                            (
                                                "direction_filter",
                                                "skip raw direction 1",
                                            ),
                                            (
                                                "other_direction_values",
                                                "pass this filter",
                                            ),
                                            (
                                                "position_gate",
                                                "fixed-position match must end at subject window end",
                                            ),
                                        )
                                    ),
                                )
                            ),
                        ),
                        (
                            "position_runtime_use",
                            JSONObject(
                                (
                                    (
                                        "storage",
                                        "wire u32 is accepted only in 0..0xFFFF or as 0xFFFFFFFF, then stored as u16",
                                    ),
                                    (
                                        "sentinel",
                                        "0xFFFFFFFF becomes stored 0xFFFF and bypasses the fixed-position gates",
                                    ),
                                    (
                                        "non_sentinel",
                                        "gates first-pass state and requires second-pass match_end == window_end",
                                    ),
                                    (
                                        "literal_offset_use",
                                        "not observed in Kcrce_SearchBrute",
                                    ),
                                )
                            ),
                        ),
                        (
                            "capture_observation",
                            (
                                "BMMatchEx2 writes absolute match_end; pass_flag 0 "
                                "with non-sentinel position compares it to "
                                "subject_base + subject_size"
                            ),
                        ),
                        (
                            "validator_result_observation",
                            (
                                "result 0 skips candidate; 1/2 enter ordinary result "
                                "path; 3/6 call MpReportLowfiMatch with "
                                "telemetry_only=false and lowfi_mode=(result==6); "
                                "8 calls it with telemetry_only=true; 10/11 call "
                                "HipsManager::OnStreamDetection; result 1 can "
                                "aggregate attributes and all ordinary results are "
                                "subject to continuation/delay/best-match policy"
                            ),
                        ),
                        (
                            "unresolved",
                            JSONArray(
                                (
                                    "business names for raw direction values and the exact relation between the two reply windows and file/stream direction",
                                    "business meaning of the position mode and its first-pass state gate",
                                    "complete mapping from validator result and SCAN_REPLY policy to externally visible threat verdict",
                                )
                            ),
                        ),
                    )
                ),
            ),
        )
    )
    data = JSONObject(pattern_data.items + (("outer", outer),))
    return RuleSemantics(
        status="confirmed_subset",
        representation="brute.bm_candidate.ir.v3",
        data=data,
        evidence=(
            "BM wire framing and decoded fields for mpengine 1.443.903.0",
            "init_brute @ 0x180AFD578 and kcrce_pushBrute @ 0x1800FEE80",
            "Kcrce_SearchBrute @ 0x180131A38 calls BMMatchEx2 @ 0x1800EC420",
            "Kcrce_SearchBrute applies the documented two-pass filters and match-end gate",
            "BM candidate success is followed by ValidateSignatureWithPcode @ 0x180135494",
            "Kcrce_SearchBrute documents validator result routing without a final-verdict mapping",
        ),
        profile=f"mpengine-{parsed.pattern.profile}",
        claims=(claim,),
        claim_evidence=(claim_evidence,),
        issues=(
            SemanticIssue(
                "outer_verdict_unknown",
                "This export confirms only the modeled BM candidate subset. Raw "
                "direction values have no domain names here, position's business "
                "meaning remains unresolved despite its confirmed gates, and validator/report "
                "branches do not establish an externally visible final verdict.",
                (
                    ("direction_raw", parsed.direction_raw),
                    ("position_raw", parsed.position_raw),
                ),
            ),
            *pattern_issues,
        ),
    )


SPEC = FamilySpec(
    0xD0,
    "BRUTE",
    parse_brute,
    render_brute,
    semantic_exporter=export_brute_semantics,
)
