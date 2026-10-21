"""Typed parser for the standalone 0x95 PEBMPAT record."""

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

_PREVIEW = 64
_TEXT_PREVIEW = 512


@dataclass(frozen=True, slots=True)
class PEBMPat:
    """Lossless PEBMPAT fields and the receiver's BM insertion outcome."""

    raw: bytes
    flags: int
    name: bytes
    pattern_raw: bytes
    pattern: BmPattern | None
    receiver_result: str


def parse_pebmpat(payload: bytes) -> PEBMPat:
    """Parse exact PEBMPAT framing and validate its BM program."""
    if len(payload) < 4:
        raise ValueError("truncated PEBMPAT header")
    flags = payload[0]
    name_len = payload[1]
    pattern_len = int.from_bytes(payload[2:4], "little")
    expected = 4 + name_len + pattern_len
    if len(payload) != expected:
        raise ValueError("PEBMPAT size does not match its length fields")
    name_end = 4 + name_len
    name = payload[4:name_end]
    pattern_raw = payload[name_end:]
    pattern = None
    if flags & ~1:
        receiver_result = "no_op.unsupported_flags"
    elif len(payload) <= 4:
        receiver_result = "no_op.payload_length_le_4"
    else:
        sentinel = pattern_raw.find(b"\x90", 0, min(8, len(pattern_raw)))
        if 0 <= sentinel < 4:
            receiver_result = "error.first_90_before_offset_4"
        else:
            try:
                pattern = validate_bm_framing(pattern_raw, label="PEBMPAT")
            except ValueError as exc:
                receiver_result = f"error.{exc}"
            else:
                receiver_result = "added_candidate"
    return PEBMPat(payload, flags, name, pattern_raw, pattern, receiver_result)


def export_pebmpat_semantics(parsed: PEBMPat) -> RuleSemantics:
    """Export raw PEBMPAT framing and a non-authoritative BM decoder view."""
    name_start = 4
    pattern_start = name_start + len(parsed.name)
    framing = JSONArray(
        (
            JSONObject(
                (
                    ("kind", "flags"),
                    ("raw_span", JSONObject((("offset", 0), ("length", 1)))),
                    ("raw_hex", parsed.raw[:1].hex()),
                )
            ),
            JSONObject(
                (
                    ("kind", "name_length"),
                    ("raw_span", JSONObject((("offset", 1), ("length", 1)))),
                    ("raw_hex", parsed.raw[1:2].hex()),
                )
            ),
            JSONObject(
                (
                    ("kind", "pattern_length"),
                    ("raw_span", JSONObject((("offset", 2), ("length", 2)))),
                    ("raw_hex", parsed.raw[2:4].hex()),
                )
            ),
            JSONObject(
                (
                    ("kind", "name"),
                    (
                        "raw_span",
                        JSONObject(
                            (("offset", name_start), ("length", len(parsed.name)))
                        ),
                    ),
                    ("raw_hex", parsed.name.hex()),
                )
            ),
            JSONObject(
                (
                    ("kind", "pattern"),
                    (
                        "raw_span",
                        JSONObject(
                            (
                                ("offset", pattern_start),
                                ("length", len(parsed.pattern_raw)),
                            )
                        ),
                    ),
                    ("raw_hex", parsed.pattern_raw.hex()),
                )
            ),
        )
    )
    issues = [
        SemanticIssue(
            "runtime_region_unknown",
            "ScanContext supplies guest VAs to PEEmuMapper; static flow does not identify "
            "the mapped subject's backing file bytes or file/RVA translation.",
        ),
        SemanticIssue(
            "final_detection_policy_unknown",
            "A BM candidate still requires runtime matching and validation; final policy is not modeled.",
        ),
    ]
    pattern_data = None
    if parsed.pattern is not None:
        pattern_data, pattern_issues = serialize_bm_pattern(parsed.pattern)
        issues.extend(pattern_issues)
        issues.append(
            SemanticIssue(
                "bm_operand_semantics_incomplete",
                "PEMapper window flow is documented; BM opcode operands and reader-state effects remain only partially modeled.",
            )
        )
    else:
        if parsed.receiver_result.startswith("no_op."):
            issues.append(
                SemanticIssue(
                    "receiver_no_op",
                    "The receiver accepts this record without adding a pattern candidate; raw bytes are retained.",
                    (("receiver_result", parsed.receiver_result),),
                )
            )
        else:
            issues.append(
                SemanticIssue(
                    "receiver_rejected",
                    "The receiver rejects this record and does not add a pattern candidate; raw bytes are retained.",
                    (("receiver_result", parsed.receiver_result),),
                )
            )
    data = JSONObject(
        (
            ("raw_hex", parsed.raw.hex()),
            ("framing", framing),
            ("flags", parsed.flags),
            ("unknown_flag_bits", parsed.flags & ~1),
            ("name_raw_hex", parsed.name.hex()),
            ("pattern_length", len(parsed.pattern_raw)),
            ("pattern_raw_hex", parsed.pattern_raw.hex()),
            ("receiver_result", parsed.receiver_result),
            (
                "mapping_strategy",
                JSONObject(
                    (
                        (
                            "coordinate",
                            (
                                "mapper address argument from ScanEx passed to "
                                "PEEmuMapper::mmap / __mmap_ex"
                            ),
                        ),
                        ("primary_request_length", "prefix + 2048"),
                        ("primary_request_start", "mapper_address - prefix"),
                        ("bm_match_length_argument", 2048),
                        ("bm_match_start_argument", "mapped_pointer + prefix"),
                        (
                            "bm_start_argument_interpretation",
                            "mapped subject pointer plus requested prefix; backing file/RVA coordinate unknown",
                        ),
                        ("address_translation", None),
                        (
                            "address_translation_status",
                            (
                                "not recovered; BM_MAP_ALL is BM byte translation, "
                                "not a file/RVA mapping"
                            ),
                        ),
                        ("bm_byte_translation", "BM_MAP_ALL"),
                        (
                            "bm_match_flags",
                            "(2 * !trie_flags_bit1) | 1",
                        ),
                        ("match_offset_outputs_requested", False),
                        (
                            "fallback_requests",
                            "(scan_va, 2048), then (scan_va, 1); the fallback uses the mapped length",
                        ),
                        ("runtime_bytes_observed", False),
                        ("file_or_rva_translation", None),
                    )
                ),
            ),
            (
                "candidate_pipeline",
                JSONObject(
                    (
                        (
                            "matcher_stage",
                            "trie prefix candidate -> BMMatchPEMapper -> P-code validation",
                        ),
                        (
                            "post_bm_behavior",
                            (
                                "with SCAN_REPLY, ValidateSignatureWithPcode may "
                                "update recid/status; without it, a BM hit is returned "
                                "as a candidate entry"
                            ),
                        ),
                        (
                            "observed_status_routes",
                            JSONObject(
                                (
                                    ("3,6,8", "MpReportLowfiMatch"),
                                    ("10,11", "HipsManager::OnStreamDetection"),
                                    (
                                        "1,2",
                                        (
                                            "candidate-entry states when returned by "
                                            "P-code or when SCAN_REPLY is absent"
                                        ),
                                    ),
                                    (
                                        "0",
                                        "no report or candidate-entry branch in ScanEx",
                                    ),
                                )
                            ),
                        ),
                        (
                            "status_interpretation",
                            (
                                "ScanEx branch behavior only; status names and final "
                                "policy are not established"
                            ),
                        ),
                        ("pcode_context", "trie_flags_bit0 selects context 1 or 2"),
                        ("final_verdict", None),
                    )
                ),
            ),
            ("bm_pattern", pattern_data),
        )
    )
    return RuleSemantics(
        status=(
            "ignored" if parsed.receiver_result.startswith("no_op.") else "unsupported"
        ),
        representation="pebmpat.pattern.ir.v3",
        data=data,
        evidence=(
            (
                "PEBMPatScanner::AddNewPattern framing and BMGetPatternFlags "
                "validation for mpengine 1.443.903.0"
            ),
            "PEBMPatScanner::ScanEx @ 0x1803D5A5C",
            "BMMatchPEMapper @ 0x1803D5E44",
            "BMMatchEx2 @ 0x1800EC420",
            "ScanContext::GetChar @ 0x180250F0C",
            "PEEmuMapper::mmap @ 0x180251080",
            "__mmap_ex @ 0x180035ED0",
        ),
        profile="mpengine-1.443.903.0",
        issues=tuple(issues),
    )


def _preview(raw: bytes) -> str:
    return raw[:_PREVIEW].hex(" ") + (" ..." if len(raw) > _PREVIEW else "")


def render_pebmpat(parsed: PEBMPat) -> FormatResult:
    """Render bounded raw fields and a conservative BM/YARA-like candidate."""
    yara = render_bm_yara(parsed.pattern) if parsed.pattern is not None else None
    rows = [
        ("flags", f"0x{parsed.flags:02X}"),
        ("flags_bit0_raw", str(parsed.flags & 1)),
        ("name_length", str(len(parsed.name))),
        ("name_raw", _preview(parsed.name)),
        ("name_preview", repr(parsed.name[:_TEXT_PREVIEW])),
        ("pattern_length", str(len(parsed.pattern_raw))),
        ("pattern_preview", _preview(parsed.pattern_raw)),
        ("receiver_result", parsed.receiver_result),
        (
            "bm_validation",
            "available" if parsed.pattern is not None else "not_available",
        ),
        (
            "bm_issue",
            f"{parsed.pattern.issue.code}@{parsed.pattern.issue.offset}"
            if parsed.pattern is not None and parsed.pattern.issue
            else "none",
        ),
    ]
    if yara is not None:
        rows.append(("bm_consumed", str(parsed.pattern.consumed)))
        rows.append(("bm_remaining_length", str(len(parsed.pattern.remaining_raw))))
        rows.append(("yara_fidelity", yara.fidelity.value))
    if yara is not None and yara.body:
        rows.append(("yara_like_preview", yara.body[:_TEXT_PREVIEW]))
    if yara is not None and yara.requirements:
        rows.append(("yara_requirements", "; ".join(yara.requirements)))
    rows.extend(
        (f"pattern_issue[{index}]", f"{issue.code}@{issue.offset}")
        for index, issue in enumerate(yara.diagnostics[:16] if yara else ())
    )
    if yara is not None and len(yara.diagnostics) > 16:
        rows.append(("remaining_issues", str(len(yara.diagnostics) - 16)))
    if yara is not None and yara.printable_preview:
        rows.append(("printable_preview", yara.printable_preview[:_TEXT_PREVIEW]))
    return FormatResult(sections=(DisplaySection("PEBMPAT", rows=tuple(rows)),))


SPEC = FamilySpec(
    0x95,
    "PEBMPAT",
    parse_pebmpat,
    render_pebmpat,
    semantic_exporter=export_pebmpat_semantics,
)
