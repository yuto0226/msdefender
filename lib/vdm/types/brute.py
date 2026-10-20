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
    """Export portable raw BM IR while withholding an engine verdict claim."""
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
        )
    )
    data = JSONObject(pattern_data.items + (("outer", outer),))
    return RuleSemantics(
        status="observed_only",
        representation="bm.pattern.ir.v1",
        data=data,
        evidence=("BM wire framing and decoded fields for mpengine 1.443.903.0",),
        profile=f"mpengine-{parsed.pattern.profile}",
        issues=(
            SemanticIssue(
                "outer_verdict_unknown",
                "BRUTE direction and metadata are retained without assigning "
                "verdict semantics.",
                (("direction_raw", parsed.direction_raw),),
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
