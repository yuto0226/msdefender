"""Typed parser for the standalone 0x95 PEBMPAT record."""

from dataclasses import dataclass

from ..bm import BmPattern, validate_bm_framing
from ..bm_yara import render_bm_yara
from ..core import DisplaySection, FamilySpec, FormatResult

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
    if flags & ~1:
        raise ValueError("PEBMPAT flags contain unsupported bits")
    name_len = payload[1]
    pattern_len = int.from_bytes(payload[2:4], "little")
    expected = 4 + name_len + pattern_len
    if len(payload) != expected:
        raise ValueError("PEBMPAT size does not match its length fields")
    name_end = 4 + name_len
    name = payload[4:name_end]
    pattern_raw = payload[name_end:]
    pattern = None
    if pattern_len <= 4:
        receiver_result = "no_op.pattern_length_le_4"
    else:
        sentinel = pattern_raw.find(b"\x90", 0, min(8, len(pattern_raw)))
        if 0 <= sentinel < 4:
            receiver_result = "no_op.first_90_before_offset_4"
        else:
            try:
                pattern = validate_bm_framing(pattern_raw, label="PEBMPAT")
            except ValueError as exc:
                receiver_result = f"no_op.{exc}"
            else:
                receiver_result = "added_candidate"
    return PEBMPat(payload, flags, name, pattern_raw, pattern, receiver_result)


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


SPEC = FamilySpec(0x95, "PEBMPAT", parse_pebmpat, render_pebmpat)
