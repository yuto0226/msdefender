"""Lossless NSCRIPT wire models for the 1.443.903.0 receiver layouts."""

from dataclasses import dataclass

from ..bm import (
    BmPattern,
    decode_bm_pattern,
    render_byte_fragments,
    validate_bm_framing,
)
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

_BYTE_PREVIEW = 64
_PAIR_PREVIEW = 16
_TEXT_PREVIEW = 512


@dataclass(frozen=True, slots=True)
class NScriptPayload:
    raw: bytes
    name_bytes: bytes
    primary: tuple[int, ...]
    mode: int
    anchor_crc32: int | None
    normalized_length: int | None
    secondary: tuple[int, ...] | None
    match_flags_raw: int | None
    trailing: bytes

    @property
    def count(self) -> int:
        return len(self.primary)

    @property
    def pairs(self) -> tuple[tuple[int, int], ...]:
        return tuple(
            zip(self.primary, self.secondary or (0,) * self.count, strict=True)
        )

    @property
    def match_flags(self) -> int:
        return (self.match_flags_raw or 0) & 0xFF


@dataclass(frozen=True, slots=True)
class NScriptSPPayload:
    raw: bytes
    name_bytes: bytes
    anchor_crc32: int
    mode_flags: int
    full_crc32: int
    normalized_length: int
    trailing: bytes

    @property
    def mode(self) -> int:
        return self.mode_flags & 0x7F

    @property
    def lowfi(self) -> bool:
        return bool(self.mode_flags & 0x80)


@dataclass(frozen=True, slots=True)
class NScriptBrutePayload:
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
    def runtime_script_type(self) -> int:
        return self.script_type_raw - 1 if self.script_type_raw else 6

    @property
    def lowfi(self) -> bool:
        return bool(self.script_type_flags & 0x80)

    @property
    def body_len(self) -> int:
        return len(self.body)

    @property
    def runtime_consumer(self) -> str | None:
        if self.runtime_script_type == 6:
            return "SearchBruteWorker -> BMMatchEx2"
        return None


@dataclass(frozen=True, slots=True)
class NScriptCurePayload:
    raw: bytes
    kind: int
    name_crc32: int
    span_or_offset: int | None
    data: bytes
    pattern: BmPattern | None
    trailing: bytes

    @property
    def data_len(self) -> int:
        return len(self.data)

    @property
    def accepted_by_receiver(self) -> bool:
        """Whether the receiver appends this entry rather than success-and-ignore."""
        if self.kind not in (1, 2):
            return True
        packed = ((self.span_or_offset << 16) | self.data_len) & 0xFFFFFFFF
        return packed >> 16 == self.span_or_offset


def _take(payload: bytes, offset: int, size: int, label: str) -> tuple[bytes, int]:
    end = offset + size
    if end > len(payload):
        raise ValueError(f"truncated NSCRIPT {label}: need {size} bytes")
    return payload[offset:end], end


def _name(payload: bytes) -> tuple[bytes, int]:
    length, offset = _take(payload, 0, 1, "name length")
    if length[0] >= 64:
        raise ValueError("NSCRIPT name length must be less than 64")
    return _take(payload, offset, length[0], "name")


def _u32(payload: bytes, offset: int, label: str) -> tuple[int, int]:
    raw, end = _take(payload, offset, 4, label)
    return int.from_bytes(raw, "little"), end


def _words(raw: bytes) -> tuple[int, ...]:
    return tuple(
        int.from_bytes(raw[i : i + 4], "little") for i in range(0, len(raw), 4)
    )


def parse_nscript(payload: bytes) -> NScriptPayload:
    """Parse NORMAL; optional secondary values are consumed as a whole group."""
    name, cursor = _name(payload)
    count_raw, cursor = _take(payload, cursor, 1, "count")
    count = count_raw[0]
    if not count:
        raise ValueError("NSCRIPT count must be nonzero")
    primary_raw, cursor = _take(payload, cursor, count * 4, "primary")
    mode_raw, cursor = _take(payload, cursor, 1, "mode")
    mode = mode_raw[0]
    anchor = length = None
    if mode:
        anchor, cursor = _u32(payload, cursor, "anchor CRC32")
        length, cursor = _u32(payload, cursor, "normalized length")
        if length <= 32:
            raise ValueError("NSCRIPT nonzero-mode normalized length must exceed 32")
    secondary = None
    if len(payload) - cursor >= count * 4:
        secondary_raw, cursor = _take(payload, cursor, count * 4, "secondary")
        secondary = _words(secondary_raw)
    flags = None
    if len(payload) - cursor >= 4:
        flags, cursor = _u32(payload, cursor, "match flags")
    return NScriptPayload(
        payload,
        name,
        _words(primary_raw),
        mode,
        anchor,
        length,
        secondary,
        flags,
        payload[cursor:],
    )


def parse_nscript_sp(payload: bytes) -> NScriptSPPayload:
    """Parse the fixed SP prefix and preserve receiver-accepted trailing data."""
    name, cursor = _name(payload)
    anchor, cursor = _u32(payload, cursor, "SP anchor CRC32")
    flags, cursor = _take(payload, cursor, 1, "SP mode flags")
    full, cursor = _u32(payload, cursor, "SP full CRC32")
    length, cursor = _u32(payload, cursor, "SP normalized length")
    return NScriptSPPayload(
        payload, name, anchor, flags[0], full, length, payload[cursor:]
    )


def _validate_brute_body(body: bytes) -> BmPattern:
    """Validate all NSCRIPT BRUTE segments and retain the first BM view."""
    return validate_bm_framing(body, label="NSCRIPT BRUTE")


def parse_nscript_brute(payload: bytes) -> NScriptBrutePayload:
    """Validate every BM instruction without treating internal END as outer EOF."""
    name, cursor = _name(payload)
    flags, cursor = _take(payload, cursor, 1, "BRUTE script type")
    direction, cursor = _take(payload, cursor, 1, "BRUTE direction")
    position, cursor = _u32(payload, cursor, "BRUTE position")
    if position > 0xFFFF and position != 0xFFFFFFFF:
        raise ValueError("invalid NSCRIPT BRUTE position")
    length, cursor = _u32(payload, cursor, "BRUTE body length")
    if not 1 <= length <= 0xFFFF:
        raise ValueError("NSCRIPT BRUTE body length must be in 1..65535")
    body, cursor = _take(payload, cursor, length, "BRUTE body")
    pattern = _validate_brute_body(body)
    return NScriptBrutePayload(
        payload,
        name,
        flags[0],
        direction[0],
        position,
        body,
        pattern,
        payload[cursor:],
    )


def parse_nscript_cure(payload: bytes) -> NScriptCurePayload:
    """Parse CURE data, preserving ignored entries and all trailing bytes."""
    kind_raw, cursor = _take(payload, 0, 1, "CURE kind")
    kind = kind_raw[0]
    crc, cursor = _u32(payload, cursor, "CURE name CRC32")
    span = None
    data = b""
    if kind not in (3, 4):
        span, cursor = _u32(payload, cursor, "CURE span/offset")
        length, cursor = _u32(payload, cursor, "CURE data length")
        if not length:
            raise ValueError("NSCRIPT CURE data length must be nonzero")
        data, cursor = _take(payload, cursor, length, "CURE data")
    pattern = decode_bm_pattern(data) if kind in (1, 2) else None
    return NScriptCurePayload(payload, kind, crc, span, data, pattern, payload[cursor:])


def _preview(raw: bytes) -> str:
    return raw[:_BYTE_PREVIEW].hex(" ") + (" ..." if len(raw) > _BYTE_PREVIEW else "")


def _text_preview(value: str) -> str:
    return value[:_TEXT_PREVIEW] + (" ..." if len(value) > _TEXT_PREVIEW else "")


def _trailing(raw: bytes) -> tuple[tuple[str, str], ...]:
    return (("trailing_length", str(len(raw))), ("trailing_preview", _preview(raw)))


def _name_fields(name: bytes) -> tuple[tuple[str, str], ...]:
    return (("name_bytes", _preview(name)), ("name_preview", repr(name)))


def _pattern_section(pattern: BmPattern, *, lowcase: bool = False) -> DisplaySection:
    rendered = render_bm_yara(pattern)
    rows = [
        ("body_length", str(len(pattern.raw))),
        ("body_preview", _preview(pattern.raw)),
        ("bm_consumed", str(pattern.consumed)),
        ("bm_remaining_length", str(len(pattern.remaining_raw))),
        ("bm_remaining_preview", _preview(pattern.remaining_raw)),
        (
            "bm_issue",
            f"{pattern.issue.code}@{pattern.issue.offset}" if pattern.issue else "none",
        ),
        (
            "yara_fidelity",
            "unsupported: BM_MAP_LOWCASE context"
            if lowcase
            else rendered.fidelity.value,
        ),
    ]
    if rendered.body and not lowcase:
        rows.append(("yara_like_preview", _text_preview(rendered.body)))
    if lowcase:
        rows.append(
            ("pattern_preview", render_byte_fragments(pattern.raw[:_BYTE_PREVIEW]))
        )
        rows.append(("matching_context", "BM_MAP_LOWCASE; no YARA equivalence claimed"))
    if rendered.requirements:
        rows.append(("yara_requirements", "; ".join(rendered.requirements)))
    rows.extend(
        (f"pattern_issue[{i}]", f"{issue.code}@{issue.offset}")
        for i, issue in enumerate(rendered.diagnostics[:_PAIR_PREVIEW])
    )
    if len(rendered.diagnostics) > _PAIR_PREVIEW:
        rows.append(
            ("remaining_issues", str(len(rendered.diagnostics) - _PAIR_PREVIEW))
        )
    if rendered.printable_preview:
        rows.append(("printable_preview", _text_preview(rendered.printable_preview)))
    return DisplaySection("BM pattern", rows=tuple(rows))


def render_nscript(parsed: NScriptPayload) -> FormatResult:
    rows = list(_name_fields(parsed.name_bytes))
    rows.extend(
        (
            ("count", str(parsed.count)),
            ("mode", str(parsed.mode)),
            (
                "secondary",
                "present"
                if parsed.secondary is not None
                else "absent (effective zero)",
            ),
            (
                "match_flags_raw",
                f"0x{parsed.match_flags_raw:08X}"
                if parsed.match_flags_raw is not None
                else "absent",
            ),
            ("match_flags_low_byte", f"0x{parsed.match_flags:02X}"),
        )
    )
    if parsed.mode:
        rows.extend(
            (
                ("anchor_crc32", f"0x{parsed.anchor_crc32:08X}"),
                ("normalized_length", str(parsed.normalized_length)),
            )
        )
    rows.extend(_trailing(parsed.trailing))
    pairs = tuple(
        (f"pair[{i}]", f"0x{a:08X}, 0x{b:08X}")
        for i, (a, b) in enumerate(parsed.pairs[:_PAIR_PREVIEW])
    )
    if parsed.count > _PAIR_PREVIEW:
        pairs += (("remaining_pairs", str(parsed.count - _PAIR_PREVIEW)),)
    return FormatResult(
        sections=(
            DisplaySection("NSCRIPT", rows=tuple(rows)),
            DisplaySection("Pairs", rows=pairs),
        )
    )


def render_nscript_sp(parsed: NScriptSPPayload) -> FormatResult:
    return FormatResult(
        sections=(
            DisplaySection(
                "NSCRIPT_SP",
                rows=(
                    *_name_fields(parsed.name_bytes),
                    ("anchor_crc32", f"0x{parsed.anchor_crc32:08X}"),
                    ("mode_flags", f"0x{parsed.mode_flags:02X}"),
                    ("mode", str(parsed.mode)),
                    ("lowfi", str(parsed.lowfi)),
                    ("full_crc32", f"0x{parsed.full_crc32:08X}"),
                    ("normalized_length", str(parsed.normalized_length)),
                    *_trailing(parsed.trailing),
                ),
            ),
        )
    )


def render_nscript_brute(parsed: NScriptBrutePayload) -> FormatResult:
    return FormatResult(
        sections=(
            DisplaySection(
                "NSCRIPT_BRUTE",
                rows=(
                    *_name_fields(parsed.name_bytes),
                    ("script_type_flags", f"0x{parsed.script_type_flags:02X}"),
                    ("script_type_raw", str(parsed.script_type_raw)),
                    ("runtime_script_type", str(parsed.runtime_script_type)),
                    (
                        "runtime_consumer",
                        parsed.runtime_consumer or "unknown",
                    ),
                    (
                        "runtime_gate",
                        "UFS base plugin id 6"
                        if parsed.runtime_consumer is not None
                        else "unknown",
                    ),
                    ("lowfi", str(parsed.lowfi)),
                    ("direction_raw", f"0x{parsed.direction_raw:02X}"),
                    ("position_raw", f"0x{parsed.position_raw:08X}"),
                    *_trailing(parsed.trailing),
                ),
            ),
            _pattern_section(parsed.pattern),
        )
    )


def export_nscript_brute_semantics(parsed: NScriptBrutePayload) -> RuleSemantics:
    """Export lossless BM IR without assigning NSCRIPT verdict semantics."""
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
            ("runtime_script_type", parsed.runtime_script_type),
            ("lowfi", parsed.lowfi),
            ("direction_raw", parsed.direction_raw),
            ("position_raw", parsed.position_raw),
            ("body_length", parsed.body_len),
            ("trailing_raw_hex", parsed.trailing.hex()),
        )
    )
    return RuleSemantics(
        status="observed_only",
        representation="bm.pattern.ir.v1",
        data=JSONObject(pattern_data.items + (("outer", outer),)),
        evidence=(
            "NSCRIPT_BRUTE wire framing and decoded fields for mpengine 1.443.903.0",
        ),
        profile=f"mpengine-{parsed.pattern.profile}",
        issues=(
            SemanticIssue(
                "nscript_brute_outer_semantics_unknown",
                "NSCRIPT_BRUTE routing, direction, position, and metadata are "
                "retained without assigning detection or verdict semantics.",
                (
                    ("runtime_script_type", parsed.runtime_script_type),
                    ("direction_raw", parsed.direction_raw),
                    ("position_raw", parsed.position_raw),
                ),
            ),
            *pattern_issues,
        ),
    )


def render_nscript_cure(parsed: NScriptCurePayload) -> FormatResult:
    rows = [
        ("kind", str(parsed.kind)),
        ("name_crc32", f"0x{parsed.name_crc32:08X}"),
        (
            "span_or_offset",
            str(parsed.span_or_offset)
            if parsed.span_or_offset is not None
            else "absent",
        ),
        ("data_length", str(parsed.data_len)),
        ("data_preview", _preview(parsed.data)),
        ("accepted_by_receiver", str(parsed.accepted_by_receiver)),
        (
            "data_kind",
            "BM_MAP_LOWCASE pattern"
            if parsed.kind in (1, 2)
            else "raw replacement"
            if parsed.kind == 5
            else "opaque",
        ),
        *_trailing(parsed.trailing),
    ]
    if not parsed.accepted_by_receiver:
        rows.append(
            (
                "warning",
                "receiver returns success without appending: packed span mismatch",
            )
        )
    sections = [DisplaySection("NSCRIPT_CURE", rows=tuple(rows))]
    if parsed.pattern is not None:
        sections.append(_pattern_section(parsed.pattern, lowcase=True))
    return FormatResult(sections=tuple(sections))


NSCRIPT_SPECS = (
    FamilySpec(0x27, "NSCRIPT_NORMAL", parse_nscript, render_nscript),
    FamilySpec(0x28, "NSCRIPT_SP", parse_nscript_sp, render_nscript_sp),
    FamilySpec(
        0x29,
        "NSCRIPT_BRUTE",
        parse_nscript_brute,
        render_nscript_brute,
        semantic_exporter=export_nscript_brute_semantics,
    ),
    FamilySpec(0x2C, "NSCRIPT_CURE", parse_nscript_cure, render_nscript_cure),
)
