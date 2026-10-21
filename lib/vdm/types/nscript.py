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
        # nscript_scan always passes the containing context to the worker, but
        # only candidate entries with runtime type 6 enter its BMMatchEx2 path.
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


def _raw_framing(raw: bytes, fields: tuple[tuple[str, int, int], ...]) -> JSONArray:
    """Serialize exact wire spans; semantic decoding never replaces raw bytes."""
    return JSONArray(
        tuple(
            JSONObject(
                (
                    ("kind", name),
                    ("raw_span", JSONObject((("offset", offset), ("length", size)))),
                    ("raw_hex", raw[offset : offset + size].hex()),
                )
            )
            for name, offset, size in fields
        )
    )


def _outer(raw: bytes, framing: JSONArray, **fields: object) -> JSONObject:
    return JSONObject(
        (("raw_hex", raw.hex()), ("framing", framing)) + tuple(fields.items())
    )


def _tail_issue(family: str, tail: bytes) -> SemanticIssue | None:
    if not tail:
        return None
    return SemanticIssue(
        f"{family.lower()}_trailing_bytes",
        "Receiver accepts trailing bytes, but their meaning is unknown; export is fail-closed.",
        (("length", len(tail)), ("raw_hex", tail.hex())),
    )


def _semantic_layers(
    parser: str, receiver: str, runtime: str, verdict: str
) -> JSONObject:
    return JSONObject(
        (
            ("parser", parser),
            ("receiver", receiver),
            ("runtime_effect", runtime),
            ("final_verdict", verdict),
        )
    )


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


def export_nscript_semantics(parsed: NScriptPayload) -> RuleSemantics:
    """Export NORMAL receiver facts without inventing script or verdict meaning."""
    n = len(parsed.name_bytes)
    count_offset = 1 + n
    primary_offset = count_offset + 1
    mode_offset = primary_offset + parsed.count * 4
    cursor = mode_offset + 1
    fields: list[tuple[str, int, int]] = [
        ("name_length", 0, 1),
        ("name", 1, n),
        ("count", count_offset, 1),
        ("primary", primary_offset, parsed.count * 4),
        ("mode", mode_offset, 1),
    ]
    if parsed.mode:
        fields.extend(
            (("anchor_crc32", cursor, 4), ("normalized_length", cursor + 4, 4))
        )
        cursor += 8
    secondary_present = parsed.secondary is not None
    secondary_len = parsed.count * 4 if secondary_present else 0
    if secondary_present:
        fields.append(("secondary", cursor, secondary_len))
        cursor += secondary_len
    flags_len = 4 if parsed.match_flags_raw is not None else 0
    if flags_len:
        fields.append(("match_flags", cursor, flags_len))
        cursor += flags_len
    fields.append(("trailing", cursor, len(parsed.trailing)))
    issues = []
    if parsed.match_flags_raw is not None:
        issues.append(
            SemanticIssue(
                "nscript_normal_match_flags_unknown",
                "Receiver stores only the low byte; flag meaning and scan policy are unknown.",
                (("raw", parsed.match_flags_raw),),
            )
        )
    tail = _tail_issue("NSCRIPT_NORMAL", parsed.trailing)
    if tail:
        issues.append(tail)
    crc_candidates = []
    append_candidates = []
    for index, (primary, secondary) in enumerate(parsed.pairs):
        if parsed.mode and index == 0:
            append_candidates.append(
                JSONObject(
                    (
                        ("source_index", index),
                        ("anchor_crc32", parsed.anchor_crc32),
                        ("normalized_length", parsed.normalized_length),
                        ("primary", primary),
                        ("mode", parsed.mode),
                    )
                )
            )
        else:
            crc_candidates.append(
                JSONObject(
                    (
                        ("source_index", index),
                        ("primary", primary),
                        ("secondary", secondary),
                    )
                )
            )
    issues.append(
        SemanticIssue(
            "nscript_normal_interpreter_and_verdict_unknown",
            "These are confirmed receiver vectors and token/state-search candidates; "
            "the complete interpreter and final verdict policy remain unknown.",
        )
    )
    outer = _outer(
        parsed.raw,
        _raw_framing(parsed.raw, tuple(fields)),
        name_length=n,
        name_raw_hex=parsed.name_bytes.hex(),
        count=parsed.count,
        primary=JSONArray(tuple(parsed.primary)),
        mode=parsed.mode,
        anchor_crc32=parsed.anchor_crc32,
        normalized_length=parsed.normalized_length,
        secondary_present=secondary_present,
        secondary=JSONArray(tuple(parsed.secondary or ())),
        runtime_candidate_subset=JSONObject(
            (
                ("stdCrcArr", JSONArray(tuple(crc_candidates))),
                ("stdAppendArr", JSONArray(tuple(append_candidates))),
                (
                    "match_flags_low_byte",
                    parsed.match_flags if parsed.match_flags_raw is not None else None,
                ),
                (
                    "consumer_functions",
                    JSONArray(
                        (
                            "nscript::EndRoutine",
                            "nscript::SearchStdEndMatches",
                            "nscript::AddToken",
                        )
                    ),
                ),
            )
        ),
        match_flags_raw=parsed.match_flags_raw,
        match_flags_low_byte=(
            parsed.match_flags if parsed.match_flags_raw is not None else None
        ),
        trailing_raw_hex=parsed.trailing.hex(),
        layers=_semantic_layers(
            "counted u32 fields and optional groups decoded",
            "mode 0 entries go to stdCrcArr; nonzero mode adds first entry "
            "to stdAppendArr; low match-flags byte is stored",
            "stdCrcArr/stdAppendArr are read by token/state search routines; "
            "full interpreter policy is unknown",
            "unknown",
        ),
    )
    return RuleSemantics(
        status="unsupported" if tail else "confirmed_subset",
        representation="nscript.normal.receiver_runtime_candidates.v1",
        data=outer,
        evidence=(
            "pushNScriptWorker @ 0x1804A836C receiver layout and writes",
            "NORMAL consumer dataflow in EndRoutine, SearchStdEndMatches, and AddToken",
        ),
        profile="mpengine-1.443.903.0",
        issues=tuple(issues),
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


def export_nscript_sp_semantics(parsed: NScriptSPPayload) -> RuleSemantics:
    """Export SP signature fields and the limited SearchExact dataflow."""
    n = len(parsed.name_bytes)
    base = 1 + n
    fields = (
        ("name_length", 0, 1),
        ("name", 1, n),
        ("anchor_crc32", base, 4),
        ("mode_flags", base + 4, 1),
        ("full_crc32", base + 5, 4),
        ("normalized_length", base + 9, 4),
        ("trailing", base + 13, len(parsed.trailing)),
    )
    issues = []
    tail = _tail_issue("NSCRIPT_SP", parsed.trailing)
    if tail:
        issues.append(tail)
    issues.append(
        SemanticIssue(
            "nscript_sp_pcode_and_verdict_policy_unknown",
            "SearchExact candidate checks and PCode handoff are confirmed; "
            "PCode result interpretation and final report policy remain unknown.",
        )
    )
    return RuleSemantics(
        status="unsupported" if tail else "confirmed_subset",
        representation="nscript.sp.receiver_runtime_candidates.v2",
        data=_outer(
            parsed.raw,
            _raw_framing(parsed.raw, fields),
            name_length=n,
            name_raw_hex=parsed.name_bytes.hex(),
            anchor_crc32=parsed.anchor_crc32,
            mode_flags=parsed.mode_flags,
            mode=parsed.mode,
            lowfi=parsed.lowfi,
            full_crc32=parsed.full_crc32,
            normalized_length=parsed.normalized_length,
            trailing_raw_hex=parsed.trailing.hex(),
            runtime_candidate_subset=JSONObject(
                (
                    (
                        "route",
                        (
                            "mode 1/2 with unpacked name containing :IRC/ -> "
                            "synthesized NORMAL via pushNScriptWorker; otherwise spArr"
                        ),
                    ),
                    ("spArr_consumer", "SearchExact"),
                    ("candidate_key", "mapped anchor CRC32"),
                    (
                        "candidate_fields",
                        JSONArray(
                            (
                                "anchor_crc32",
                                "normalized_length",
                                "full_crc32",
                                "mode",
                                "recid",
                                "lowfi",
                            )
                        ),
                    ),
                    (
                        "scan_pass_mode_gate",
                        JSONObject(
                            (
                                ("forward", "mode == 0 or mode bit 0 is set"),
                                ("reverse", "mode == 2 or mode == 4"),
                            )
                        ),
                    ),
                    (
                        "post_crc_handoff",
                        "sigseqfromrecid -> ValidateSignatureWithPcode",
                    ),
                    ("lowfi_forwarded", parsed.lowfi),
                )
            ),
            layers=_semantic_layers(
                "fixed SP prefix decoded",
                "spType appended; mode 1/2 with IRC name may be converted into NORMAL",
                "SearchExact performs CRC/length/mode candidate checks then "
                "PCode validation",
                "unknown; validation result policy and final report are not "
                "fully mapped",
            ),
        ),
        evidence=(
            "pushSP @ 0x1804A7F90 receiver layout and spType writes",
            "SearchExact @ 0x1803D5200 candidate and PCode dataflow",
        ),
        profile="mpengine-1.443.903.0",
        issues=tuple(issues),
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
                        (
                            "UFS base plugin id 6; worker candidate entry type byte == 6"
                            if parsed.runtime_consumer is not None
                            else "record-specific consumer unknown"
                        ),
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
    """Export the confirmed receiver-to-BM candidate subset, not verdicts."""
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
            ("context_consumer", "nscript_scan -> SearchBruteWorker"),
            ("runtime_consumer", parsed.runtime_consumer),
            (
                "runtime_gate",
                (
                    "conditional: UFS base plugin id 6 and worker candidate "
                    "entry byte +0x15 == 6"
                    if parsed.runtime_consumer is not None
                    else "this entry type does not enter the BMMatchEx2 branch"
                ),
            ),
            (
                "worker_candidate_subset",
                JSONObject(
                    (
                        (
                            "receiver",
                            "pushBruteWorker stores this record as a 24-byte BruteContext entry",
                        ),
                        ("stored_body", "entry +0x00; kpopobject result for wire body"),
                        (
                            "stored_position",
                            "entry +0x10; wire u32 stored as u16; 0xFFFFFFFF becomes 0xFFFF",
                        ),
                        ("stored_direction", "entry +0x14; wire byte"),
                        (
                            "stored_script_type",
                            "entry +0x15; low7 minus 1, with 0 mapping to 6",
                        ),
                        ("context_transform", "mapSP byte mapping before trie search"),
                        ("candidate_index", "FilteredTrie::matchUsingMap output"),
                        ("entry_size", 24),
                        ("entry_type_offset", 0x15),
                        ("entry_type_gate", 6),
                        ("matcher", "BMMatchEx2"),
                        ("base_plugin_id_gate", 6),
                    )
                ),
            ),
        )
    )
    return RuleSemantics(
        status="confirmed_subset",
        representation="nscript.brute.receiver_runtime_candidates.v1",
        data=JSONObject(pattern_data.items + (("outer", outer),)),
        evidence=(
            (
                "nscript_scan @ 0x18011BE20 passes g_VdmBruteSigs to "
                "SearchBruteWorker @ 0x1800AA6F0"
            ),
            (
                "SearchBruteWorker uses mapSP + FilteredTrie::matchUsingMap; "
                "24-byte entries with byte +0x15 == 6 enter BMMatchEx2"
            ),
            (
                "pushBruteWorker @ 0x1800FAFE8 stores the body pointer, recid, "
                "position, body length, direction, and normalized script type "
                "in 24-byte BruteContext entries"
            ),
            "0x29 NSCRIPT_BRUTE registration is distinct from 0xD0 BRUTE",
        ),
        profile=f"mpengine-{parsed.pattern.profile}",
        issues=(
            SemanticIssue(
                "nscript_brute_direction_position_and_verdict_unknown",
                "Receiver-to-entry mapping and the conditional BMMatchEx2 "
                "candidate gate are confirmed; direction/position meaning, "
                "validator policy, and final report/verdict remain unknown.",
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


def export_nscript_cure_semantics(parsed: NScriptCurePayload) -> RuleSemantics:
    """Export CURE payload bytes while separating receiver storage and scanner use."""
    fields: list[tuple[str, int, int]] = [("kind", 0, 1), ("name_crc32", 1, 4)]
    data_offset = 5
    if parsed.kind not in (3, 4):
        fields.extend((("span_or_offset", 5, 4), ("data_length", 9, 4)))
        data_offset = 13
        fields.append(("data", data_offset, parsed.data_len))
        data_offset += parsed.data_len
    fields.append(("trailing", data_offset, len(parsed.trailing)))
    bm_data = None
    issues: list[SemanticIssue] = []
    if parsed.pattern is not None:
        bm_data, bm_issues = serialize_bm_pattern(parsed.pattern)
        issues.extend(bm_issues)
    if parsed.kind not in (1, 2, 3, 4, 5):
        issues.append(
            SemanticIssue(
                "nscript_cure_unknown_kind",
                "CURE kind has no confirmed receiver or runtime interpretation.",
                (("kind", parsed.kind),),
            )
        )
    tail = _tail_issue("NSCRIPT_CURE", parsed.trailing)
    if tail:
        issues.append(tail)
    ignored = parsed.kind in (1, 2) and not parsed.accepted_by_receiver
    if ignored:
        issues.append(
            SemanticIssue(
                "nscript_cure_receiver_ignored",
                "Receiver returns success without appending this kind 1/2 entry.",
                (
                    ("span_or_offset", parsed.span_or_offset),
                    ("data_length", parsed.data_len),
                ),
            )
        )
    issues.append(
        SemanticIssue(
            "nscript_cure_final_cure_and_report_policy_unknown",
            "The wire-kind dispatch and helper branches are confirmed, but "
            "helper results and the final cure/report outcome are not fully "
            "mapped.",
            (("wire_kind", parsed.kind),),
        )
    )
    runtime_selector = parsed.kind
    selector_candidate = {
        1: "ScriptCureRemoveStart",
        2: "ScriptCureRemoveEnd",
        5: "ScriptCureReplace",
    }.get(runtime_selector)
    runtime_context = {
        1: "non-HTML branch; BMSearch with BM_MAP_LOWCASE",
        2: "non-HTML branch; BMSearch with BM_MAP_LOWCASE",
        3: "stored, but skipped by the sole nscript_scan cure consumer",
        4: "stored, but skipped by the sole nscript_scan cure consumer",
        5: "HTML and non-HTML branches call ScriptCureReplace",
    }.get(parsed.kind, "unknown")
    details = (
        ("kind", parsed.kind),
        ("name_crc32", parsed.name_crc32),
        ("span_or_offset", parsed.span_or_offset),
        ("data_length", parsed.data_len),
        ("data_raw_hex", parsed.data.hex()),
        ("accepted_by_receiver", parsed.accepted_by_receiver),
        (
            "runtime_candidate_subset",
            JSONObject(
                (
                    ("consumer", "nscript_scan"),
                    ("lookup", "CRC_1 key against cureArr"),
                    ("runtime_selector_byte", runtime_selector),
                    ("selector_candidate", selector_candidate),
                    ("selector_source", "wire kind"),
                    ("runtime_context", runtime_context),
                    ("final_cure_and_report_policy", "unknown"),
                )
            ),
        ),
        ("bm_pattern", bm_data),
        ("trailing_raw_hex", parsed.trailing.hex()),
        (
            "layers",
            _semantic_layers(
                "kind/name CRC and kind-dependent payload decoded",
                "kind 3/4 append without data; other kinds store data; "
                "kind 1/2 may success-and-ignore",
                "cureArr candidates are searched by name CRC; wire kind 1/2/5 "
                "dispatches remove-start/remove-end/replace helpers",
                "unknown; helper-result and final cure/report policy remain unresolved",
            ),
        ),
    )
    return RuleSemantics(
        status=(
            "ignored"
            if ignored
            else "unsupported"
            if tail or parsed.kind not in (1, 2, 3, 4, 5)
            else "confirmed_subset"
        ),
        representation="nscript.cure.receiver_runtime_candidates.v2",
        data=_outer(
            parsed.raw, _raw_framing(parsed.raw, tuple(fields)), **dict(details)
        ),
        evidence=(
            "pushCure @ 0x180470AC0 receiver layout and cureType writes",
            (
                "nscript_scan @ 0x18011BE20 CRC_1/equal_range lookup and selector "
                "calls at 0x18011DD25-0x18011DD8B"
            ),
            (
                "ScriptCureRemoveStart @ 0x180BF7BD4; "
                "ScriptCureRemoveEnd @ 0x180BF79F0; "
                "ScriptCureReplace @ 0x180BF7CE4"
            ),
        ),
        profile=(
            f"mpengine-{parsed.pattern.profile}"
            if parsed.pattern
            else "mpengine-1.443.903.0"
        ),
        issues=tuple(issues),
    )


NSCRIPT_SPECS = (
    FamilySpec(
        0x27,
        "NSCRIPT_NORMAL",
        parse_nscript,
        render_nscript,
        semantic_exporter=export_nscript_semantics,
    ),
    FamilySpec(
        0x28,
        "NSCRIPT_SP",
        parse_nscript_sp,
        render_nscript_sp,
        semantic_exporter=export_nscript_sp_semantics,
    ),
    FamilySpec(
        0x29,
        "NSCRIPT_BRUTE",
        parse_nscript_brute,
        render_nscript_brute,
        semantic_exporter=export_nscript_brute_semantics,
    ),
    FamilySpec(
        0x2C,
        "NSCRIPT_CURE",
        parse_nscript_cure,
        render_nscript_cure,
        semantic_exporter=export_nscript_cure_semantics,
    ),
)
