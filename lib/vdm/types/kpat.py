"""Lossless typed models for kernel pattern records 0xBB and 0xBC."""

from dataclasses import dataclass

from ..core import (
    DisplaySection,
    FamilySpec,
    FormatResult,
    JSONObject,
    RuleSemantics,
    SemanticIssue,
)

_PREVIEW = 64
_TEXT_PREVIEW = 512


@dataclass(frozen=True, slots=True)
class KpatPayload:
    raw: bytes
    prefix_size: int
    key: bytes
    pattern_raw: bytes
    name_raw: bytes | None
    suffix: bytes

    @property
    def name(self) -> bytes | None:
        """Name bytes only when the runtime would retain a nonempty C name."""
        if self.name_raw is None or not self.name_raw or self.name_raw[0] == 0:
            return None
        return self.name_raw.split(b"\0", 1)[0]


def parse_kpat(payload: bytes) -> KpatPayload:
    """Parse KPAT prefix framing while keeping opaque pattern and suffix bytes."""
    if not payload:
        raise ValueError("truncated KPAT prefix size")
    prefix_size = payload[0]
    if prefix_size < 8:
        raise ValueError("KPAT prefix size must be at least 8")
    prefix_end = prefix_size + 1
    if len(payload) < prefix_end:
        raise ValueError("truncated KPAT key/pattern prefix")
    key = payload[1:9]
    pattern_raw = payload[9:prefix_end]
    cursor = prefix_end
    name_raw = None
    if cursor < len(payload):
        name_len = payload[cursor]
        cursor += 1
        if cursor + name_len > len(payload):
            raise ValueError("truncated KPAT name")
        name_raw = payload[cursor : cursor + name_len]
        cursor += name_len
    return KpatPayload(
        payload, prefix_size, key, pattern_raw, name_raw, payload[cursor:]
    )


def parse_kpatex(payload: bytes) -> KpatPayload:
    """Parse KPATEX framing without assigning unverified matcher semantics."""
    return parse_kpat(payload)


def _preview(raw: bytes) -> str:
    return raw[:_PREVIEW].hex(" ") + (" ..." if len(raw) > _PREVIEW else "")


def _render(parsed: KpatPayload, *, extended: bool) -> FormatResult:
    rows = [
        ("prefix_size", str(parsed.prefix_size)),
        ("key", parsed.key.hex(" ")),
        ("pattern_length", str(len(parsed.pattern_raw))),
        ("pattern_preview", _preview(parsed.pattern_raw)),
        (
            "name_length",
            "absent" if parsed.name_raw is None else str(len(parsed.name_raw)),
        ),
        (
            "name_raw",
            "absent" if parsed.name_raw is None else _preview(parsed.name_raw),
        ),
        (
            "name_preview",
            "anonymous" if parsed.name is None else repr(parsed.name[:_TEXT_PREVIEW]),
        ),
        ("suffix_length", str(len(parsed.suffix))),
        ("suffix_preview", _preview(parsed.suffix)),
    ]
    if extended:
        rows.append(
            (
                "pattern_semantics",
                "BMMatchEx2 matcher confirmed; pattern projection confirmed",
            )
        )
    return FormatResult(
        sections=(DisplaySection("KPATEX" if extended else "KPAT", rows=tuple(rows)),)
    )


def render_kpat(parsed: KpatPayload) -> FormatResult:
    return _render(parsed, extended=False)


def render_kpatex(parsed: KpatPayload) -> FormatResult:
    return _render(parsed, extended=True)


def _export_semantics(
    parsed: KpatPayload, *, record_type: str, extended: bool
) -> RuleSemantics:
    """Export the projected matcher subset without claiming a final verdict."""
    name_length_offset = parsed.prefix_size + 1
    name_offset = name_length_offset + (parsed.name_raw is not None)
    suffix_offset = name_offset + (len(parsed.name_raw) if parsed.name_raw else 0)
    issues = [
        SemanticIssue(
            "final_verdict_unknown",
            "The registered template projects this record into the matcher row, "
            "but complete candidate validation and final report policy remain unknown.",
        )
    ]
    status = "confirmed_subset"
    if extended:
        matcher = JSONObject(
            (
                ("kind", "bm_match_ex2"),
                ("registration_group", "second tsig row group"),
                ("flags_source", "BMGetPatternFlags"),
                ("match_function", "BMMatchEx2"),
                ("match_map", "BM_MAP_ALL"),
                ("loaded_row_matcher", "BM token matcher with row flags"),
                ("wire_payload_projection", "confirmed"),
                ("pattern_input_equivalence", "confirmed"),
            )
        )
        matcher_evidence = (
            "mpengine 1.443.903.0 pattsearch_init registers type 0x4BC in the second tsig row group",
            "mpengine 1.443.903.0 tsig_push_end calls BMGetPatternFlags for the second group and stores row flags",
            "mpengine 1.443.903.0 kpatsearchex calls BMMatchEx2 with BM_MAP_ALL and the loaded row flags",
        )
    else:
        matcher = JSONObject(
            (
                ("kind", "wildcard_raw_byte_compare"),
                ("registration_group", "first tsig row group"),
                ("comparison", "bytewise pattern/subject comparison"),
                ("wildcard_byte", 0x90),
                ("wildcard_behavior", "matches any one subject byte"),
                ("wire_payload_projection", "confirmed"),
                ("pattern_input_equivalence", "confirmed"),
            )
        )
        matcher_evidence = (
            "mpengine 1.443.903.0 pattsearch_init registers type 0x4BB in the first tsig row group",
            "mpengine 1.443.903.0 tsig_push_end adds the first-group pattern object to FilteredTrie without BMGetPatternFlags",
            "mpengine 1.443.903.0 kpatsearchex byte-compares first-group candidates; pattern byte 0x90 matches any subject byte",
        )
    data = JSONObject(
        (
            ("record_type", record_type),
            ("raw_hex", parsed.raw.hex()),
            ("prefix_size", parsed.prefix_size),
            ("prefix_size_raw_hex", parsed.raw[:1].hex()),
            ("key_offset", 1),
            ("key_raw_hex", parsed.key.hex()),
            ("pattern_offset", 9),
            ("pattern_length_observed", len(parsed.pattern_raw)),
            ("pattern_raw_hex", parsed.pattern_raw.hex()),
            ("name_length_offset", name_length_offset),
            (
                "name_length_raw_hex",
                parsed.raw[name_length_offset : name_length_offset + 1].hex()
                if parsed.name_raw is not None
                else "",
            ),
            ("name_offset", name_offset),
            ("name_raw_hex", (parsed.name_raw or b"").hex()),
            ("suffix_offset", suffix_offset),
            ("suffix_raw_hex", parsed.suffix.hex()),
            ("runtime_matcher", matcher),
            ("runtime_matcher_scope", "record_projected_matcher_subset"),
            ("runtime_matcher_association", "confirmed_by_registered_template"),
            ("wire_payload_projection", "confirmed"),
        )
    )
    return RuleSemantics(
        status=status,
        representation="kpat.runtime_matcher_subset.ir.v4",
        data=data,
        evidence=(
            *matcher_evidence,
            "mpengine 1.443.903.0 descriptor 0x180F67150 maps prefix-derived pattern length to row +0x10 and the following pattern span to the object index at row +0x0C",
            "mpengine 1.443.903.0 ReceiveNewTemplate opcode sequence also maps key to row +0 and optional length-prefixed name to recid at row +8",
            "ReceiveNewTemplate ends after registered descriptors without requiring payload exhaustion; trailing bytes do not enter the matcher row",
            "ValidateKpatMatch may validate/report candidates; complete verdict policy remains unresolved",
        ),
        profile="mpengine-1.443.903.0",
        issues=tuple(issues),
    )


def export_kpat_semantics(parsed: KpatPayload) -> RuleSemantics:
    return _export_semantics(parsed, record_type="KPAT", extended=False)


def export_kpatex_semantics(parsed: KpatPayload) -> RuleSemantics:
    return _export_semantics(parsed, record_type="KPATEX", extended=True)


KPAT_SPEC = FamilySpec(
    0xBB,
    "KPAT",
    parse_kpat,
    render_kpat,
    semantic_exporter=export_kpat_semantics,
)
KPATEX_SPEC = FamilySpec(
    0xBC,
    "KPATEX",
    parse_kpatex,
    render_kpatex,
    semantic_exporter=export_kpatex_semantics,
)
