"""Lossless typed parser for IL2_PATTERN (0xA6)."""

from dataclasses import dataclass
from typing import Final

from ..core import (
    DisplaySection,
    FamilySpec,
    FormatResult,
    JSONArray,
    JSONObject,
    RuleSemantics,
    SemanticClaim,
    SemanticEvidence,
    SemanticIssue,
    SemanticUnknown,
)

IL2_PATTERN_TYPE: Final = 0xA6
_HEADER_SIZE: Final = 28
_ARRAY_PREVIEW: Final = 16
_RAW_PREVIEW: Final = 64


@dataclass(frozen=True, slots=True)
class IL2Pattern:
    """IL2_PATTERN receiver fields and operand arrays."""

    raw: bytes
    v1_count: int
    tag_count: int
    unknown_04: bytes
    lookup_key: bytes
    v1_operands: tuple[int, ...]
    tag_operands: tuple[tuple[int, int], ...]
    trailing: bytes

    @property
    def lookup_hash_words(self) -> tuple[int, int]:
        """Return the two key DWORDs used by the lookup bucket hash."""
        return (
            int.from_bytes(self.lookup_key[0:4], "little"),
            int.from_bytes(self.lookup_key[4:8], "little"),
        )


def parse_il2_pattern(payload: bytes) -> IL2Pattern:
    """Parse observed offsets, retaining opaque bytes and accepted trailing data."""
    if len(payload) < 12:
        raise ValueError(
            "IL2_PATTERN receiver error 0xA004: payload shorter than 12 bytes"
        )

    v1_count = int.from_bytes(payload[0:2], "little")
    tag_count = int.from_bytes(payload[2:4], "little")
    if v1_count > 0xFFF or tag_count > 0xFF:
        raise ValueError("IL2_PATTERN receiver error 0x8002: count out of range")

    required_size = _HEADER_SIZE + 4 * (v1_count + 2 * tag_count)
    if required_size < _HEADER_SIZE or required_size > len(payload):
        raise ValueError(
            "IL2_PATTERN receiver error 0x8002: required size exceeds payload"
        )

    v1_start = _HEADER_SIZE
    v1_end = v1_start + v1_count * 4
    v1_operands = tuple(
        int.from_bytes(payload[offset : offset + 4], "little")
        for offset in range(v1_start, v1_end, 4)
    )
    tag_end = v1_end + tag_count * 8
    tag_operands = tuple(
        (
            int.from_bytes(payload[offset : offset + 4], "little"),
            int.from_bytes(payload[offset + 4 : offset + 8], "little"),
        )
        for offset in range(v1_end, tag_end, 8)
    )
    return IL2Pattern(
        raw=payload,
        v1_count=v1_count,
        tag_count=tag_count,
        unknown_04=payload[4:8],
        lookup_key=payload[8:28],
        v1_operands=v1_operands,
        tag_operands=tag_operands,
        trailing=payload[required_size:],
    )


def _preview(raw: bytes) -> str:
    return raw[:_RAW_PREVIEW].hex(" ") + (" ..." if len(raw) > _RAW_PREVIEW else "")


def render_il2_pattern(parsed: IL2Pattern) -> FormatResult:
    """Render bounded previews and observed structure without interpreting arrays."""
    v1_preview = ", ".join(
        f"0x{value:08X}" for value in parsed.v1_operands[:_ARRAY_PREVIEW]
    )
    tag_preview = ", ".join(
        f"(0x{first:08X}, 0x{second:08X})"
        for first, second in parsed.tag_operands[:_ARRAY_PREVIEW]
    )
    hash_word0, hash_word1 = parsed.lookup_hash_words
    rows = (
        ("v1_count", str(parsed.v1_count)),
        ("tag_count", str(parsed.tag_count)),
        ("unknown_04", parsed.unknown_04.hex(" ")),
        ("lookup_key_length", str(len(parsed.lookup_key))),
        ("lookup_key", parsed.lookup_key.hex(" ")),
        ("lookup_hash_words", f"0x{hash_word0:08X}, 0x{hash_word1:08X}"),
        ("key_match", "exact 20-byte key; first two DWORDs select bucket"),
        ("v1_operand_count", str(len(parsed.v1_operands))),
        ("v1_operand_preview", v1_preview or "(empty)"),
        (
            "v1_operand_remaining",
            str(max(0, len(parsed.v1_operands) - _ARRAY_PREVIEW)),
        ),
        ("tag_operand_count", str(len(parsed.tag_operands))),
        ("tag_operand_preview", tag_preview or "(empty)"),
        (
            "tag_operand_remaining",
            str(max(0, len(parsed.tag_operands) - _ARRAY_PREVIEW)),
        ),
        (
            "operand_semantics",
            "IL execution operands; individual operations unresolved",
        ),
        ("trailing_length", str(len(parsed.trailing))),
        ("trailing_preview", _preview(parsed.trailing) or "(empty)"),
    )
    return FormatResult(sections=(DisplaySection("IL2_PATTERN", rows=rows),))


def export_il2_pattern_semantics(parsed: IL2Pattern) -> RuleSemantics:
    """Export receiver and storage semantics without decoding IL operands."""
    issues: list[SemanticIssue] = [
        SemanticIssue(
            "il_operand_meaning_unknown",
            "The receiver routes the arrays to distinct IL storage fields, but "
            "the meaning of individual operand values is unresolved.",
        ),
        SemanticIssue(
            "runtime_verdict_unknown",
            "The IL interpreter consumes loaded data, but wire operands have "
            "not been mapped to interpreter handlers or final verdicts.",
        ),
        SemanticIssue(
            "corpus_observation_not_distribution",
            "The local corpus count is an observation for this profile and "
            "does not establish broader database coverage.",
            (("mpas_record_count", 140), ("mpav_record_count", 0)),
        ),
    ]
    if parsed.trailing:
        issues.append(
            SemanticIssue(
                "receiver_ignored_trailing_bytes",
                "The receiver copies only the count-bounded arrays and accepts "
                "remaining payload bytes without storing them.",
                (("trailing_raw_hex", parsed.trailing.hex()),),
            )
        )

    hash_word0, hash_word1 = parsed.lookup_hash_words
    data = JSONObject(
        (
            ("raw_hex", parsed.raw.hex()),
            ("v1_count_observed", parsed.v1_count),
            ("tag_count_observed", parsed.tag_count),
            ("receiver_count_limits", JSONObject((("v1", 0xFFF), ("tag", 0xFF)))),
            ("unknown_04_raw_hex", parsed.unknown_04.hex()),
            ("lookup_key_raw_hex", parsed.lookup_key.hex()),
            ("lookup_hash_words", JSONArray((hash_word0, hash_word1))),
            (
                "lookup",
                "bucket selected from first two DWORDs; full 20-byte key compared",
            ),
            ("v1_operands_raw", JSONArray(parsed.v1_operands)),
            ("v1_storage_role", "passed to IL_v2_stor::add_v1_operands"),
            (
                "tag_operands_raw",
                JSONArray(
                    tuple(
                        JSONArray((first, second))
                        for first, second in parsed.tag_operands
                    )
                ),
            ),
            ("tag_storage_role", "passed to IL_v2_stor::add_operands"),
            ("trailing_raw_hex", parsed.trailing.hex()),
            ("trailing_disposition", "accepted_and_ignored_by_receiver"),
            ("runtime_consumer", "IL interpreter; operand-to-handler mapping unknown"),
            ("final_verdict", "unknown"),
        )
    )
    return RuleSemantics(
        status="confirmed_subset",
        representation="il2_pattern.receiver_storage.v1",
        data=data,
        evidence=(
            (
                "WIRE PARSER: parse_il2_pattern retains the entire payload and "
                "frames count_A U32 values and count_B pairs of DWORDs."
            ),
            (
                "RECEIVER: IL_pattern_receiver accepts the count limits and copies "
                "the header and bounded arrays; trailing bytes are not copied."
            ),
            (
                "STORAGE: try_breakloop routes array_A to "
                "IL_v2_stor::add_v1_operands and array_B to add_operands, then "
                "passes both to IL_container::load_IL."
            ),
            (
                "RUNTIME CONSUMER: run_IL_emulator has a large dispatch, but the "
                "wire operands are not mapped to handlers; verdict stays unknown."
            ),
            (
                "CORPUS: local mpas.sig contains 140 0xA6 records and mpav.sig "
                "contains none; this is profile-local observation only."
            ),
        ),
        profile="mpengine-1.443.903.0",
        issues=tuple(issues),
        claims=(
            SemanticClaim(
                "il2-bounded-receiver",
                "receiver_transform",
                "IL2_PATTERN validates count bounds, stores count-bounded operand arrays, and ignores accepted trailing bytes.",
                "subset",
                ("il2-receiver",),
                (
                    SemanticUnknown(
                        "receiver_transform",
                        "Operand values are not interpreted by the receiver.",
                    ),
                ),
            ),
            SemanticClaim(
                "il2-lookup",
                "runtime_consumer",
                "IL2_PATTERN lookup buckets use the first two key DWORDs and compare the complete 20-byte key.",
                "complete",
                ("il2-lookup-evidence",),
            ),
            SemanticClaim(
                "il2-operand-meaning",
                "runtime_consumer",
                "The individual operand emulator meaning remains unknown.",
                "unknown",
                (),
                (
                    SemanticUnknown(
                        "runtime_consumer",
                        "Wire operands have not been mapped to emulator handlers.",
                    ),
                ),
            ),
            SemanticClaim(
                "il2-final-verdict",
                "final_verdict",
                "IL2_PATTERN lookup does not establish a final verdict.",
                "unknown",
                (),
                (
                    SemanticUnknown(
                        "final_verdict", "The final verdict policy is not established."
                    ),
                ),
            ),
        ),
        claim_evidence=(
            SemanticEvidence(
                "il2-receiver",
                "receiver",
                "engine_static",
                "IL_pattern_receiver / try_breakloop",
                ("il2-bounded-receiver",),
            ),
            SemanticEvidence(
                "il2-lookup-evidence",
                "consumer",
                "engine_static",
                "IL2_PATTERN bucket hash and full-key comparison",
                ("il2-lookup",),
            ),
        ),
    )


SPEC = FamilySpec(
    IL2_PATTERN_TYPE,
    "IL2_PATTERN",
    parse_il2_pattern,
    render_il2_pattern,
    semantic_exporter=export_il2_pattern_semantics,
)
