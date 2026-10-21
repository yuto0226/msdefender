import json
from collections.abc import Callable
from dataclasses import dataclass
from types import MappingProxyType
from typing import Literal

from ..bm import (
    BmControlFlow,
    BmOpaque,
    BmPattern,
    BmScan,
    decode_bm_pattern,
    interpret_bm_pattern,
    render_printable_bytes_preview,
)
from ..bm_semantic import BmSemanticContext, serialize_bm_pattern
from ..bm_yara import (
    BmMatchContext,
    BmYaraRender,
    render_bm_yara,
)
from ..condition import (
    Atom,
    Expr,
    Or,
    at_least,
    conjunction,
    disjunction,
    evaluate,
    minimize_dnf,
    negate,
    render_yara_like,
    rendered_length,
    select_equivalent,
)
from ..core import (
    DisplaySection,
    FamilySpec,
    Field,
    FormatResult,
    JSONArray,
    JSONObject,
    RuleSemantics,
    SemanticClaim,
    SemanticEvidence,
    SemanticIssue,
    SemanticUnknown,
)


@dataclass(frozen=True, slots=True)
class HstrFlags:
    value: int
    raw: bytes


@dataclass(frozen=True, slots=True)
class HstrSubsignature:
    raw: bytes
    tag: int
    flags: HstrFlags | None
    data: bytes


@dataclass(frozen=True, slots=True)
class HstrPayload:
    raw: bytes
    type_byte: int
    header_word0: int
    header_word1: int
    name_raw: bytes
    subsignatures: tuple[HstrSubsignature, ...]
    tail_word0: int | None
    tail_word1: int | None
    trailing_raw: bytes

    @property
    def receiver_ignored(self) -> bool:
        """Whether HSTR ingest returns success without registering this record."""
        return any(
            subsig.flags is not None and subsig.flags.value & ~0x03FF
            for subsig in self.subsignatures
        )


@dataclass(frozen=True, slots=True)
class HstrSubsignatureMeaning:
    """A conservative interpretation, separate from the lossless wire model."""

    kind: Literal["LITERAL", "BM_PATTERN", "BINARY", "OPAQUE"]
    matching: Literal["ASCII_FOLD_AZ", "BYTE_EXACT", "BM_PATTERN", "UNKNOWN"]
    display_encoding: Literal["ASCII", "UTF16LE", "HEX"]
    display_text: str | None
    flag_names: tuple[str, ...]
    contextual_bits: tuple[int, ...]
    contextual_effects: tuple[str, ...]
    unknown_flag_bits: int
    score_add: int | None


@dataclass(frozen=True, slots=True)
class HstrScoreThresholds:
    """Score classification eligibility; validators/policy may modify or cancel it.

    The condition is base eligibility. The level 1 filter routes/promotes eligible
    matches to level 1; it does not discard other eligible matches. Level 2 is the
    exact condition-and-not-filter predicate. These assume one contribution per
    subsig and are not final verdicts.

    The displayed combined_condition is selected by exhaustive equivalence
    checks after composing the reachable engine level branches as an Or AST.

    The report candidate gate is score > 0 and (score >= header_word1 or a
    nonzero tail_word1 whose low 15 bits are reached). Projection is restricted
    to positive ordered headers and no tail candidate branch.
    """

    level1: int
    level2: int
    retained_minimum: int | None
    retained_level: int | None
    maximum_once: int | None
    condition: Expr | None
    level1_filter: Expr | None
    level2_condition: Expr | None
    identifiers: tuple[str, ...]
    combined_condition: Expr | None = None
    tail_condition: Expr | None = None


_FLAG_NAMES = (
    (0x0001, "BYTE_EXACT"),
    (0x0002, "BM_PATTERN"),
    (0x0100, "EMIT_WIDE_COPY"),
)
_KNOWN_FLAG_MASK = sum(mask for mask, _ in _FLAG_NAMES)
_CONTEXTUAL_FLAG_EFFECTS = (
    (0x0004, "validator_gate"),
    (0x0008, "validator_gate"),
    (0x0010, "validator_gate"),
    (0x0020, "bm_crc_virtual_type_vector"),
    (0x0040, "validator_gate"),
    (0x0080, "bm_match_option_bit_1"),
    (0x0200, "full_subject_copy_in_search_mode_1"),
)
_RECEIVER_FLAG_MASK = 0x03FF
_PE_DYNAMIC_PAGE_HSTR_FAMILIES = frozenset({0x78, 0x85})


def _text_display(data: bytes) -> tuple[Literal["ASCII", "UTF16LE", "HEX"], str | None]:
    # Decode only complete printable shapes. Do not strip length prefixes or NULs:
    # they are matcher bytes, even when an embedded string looks readable.
    if data and all(byte in (9, 10, 13) or 0x20 <= byte <= 0x7E for byte in data):
        return "ASCII", data.decode("ascii")
    if len(data) >= 2 and len(data) % 2 == 0:
        try:
            text = data.decode("utf-16le")
        except UnicodeDecodeError:
            pass
        else:
            if all(char.isprintable() or char in "\t\r\n" for char in text) and any(
                byte == 0 for byte in data[1::2]
            ):
                return "UTF16LE", text
    return "HEX", None


def classify_hstr_subsignature(
    subsig: HstrSubsignature, *, type_byte: int | None = None
) -> HstrSubsignatureMeaning:
    """Classify display bytes without deriving matcher behavior from their shape."""
    flags = subsig.flags.value if subsig.flags is not None else 0
    names = tuple(name for mask, name in _FLAG_NAMES if flags & mask)
    receiver_ignored = bool(flags & ~_RECEIVER_FLAG_MASK)
    if receiver_ignored:
        contextual_bits = ()
        contextual_effects = ()
        unknown = flags & ~_KNOWN_FLAG_MASK
    else:
        contextual_bits = tuple(
            mask for mask, _ in _CONTEXTUAL_FLAG_EFFECTS if flags & mask
        )
        contextual_effects = tuple(
            dict.fromkeys(
                effect for mask, effect in _CONTEXTUAL_FLAG_EFFECTS if flags & mask
            )
        )
        unknown = flags & ~_RECEIVER_FLAG_MASK
    encoding, text = _text_display(subsig.data)
    bit_0080_literal_neutral = (
        type_byte in _CONFIRMED_MATCHER_FAMILIES
        and contextual_bits == (0x0080,)
        and not flags & 0x0002
    )
    pe_dynamic_page_candidate = (
        type_byte in _PE_DYNAMIC_PAGE_HSTR_FAMILIES
        and contextual_bits == (0x0010,)
        and not receiver_ignored
    )
    # BM bytes stay hex even if every byte happens to be printable.
    if flags & 0x0002:
        kind = "BM_PATTERN"
        encoding, text = "HEX", None
        matching = "UNKNOWN" if unknown else "BM_PATTERN"
    elif (
        unknown
        or (
            contextual_bits
            and not bit_0080_literal_neutral
            and not pe_dynamic_page_candidate
        )
        or not subsig.data
    ):
        kind, matching = "OPAQUE", "UNKNOWN"
    else:
        kind = "BINARY" if encoding == "HEX" else "LITERAL"
        matching = "BYTE_EXACT" if flags & 0x0001 else "ASCII_FOLD_AZ"
    return HstrSubsignatureMeaning(
        kind=kind,
        matching=matching,
        display_encoding=encoding,
        display_text=text,
        flag_names=names,
        contextual_bits=contextual_bits,
        contextual_effects=contextual_effects,
        unknown_flag_bits=unknown,
        # The engine adds the raw WORD modulo 2^16 and interprets only the final
        # aggregate as signed. Keep high-bit words out of the monotone AST.
        score_add=subsig.tag if subsig.tag < 0x8000 else None,
    )


def _semantic_identifiers(
    meanings: tuple[HstrSubsignatureMeaning, ...],
) -> tuple[str, ...]:
    """Assign fixed syntax-kind names in wire order, independent of thresholds."""
    counts: dict[str, int] = {}
    identifiers = []
    for meaning in meanings:
        if meaning.kind == "BM_PATTERN":
            prefix = "bm"
        elif meaning.display_encoding == "ASCII" and (
            meaning.kind == "LITERAL" or "EMIT_WIDE_COPY" in meaning.flag_names
        ):
            prefix = "str"
        elif meaning.kind == "LITERAL" and meaning.display_encoding == "UTF16LE":
            prefix = "wstr"
        else:
            prefix = "bin"
        counts[prefix] = counts.get(prefix, 0) + 1
        identifiers.append(f"${prefix}_{counts[prefix]}")
    return tuple(identifiers)


def _count_truth(members: frozenset[int], count: int, size: int) -> int:
    member_mask = sum(1 << index for index in members)
    return sum(
        1 << assignment
        for assignment in range(1 << size)
        if (assignment & member_mask).bit_count() >= count
    )


def _semantic_sets(identifiers: tuple[str, ...]) -> dict[str, frozenset[int]]:
    return {
        f"${prefix}_*": frozenset(
            index
            for index, name in enumerate(identifiers)
            if name.startswith(f"${prefix}_")
        )
        for prefix in ("str", "wstr", "bm", "bin")
        if any(name.startswith(f"${prefix}_") for name in identifiers)
    }


def _verified_projection(
    expr: Expr, expected: int, identifiers: tuple[str, ...]
) -> Expr | None:
    if rendered_length(expr) > 160:
        return None
    actual = sum(
        1 << assignment
        for assignment in range(1 << len(identifiers))
        if evaluate(
            expr,
            frozenset(
                identifier
                for index, identifier in enumerate(identifiers)
                if assignment & (1 << index)
            ),
        )
    )
    return expr if actual == expected else None


def _threshold_projection(
    weights: tuple[int, ...], identifiers: tuple[str, ...], threshold: int
) -> Expr | None:
    """Lower bounded score eligibility to AST without presentation-dependent parsing."""
    size = len(weights)
    atoms = tuple(Atom(identifier) for identifier in identifiers)
    scores = [
        sum(weight for index, weight in enumerate(weights) if assignment & (1 << index))
        for assignment in range(1 << size)
    ]
    expected = sum(
        1 << assignment for assignment, score in enumerate(scores) if score >= threshold
    )
    whole = frozenset(range(size))
    if expected == _count_truth(whole, size, size):
        return _verified_projection(
            at_least(size, atoms, "them"), expected, identifiers
        )
    if expected == _count_truth(whole, 1, size):
        return _verified_projection(at_least(1, atoms, "them"), expected, identifiers)
    if len(set(weights)) == 1 and weights[0] > 0:
        required = (threshold + weights[0] - 1) // weights[0]
        return _verified_projection(
            at_least(required, atoms, "them"), expected, identifiers
        )
    sets = _semantic_sets(identifiers)
    for selector, members in sets.items():
        selected = tuple(atoms[index] for index in sorted(members))
        for required in range(1, len(members) + 1):
            if expected == _count_truth(members, required, size):
                return _verified_projection(
                    at_least(required, selected, selector), expected, identifiers
                )
    minima = []
    for assignment in sorted(
        range(1 << size), key=lambda value: (value.bit_count(), value)
    ):
        if scores[assignment] < threshold or any(
            term & assignment == term for term in minima
        ):
            continue
        minima.append(assignment)
        if len(minima) > 4:
            return None
    terms = []
    for term in minima:
        members = frozenset(index for index in range(size) if term & (1 << index))
        parts = []
        for selector, group in sets.items():
            if len(group) > 1 and group <= members:
                selected = tuple(atoms[index] for index in sorted(group))
                grouped = at_least(len(selected), selected, selector)
                if rendered_length(grouped) < rendered_length(conjunction(*selected)):
                    parts.append(grouped)
                    members -= group
        parts.extend(atoms[index] for index in sorted(members))
        terms.append(conjunction(*parts))
    return _verified_projection(
        minimize_dnf(disjunction(*terms)), expected, identifiers
    )


def _level_conditions(
    weights: tuple[int, ...], identifiers: tuple[str, ...], header0: int, header1: int
) -> tuple[Expr | None, Expr | None, Expr | None]:
    level1 = _threshold_projection(weights, identifiers, header0)
    if header0 == header1:
        return level1, level1, None
    candidate = _threshold_projection(weights, identifiers, header1)
    level2 = None
    if level1 is not None and candidate is not None:
        expected = sum(
            1 << assignment
            for assignment in range(1 << len(weights))
            if header1
            <= sum(
                weight
                for index, weight in enumerate(weights)
                if assignment & (1 << index)
            )
            < header0
        )
        level2 = _verified_projection(
            conjunction(candidate, negate(level1)), expected, identifiers
        )
    return candidate, level1, level2


def _combined_condition(
    candidate: Expr | None,
    level1: Expr | None,
    level2: Expr | None,
    identifiers: tuple[str, ...],
    same_threshold: bool,
) -> Expr | None:
    if candidate is None or level1 is None or (level2 is None and not same_threshold):
        return None
    # Same thresholds make level 2 unreachable. Nonzero tail is excluded by the
    # projection domain; an absent tail AST is never treated as a modeled branch.
    branches = (level1,) if same_threshold else (level1, level2)
    source = Or(branches)
    best = select_equivalent(
        source, (minimize_dnf(source), candidate, minimize_dnf(candidate)), identifiers
    )
    return best if rendered_length(best) <= 160 else None


def summarize_hstr_scores(parsed: HstrPayload) -> HstrScoreThresholds:
    """Report score classification eligibility, independent of final verdict policy."""
    meanings = tuple(
        classify_hstr_subsignature(subsig, type_byte=parsed.type_byte)
        for subsig in parsed.subsignatures
    )
    identifiers = _semantic_identifiers(meanings)
    weights = tuple(meaning.score_add for meaning in meanings)
    maximum = None
    condition = None
    level1_filter = None
    level2_condition = None
    combined_condition = None
    known_weights = tuple(weight for weight in weights if weight is not None)
    # The engine accumulator is a WORD. Use the conservative signed-positive
    # range so the projection cannot imply monotonic scoring across wraparound.
    if weights and len(known_weights) == len(weights) and sum(known_weights) <= 0x7FFF:
        maximum = sum(known_weights)
        # Unknown flags and extra bytes prevent Boolean interpretation. Limit
        # variables, minimal terms, and rendered length to keep output bounded.
        if (
            len(weights) <= 8
            and all(meaning.matching != "UNKNOWN" for meaning in meanings)
            and not parsed.trailing_raw
            and 0 < parsed.header_word1 <= parsed.header_word0
            and not parsed.tail_word1
        ):
            condition, level1_filter, level2_condition = _level_conditions(
                known_weights,
                identifiers,
                parsed.header_word0,
                parsed.header_word1,
            )
            combined_condition = _combined_condition(
                condition,
                level1_filter,
                level2_condition,
                identifiers,
                parsed.header_word0 == parsed.header_word1,
            )
    tail = parsed.tail_word1
    return HstrScoreThresholds(
        level1=parsed.header_word0,
        level2=parsed.header_word1,
        retained_minimum=(tail & 0x7FFF) if tail else None,
        retained_level=(6 if tail & 0x8000 else 3) if tail else None,
        maximum_once=maximum,
        condition=condition,
        level1_filter=level1_filter,
        level2_condition=level2_condition,
        identifiers=identifiers,
        combined_condition=combined_condition,
    )


_FAMILY_NAMES = MappingProxyType(
    {
        0x61: "PEHSTR",
        0x78: "PEHSTR_EXT",
        0x85: "PEHSTR_EXT2",
        0x8C: "ELFHSTR_EXT",
        0x8D: "MACHOHSTR_EXT",
        0x8E: "DOSHSTR_EXT",
        0x8F: "MACROHSTR_EXT",
        0x92: "ASCRIPTHSTR_EXT",
        0xBE: "DEXHSTR_EXT",
        0xBF: "JAVAHSTR_EXT",
        0xC5: "ARHSTR_EXT",
        0xD1: "SWFHSTR_EXT",
        0xD3: "AUTOITHSTR_EXT",
        0xD4: "INNOHSTR_EXT",
        0xD7: "CMDHSTR_EXT",
        0xE4: "MDBHSTR_EXT",
        0xEA: "DMGHSTR_EXT",
        0xEF: "ARHSTR_POSIX_EXT",
    }
)

# Only list families with an identified scan consumer in this engine database.
_CONFIRMED_MATCHER_FAMILIES = frozenset(
    {
        0x61,  # PEHSTR
        0x78,  # PEHSTR_EXT
        0x85,  # PEHSTR_EXT2
        0x8C,  # ELFHSTR_EXT
        0x8D,  # MACHOHSTR_EXT
        0x8F,  # MACROHSTR_EXT
        0x92,  # ASCRIPTHSTR_EXT
        0xBE,  # DEXHSTR_EXT
        0xBF,  # JAVAHSTR_EXT
        0xC5,  # ARHSTR_EXT
        0xD1,  # SWFHSTR_EXT
        0xD3,  # AUTOITHSTR_EXT
        0xD4,  # INNOHSTR_EXT
        0xD7,  # CMDHSTR_EXT
        0xEA,  # DMGHSTR_EXT
    }
)

_CONFIRMED_SCANNER_CONTEXTS = {
    0x61: {
        "family_index": 0,
        "reader_kinds": ("PE_VMM_RANGES",),
        "report_route": "PE_SCAN_VMEM_REPORT",
        "report_family_index": 0,
        "search_mode": 0,
        "validator_argument": "PefileExtendedAttributesValidator",
        "state_lifecycle": "shared_across_ranges_within_invocation",
        "cross_range_score": "distinct_subsignature_contributions_accumulate",
        "cross_boundary_pattern": "separate_subject_spans",
        "invocation_reset": "unknown",
    },
    0x78: {
        "family_index": 0,
        "reader_kinds": ("PE_VMM_RANGES",),
        "report_route": "PE_SCAN_VMEM_REPORT",
        "report_family_index": 0,
        "search_mode": 0,
        "validator_argument": "PefileExtendedAttributesValidator",
        "state_lifecycle": "shared_across_ranges_within_invocation",
        "cross_range_score": "distinct_subsignature_contributions_accumulate",
        "cross_boundary_pattern": "separate_subject_spans",
        "invocation_reset": "unknown",
    },
    0x85: {
        "family_index": 0,
        "reader_kinds": ("PE_VMM_RANGES",),
        "report_route": "PE_SCAN_VMEM_REPORT",
        "report_family_index": 0,
        "search_mode": 0,
        "validator_argument": "PefileExtendedAttributesValidator",
        "state_lifecycle": "shared_across_ranges_within_invocation",
        "cross_range_score": "distinct_subsignature_contributions_accumulate",
        "cross_boundary_pattern": "separate_subject_spans",
        "invocation_reset": "unknown",
    },
    0x8D: {
        "family_index": 2,
        "reader_kinds": ("MACHO_REGION_WITH_OVERLAP",),
        "report_route": "MACHO_REGION_STATE_WRITE_THROUGH",
        "report_family_index": None,
        "search_mode": 1,
        "validator_argument": None,
        "state_lifecycle": "caller_owned_state",
        "cross_boundary_pattern": "helper_overlap",
    },
    0x8F: {
        "family_index": 1,
        "reader_kinds": ("MACRO_CALLER_BUFFER",),
        "report_route": "MACRO_HSTR_SEARCH_API_ONLY",
        "report_family_index": None,
        "search_mode": 1,
        "validator_argument": None,
        "state_lifecycle": "caller_owned_unknown",
    },
    0xD3: {
        "family_index": 9,
        "reader_kinds": ("AUTOIT_UFS_FILE_CHUNKS",),
        "report_route": "AUTOITSCAN_REPORT_INDEX",
        "report_family_index": 9,
    },
    0x8C: {
        "family_index": 3,
        "reader_kinds": ("ELF_SEGMENT_INTERVAL", "ELF_CALLER_RANGE"),
        "report_route": "ELFFILE_SCAN_REPORTS_AFTER_HELPERS",
        "report_family_index": None,
        "search_mode": 1,
        "validator_argument": None,
        "state_lifecycle": "helper_local_reset_per_chunk_or_interval",
        "cross_range_score": "not_accumulated_within_each_helper",
        "cross_helper_aggregation": "unknown",
        "cross_boundary_pattern": "helper_specific_overlap",
        "invocation_reset": "helper_local_state_reset_confirmed",
    },
    0xC5: {
        "family_index": 7,
        "reader_kinds": ("CSMS_CALLER_BUFFER_OR_RANGES",),
        "report_route": "CSMSSCANNER_CHECKDETECTION_FLAG_SELECTS_INDEX",
        "report_family_index": 7,
    },
    0xD4: {
        "family_index": 10,
        "reader_kinds": ("INNO_UFS_FILE_CHUNKS",),
        "report_route": "INNOSCAN_REPORT_INDEX",
        "report_family_index": 10,
    },
}


def _hstr_scanner_context(type_byte: int) -> JSONObject | None:
    """Expose per-family caller facts without extending matcher/verdict scope."""
    context = _CONFIRMED_SCANNER_CONTEXTS.get(type_byte)
    if context is None:
        return None
    return JSONObject(
        (
            ("family_index", context["family_index"]),
            ("reader_kinds", JSONArray(context["reader_kinds"])),
            ("search_mode", context.get("search_mode", 1)),
            ("validator_argument", context.get("validator_argument")),
            ("report_route", context["report_route"]),
            ("report_family_index", context["report_family_index"]),
            ("state_lifecycle", context.get("state_lifecycle", "unknown")),
            ("cross_range_score", context.get("cross_range_score", "unknown")),
            (
                "cross_helper_aggregation",
                context.get("cross_helper_aggregation", "not_applicable"),
            ),
            (
                "cross_boundary_pattern",
                context.get("cross_boundary_pattern", "unknown"),
            ),
            ("invocation_reset", context.get("invocation_reset", "unknown")),
            ("final_verdict", "unknown"),
        )
    )


def _hstr_contextual_disposition(
    type_byte: int, subsig: HstrSubsignature, meaning: HstrSubsignatureMeaning
) -> JSONObject | None:
    """Project only contextual effects closed through the selected worker path."""
    if subsig.flags is None:
        return None
    if type_byte in _CONFIRMED_MATCHER_FAMILIES and meaning.contextual_bits == (
        0x0080,
    ):
        bm_pattern = bool(subsig.flags.value & 0x0002)
        if not bm_pattern:
            return JSONObject(
                (
                    ("status", "exact_matcher_neutral"),
                    ("reason", "literal_compare_does_not_read_bit_0080"),
                    ("subsignature_scope_only", True),
                )
            )
        pattern = decode_bm_pattern(subsig.data)
        if (
            pattern.issue is None
            and pattern.ended
            and not pattern.remaining_raw
            and b"\x90\x1b" not in pattern.raw
        ):
            return JSONObject(
                (
                    ("status", "exact_matcher_neutral"),
                    (
                        "reason",
                        "bm_mode_bit_1_only_changes_backref_setup_without_raw_90_1b",
                    ),
                    (
                        "confirmed_scope",
                        JSONArray(("match", "cursor", "match_end", "bmMatchOffset")),
                    ),
                    ("subsignature_scope_only", True),
                )
            )
    if (
        type_byte in _PE_DYNAMIC_PAGE_HSTR_FAMILIES
        and meaning.contextual_bits == (0x0010,)
        and meaning.unknown_flag_bits == 0
        and subsig.data
    ):
        return JSONObject(
            (
                ("status", "conditional_location_candidate"),
                ("stage", "post_match_validator"),
                ("predicate", "mmap_is_dynamic_page"),
                ("arguments", "pe_vars, base + match_offset"),
                ("true_disposition", "enters_location_candidate_management"),
                ("false_disposition", "this_subsignature_match_not_inserted"),
                (
                    "preconditions",
                    JSONObject(
                        (
                            ("subsignature_match_succeeded", True),
                            ("matched_span_length_nonzero", True),
                            ("match_offset_nonzero_required", False),
                        )
                    ),
                ),
                ("subsignature_scope_only", True),
            )
        )
    gate_bits = subsig.flags.value & 0x005C
    if not gate_bits or meaning.unknown_flag_bits:
        return None
    validator_gate_bits = (0x0004, 0x0008, 0x0010, 0x0040)
    if any(bit not in validator_gate_bits for bit in meaning.contextual_bits):
        return None
    # Context coverage may include callers that use a validator (notably PE).
    # Keep the no-candidate proof limited to families whose complete known
    # reader set is explicitly documented to pass a null validator.
    if type_byte not in {0x8C, 0xC5, 0xD3, 0xD4}:
        return None
    return JSONObject(
        (
            ("status", "exact_no_candidate"),
            (
                "reason",
                "validator_required_but_null_at_all_confirmed_readers",
            ),
            ("gate_mask", 0x005C),
            ("subsignature_scope_only", True),
        )
    )


def _hstr_bm_buffer_reader_disposition(
    type_byte: int,
    pattern: BmPattern,
) -> tuple[JSONArray, JSONObject | None]:
    """Project dispatch 0x09 failure without treating it as a final verdict."""
    if type_byte not in _CONFIRMED_MATCHER_FAMILIES:
        return JSONArray(()), None

    operations = interpret_bm_pattern(pattern).operations
    rejecting = tuple(
        JSONObject(
            (
                ("offset", operation.offset),
                ("raw_id", operation.token.raw_id),
                ("dispatch", operation.token.dispatch_id),
                ("effect", "default_false_when_reached"),
                (
                    "reason",
                    "BMSBufferReader dispatch 0x09 reaches the worker default false branch",
                ),
            )
        )
        for operation in operations
        if isinstance(operation, BmScan) and operation.token.dispatch_id == 0x09
    )
    if not rejecting:
        return JSONArray(()), None

    uncertain_operation = any(
        isinstance(operation, (BmOpaque, BmControlFlow)) for operation in operations
    )
    exact_projection = (
        pattern.issue is None
        and pattern.ended
        and not pattern.remaining_raw
        and not uncertain_operation
    )
    if not exact_projection:
        return JSONArray(rejecting), JSONObject(
            (
                ("status", "bounded_unknown"),
                ("stage", "matcher"),
                (
                    "reason",
                    "dispatch_0x09_is_rejecting_when_reached_but_framing_or_pattern_control_flow_is_not_fully_closed",
                ),
                ("subsignature_scope_only", True),
            )
        )

    # A 0x03 choice recursively tries each raw chunk against one shared suffix;
    # all successful paths must still consume the suffix containing dispatch 0x09.
    return JSONArray(rejecting), JSONObject(
        (
            ("status", "exact_no_candidate"),
            ("stage", "matcher"),
            (
                "reason",
                "every_decoded_BM_path_must_match_the_suffix_and_buffer_dispatch_0x09_returns_false",
            ),
            ("scope", "this_HSTR_BM_subsignature_candidate"),
            ("downstream_validator_reachable", False),
            ("subsignature_scope_only", True),
        )
    )


def _compose_candidate_disposition(
    validator: JSONObject | None,
    matcher: JSONObject | None,
) -> JSONObject | None:
    """Compose matcher and post-match validator stages conservatively."""
    matcher_status = None if matcher is None else dict(matcher.items)["status"]
    validator_status = None if validator is None else dict(validator.items)["status"]
    if matcher_status == "exact_no_candidate":
        return matcher
    if validator_status == "exact_no_candidate":
        return validator
    if matcher is not None:
        return matcher
    return validator


def _read_u16(payload: bytes, cursor: int, label: str) -> tuple[int, int]:
    end = cursor + 2
    if end > len(payload):
        raise ValueError(f"truncated {label}")
    return int.from_bytes(payload[cursor:end], "little"), end


def _read_flags(payload: bytes, cursor: int) -> tuple[HstrFlags, int]:
    start = cursor
    if cursor >= len(payload):
        raise ValueError("truncated subsignature flags")

    value = payload[cursor]
    cursor += 1
    if value & 0x80:
        if cursor >= len(payload):
            raise ValueError("truncated extended subsignature flags")
        value |= payload[cursor] << 8
        cursor += 1
    if value & 0x8000:
        end = cursor + 2
        if end > len(payload):
            raise ValueError("truncated long subsignature flags")
        value |= int.from_bytes(payload[cursor:end], "little") << 16
        cursor = end

    return HstrFlags(value=value, raw=payload[start:cursor]), cursor


def parse_hstr(payload: bytes, *, type_byte: int) -> HstrPayload:
    """Parse one HSTR family payload, retaining every unclassified byte."""
    if type_byte not in _FAMILY_NAMES:
        raise ValueError(f"unsupported HSTR type 0x{type_byte:02X}")
    if len(payload) < 6:
        raise ValueError("truncated HSTR header")

    header_word0 = int.from_bytes(payload[0:2], "little")
    header_word1 = int.from_bytes(payload[2:4], "little")
    subsignature_count = int.from_bytes(payload[4:6], "little")

    name_start = 6
    name_end = payload.find(b"\0", name_start, min(len(payload), name_start + 65))
    if name_end < 0:
        raise ValueError("unterminated HSTR name (maximum 64 bytes)")
    name_raw = payload[name_start:name_end]
    cursor = name_end + 1

    subsignatures: list[HstrSubsignature] = []
    for index in range(subsignature_count):
        start = cursor
        tag, cursor = _read_u16(payload, cursor, f"subsignature {index} tag")
        if cursor >= len(payload):
            raise ValueError(f"truncated subsignature {index} data length")
        data_len = payload[cursor]
        cursor += 1

        flags = None
        if type_byte != 0x61:
            flags, cursor = _read_flags(payload, cursor)

        data_end = cursor + data_len
        if data_end > len(payload):
            raise ValueError(f"truncated subsignature {index} data")
        data = payload[cursor:data_end]
        cursor = data_end
        subsignatures.append(
            HstrSubsignature(
                raw=payload[start:cursor],
                tag=tag,
                flags=flags,
                data=data,
            )
        )

    tail_word0 = None
    tail_word1 = None
    if len(payload) - cursor >= 2:
        tail_word0, cursor = _read_u16(payload, cursor, "tail_word0")
    if len(payload) - cursor >= 2:
        tail_word1, cursor = _read_u16(payload, cursor, "tail_word1")

    return HstrPayload(
        raw=payload,
        type_byte=type_byte,
        header_word0=header_word0,
        header_word1=header_word1,
        name_raw=name_raw,
        subsignatures=tuple(subsignatures),
        tail_word0=tail_word0,
        tail_word1=tail_word1,
        trailing_raw=payload[cursor:],
    )


def _hstr_bm_runtime_context(
    subsig: HstrSubsignature, pattern: BmPattern
) -> tuple[JSONObject, BmMatchContext | None, BmSemanticContext]:
    """Derive BM worker facts from an explicitly selected HSTR BM subsig."""
    assert subsig.flags is not None
    flags = subsig.flags.value
    identity = bool(flags & 0x0001)
    translation = bytes(
        byte + 0x20 if 0x41 <= byte <= 0x5A else byte for byte in range(256)
    )
    if identity:
        translation = bytes(range(256))
    capture_marker_bytes_present = b"\x90\x1b" in pattern.raw
    worker_mode = ((flags >> 6) & 2) | 1
    display = JSONObject(
        (
            ("reader_kind", "BUFFER"),
            ("translation", "identity" if identity else "ascii_lowercase"),
            ("worker_mode", worker_mode),
            ("offsets_argument_present", False),
            ("capture_marker_bytes_present", capture_marker_bytes_present),
        )
    )
    match_context = None
    if not capture_marker_bytes_present:
        match_context = BmMatchContext(
            reader_kind="BUFFER",
            translation=translation if identity else "ascii_lowercase",
            worker_mode=worker_mode,
            capture_enabled=False,
        )
    complete_single_segment = (
        pattern.issue is None and pattern.ended and not pattern.remaining_raw
    )
    semantic_context = BmSemanticContext(
        reader_kind="BUFFER",
        translation="identity" if identity else "ascii_lowercase",
        worker_modes=(worker_mode,),
        capture_enabled=(
            False
            if complete_single_segment
            and worker_mode == 1
            and not capture_marker_bytes_present
            else None
        ),
    )
    return display, match_context, semantic_context


def _render_hstr_bm_yara(
    subsig: HstrSubsignature, pattern: BmPattern
) -> tuple[BmYaraRender, JSONObject, BmSemanticContext]:
    runtime_context, match_context, semantic_context = _hstr_bm_runtime_context(
        subsig, pattern
    )
    rendered = render_bm_yara(pattern, context=match_context)
    return rendered, runtime_context, semantic_context


def _render_hstr_subsignature_display(
    subsig: HstrSubsignature, meaning: HstrSubsignatureMeaning
) -> tuple[str, BmPattern | None, BmYaraRender | None, str | None, tuple[str, ...]]:
    """Present wire bytes consistently; modifiers require confirmed semantics."""
    if meaning.kind == "BM_PATTERN":
        pattern = decode_bm_pattern(subsig.data)
        rendered, _, _ = _render_hstr_bm_yara(subsig, pattern)
        display = rendered.body or (
            "unsupported ("
            + ", ".join(issue.code for issue in rendered.diagnostics)
            + ")"
        )
        return display, pattern, rendered, None, ()
    if not subsig.data:
        return "", None, None, None, ("unsupported.empty",)
    text = meaning.display_text
    known_matching = meaning.matching in ("ASCII_FOLD_AZ", "BYTE_EXACT")
    if not known_matching or text is None or any(ord(char) > 0x7F for char in text):
        return _render_hex_subsignature(subsig, meaning)
    emit_wide = subsig.flags is not None and bool(subsig.flags.value & 0x0100)
    modifiers: list[str] = []
    if meaning.display_encoding == "ASCII":
        if emit_wide:
            modifiers.extend(("ascii", "wide"))
    elif meaning.display_encoding == "UTF16LE":
        if emit_wide:
            # Widening UTF16LE wire bytes again is not the ascii+wide pair.
            return _render_hex_subsignature(subsig, meaning)
        modifiers.append("wide")
    else:
        return _render_hex_subsignature(subsig, meaning)
    if meaning.matching == "ASCII_FOLD_AZ":
        # YARA-style display correspondence; Defender folds only ASCII A-Z.
        modifiers.append("nocase")
    suffix = f" {' '.join(modifiers)}" if modifiers else ""
    return (
        json.dumps(text) + suffix,
        None,
        None,
        render_printable_bytes_preview(subsig.data)
        if meaning.kind == "BINARY"
        else None,
        (),
    )


def _render_hex_rhs(data: bytes) -> str:
    return "{ " + data.hex(" ").upper() + " }" if data else "{ }"


def _render_hex_subsignature(
    subsig: HstrSubsignature, meaning: HstrSubsignatureMeaning
) -> tuple[str, None, None, str | None, tuple[str, ...]]:
    if not subsig.data:
        return "", None, None, None, ("unsupported.empty",)
    preview = (
        render_printable_bytes_preview(subsig.data)
        if meaning.kind == "BINARY"
        else None
    )
    return _render_hex_rhs(subsig.data), None, None, preview, ()


def render_hstr(parsed: HstrPayload) -> FormatResult:
    """Render interpreted HSTR fields without terminal styling or wire mutation."""
    scores = summarize_hstr_scores(parsed)
    threshold_rows: list[Field] = [
        (
            "header_word0",
            f"level 1 threshold = {scores.level1} (0x{parsed.header_word0:04X})",
        ),
        (
            "header_word1",
            f"candidate threshold = {scores.level2} (0x{parsed.header_word1:04X})",
        ),
    ]
    if parsed.tail_word1 is None:
        threshold_rows.append(("tail_word1", "NOT_PRESENT"))
    elif scores.retained_minimum is None:
        threshold_rows.append(
            ("tail_word1", "0x0000 (no retained-candidate threshold)")
        )
    else:
        threshold_rows.append(
            (
                "tail_word1",
                (
                    f"level {scores.retained_level} >= {scores.retained_minimum}, "
                    f"below levels 1 and 2 (0x{parsed.tail_word1:04X})"
                ),
            )
        )
    if scores.maximum_once is not None:
        threshold_rows.append(("maximum", str(scores.maximum_once)))
    if scores.combined_condition is not None:
        threshold_rows.append(
            ("condition", render_yara_like(scores.combined_condition))
        )
    sections = [DisplaySection(title="Score Thresholds", rows=tuple(threshold_rows))]

    for index, subsig in enumerate(parsed.subsignatures):
        meaning = classify_hstr_subsignature(subsig, type_byte=parsed.type_byte)
        tag_note = (
            f"score +{meaning.score_add}"
            if meaning.score_add is not None
            else f"score +0x{subsig.tag:04X} modulo 2^16"
        )
        if subsig.flags is None:
            flags_text = "NOT_PRESENT"
        else:
            names = list(meaning.flag_names)
            if meaning.contextual_bits:
                names.append(f"CONTEXT_BITS(0x{sum(meaning.contextual_bits):04X})")
            if meaning.unknown_flag_bits:
                names.append(f"UNKNOWN_BITS(0x{meaning.unknown_flag_bits:04X})")
            flags_text = "|".join(names) or "NONE"
            flags_text += f"(0x{subsig.flags.value:04X})"
        candidate = _hstr_contextual_disposition(parsed.type_byte, subsig, meaning)
        if (
            candidate is not None
            and dict(candidate.items)["status"] == "conditional_location_candidate"
        ):
            flags_text += "; PE_DYNAMIC_PAGE_VALIDATOR"
        display, pattern, bm_yara, printable_preview, yara_unsupported = (
            _render_hstr_subsignature_display(subsig, meaning)
        )
        bm_candidate = (
            _hstr_bm_buffer_reader_disposition(parsed.type_byte, pattern)[1]
            if pattern is not None
            else None
        )
        rows: list[Field] = [
            ("identifier", scores.identifiers[index]),
            ("tag", f"0x{subsig.tag:04X} ({tag_note})"),
            ("flags", flags_text),
            ("matching", meaning.matching),
            ("display", display),
            ("raw", subsig.data.hex(" ").upper() or "(empty)"),
        ]
        if candidate is not None and dict(candidate.items)["status"] == (
            "conditional_location_candidate"
        ):
            bm_rejects = (
                bm_candidate is not None
                and dict(bm_candidate.items)["status"] == "exact_no_candidate"
            )
            rows.append(
                (
                    "candidate validator",
                    (
                        "unreachable: BM dispatch 0x09 rejects at matcher stage"
                        if bm_rejects
                        else "mmap_is_dynamic_page(pe_vars, base + match_offset); "
                        "requires successful match and nonzero matched span; "
                        "offset may be 0; subsignature scope only"
                    ),
                )
            )
        if pattern is not None and (pattern.issue is not None or pattern.remaining_raw):
            status = (
                f"{pattern.issue.code}@+0x{pattern.issue.offset:X}"
                if pattern.issue is not None
                else "remaining bytes"
            )
            rows.append(("warning", f"{status}; profile {pattern.profile}"))
        sections.append(
            DisplaySection(
                title=f"subsig ({meaning.kind}, {len(subsig.data)} bytes)",
                rows=tuple(rows),
                bm_yara=bm_yara,
                printable_preview=printable_preview,
                yara_unsupported=yara_unsupported,
            )
        )

    return FormatResult(
        fields=(
            ("family", _FAMILY_NAMES[parsed.type_byte]),
            (
                "loader_disposition",
                (
                    "skipped: subsignature flags exceed 0x03FF"
                    if parsed.receiver_ignored
                    else "passed HSTR flag prevalidation"
                ),
            ),
            ("name", json.dumps(parsed.name_raw.decode("latin-1"), ensure_ascii=False)),
            ("name_raw", parsed.name_raw.hex(" ").upper() or "(empty)"),
            ("subsig_count", str(len(parsed.subsignatures))),
            (
                "tail_word0",
                (
                    f"0x{parsed.tail_word0:04X} "
                    "(candidate order key when retained rows are validator-sorted)"
                )
                if parsed.tail_word0 is not None
                else "NOT_PRESENT",
            ),
            (
                "trailing_raw",
                f"{len(parsed.trailing_raw)} B [{parsed.trailing_raw.hex(' ').upper()}]",
            ),
        ),
        sections=tuple(sections),
    )


def _raw_field(kind: str, raw: bytes, offset: int) -> JSONObject:
    return JSONObject(
        (
            ("kind", kind),
            (
                "raw_span",
                JSONObject((("offset", offset), ("length", len(raw)))),
            ),
            ("raw_hex", raw.hex()),
        )
    )


def _outer_verdict_issue(type_byte: int) -> SemanticIssue:
    context = _CONFIRMED_SCANNER_CONTEXTS.get(type_byte)
    details = (
        ()
        if context is None
        else (
            ("family_index", context["family_index"]),
            ("report_route", context["report_route"]),
        )
    )
    if type_byte in {0x61, 0x78, 0x85}:
        message = (
            "PE HSTR candidate scoring and the scan_vmem report route are "
            "confirmed, but their result is not mapped to a final scan or "
            "host-visible verdict."
        )
    elif type_byte == 0x8C:
        message = (
            "ELF helper searches and the post-helper report call are confirmed; "
            "cross-helper aggregation and the final result policy are unknown."
        )
    elif type_byte == 0x8F:
        message = (
            "The Macro HSTR API is confirmed only through buffer search; its "
            "result is not linked to RME reporting or an outer verdict."
        )
    elif type_byte == 0x8D:
        message = (
            "Mach-O region search writes caller-owned state, but the parser or "
            "scanner path to a final verdict is not confirmed."
        )
    else:
        message = (
            "A candidate match does not establish this HSTR family's consumer, "
            "report policy, or final verdict."
        )
    return SemanticIssue("outer_verdict_unknown", message, details)


_HSTR_FAMILY_INDEX = MappingProxyType(
    {
        0x61: 0,
        0x78: 0,
        0x85: 0,
        0x8C: 3,
        0x8D: 2,
        0x8E: 4,
        0x8F: 1,
        0x92: 14,
        0xBE: 5,
        0xBF: 6,
        0xC5: 7,
        0xD1: 8,
        0xD3: 9,
        0xD4: 10,
        0xD7: 11,
        0xE4: 12,
        0xEA: 13,
        0xEF: 15,
    }
)

_HSTR_CONSUMER_LOCATORS = MappingProxyType(
    {
        0x61: "scan_vmem @ 0x1801379A0; scan_vbuff @ 0x1801A2DFC",
        0x78: "scan_vmem @ 0x1801379A0; scan_vbuff @ 0x1801A2DFC",
        0x85: "scan_vmem @ 0x1801379A0; scan_vbuff @ 0x1801A2DFC",
        0x8C: (
            "elfscan_hstr_region @ 0x180A57EBC; segment_based_hstr_scan @ 0x180A58870"
        ),
        0x8D: "MachoParser::machoscan_hstr_region @ 0x1805E6674",
        0x8F: "RpfAPI_hstr_macro_search_buff @ 0x1805167D0",
        0x92: "macappl_scanfile_legacy @ 0x1803E8340",
        0xBE: "dexscan_hstr_region @ 0x1805E6F1C",
        0xBF: "javan_userdata_t::Scan @ 0x180298D88",
        0xC5: "CSMSScanner::ScanWorker @ 0x1800E9698",
        0xD1: "swf_scan_kpat @ 0x18042771C",
        0xD3: "AutoitScan @ 0x1803DC8E0",
        0xD4: "InnoScan @ 0x1803DC690",
        0xD7: "cmd_search_buffer @ 0x1804AD2DC",
        0xEA: "RpfAPI_dmg_hstrsearch @ 0x180A078E0",
    }
)

_HSTR_REPORT_LOCATORS = MappingProxyType(
    {
        0x61: (
            "scan_vmem @ 0x1801379A0; hstr_internal_report_match_worker @ 0x180136268"
        ),
        0x78: (
            "scan_vmem @ 0x1801379A0; hstr_internal_report_match_worker @ 0x180136268"
        ),
        0x85: (
            "scan_vmem @ 0x1801379A0; hstr_internal_report_match_worker @ 0x180136268"
        ),
        0x8C: "elffile_scan; hstr_internal_report_match_worker @ 0x180136268",
        0xC5: (
            "CSMSScanner::CheckDetection @ 0x1800BC730; "
            "hstr_internal_report_match_worker @ 0x180136268"
        ),
        0xD3: (
            "AutoitScan @ 0x1803DC8E0; hstr_internal_report_match_worker @ 0x180136268"
        ),
        0xD4: (
            "InnoScan @ 0x1803DC690; hstr_internal_report_match_worker @ 0x180136268"
        ),
    }
)


def _hstr_loader_locator(type_byte: int) -> str:
    if type_byte == 0x61:
        wrapper = "hstr_push @ 0x180502B40"
    elif type_byte == 0x78:
        wrapper = "hstr_push_ext @ 0x1800FEBD0"
    elif type_byte == 0x85:
        wrapper = "hstr_push_ext2 @ 0x180BBBEA0"
    else:
        wrapper = "hstr_push_common @ 0x1800FEE50"
    return (
        f"pattsearch_init @ 0x1805653B8; {wrapper}; "
        f"family index {_HSTR_FAMILY_INDEX[type_byte]}"
    )


def _hstr_typed_semantics(
    parsed: HstrPayload,
) -> tuple[tuple[SemanticClaim, ...], tuple[SemanticEvidence, ...]]:
    """Build claims without projecting one family's caller facts onto another."""
    type_byte = parsed.type_byte
    prefix = f"hstr_{type_byte:02x}"
    family = _FAMILY_NAMES[type_byte]
    accepted = not parsed.receiver_ignored
    wire_complete = not parsed.trailing_raw
    consumer_locator = _HSTR_CONSUMER_LOCATORS.get(type_byte)
    report_locator = _HSTR_REPORT_LOCATORS.get(type_byte)

    claims: list[SemanticClaim] = [
        SemanticClaim(
            id=f"{prefix}_wire_layout",
            scope="wire_layout",
            statement=(
                f"{family} uses the HSTR header, NUL-terminated name, ordered "
                "subsignature records, and up to two trailing WORD fields; only "
                "0x61 omits per-subsignature wire flags."
            ),
            coverage="complete" if wire_complete else "subset",
            evidence_refs=(f"{prefix}_receiver",),
            unknowns=(
                ()
                if wire_complete
                else (
                    SemanticUnknown(
                        "wire_layout",
                        "Bytes after the two recognized tail WORD fields remain uninterpreted.",
                    ),
                )
            ),
        ),
        SemanticClaim(
            id=f"{prefix}_loader_dispatch",
            scope="loader_dispatch",
            statement=(
                f"Record type 0x{type_byte:02X} is registered to the HSTR "
                f"receiver path for family index {_HSTR_FAMILY_INDEX[type_byte]}."
            ),
            coverage="complete",
            evidence_refs=(f"{prefix}_dispatch",),
        ),
        SemanticClaim(
            id=f"{prefix}_receiver_transform",
            scope="receiver_transform",
            statement=(
                "The receiver rejects this record before registration because a "
                "subsignature flag value exceeds 0x03FF."
                if parsed.receiver_ignored
                else "The receiver materializes the shared HSTR row and ordered "
                "subsignature entries for this family."
            ),
            coverage="complete" if parsed.receiver_ignored else "subset",
            evidence_refs=(f"{prefix}_receiver",),
            unknowns=(
                ()
                if parsed.receiver_ignored
                else (
                    SemanticUnknown(
                        "receiver_transform",
                        "Type-dependent signature-property metadata and unknown stored flag bits are not projected.",
                    ),
                )
            ),
        ),
    ]
    evidence: list[SemanticEvidence] = [
        SemanticEvidence(
            id=f"{prefix}_dispatch",
            axis="dispatch",
            kind="engine_static",
            source_ref="mpengine 1.443.903.0",
            locator=_hstr_loader_locator(type_byte),
            supports=(f"{prefix}_loader_dispatch",),
        ),
        SemanticEvidence(
            id=f"{prefix}_receiver",
            axis="receiver",
            kind="engine_static",
            source_ref="mpengine 1.443.903.0",
            locator=(
                "hstr_internal_push_ex @ 0x1800FDA6C; "
                "add_sstring_internal @ 0x1800FE008"
            ),
            supports=(f"{prefix}_wire_layout", f"{prefix}_receiver_transform"),
        ),
    ]

    consumer_confirmed = accepted and consumer_locator is not None
    if consumer_confirmed:
        claims.extend(
            (
                SemanticClaim(
                    id=f"{prefix}_runtime_consumer",
                    scope="runtime_consumer",
                    statement=(
                        f"The confirmed {family} caller submits a family-specific "
                        "buffer or region to the shared HSTR search worker."
                    ),
                    coverage="subset",
                    evidence_refs=(f"{prefix}_consumer",),
                    unknowns=(
                        SemanticUnknown(
                            "runtime_consumer",
                            "The complete caller set, subject-selection policy, and invocation lifecycle are not closed.",
                        ),
                    ),
                ),
                SemanticClaim(
                    id=f"{prefix}_candidate_predicate",
                    scope="detection_predicate",
                    statement=(
                        "The shared worker compares literal or BM subsignatures, "
                        "deduplicates logical hits, and accumulates tags into "
                        "candidate state."
                    ),
                    coverage="subset",
                    evidence_refs=(f"{prefix}_consumer",),
                    unknowns=(
                        SemanticUnknown(
                            "detection_predicate",
                            "Opaque BM operations, contextual flags, scanner policy, and record-to-threat composition remain outside this subset.",
                        ),
                    ),
                ),
            )
        )
        evidence.append(
            SemanticEvidence(
                id=f"{prefix}_consumer",
                axis="consumer",
                kind="engine_static",
                source_ref="mpengine 1.443.903.0",
                locator=(
                    f"{consumer_locator}; hstr_internal_search_worker @ 0x1800E9F70"
                ),
                supports=(
                    f"{prefix}_runtime_consumer",
                    f"{prefix}_candidate_predicate",
                ),
            )
        )
    else:
        reason = (
            "Receiver rejection prevents this record from reaching a loaded matcher."
            if not accepted
            else "No family-specific scan consumer is encoded in the typed evidence table."
        )
        claims.extend(
            (
                SemanticClaim(
                    id=f"{prefix}_runtime_consumer",
                    scope="runtime_consumer",
                    statement=f"The runtime consumer for this {family} record is unresolved.",
                    coverage="unknown",
                    unknowns=(SemanticUnknown("runtime_consumer", reason),),
                ),
                SemanticClaim(
                    id=f"{prefix}_candidate_predicate",
                    scope="detection_predicate",
                    statement=(
                        "The record cannot yet be projected as a complete detection predicate."
                    ),
                    coverage="unknown",
                    unknowns=(
                        SemanticUnknown(
                            "detection_predicate",
                            "A receiver or byte-level rendering does not establish a family scanner predicate.",
                        ),
                    ),
                ),
            )
        )

    if accepted and report_locator is not None:
        claims.append(
            SemanticClaim(
                id=f"{prefix}_report_mapping",
                scope="report_mapping",
                statement=(
                    f"The confirmed {family} scanner path passes accumulated HSTR "
                    "state into a family-selected report route."
                ),
                coverage="subset",
                evidence_refs=(f"{prefix}_report",),
                unknowns=(
                    SemanticUnknown(
                        "report_mapping",
                        "Cross-helper aggregation, policy filtering, or downstream report interpretation remains unresolved.",
                    ),
                ),
            )
        )
        evidence.append(
            SemanticEvidence(
                id=f"{prefix}_report",
                axis="report",
                kind="engine_static",
                source_ref="mpengine 1.443.903.0",
                locator=report_locator,
                supports=(f"{prefix}_report_mapping",),
            )
        )
    else:
        claims.append(
            SemanticClaim(
                id=f"{prefix}_report_mapping",
                scope="report_mapping",
                statement=f"The {family} candidate-to-report mapping is unresolved.",
                coverage="unknown",
                unknowns=(
                    SemanticUnknown(
                        "report_mapping",
                        "No record-specific report mapping is established by the available family evidence.",
                    ),
                ),
            )
        )

    claims.append(
        SemanticClaim(
            id=f"{prefix}_final_verdict",
            scope="final_verdict",
            statement="An HSTR candidate or report result is not a confirmed final verdict.",
            coverage="unknown",
            unknowns=(
                SemanticUnknown(
                    "final_verdict",
                    "Outer scan arbitration and the host-visible verdict remain unresolved.",
                ),
            ),
        )
    )
    return tuple(claims), tuple(evidence)


def export_hstr_semantics(parsed: HstrPayload) -> RuleSemantics:
    """Export a lossless HSTR matcher subset, never a final engine verdict."""
    unsupported = False
    issues: list[SemanticIssue] = [_outer_verdict_issue(parsed.type_byte)]
    if parsed.receiver_ignored:
        issues.append(
            SemanticIssue(
                "receiver_ignored",
                "The receiver skips this record because a flag exceeds 0x03FF.",
            )
        )
    if parsed.type_byte not in _CONFIRMED_MATCHER_FAMILIES:
        unsupported = True
        issues.append(
            SemanticIssue(
                "family_matcher_context_unconfirmed",
                "This family has no confirmed scan consumer in the analyzed database.",
                (("type_byte", parsed.type_byte),),
            )
        )
    if not parsed.subsignatures:
        unsupported = True
        issues.append(
            SemanticIssue(
                "empty_subsignature_set",
                "No HSTR matcher was available to confirm a non-empty subset.",
            )
        )

    cursor = 6 + len(parsed.name_raw) + 1
    framing: list[JSONObject] = [
        _raw_field("header_word0", parsed.raw[0:2], 0),
        _raw_field("header_word1", parsed.raw[2:4], 2),
        _raw_field("subsignature_count", parsed.raw[4:6], 4),
        _raw_field("name", parsed.name_raw, 6),
        _raw_field(
            "name_terminator",
            parsed.raw[6 + len(parsed.name_raw) : cursor],
            6 + len(parsed.name_raw),
        ),
    ]
    subsignatures: list[JSONObject] = []
    for index, subsig in enumerate(parsed.subsignatures):
        start = cursor
        flags_length = len(subsig.flags.raw) if subsig.flags is not None else 0
        flags_offset = start + 3
        data_offset = flags_offset + flags_length
        meaning = classify_hstr_subsignature(subsig, type_byte=parsed.type_byte)
        pattern_data = None
        bm_runtime_context = None
        bm_yara_data = None
        bm_buffer_reader_rejecting_operations = None
        bm_candidate_disposition = None
        candidate_disposition = _hstr_contextual_disposition(
            parsed.type_byte, subsig, meaning
        )

        if meaning.unknown_flag_bits:
            unsupported = True
            issues.append(
                SemanticIssue(
                    "unknown_subsignature_flags",
                    "Unknown HSTR flag bits are retained without assigned semantics.",
                    (
                        ("subsignature_index", index),
                        ("bits", meaning.unknown_flag_bits),
                    ),
                )
            )
        if meaning.contextual_bits:
            if candidate_disposition is None:
                unsupported = True
                issues.append(
                    SemanticIssue(
                        "contextual_subsignature_flags",
                        (
                            "Contextual HSTR flags require validator, offset-vector, "
                            "BM option, or full-subject match context."
                        ),
                        (
                            ("subsignature_index", index),
                            ("bits", sum(meaning.contextual_bits)),
                            ("contextual_bits", JSONArray(meaning.contextual_bits)),
                            ("effects", JSONArray(meaning.contextual_effects)),
                        ),
                    )
                )
            else:
                disposition_status = dict(candidate_disposition.items)["status"]
                if disposition_status == "exact_no_candidate":
                    issues.append(
                        SemanticIssue(
                            "candidate_no_match_validator_missing",
                            (
                                "The shared 0x005C gate requires a validator; all "
                                "confirmed readers for this family pass null, so this "
                                "subsignature cannot be retained as a candidate."
                            ),
                            (
                                ("subsignature_index", index),
                                ("gate_mask", 0x005C),
                            ),
                        )
                    )
                elif disposition_status == "conditional_location_candidate":
                    issues.append(
                        SemanticIssue(
                            "candidate_dynamic_page_validator_condition",
                            (
                                "This PE subsignature match enters location-candidate "
                                "management only when the dynamic-page validator "
                                "returns true; this is not a final report verdict."
                            ),
                            (
                                ("subsignature_index", index),
                                ("predicate", "mmap_is_dynamic_page"),
                                ("match_offset_zero_allowed", True),
                            ),
                        )
                    )
                else:
                    issues.append(
                        SemanticIssue(
                            "contextual_flag_matching_neutral",
                            (
                                "HSTR bit 0x0080 has no matcher effect in the "
                                "confirmed literal or no-backref BM subset."
                            ),
                            (("subsignature_index", index), ("bit", 0x0080)),
                        )
                    )
        if not subsig.data:
            unsupported = True
            issues.append(
                SemanticIssue(
                    "empty_subsignature_data",
                    "The empty matcher payload is retained without match semantics.",
                    (("subsignature_index", index),),
                )
            )

        # Only the explicit extended-family BM flag selects the BM decoder.
        # PEHSTR (0x61) has no flag field and is never shape-guessed as BM.
        if subsig.flags is not None and subsig.flags.value & 0x0002:
            pattern = decode_bm_pattern(subsig.data)
            bm_render, bm_runtime_context, semantic_context = _render_hstr_bm_yara(
                subsig, pattern
            )
            pattern_data, pattern_issues = serialize_bm_pattern(
                pattern,
                context=semantic_context,
                explain_sequential_alternatives=True,
            )
            (
                bm_buffer_reader_rejecting_operations,
                bm_candidate_disposition,
            ) = _hstr_bm_buffer_reader_disposition(parsed.type_byte, pattern)
            pattern_fields = dict(pattern_data.items)
            pattern_fields["buffer_reader_rejecting_operations"] = (
                bm_buffer_reader_rejecting_operations
            )
            pattern_data = JSONObject(tuple(pattern_fields.items()))
            if bm_candidate_disposition is not None:
                bm_status = dict(bm_candidate_disposition.items)["status"]
                issues.append(
                    SemanticIssue(
                        "bm_buffer_reader_candidate_disposition",
                        (
                            "BMSBufferReader dispatch 0x09 fails at the matcher stage; "
                            "downstream validators are unreachable for this pattern."
                            if bm_status == "exact_no_candidate"
                            else "Dispatch 0x09 is rejecting when reached, but framing "
                            "or pattern control flow prevents an exact candidate conclusion."
                        ),
                        (
                            ("subsignature_index", index),
                            ("status", bm_status),
                        ),
                    )
                )
                unsupported |= bm_status == "bounded_unknown"
            bm_yara_data = JSONObject(
                (
                    ("fidelity", bm_render.fidelity.value),
                    ("body", bm_render.body),
                    ("requirements", JSONArray(bm_render.requirements)),
                    (
                        "diagnostics",
                        JSONArray(
                            tuple(
                                JSONObject(
                                    (
                                        ("code", diagnostic.code),
                                        ("offset", diagnostic.offset),
                                        ("raw_id", diagnostic.raw_id),
                                    )
                                )
                                for diagnostic in bm_render.diagnostics
                            )
                        ),
                    ),
                )
            )
            unsupported |= bool(pattern_issues)
            for issue in pattern_issues:
                issues.append(
                    SemanticIssue(
                        issue.code,
                        issue.message,
                        (("subsignature_index", index), *issue.details),
                    )
                )

            rejecting_scans = tuple(
                operation
                for operation in interpret_bm_pattern(pattern).operations
                if isinstance(operation, BmScan)
                and operation.token.raw_id == 0x09
                and operation.token.dispatch_id == 0x09
            )
            rejection_dominates_render_diagnostics = (
                bm_candidate_disposition is not None
                and dict(bm_candidate_disposition.items)["status"]
                == "exact_no_candidate"
                and dict(bm_candidate_disposition.items)["stage"] == "matcher"
                and bool(bm_render.diagnostics)
                and not pattern_issues
                and not bm_render.requirements
                and all(
                    diagnostic.code == "unsupported.backward_scan"
                    and diagnostic.raw_id == 0x09
                    for diagnostic in bm_render.diagnostics
                )
                and {
                    (diagnostic.offset, diagnostic.raw_id)
                    for diagnostic in bm_render.diagnostics
                }
                == {
                    (operation.offset, operation.token.raw_id)
                    for operation in rejecting_scans
                }
            )
            unsupported_render_diagnostic = (
                bool(bm_render.diagnostics)
                and not rejection_dominates_render_diagnostics
            )
            if (
                any(
                    isinstance(operation, BmOpaque)
                    for operation in interpret_bm_pattern(pattern).operations
                )
                or unsupported_render_diagnostic
            ):
                unsupported = True
                issues.append(
                    SemanticIssue(
                        "unsupported_bm_operation",
                        "At least one BM operation has no confirmed semantics.",
                        (("subsignature_index", index),),
                    )
                )
            if bm_render.fidelity.value == "conditional" or bm_render.requirements:
                unsupported = True
                issues.append(
                    SemanticIssue(
                        "bm_match_context_unconfirmed",
                        "BM lowering still requires matcher context not established by this export.",
                        (("subsignature_index", index),),
                    )
                )

        effective_candidate_disposition = _compose_candidate_disposition(
            candidate_disposition,
            bm_candidate_disposition,
        )

        flags_data = (
            None
            if subsig.flags is None
            else JSONObject(
                (
                    ("value", subsig.flags.value),
                    (
                        "raw_span",
                        JSONObject(
                            (("offset", flags_offset), ("length", flags_length))
                        ),
                    ),
                    ("raw_hex", subsig.flags.raw.hex()),
                    ("known_names", JSONArray(meaning.flag_names)),
                    (
                        "contextual_bits",
                        JSONArray(
                            tuple(
                                JSONObject(
                                    (
                                        ("mask", mask),
                                        ("name", f"BIT_{mask:04X}"),
                                        (
                                            "effects",
                                            JSONArray(
                                                tuple(
                                                    effect
                                                    for bit, effect in _CONTEXTUAL_FLAG_EFFECTS
                                                    if bit == mask
                                                )
                                            ),
                                        ),
                                    )
                                )
                                for mask in meaning.contextual_bits
                            )
                        ),
                    ),
                    ("contextual_effects", JSONArray(meaning.contextual_effects)),
                    ("unknown_bits", meaning.unknown_flag_bits),
                    (
                        "bm_option_bit_1_provenance",
                        JSONObject(
                            (
                                (
                                    "wire_decoded_bit_set",
                                    bool(subsig.flags.value & 0x80),
                                ),
                                (
                                    "wire_continuation_marker",
                                    bool(
                                        subsig.flags.raw and subsig.flags.raw[0] & 0x80
                                    ),
                                ),
                                (
                                    "runtime_may_also_be_derived_from_bm_pattern",
                                    bool(subsig.flags.value & 0x0002),
                                ),
                            )
                        ),
                    ),
                )
            )
        )
        subsignatures.append(
            JSONObject(
                (
                    ("index", index),
                    (
                        "raw_span",
                        JSONObject((("offset", start), ("length", len(subsig.raw)))),
                    ),
                    ("raw_hex", subsig.raw.hex()),
                    ("tag", subsig.tag),
                    ("tag_raw_hex", parsed.raw[start : start + 2].hex()),
                    ("data_length", len(subsig.data)),
                    ("flags", flags_data),
                    (
                        "data_raw_span",
                        JSONObject(
                            (("offset", data_offset), ("length", len(subsig.data)))
                        ),
                    ),
                    ("data_raw_hex", subsig.data.hex()),
                    ("kind", meaning.kind),
                    ("matching", meaning.matching),
                    ("data_shape", meaning.display_encoding),
                    ("bm_pattern", pattern_data),
                    (
                        "bm_buffer_reader_rejecting_operations",
                        bm_buffer_reader_rejecting_operations,
                    ),
                    ("bm_candidate_disposition", bm_candidate_disposition),
                    ("bm_runtime_context", bm_runtime_context),
                    ("candidate_disposition", candidate_disposition),
                    (
                        "effective_candidate_disposition",
                        effective_candidate_disposition,
                    ),
                    ("bm_yara", bm_yara_data),
                )
            )
        )
        framing.append(_raw_field(f"subsignature[{index}]", subsig.raw, start))
        cursor += len(subsig.raw)

    if parsed.tail_word0 is not None:
        framing.append(
            _raw_field("tail_word0", parsed.raw[cursor : cursor + 2], cursor)
        )
        cursor += 2
    if parsed.tail_word1 is not None:
        framing.append(
            _raw_field("tail_word1", parsed.raw[cursor : cursor + 2], cursor)
        )
        cursor += 2
    framing.append(_raw_field("trailing", parsed.trailing_raw, cursor))
    if parsed.trailing_raw:
        unsupported = True
        issues.append(
            SemanticIssue(
                "trailing_bytes_uninterpreted",
                "Bytes after the confirmed HSTR fields are retained without semantics.",
                (("length", len(parsed.trailing_raw)),),
            )
        )

    data = JSONObject(
        (
            ("raw_hex", parsed.raw.hex()),
            ("semantic_scope", "generic_matcher_subset_not_detection"),
            (
                "scope_excludes",
                JSONArray(
                    (
                        "tag_score_aggregation_and_thresholds",
                        "report_gates_and_match_levels",
                        "validator_outcomes",
                        "final_detection_verdict",
                    )
                ),
            ),
            ("framing", JSONArray(tuple(framing))),
            ("type_byte", parsed.type_byte),
            ("family", _FAMILY_NAMES[parsed.type_byte]),
            ("header_word0", parsed.header_word0),
            ("header_word1", parsed.header_word1),
            ("name_raw_hex", parsed.name_raw.hex()),
            ("subsignature_count", len(parsed.subsignatures)),
            ("subsignatures", JSONArray(tuple(subsignatures))),
            ("tail_word0", parsed.tail_word0),
            ("tail_word1", parsed.tail_word1),
            ("trailing_raw_hex", parsed.trailing_raw.hex()),
            ("receiver_ignored", parsed.receiver_ignored),
            ("scanner_context", _hstr_scanner_context(parsed.type_byte)),
        )
    )
    claims, claim_evidence = _hstr_typed_semantics(parsed)
    legacy_evidence = [
        "mpengine 1.443.903.0 hstr_internal_push_ex @ 0x1800FDA6C",
        "mpengine 1.443.903.0 add_sstring_internal @ 0x1800FE008",
    ]
    consumer_locator = _HSTR_CONSUMER_LOCATORS.get(parsed.type_byte)
    if consumer_locator is not None:
        legacy_evidence.extend(
            (
                "mpengine 1.443.903.0 hstr_internal_search_worker @ 0x1800E9F70",
                f"mpengine 1.443.903.0 family-specific consumer: {consumer_locator}",
            )
        )
    has_bm_subsignature = any(
        subsig.flags is not None and subsig.flags.value & 0x0002
        for subsig in parsed.subsignatures
    )
    if consumer_locator is not None and has_bm_subsignature:
        legacy_evidence.extend(
            (
                "mpengine 1.443.903.0 BMMatchEx2 @ 0x1800EC420",
                (
                    "mpengine 1.443.903.0 BMMatchWorker_BMSBufferReader_ "
                    "@ 0x1800EDB60: raw opcode 0x03 reads two widths and tries "
                    "non-overlapping chunks with a recursively matched shared "
                    "suffix (0x1800EE4A1-0x1800EE55F)"
                ),
                (
                    "mpengine 1.443.903.0 BMMatchWorker_BMSBufferReader_ "
                    "@ 0x1800EDB60: dispatch 0x09 is absent from the handler "
                    "cases and reaches default false at 0x1800EDECB; HSTR "
                    "BMMatchEx2 at 0x1800EA2F9 uses this worker"
                ),
                "mpengine 1.443.903.0 BMPatternToLower @ 0x1800FECFC",
                (
                    "mpengine 1.443.903.0 BM_MAP_LOWCASE selected when HSTR "
                    "flags bit0 is clear"
                ),
            )
        )
    report_locator = _HSTR_REPORT_LOCATORS.get(parsed.type_byte)
    if report_locator is not None:
        legacy_evidence.append(
            f"mpengine 1.443.903.0 family-specific report route: {report_locator}"
        )
    if parsed.type_byte in {0x61, 0x78, 0x85}:
        legacy_evidence.append(
            "mpengine 1.443.903.0 "
            "PefileExtendedAttributesValidator::ValidateAttribute "
            "@ 0x1800E94C0: exact validator mask 0x10 calls "
            "mmap_is_dynamic_page(pe_vars, base + match_offset)"
        )
    return RuleSemantics(
        status=(
            "ignored"
            if parsed.receiver_ignored
            else "unsupported"
            if unsupported
            else "confirmed_subset"
        ),
        representation="hstr.matcher-subset.ir.v10",
        data=data,
        evidence=tuple(legacy_evidence),
        profile="mpengine-1.443.903.0",
        issues=tuple(issues),
        claims=claims,
        claim_evidence=claim_evidence,
    )


def _parser_for(type_byte: int) -> Callable[[bytes], HstrPayload]:
    def parser(payload: bytes) -> HstrPayload:
        return parse_hstr(payload, type_byte=type_byte)

    return parser


HSTR_SPECS = tuple(
    FamilySpec(
        type_byte,
        name,
        _parser_for(type_byte),
        render_hstr,
        semantic_exporter=export_hstr_semantics,
    )
    for type_byte, name in _FAMILY_NAMES.items()
)
