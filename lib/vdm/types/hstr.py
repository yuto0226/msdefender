import json
from collections.abc import Callable
from dataclasses import dataclass
from types import MappingProxyType
from typing import Literal

from ..bm import (
    BmPattern,
    decode_bm_pattern,
    render_printable_bytes_preview,
)
from ..bm_yara import BmYaraRender, render_bm_yara
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
from ..core import DisplaySection, FamilySpec, Field, FormatResult


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


@dataclass(frozen=True, slots=True)
class HstrSubsignatureMeaning:
    """A conservative interpretation, separate from the lossless wire model."""

    kind: Literal["LITERAL", "BM_PATTERN", "BINARY", "OPAQUE"]
    matching: Literal["ASCII_FOLD_AZ", "BYTE_EXACT", "BM_PATTERN", "UNKNOWN"]
    display_encoding: Literal["ASCII", "UTF16LE", "HEX"]
    display_text: str | None
    flag_names: tuple[str, ...]
    unknown_flag_bits: int
    tag_int16: int
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


def classify_hstr_subsignature(subsig: HstrSubsignature) -> HstrSubsignatureMeaning:
    """Classify display bytes without deriving matcher behavior from their shape."""
    flags = subsig.flags.value if subsig.flags is not None else 0
    names = tuple(name for mask, name in _FLAG_NAMES if flags & mask)
    unknown = flags & ~_KNOWN_FLAG_MASK
    encoding, text = _text_display(subsig.data)
    # BM bytes stay hex even if every byte happens to be printable.
    if flags & 0x0002:
        kind = "BM_PATTERN"
        encoding, text = "HEX", None
        matching = "UNKNOWN" if unknown else "BM_PATTERN"
    elif unknown or not subsig.data:
        kind, matching = "OPAQUE", "UNKNOWN"
    else:
        kind = "BINARY" if encoding == "HEX" else "LITERAL"
        matching = "BYTE_EXACT" if flags & 0x0001 else "ASCII_FOLD_AZ"
    signed = subsig.tag - 0x10000 if subsig.tag & 0x8000 else subsig.tag
    return HstrSubsignatureMeaning(
        kind=kind,
        matching=matching,
        display_encoding=encoding,
        display_text=text,
        flag_names=names,
        unknown_flag_bits=unknown,
        tag_int16=signed,
        # The confirmed add path supports positive weights; a signed view alone
        # does not establish a negative-score effect for high-bit wire values.
        score_add=subsig.tag if signed >= 0 else None,
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
        classify_hstr_subsignature(subsig) for subsig in parsed.subsignatures
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


def _render_hstr_subsignature_display(
    subsig: HstrSubsignature, meaning: HstrSubsignatureMeaning
) -> tuple[str, BmPattern | None, BmYaraRender | None, str | None, tuple[str, ...]]:
    """Present wire bytes consistently; modifiers require confirmed semantics."""
    if meaning.kind == "BM_PATTERN":
        pattern = decode_bm_pattern(subsig.data)
        rendered = render_bm_yara(pattern)
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
        meaning = classify_hstr_subsignature(subsig)
        tag_note = (
            f"score +{meaning.score_add}"
            if meaning.score_add is not None
            else f"int16 {meaning.tag_int16}"
        )
        if subsig.flags is None:
            flags_text = "NOT_PRESENT"
        else:
            names = list(meaning.flag_names)
            if meaning.unknown_flag_bits:
                names.append(f"UNKNOWN_BITS(0x{meaning.unknown_flag_bits:04X})")
            flags_text = "|".join(names) or "NONE"
            flags_text += f"(0x{subsig.flags.value:04X})"
        display, pattern, bm_yara, printable_preview, yara_unsupported = (
            _render_hstr_subsignature_display(subsig, meaning)
        )
        rows: list[Field] = [
            ("identifier", scores.identifiers[index]),
            ("tag", f"0x{subsig.tag:04X} ({tag_note})"),
            ("flags", flags_text),
            ("matching", meaning.matching),
            ("display", display),
            ("raw", subsig.data.hex(" ").upper() or "(empty)"),
        ]
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
            ("name", json.dumps(parsed.name_raw.decode("latin-1"), ensure_ascii=False)),
            ("name_raw", parsed.name_raw.hex(" ").upper() or "(empty)"),
            ("subsig_count", str(len(parsed.subsignatures))),
            (
                "tail_word0",
                f"0x{parsed.tail_word0:04X} (semantics unresolved)"
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


def _parser_for(type_byte: int) -> Callable[[bytes], HstrPayload]:
    def parser(payload: bytes) -> HstrPayload:
        return parse_hstr(payload, type_byte=type_byte)

    return parser


HSTR_SPECS = tuple(
    FamilySpec(type_byte, name, _parser_for(type_byte), render_hstr)
    for type_byte, name in _FAMILY_NAMES.items()
)
