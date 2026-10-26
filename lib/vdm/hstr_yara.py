"""Fail-closed YARA score eligibility for one selected HSTR subject."""

import hashlib
import json
import re

from .bm import decode_bm_pattern
from .bm_yara import (
    MAX_YARA_REGEX_MATCH_BYTES,
    MAX_YARA_REGEX_RHS_CHARS,
    BmYaraFidelity,
)
from .condition import _atom_identifiers, render_yara
from .core import Artifact, ArtifactExport, semantic_json_to_data
from .types.hstr import (
    EXPORT_PROJECTION_LIMITS,
    HstrPayload,
    HstrSubsignature,
    _hstr_scanner_context,
    _render_hstr_bm_yara,
    classify_hstr_subsignature,
    summarize_hstr_scores,
)

PROFILE = "hstr.selected-subject-score.v2"
_SUPPORTED_PROFILES = {
    0xC5: {
        "type_name": "ARHSTR_EXT",
        "reader_kinds": ("CSMS_CALLER_BUFFER_OR_RANGES",),
        "scanner_contract": "CSMS_CALLER_BUFFER_OR_RANGES",
        "input": "caller-selected single subject buffer",
    },
    0x8C: {
        "type_name": "ELFHSTR_EXT",
        "reader_kinds": ("ELF_CALLER_RANGE", "ELF_SEGMENT_INTERVAL"),
        "scanner_contract": "ELF_CALLER_RANGE | ELF_SEGMENT_INTERVAL",
        "input": "caller-selected single ELF subject span",
    },
    0x8F: {
        "type_name": "MACROHSTR_EXT",
        "reader_kinds": ("MACRO_CALLER_BUFFER",),
        "scanner_contract": "MACRO_CALLER_BUFFER",
        "input": "caller-selected single actual Macro API buffer",
    },
}
_LOWERCASE_HEX_TOKEN = re.compile(
    r"\( [0-9A-F]{2} \| [0-9A-F]{2} \)|\[[0-9]+(?:-[0-9]+)?\]|[0-9A-F]{2}"
)
_BYTE_ALTERNATIVE_HEX_TOKEN = re.compile(
    r"\( [0-9A-F]{2}(?: \| [0-9A-F]{2})+ \)|\[[0-9]+(?:-[0-9]+)?\]|[0-9A-F]{2}"
)


def _unsupported(reason: str) -> ArtifactExport:
    return ArtifactExport("unsupported", reason=reason)


class _BmRegexBackendLimit(ValueError):
    """A recognized lowering exceeds a YARA backend limit, not its grammar."""


def _check_regex_segment(maximum_bytes: int) -> None:
    if maximum_bytes > MAX_YARA_REGEX_MATCH_BYTES:
        raise _BmRegexBackendLimit("bm_yara: regex_span_limit")


def _regex_rhs(parts: list[str], *, dotall: bool = False) -> str:
    content = "".join(parts)
    if len(content) + 2 > MAX_YARA_REGEX_RHS_CHARS:
        raise _BmRegexBackendLimit("bm_yara: regex_lexer_limit")
    return "/" + content + ("/s" if dotall else "/")


def _flat_hex_tokens_to_regex(
    tokens: list[str], *, lowercase_pairs: bool = False
) -> str:
    """Lower the flat byte/class/jump grammar with YARA verification budgets.

    Lazy dot ranges become RE_NODE_RANGE_ANY. libyara splits a root concat at
    such a node only when both neighbors exist and either bound exceeds 200
    (re.c:yr_re_ast_split_at_chaining_point). A class covering all bytes does
    not receive this treatment. Track each resulting verification segment.
    """
    parts = []
    maximum_bytes = 0
    segment_start = 0
    dotall = False
    for index, token in enumerate(tokens):
        if token.startswith("["):
            bounds = [int(value) for value in token[1:-1].split("-")]
            maximum = bounds[-1]
            if maximum > 32767:
                raise _BmRegexBackendLimit("bm_yara: regex_interval_limit")
            if maximum > 200 and index > segment_start and index + 1 < len(tokens):
                _check_regex_segment(maximum_bytes)
                maximum_bytes = 0
                segment_start = index + 1
            else:
                maximum_bytes += maximum
            parts.append(".{" + ",".join(map(str, bounds)) + "}?")
            dotall = True
        elif token.startswith("("):
            values = sorted({int(value, 16) for value in token[2:-2].split(" | ")})
            if lowercase_pairs:
                if not (
                    len(values) == 2
                    and 0x41 <= values[0] <= 0x5A
                    and values[1] == values[0] + 0x20
                ):
                    raise ValueError("bm_yara: invalid ASCII lowercase choice")
                parts.append(f"[{chr(values[0])}{chr(values[1])}]")
            else:
                ranges = []
                start = end = values[0]
                for value in values[1:]:
                    if value == end + 1:
                        end = value
                    else:
                        ranges.append((start, end))
                        start = end = value
                ranges.append((start, end))
                parts.append(
                    "["
                    + "".join(
                        f"\\x{start:02X}" + (f"-\\x{end:02X}" if start != end else "")
                        for start, end in ranges
                    )
                    + "]"
                )
            maximum_bytes += 1
        else:
            parts.append(f"\\x{token}")
            maximum_bytes += 1
    _check_regex_segment(maximum_bytes)
    return _regex_rhs(parts, dotall=dotall)


def _lowercase_hex_to_regex(body: str) -> str:
    """Compact only the EXACT lowercase literal/jump hex grammar into byte regex."""
    if not body.startswith("{ ") or not body.endswith(" }"):
        raise ValueError("bm_yara: unrecognized lowercase hex body")
    inner = body[2:-2]
    tokens = _LOWERCASE_HEX_TOKEN.findall(inner)
    if " ".join(tokens) != inner:
        raise ValueError("bm_yara: unrecognized lowercase hex token")
    return _flat_hex_tokens_to_regex(tokens, lowercase_pairs=True)


def _ascii_fold_literal_regex(data: bytes) -> str:
    """Match a fixed byte sequence after ASCII A-Z folding on both sides."""
    _check_regex_segment(len(data))
    parts = []
    for byte in data:
        if 0x41 <= byte <= 0x5A or 0x61 <= byte <= 0x7A:
            upper = byte & ~0x20
            parts.append(f"[{chr(upper)}{chr(upper + 0x20)}]")
        else:
            parts.append(f"\\x{byte:02X}")
    return _regex_rhs(parts)


def _compact_byte_alternatives(body: str) -> str:
    """Replace single-byte hex ORs with exact byte classes, without RE splits.

    Only literal bytes, finite jumps and flat single-byte alternatives are
    accepted. Other EXACT BM grammars retain their original lowering.
    """
    if not body.startswith("{ ") or not body.endswith(" }"):
        return body
    inner = body[2:-2]
    tokens = _BYTE_ALTERNATIVE_HEX_TOKEN.findall(inner)
    if " ".join(tokens) != inner or not any(t.startswith("(") for t in tokens):
        return body
    return _flat_hex_tokens_to_regex(tokens)


def _matcher_rhs(subsig: HstrSubsignature, type_byte: int) -> tuple[str, str, dict]:
    """Lower one complete subsignature, or reject the whole record."""
    if not subsig.data:
        raise ValueError("empty_subsignature_data")
    if subsig.flags is None:
        raise ValueError("missing_subsignature_flags")
    meaning = classify_hstr_subsignature(subsig, type_byte=type_byte)
    if meaning.unknown_flag_bits:
        raise ValueError("unknown_subsignature_flags")
    if meaning.contextual_bits:
        raise ValueError("contextual_subsignature_flags: validator or context gate")
    if subsig.flags.value not in (0x0000, 0x0001, 0x0002, 0x0003):
        raise ValueError("subsignature_flags: matcher behavior is outside profile")

    if subsig.flags.value & 0x0002:
        if meaning.matching != "BM_PATTERN":
            raise ValueError("bm_matching: unconfirmed matcher interpretation")
        rendered, runtime_context, _ = _render_hstr_bm_yara(
            subsig, decode_bm_pattern(subsig.data)
        )
        if (
            rendered.fidelity is not BmYaraFidelity.EXACT
            or rendered.body is None
            or rendered.requirements
            or rendered.diagnostics
        ):
            details = ",".join(issue.code for issue in rendered.diagnostics)
            raise ValueError(
                "bm_yara: requires EXACT fidelity with no requirements or diagnostics"
                + (f" ({details})" if details else "")
            )
        context = semantic_json_to_data(runtime_context)
        body = rendered.body
        if context["translation"] == "ascii_lowercase":
            try:
                body = _lowercase_hex_to_regex(body)
            except _BmRegexBackendLimit:
                raise
            except ValueError:
                pass  # An unrecognized EXACT body keeps the original BM lowering.
        body = _compact_byte_alternatives(body)
        # Generated hex literals spell byte 0x7C as "7C"; every remaining
        # vertical bar is an ALT split. Preserve unfamiliar hex grammars only
        # within libyara's known split-ID limit.
        if body.startswith("{ ") and body.count("|") > 128:
            raise _BmRegexBackendLimit("bm_yara: regex_complexity_limit")
        return body, "bm_exact_selected_subject", context

    if subsig.flags.value == 0:
        if meaning.matching != "ASCII_FOLD_AZ":
            raise ValueError("literal_matching: ASCII_FOLD_AZ is required")
        return (
            _ascii_fold_literal_regex(subsig.data),
            "literal_ascii_fold_selected_subject",
            {"translation": "ascii_lowercase", "reader_kind": "BUFFER"},
        )

    if meaning.matching != "BYTE_EXACT":
        raise ValueError("literal_matching: BYTE_EXACT is required")
    return (
        "{ " + subsig.data.hex(" ").upper() + " }",
        "literal_byte_exact_selected_subject",
        {"translation": "identity", "reader_kind": "BUFFER"},
    )


def export_hstr_yara(parsed: HstrPayload) -> ArtifactExport:
    """Emit score eligibility for one fresh, static, caller-selected span."""
    profile = _SUPPORTED_PROFILES.get(parsed.type_byte)
    if profile is None:
        return _unsupported("unsupported_family: no selected-subject profile")
    scanner_context = _hstr_scanner_context(parsed.type_byte)
    if scanner_context is None:
        return _unsupported("unconfirmed_subject_contract")
    context = dict(scanner_context.items)
    if not (
        set(profile["reader_kinds"]).issubset(set(context["reader_kinds"].items))
        and context["search_mode"] == 1
        and context["validator_argument"] is None
    ):
        return _unsupported("unconfirmed_subject_contract")
    if parsed.receiver_ignored:
        return _unsupported("receiver_ignored: subsignature flags exceed 0x03FF")
    if not parsed.subsignatures:
        return _unsupported("subsignature_count: at least one is required")
    # The observed zero tail_word0 cannot trigger the nonzero-gated candidate
    # sort. Its wider report meaning remains outside this eligibility artifact.
    if parsed.tail_word0 != 0 or parsed.tail_word1 is not None:
        return _unsupported(
            "tail_words: profile requires zero tail_word0 and absent tail_word1"
        )
    if parsed.trailing_raw:
        return _unsupported("trailing_raw: uninterpreted bytes are present")
    if not 0 < parsed.header_word1 <= parsed.header_word0:
        return _unsupported("score_thresholds: positive ordered headers are required")
    weights = tuple(subsig.tag for subsig in parsed.subsignatures)
    if any(weight <= 0 or weight > 0x7FFF for weight in weights):
        return _unsupported("score_weights: positive signed WORD tags are required")
    if sum(weights) > 0x7FFF:
        return _unsupported("score_weights: sum exceeds signed WORD range")
    scores = summarize_hstr_scores(parsed, limits=EXPORT_PROJECTION_LIMITS)
    identifiers = scores.identifiers
    condition = scores.combined_condition
    if len(identifiers) != len(parsed.subsignatures):
        return _unsupported("score_condition: identifier count is inconsistent")
    strings = []
    matchers = []
    for index, (identifier, subsig) in enumerate(
        zip(identifiers, parsed.subsignatures, strict=True)
    ):
        try:
            rhs, matcher, context = _matcher_rhs(subsig, parsed.type_byte)
        except ValueError as exc:
            return _unsupported(f"subsignature[{index}]: {exc}")
        strings.append(f"        {identifier} = {rhs}\n")
        matchers.append(
            {
                "index": index,
                "identifier": identifier,
                "weight": subsig.tag,
                "matcher": matcher,
                "matcher_context": context,
            }
        )
    if condition is None:
        return _unsupported("score_condition: combined eligibility is unavailable")
    # YARA rejects an unreferenced string. A simplified AST may omit one;
    # fail closed instead of silently dropping that subsignature.
    if _atom_identifiers(condition) != frozenset(identifiers):
        return _unsupported("score_condition: not all subsignatures are referenced")
    digest = hashlib.sha256(parsed.raw).hexdigest()
    stem = f"{parsed.type_byte:02x}-{digest}"
    rule_name = f"HSTR_{parsed.type_byte:02X}_{digest}"
    expression = render_yara(condition)
    rule = (
        "// Selected-subject score eligibility; scan one fresh caller-selected span.\n"
        "// Multiple ranges, reused hit state, and Defender verdict are outside scope.\n"
        f"rule {rule_name} {{\n"
        "    meta:\n"
        f'        profile = "{PROFILE}"\n'
        '        artifact_scope = "selected-subject score eligibility"\n'
        f'        subject_contract = "{profile["scanner_contract"]}: fresh state, exact single span"\n'
        '        candidate_enumeration = "caller must ensure ordinary trie enumeration; AMS equivalence unproven"\n'
        + (
            '        state_precondition = "externally ensured fresh empty hit container; RPF API does not guarantee per-call reset"\n'
            '        macro_scope = "single actual caller buffer; preprocessing, selection, offset policy and reporting excluded"\n'
            if parsed.type_byte == 0x8F
            else ""
        )
        + '        cross_boundary_match = "forbidden"\n'
        '        report_mapping = "unknown"\n'
        f'        source_type = "0x{parsed.type_byte:02X}"\n'
        f'        payload_sha256 = "{digest}"\n'
        "    strings:\n" + "".join(strings) + "    condition:\n"
        f"        {expression}\n"
        "}\n"
    )
    contract = {
        "profile": PROFILE,
        "artifact_scope": "selected-subject score eligibility",
        "record": {
            "type_byte": parsed.type_byte,
            "type_name": profile["type_name"],
            "payload_raw_hex": parsed.raw.hex(),
            "payload_sha256": digest,
            "header_word0": parsed.header_word0,
            "header_word1": parsed.header_word1,
            "tail_word0": parsed.tail_word0,
            "tail_word1": parsed.tail_word1,
        },
        "rule": {
            "name": rule_name,
            "file": f"{stem}.subject.yar",
            "subsignatures": matchers,
        },
        "subject_contract": {
            "scanner_contract": profile["scanner_contract"],
            "reader_kinds": profile["reader_kinds"],
            "input": profile["input"],
            "requires_caller_selects_exact_same_subject_span": True,
            "requires_fresh_empty_hit_container": True,
            "requires_ordinary_trie_candidate_enumeration": True,
            "ams_candidate_equivalence": "unproven",
            "search_mode": 1,
            "dynamic_mask": 0,
            "static_hit_key_mask": 0,
            "dynamic_hit_key_mask": 0x80000000,
            "static_and_dynamic_rows_are_separate": True,
            "one_contribution_per_logical_subsignature_and_mask_key": True,
            "repeat_occurrences_do_not_rescore": True,
            "cross_boundary_match": False,
            "cross_range_aggregation_in_scope": False,
            "whole_file_only_if_selected_span_is_whole_file": True,
            **(
                {
                    "elf_caller_offset": "runtime_unknown",
                    "span_selection": "runtime_unknown",
                    "requires_elf_caller_gates": True,
                    "region_chunk_or_segment_interval": "one actual reader buffer",
                    "cross_chunk_or_interval_aggregation_in_scope": False,
                }
                if parsed.type_byte == 0x8C
                else {}
            ),
            **(
                {
                    "position_context": "zero-initialized fields in selected API",
                    "upstream_subject_selection": "runtime_unknown",
                    "requires_macro_caller_gates": True,
                    "macro_caller_gates": "actual byte span selection and API applicability",
                    "state_lifecycle": "caller_owned_unknown",
                    "fresh_state_is_external_precondition": True,
                    "rpf_api_guarantees_fresh_hit_container_per_call": False,
                    "macro_preprocessing_in_scope": False,
                    "macro_selection_in_scope": False,
                    "macro_offset_policy_in_scope": False,
                    "macro_reporting_in_scope": False,
                    "cross_call_aggregation_in_scope": False,
                }
                if parsed.type_byte == 0x8F
                else {}
            ),
        },
        "tail_word0_scope": (
            "zero in the observed record; the known candidate ordering branch "
            "requires a nonzero value, and report effects are outside this artifact"
        ),
        "score_condition": {
            "expression": expression,
            "identifiers": identifiers,
            "weights": weights,
            "threshold": parsed.header_word1,
            "level1_threshold": parsed.header_word0,
            "maximum_once": scores.maximum_once,
            "basis": "first hit per logical subsignature contributes its positive tag once to the static row",
        },
        "defender_detection_equivalence": None,
        "report_mapping": "unknown",
        "scanner_outcome": "unknown",
    }
    contract_data = (
        json.dumps(contract, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")
    return ArtifactExport(
        "ready",
        artifacts=(
            Artifact(
                f"{stem}.subject.yar",
                "hstr_selected_subject_yara",
                rule.encode("utf-8"),
            ),
            Artifact(
                f"{stem}.subject.contract.json", "hstr_subject_contract", contract_data
            ),
        ),
    )
