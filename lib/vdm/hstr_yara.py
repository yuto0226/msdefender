"""Fail-closed YARA artifact for one selected ARHSTR_EXT search subject."""

import hashlib
import json

from .bm import decode_bm_pattern
from .bm_yara import BmYaraFidelity
from .condition import evaluate
from .core import Artifact, ArtifactExport, semantic_json_to_data
from .types.hstr import (
    HstrPayload,
    _hstr_scanner_context,
    _render_hstr_bm_yara,
    classify_hstr_subsignature,
    summarize_hstr_scores,
)

PROFILE = "hstr.single-subject-pattern.v1"
_TYPE_BYTE = 0xC5
_READER_KIND = "CSMS_CALLER_BUFFER_OR_RANGES"


def _unsupported(reason: str) -> ArtifactExport:
    return ArtifactExport("unsupported", reason=reason)


def export_hstr_yara(parsed: HstrPayload) -> ArtifactExport:
    """Emit a pattern candidate for the exact caller-selected subject span only."""
    if parsed.type_byte != _TYPE_BYTE:
        return _unsupported(
            "unsupported_family: only ARHSTR_EXT (0xC5) has this subject profile"
        )
    scanner_context = _hstr_scanner_context(parsed.type_byte)
    if (
        scanner_context is None
        or _READER_KIND not in dict(scanner_context.items)["reader_kinds"].items
    ):
        return _unsupported("unconfirmed_subject_contract")
    if parsed.receiver_ignored:
        return _unsupported("receiver_ignored: subsignature flags exceed 0x03FF")
    if len(parsed.subsignatures) != 1:
        return _unsupported(
            "subsignature_count: profile requires exactly one subsignature"
        )
    # The observed zero tail_word0 cannot trigger the nonzero-gated candidate
    # sort. Its wider report meaning remains outside this pattern candidate.
    if parsed.tail_word0 != 0 or parsed.tail_word1 is not None:
        return _unsupported(
            "tail_words: profile requires zero tail_word0 and absent tail_word1"
        )
    if parsed.trailing_raw:
        return _unsupported("trailing_raw: uninterpreted bytes are present")

    subsig = parsed.subsignatures[0]
    if not subsig.data:
        return _unsupported("empty_subsignature_data")
    if subsig.flags is None:
        return _unsupported("missing_subsignature_flags")
    meaning = classify_hstr_subsignature(subsig, type_byte=parsed.type_byte)
    if meaning.unknown_flag_bits:
        return _unsupported("unknown_subsignature_flags")
    if meaning.contextual_bits:
        return _unsupported("contextual_subsignature_flags: validator or context gate")
    # 0x0100 creates an additional wide-copy candidate. Only the two direct
    # matcher flag combinations are in this profile.
    if subsig.flags.value not in (0x0001, 0x0002, 0x0003):
        return _unsupported("subsignature_flags: matcher behavior is outside profile")

    scores = summarize_hstr_scores(parsed)
    condition = scores.combined_condition
    if condition is None or len(scores.identifiers) != 1:
        return _unsupported("score_condition: combined eligibility is unavailable")
    atom = scores.identifiers[0]
    # Check the Boolean function, not the displayed AST or the thresholds alone.
    if evaluate(condition, frozenset()) or not evaluate(condition, frozenset((atom,))):
        return _unsupported(
            "score_condition: combined eligibility is not the single atom"
        )

    if subsig.flags.value & 0x0002:
        if meaning.matching != "BM_PATTERN":
            return _unsupported("bm_matching: unconfirmed matcher interpretation")
        bm = decode_bm_pattern(subsig.data)
        rendered, runtime_context, _ = _render_hstr_bm_yara(subsig, bm)
        if (
            rendered.fidelity is not BmYaraFidelity.EXACT
            or rendered.body is None
            or rendered.requirements
            or rendered.diagnostics
        ):
            details = ",".join(issue.code for issue in rendered.diagnostics)
            return _unsupported(
                "bm_yara: requires EXACT fidelity with no requirements or diagnostics"
                + (f" ({details})" if details else "")
            )
        rhs = rendered.body
        matcher = "bm_exact_selected_subject"
        matcher_context = semantic_json_to_data(runtime_context)
    else:
        if meaning.matching != "BYTE_EXACT":
            return _unsupported("literal_matching: BYTE_EXACT is required")
        rhs = "{ " + subsig.data.hex(" ").upper() + " }"
        matcher = "literal_byte_exact_selected_subject"
        matcher_context = {"translation": "identity", "reader_kind": "BUFFER"}

    digest = hashlib.sha256(parsed.raw).hexdigest()
    stem = f"c5-{digest}"
    rule_name = f"HSTR_C5_{digest}"
    rule = (
        "// Selected-subject pattern candidate. Scan exactly one caller-selected span.\n"
        "// A whole-file scan is valid only if that span is exactly the whole file.\n"
        f"rule {rule_name} {{\n"
        "    meta:\n"
        f'        profile = "{PROFILE}"\n'
        '        artifact_scope = "selected-subject pattern candidate"\n'
        f'        subject_contract = "{_READER_KIND}: exact same caller-selected span"\n'
        '        cross_boundary_match = "forbidden"\n'
        '        report_mapping = "unknown"\n'
        f'        source_type = "0x{parsed.type_byte:02X}"\n'
        f'        payload_sha256 = "{digest}"\n'
        "    strings:\n"
        f"        $subject = {rhs}\n"
        "    condition:\n"
        "        $subject\n"
        "}\n"
    )
    contract = {
        "profile": PROFILE,
        "artifact_scope": "selected-subject pattern candidate",
        "record": {
            "type_byte": parsed.type_byte,
            "type_name": "ARHSTR_EXT",
            "payload_raw_hex": parsed.raw.hex(),
            "payload_sha256": digest,
            "tail_word0": parsed.tail_word0,
            "tail_word1": parsed.tail_word1,
        },
        "rule": {
            "name": rule_name,
            "file": f"{stem}.subject.yar",
            "matcher": matcher,
            "matcher_context": matcher_context,
        },
        "subject_contract": {
            "scanner_contract": _READER_KIND,
            "input": "caller-selected single subject span",
            "requires_caller_selects_exact_same_subject_span": True,
            "cross_boundary_match": False,
            "whole_file_only_if_selected_span_is_whole_file": True,
        },
        "tail_word0_scope": (
            "zero in the observed record; the known candidate ordering branch "
            "requires a nonzero value, and report effects are outside this artifact"
        ),
        "score_condition": {
            "atom": atom,
            "empty_match": False,
            "single_atom_match": True,
            "basis": "combined_condition evaluated over all two single-atom assignments",
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
