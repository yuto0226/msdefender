"""Lossless wire parser for LATENT_THREAT (0x69) payloads."""

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

LATENT_THREAT_TYPE: Final = 0x69
PAYLOAD_SIZE: Final = 8
WORD_SIZE: Final = 4


@dataclass(frozen=True, slots=True)
class LatentThreat:
    """Two raw 32-bit words whose precise domain is not established."""

    raw: bytes
    word_0: int
    word_1: int


def parse_latent_threat(payload: bytes) -> LatentThreat:
    """Parse the exact 8-byte payload accepted by latent_info_receiver."""
    if len(payload) < PAYLOAD_SIZE:
        raise ValueError(
            "truncated LATENT_THREAT payload: "
            f"need {PAYLOAD_SIZE} bytes, have {len(payload)}"
        )
    if len(payload) > PAYLOAD_SIZE:
        raise ValueError(
            "LATENT_THREAT payload must be exactly "
            f"{PAYLOAD_SIZE} bytes, have {len(payload)}"
        )

    return LatentThreat(
        raw=payload,
        word_0=int.from_bytes(payload[0:WORD_SIZE], "little"),
        word_1=int.from_bytes(payload[WORD_SIZE:PAYLOAD_SIZE], "little"),
    )


def render_latent_threat(parsed: LatentThreat) -> FormatResult:
    """Render raw words and the binary-confirmed runtime role of word 1."""
    return FormatResult(
        sections=(
            DisplaySection(
                "LATENT_THREAT",
                rows=(
                    ("word_0_raw", f"0x{parsed.word_0:08x}"),
                    ("word_1_raw", f"0x{parsed.word_1:08x}"),
                    (
                        "word_1_runtime_role",
                        "secondary threat-index gate in get_threat_match_level",
                    ),
                ),
            ),
        )
    )


def export_latent_threat_semantics(parsed: LatentThreat) -> RuleSemantics:
    """Export the confirmed two-reference resolution and runtime gate."""
    return RuleSemantics(
        status="confirmed_subset",
        representation="latent_threat.reference_gate.ir.v1",
        data=JSONObject(
            (
                ("type", "latent_threat"),
                ("raw_hex", parsed.raw.hex()),
                ("wire_length", len(parsed.raw)),
                (
                    "words",
                    JSONArray(
                        (
                            JSONObject(
                                (
                                    ("offset", 0),
                                    ("value", parsed.word_0),
                                    ("wire_role", "primary_threat_reference"),
                                    (
                                        "load_transform",
                                        "get_threat_index(reference)",
                                    ),
                                    ("runtime_role", "primary_threat_index"),
                                )
                            ),
                            JSONObject(
                                (
                                    ("offset", WORD_SIZE),
                                    ("value", parsed.word_1),
                                    ("wire_role", "secondary_threat_reference"),
                                    (
                                        "load_transform",
                                        "get_threat_index(reference)",
                                    ),
                                    (
                                        "runtime_role",
                                        "secondary_threat_index",
                                    ),
                                )
                            ),
                        )
                    ),
                ),
                (
                    "load_filter",
                    "discard_pair_if_either_get_threat_index_result_is_minus_one",
                ),
                ("lookup", "exact_primary_threat_index"),
                (
                    "gate",
                    JSONObject(
                        (
                            ("consumer", "get_threat_match_level"),
                            (
                                "condition",
                                (
                                    "secondary entry exists, is enabled, and has "
                                    "nonzero concrete level"
                                ),
                            ),
                            (
                                "effect",
                                "permit primary threat concrete match level",
                            ),
                        )
                    ),
                ),
            )
        ),
        evidence=(
            "mpengine 1.443.903.0 latent_info_receiver",
            "mpengine 1.443.903.0 fix_latent_threats",
            "mpengine 1.443.903.0 get_latent_record",
            "mpengine 1.443.903.0 get_threat_match_level",
            "mpas.sig corpus: one 8-byte LATENT_THREAT record",
        ),
        profile="mpengine-1.443.903.0",
        issues=(
            SemanticIssue(
                "corpus_pair_resolution_unknown",
                "Static analysis does not establish whether the sole observed "
                "pair survives threat-table resolution in a live engine.",
            ),
            SemanticIssue(
                "outer_report_policy_unknown",
                "The reference gate is confirmed, but the complete latent-resource "
                "reporting policy is not exported.",
            ),
        ),
        claims=(
            SemanticClaim(
                id="latent_pair_normalization",
                scope="receiver_transform",
                statement=(
                    "Both DWORD references are resolved through get_threat_index; "
                    "the pair is discarded if either lookup fails."
                ),
                coverage="subset",
                evidence_refs=("latent_receiver",),
                unknowns=(
                    SemanticUnknown(
                        "receiver_transform",
                        "Whether the observed corpus pair survives live threat-table "
                        "resolution is unresolved.",
                    ),
                ),
            ),
            SemanticClaim(
                id="latent_secondary_gate",
                scope="runtime_consumer",
                statement=(
                    "The secondary index gates the primary threat's concrete match "
                    "level through entry existence, enabled state, and nonzero level."
                ),
                coverage="subset",
                evidence_refs=("latent_gate_consumer",),
                unknowns=(
                    SemanticUnknown(
                        "runtime_consumer",
                        "All caller contexts and special threat branches are not closed.",
                    ),
                ),
            ),
            SemanticClaim(
                id="latent_detection_gate",
                scope="detection_predicate",
                statement=(
                    "For latent-marked primary threats, the secondary entry can force "
                    "the returned match level to zero."
                ),
                coverage="subset",
                evidence_refs=("latent_gate_consumer",),
                unknowns=(
                    SemanticUnknown(
                        "detection_predicate",
                        "This gate is not the complete threat detection predicate.",
                    ),
                ),
            ),
            SemanticClaim(
                id="latent_report_gate",
                scope="report_mapping",
                statement=(
                    "report_latent_threats uses the gated match level to skip or "
                    "retain a primary threat in the latent resource report path."
                ),
                coverage="subset",
                evidence_refs=("latent_report_consumer",),
                unknowns=(
                    SemanticUnknown(
                        "report_mapping",
                        "Complete report fields and all policy branches are unresolved.",
                    ),
                ),
            ),
            SemanticClaim(
                id="latent_final_verdict",
                scope="final_verdict",
                statement="The final scan verdict is not established by this pair.",
                coverage="unknown",
                unknowns=(
                    SemanticUnknown(
                        "final_verdict",
                        "The latent report/resource path is not a closed final-verdict path.",
                    ),
                ),
            ),
        ),
        claim_evidence=(
            SemanticEvidence(
                id="latent_receiver",
                axis="receiver",
                kind="engine_static",
                source_ref="mpengine 1.443.903.0",
                locator=(
                    "latent_info_receiver @ 0x1805E89B0; "
                    "fix_latent_threats @ 0x180582DBC"
                ),
                supports=("latent_pair_normalization",),
            ),
            SemanticEvidence(
                id="latent_gate_consumer",
                axis="consumer",
                kind="engine_static",
                source_ref="mpengine 1.443.903.0",
                locator=(
                    "get_latent_record @ 0x180526590; "
                    "get_threat_match_level @ 0x18012E128"
                ),
                supports=("latent_secondary_gate", "latent_detection_gate"),
            ),
            SemanticEvidence(
                id="latent_report_consumer",
                axis="report",
                kind="engine_static",
                source_ref="mpengine 1.443.903.0",
                locator="report_latent_threats @ 0x18044ABEC",
                supports=("latent_report_gate",),
            ),
        ),
    )


SPEC = FamilySpec(
    LATENT_THREAT_TYPE,
    "LATENT_THREAT",
    parse_latent_threat,
    render_latent_threat,
    semantic_exporter=export_latent_threat_semantics,
)
