"""Parser and bounded renderer for BM_ENV_VAR_MAP (0xED) payloads."""

from dataclasses import dataclass
from typing import Final

from ..core import (
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

BM_ENV_VAR_MAP_TYPE: Final = 0xED
_WORD_PREVIEW_COUNT: Final = 16
_NAME_PREVIEW_BYTES: Final = 32


@dataclass(frozen=True, slots=True)
class BMEnvVarMap:
    """Lossless name and two WORD vectors from a BM_ENV_VAR_MAP payload."""

    raw: bytes
    name_len: int
    name_raw: bytes
    vector_a_count: int
    vector_a: tuple[int, ...]
    vector_b: tuple[int, ...]


def parse_bm_env_var_map(payload: bytes) -> BMEnvVarMap:
    """Parse the engine-confirmed 0xED layout without assigning word meaning."""
    if not payload:
        raise ValueError("truncated name_len")

    name_len = payload[0]
    name_end = 1 + name_len
    if name_end > len(payload):
        raise ValueError(
            f"truncated name: need {name_len} bytes, have {len(payload) - 1}"
        )

    count_start = name_end
    count_end = count_start + 2
    if len(payload) < count_end:
        raise ValueError("truncated vector_a_count")

    vector_a_count = int.from_bytes(payload[count_start:count_end], "little")
    vector_a_end = count_end + 2 * vector_a_count
    if vector_a_end + 2 > len(payload):
        raise ValueError(
            f"truncated vector_a/vector_b_count: need {2 * vector_a_count + 2} "
            f"bytes, have {len(payload) - count_end}"
        )

    vector_a_raw = payload[count_end:vector_a_end]
    vector_b_count = int.from_bytes(payload[vector_a_end : vector_a_end + 2], "little")
    vector_b_start = vector_a_end + 2
    vector_b_end = vector_b_start + 2 * vector_b_count
    if vector_b_end > len(payload):
        raise ValueError(
            f"truncated vector_b: need {2 * vector_b_count} bytes, "
            f"have {len(payload) - vector_b_start}"
        )
    if vector_b_end != len(payload):
        raise ValueError(f"unexpected trailing bytes: {len(payload) - vector_b_end}")

    vector_b_raw = payload[vector_b_start:vector_b_end]

    vector_a = tuple(
        int.from_bytes(vector_a_raw[offset : offset + 2], "little")
        for offset in range(0, len(vector_a_raw), 2)
    )
    vector_b = tuple(
        int.from_bytes(vector_b_raw[offset : offset + 2], "little")
        for offset in range(0, len(vector_b_raw), 2)
    )

    return BMEnvVarMap(
        raw=payload,
        name_len=name_len,
        name_raw=payload[1:name_end],
        vector_a_count=vector_a_count,
        vector_a=vector_a,
        vector_b=vector_b,
    )


def _preview_words(words: tuple[int, ...]) -> str:
    preview = " ".join(f"0x{word:04x}" for word in words[:_WORD_PREVIEW_COUNT])
    if len(words) > _WORD_PREVIEW_COUNT:
        preview += f" … ({len(words) - _WORD_PREVIEW_COUNT} more words)"
    return preview or "(empty)"


def render_bm_env_var_map(parsed: BMEnvVarMap) -> FormatResult:
    """Render bounded metadata and previews; retain complete bytes in the model."""
    name_preview = parsed.name_raw[:_NAME_PREVIEW_BYTES].hex(" ")
    if len(parsed.name_raw) > _NAME_PREVIEW_BYTES:
        remaining = len(parsed.name_raw) - _NAME_PREVIEW_BYTES
        name_preview += f" … ({remaining} more bytes)"

    return FormatResult(
        fields=(
            ("name_len", str(parsed.name_len)),
            ("name_raw", name_preview or "(empty)"),
            ("vector_a_count", str(len(parsed.vector_a))),
            ("vector_a_preview", _preview_words(parsed.vector_a)),
            ("vector_b_count", str(len(parsed.vector_b))),
            ("vector_b_preview", _preview_words(parsed.vector_b)),
            ("raw_len", str(len(parsed.raw))),
        )
    )


def export_bm_env_var_map_semantics(parsed: BMEnvVarMap) -> RuleSemantics:
    """Export the confirmed receiver mutation and tokenized-path handoff."""
    name_offset = 1
    vector_a_count_offset = name_offset + len(parsed.name_raw)
    vector_a_offset = vector_a_count_offset + 2
    vector_b_count_offset = vector_a_offset + 2 * len(parsed.vector_a)
    vector_b_offset = vector_b_count_offset + 2

    def word_entries(words: tuple[int, ...], offset: int) -> JSONArray:
        return JSONArray(
            tuple(
                JSONObject(
                    (
                        ("index", index),
                        ("word_raw", word),
                        ("raw_hex", word.to_bytes(2, "little").hex()),
                        ("payload_offset", offset + index * 2),
                    )
                )
                for index, word in enumerate(words)
            )
        )

    issues = (
        SemanticIssue(
            "environment_name_lookup_not_reproduced",
            "The engine performs a case-insensitive name lookup; this exporter "
            "retains the bytes and does not duplicate the complete alias table.",
        ),
        SemanticIssue(
            "word_and_token_names_unknown",
            "WORD values and token/selector identifiers remain raw; their domain "
            "names are not established by the confirmed dataflow.",
        ),
        SemanticIssue(
            "candidate_expansion_runtime_dependent",
            "The IEnvMatch virtual methods produce wide-string candidates, but "
            "their expansion rules are not established here.",
        ),
        SemanticIssue(
            "final_detection_policy_unknown",
            "Candidate strings are passed into the general detection path; this "
            "record alone does not establish a final detection or report.",
        ),
    )
    return RuleSemantics(
        status="confirmed_subset",
        representation="bm_env_var_map.tokenized_path_manifest.v1",
        data=JSONObject(
            (
                ("record_type", BM_ENV_VAR_MAP_TYPE),
                ("raw_payload_hex", parsed.raw.hex()),
                (
                    "wire",
                    JSONObject(
                        (
                            ("name_length_offset", 0),
                            ("name_length", parsed.name_len),
                            ("name_offset", name_offset),
                            ("name_raw_hex", parsed.name_raw.hex()),
                            ("name_encoding", "unknown"),
                            ("vector_a_count_offset", vector_a_count_offset),
                            ("vector_a_count", len(parsed.vector_a)),
                            ("vector_a_offset", vector_a_offset),
                            (
                                "vector_a",
                                word_entries(parsed.vector_a, vector_a_offset),
                            ),
                            ("vector_b_count_offset", vector_b_count_offset),
                            ("vector_b_count", len(parsed.vector_b)),
                            ("vector_b_offset", vector_b_offset),
                            (
                                "vector_b",
                                word_entries(parsed.vector_b, vector_b_offset),
                            ),
                        )
                    ),
                ),
                (
                    "receiver_mutation",
                    JSONObject(
                        (
                            ("name_to_environment_id", "case_insensitive_exact_lookup"),
                            (
                                "unknown_name_effect",
                                "no_map_write_when_environment_id_is_zero",
                            ),
                            (
                                "maps",
                                JSONArray(
                                    (
                                        JSONObject(
                                            (
                                                ("vector", "a"),
                                                ("map_member_offset", 0),
                                                ("key_source", "vector_a WORD"),
                                            )
                                        ),
                                        JSONObject(
                                            (
                                                ("vector", "b"),
                                                ("map_member_offset", 16),
                                                ("key_source", "vector_b WORD"),
                                            )
                                        ),
                                    )
                                ),
                            ),
                            (
                                "insertion",
                                (
                                    "map[WORD] |= environment_id; create map[WORD] "
                                    "= environment_id when absent"
                                ),
                            ),
                        )
                    ),
                ),
                (
                    "consumer_semantics",
                    JSONObject(
                        (
                            ("consumer", "tokenized_path_signature_matcher"),
                            ("lookup_key_source", "signature_attribute WORD at +0x22"),
                            ("lookup", "query both maps and obtain two QWORD values"),
                            (
                                "candidate_boundary",
                                "IEnvMatch virtual methods at vtable +0x18/+0x20",
                            ),
                            (
                                "candidate_result",
                                (
                                    "wide-string candidates passed to general "
                                    "detection path"
                                ),
                            ),
                            ("word_meaning", "unknown"),
                            ("token_or_selector_meaning", "unknown"),
                        )
                    ),
                ),
            )
        ),
        evidence=(
            "docs/signature/0xED_BM_ENV_VAR_MAP.md",
            "docs/mpengine.dll/BMEnvVarReceiver.md",
            "docs/mpengine.dll/BmEnvVarMapping_AddVar.md",
            "docs/mpengine.dll/BmEnvVarMapping_AddVarInMap.md",
            "docs/mpengine.dll/GetVarListFromSigs.md",
            "docs/mpengine.dll/SignatureHandler_TestForDetectionWithTokenizedPath.md",
            "mpengine-1.443.903.0",
        ),
        profile="mpengine-1.443.903.0",
        issues=issues,
        claims=(
            SemanticClaim(
                "bm-env-wire-map",
                "receiver_transform",
                "BM_ENV_VAR_MAP receiver resolves the name case-insensitively and ORs the environment ID into entries keyed by WORDs in two maps.",
                "subset",
                ("bm-env-receiver",),
                (
                    SemanticUnknown(
                        "receiver_transform",
                        "Environment-name enumeration and the semantic names of WORD values are unknown.",
                    ),
                ),
            ),
            SemanticClaim(
                "bm-env-candidate-expansion",
                "runtime_consumer",
                "The tokenized-path consumer looks up both maps and delegates candidate string expansion to IEnvMatch virtual methods.",
                "subset",
                ("bm-env-consumer",),
                (
                    SemanticUnknown(
                        "runtime_consumer",
                        "Expansion rules and token/selector meanings are not established.",
                    ),
                ),
            ),
            SemanticClaim(
                "bm-env-verdict",
                "final_verdict",
                "Candidate expansion does not establish a final detection verdict.",
                "unknown",
                (),
                (
                    SemanticUnknown(
                        "final_verdict",
                        "Final policy is outside the confirmed candidate handoff.",
                    ),
                ),
            ),
        ),
        claim_evidence=(
            SemanticEvidence(
                "bm-env-receiver",
                "receiver",
                "engine_static",
                "BMEnvVarReceiver / BmEnvVarMapping_AddVar / AddVarInMap",
                ("bm-env-wire-map",),
            ),
            SemanticEvidence(
                "bm-env-consumer",
                "consumer",
                "engine_static",
                "GetVarListFromSigs / SignatureHandler_TestForDetectionWithTokenizedPath",
                ("bm-env-candidate-expansion",),
            ),
        ),
    )


SPEC = FamilySpec(
    BM_ENV_VAR_MAP_TYPE,
    "BM_ENV_VAR_MAP",
    parse_bm_env_var_map,
    render_bm_env_var_map,
    semantic_exporter=export_bm_env_var_map_semantics,
)
