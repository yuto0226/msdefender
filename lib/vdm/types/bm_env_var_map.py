"""Parser and bounded renderer for BM_ENV_VAR_MAP (0xED) payloads."""

import json
from dataclasses import dataclass
from typing import Final

from ..bm_env_map import (
    BM_ENV_ASCII_CRT_PROFILE,
    decode_bm_env_mask,
    resolve_bm_env_name,
)
from ..core import (
    Artifact,
    ArtifactExport,
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

    name = resolve_bm_env_name(parsed.name_raw, crt_profile=BM_ENV_ASCII_CRT_PROFILE)
    aliases = (
        ()
        if name.environment_id is None
        else decode_bm_env_mask(name.environment_id)[0]
    )
    return FormatResult(
        fields=(
            ("name_len", str(parsed.name_len)),
            ("name_raw", name_preview or "(empty)"),
            ("vector_a_count", str(len(parsed.vector_a))),
            ("vector_a_preview", _preview_words(parsed.vector_a)),
            ("vector_b_count", str(len(parsed.vector_b))),
            ("vector_b_preview", _preview_words(parsed.vector_b)),
            ("raw_len", str(len(parsed.raw))),
            (
                "conditional_environment_id",
                "unknown"
                if name.environment_id is None
                else f"0x{name.environment_id:x}",
            ),
            (
                "conditional_aliases",
                ", ".join(
                    alias.decode("ascii") for _, names in aliases for alias in names
                )
                or "(none)",
            ),
            ("name_lookup_profile", BM_ENV_ASCII_CRT_PROFILE),
            ("name_lookup_reason", name.reason),
            (
                "map_update_rule",
                "A/B WORD-key QWORD |= ID; absent -> ID under normal insertion",
            ),
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
            "environment_alias_crt_profile_conditional",
            "The fixed 21-alias/20-ID table is modeled using physical second-byte "
            "dispatch and an explicit ASCII CRT profile; no host environment is queried.",
        ),
        SemanticIssue(
            "word_and_token_names_unknown",
            "WORD roles are confirmed u16 selector keys in two maps and the audited "
            "caller reads src_attribute+0x22; fixed value labels remain unresolved.",
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
                            (
                                "name_to_environment_id",
                                "signed_second_byte_dispatch_then_ordered_CString_stricmp",
                            ),
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
                            (
                                "lookup",
                                "With disable BYTE0 and nonempty map A, query A then B: hit replaces corresponding output QWORD, miss preserves explicit prior. Otherwise select HRESULT80004004 on normal return.",
                            ),
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
                            (
                                "word_meaning",
                                "u16 selector key in independent maps A/B; fixed enum labels unresolved",
                            ),
                            (
                                "token_or_selector_meaning",
                                "Audited main caller uses src_attribute+0x22 WORD; value labels unresolved; other variants not projected",
                            ),
                            (
                                "audited_caller_scope",
                                "Only tokenized_path_1802C1B10: negative lookup HRESULT -> slot+0x20 fallback; success outA0 -> skip; success outA nonzero -> slot+0x18 with &outA. outB is not consumed after lookup. Other variants unprojected.",
                            ),
                        )
                    ),
                ),
                ("mapping_value_recipe_profile", _mapping_value_profile(parsed)),
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
                "bm-env-alias-instruction-profile",
                "receiver_transform",
                "Under an explicit external ASCII _stricmp seam, 344 concrete IDs and ordered comparison traces from the original 750-byte alias function agree with the portable lookup; two bounded unknown cases remain unknown, not returned enum zero.",
                "subset",
                ("bm-env-alias-instruction-test",),
                (
                    SemanticUnknown(
                        "receiver_transform",
                        "Only the alias function instructions execute under this profile; CRT internals/locale, receiver construction, map insertion/lookup, controller, tokenized caller, IEnvMatch services and verdict are not established by this instruction test.",
                    ),
                ),
            ),
            SemanticClaim(
                "bm-env-wire-map",
                "receiver_transform",
                "BM_ENV_VAR_MAP receiver resolves the name case-insensitively and ORs the environment ID into entries keyed by WORDs in two maps.",
                "subset",
                ("bm-env-receiver",),
                (
                    SemanticUnknown(
                        "receiver_transform",
                        "The fixed alias table is modeled under an explicit physical-buffer/ASCII CRT profile; WORD selector names and allocator exceptions remain outside this projection.",
                    ),
                ),
            ),
            SemanticClaim(
                "bm-env-candidate-expansion",
                "runtime_consumer",
                "For the audited main caller under its feature/GetEnvMatch gates, shared-map lookup conditionally selects fallback, skip or masked IEnvMatch requests; concrete candidate string production remains external.",
                "subset",
                ("bm-env-consumer",),
                (
                    SemanticUnknown(
                        "runtime_consumer",
                        "Fixed WORD selector labels and IEnvMatch candidate-generation backends remain unresolved; only the named tokenized_path_1802C1B10 routing is projected, not the other two variants.",
                    ),
                ),
            ),
            SemanticClaim(
                "bm-env-local-values",
                "runtime_consumer",
                "Explicit complete global map snapshots support per-record OR updates and actual QWORD lookup outputs; map A size gates lookup, hit replaces output and miss preserves prior. The audited main caller selects fallback/skip/masked requests from HRESULT and outA, without deriving path candidates or a verdict.",
                "subset",
                ("bm-env-value-static",),
                (
                    SemanticUnknown(
                        "runtime_consumer",
                        "Global shared loader state, constructed-name/CRT facts and successful insertion premise are explicit; controller normal-return effects are conditional and IEnvMatch results/report remain external.",
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
                "bm-env-alias-instruction-test",
                "receiver",
                "engine_equivalent_test",
                (
                    "Original EnvMatchGetBmEnvironmenalId @0x18042C268/750B; Unicorn 2.1.4; "
                    "344 concrete ID/ordered CRT trace agreements plus 2 bounded unknown cases; "
                    "external ASCII _stricmp hook only; tests/local_bm_env_alias_instruction_differential_v1.py SHA256 "
                    "5419d6010965486cd0b5b8d818fc1ae4e26279855106f1f87fa41d84283e2367; "
                    "final-module replay adapter tests/local_bm_env_alias_instruction_replay_v3.py SHA256 "
                    "4fdd5a399b36066d7fca1c54de1f80008f8e7a9d3c2d9fb116ebceacb8a71d5b; "
                    "result tests/local_bm_env_alias_instruction_differential_v3.json SHA256 "
                    "2c3b054fc89eac50485b44ba9f3dbe78493399a6da5c2fa77d880d1a81c3b8c1; "
                    "no receiver/maps/wrapper/caller or host-native execution"
                ),
                ("bm-env-alias-instruction-profile",),
            ),
            SemanticEvidence(
                "bm-env-value-static",
                "consumer",
                "engine_static",
                "mpengine 1.443.903.0; EnvMatchGetBmEnvironmenalId @0x18042C268/750B; AddVar @0x18042C1C0/166B; AddVarInMap @0x18042C558/109B; GetVarListFromSigs @0x18055B0A8/334B; tokenized caller @0x1802C1B10; docs/signature/BM_ENV_VAR_MAP_value_contract_private.md; DLL SHA256 928e171c60a44bb326776d2a356412ae98d78469bdf8c94ebfbfa09f8ec4b4b3",
                ("bm-env-local-values",),
            ),
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


def _mapping_value_profile(parsed: BMEnvVarMap) -> JSONObject:
    name = resolve_bm_env_name(parsed.name_raw, crt_profile=BM_ENV_ASCII_CRT_PROFILE)
    return JSONObject(
        (
            ("representation", "bm-env.shared-map-values.v1"),
            ("name_projector", "lib.vdm.bm_env_map.resolve_bm_env_name"),
            ("mutation_projector", "lib.vdm.bm_env_map.project_bm_env_receiver"),
            ("lookup_projector", "lib.vdm.bm_env_map.query_bm_env_maps"),
            ("caller_projector", "lib.vdm.bm_env_map.project_bm_env_tokenized_call"),
            ("returned_lookup_router", "lib.vdm.bm_env_map.route_bm_env_lookup"),
            ("mask_decoder", "lib.vdm.bm_env_map.decode_bm_env_mask"),
            ("mutation_snapshot_type", "lib.vdm.bm_env_map.BMEnvMutationSnapshot"),
            ("map_snapshot_type", "lib.vdm.bm_env_map.BMEnvMapSnapshot"),
            ("entry_type", "lib.vdm.bm_env_map.BMEnvMapEntry"),
            ("lookup_snapshot_type", "lib.vdm.bm_env_map.BMEnvLookupSnapshot"),
            ("caller_snapshot_type", "lib.vdm.bm_env_map.BMEnvCallerSnapshot"),
            ("error_type", "lib.vdm.bm_env_map.BMEnvSnapshotError"),
            ("runtime_inputs_resolved", False),
            ("record_local_match", None),
            ("final_verdict", None),
            (
                "conditional_name",
                JSONObject(
                    (
                        ("profile", BM_ENV_ASCII_CRT_PROFILE),
                        ("environment_id", name.environment_id),
                        ("reason", name.reason),
                        ("physical_second_byte", name.second_byte),
                        (
                            "compared_aliases",
                            JSONArray(
                                tuple(a.decode("ascii") for a in name.compared_aliases)
                            ),
                        ),
                    )
                ),
            ),
            (
                "conditional_updates",
                JSONArray(
                    tuple(
                        JSONObject(
                            (
                                ("map", label),
                                ("map_member_offset", offset),
                                ("vector_index", index),
                                ("key_u16", key),
                                ("environment_id_qword", name.environment_id),
                                (
                                    "operation",
                                    "existing QWORD |= ID; absent -> ID; ID0 -> no write",
                                ),
                            )
                        )
                        for label, offset, words in (
                            ("a", 0, parsed.vector_a),
                            ("b", 16, parsed.vector_b),
                        )
                        for index, key in enumerate(words)
                    )
                ),
            ),
            (
                "name_contract",
                (
                    "Normally constructed immutable receiver name+NUL only; empty name second byte "
                    "needs actual physical tail. Signed name[1] dispatch precedes ordered CString _stricmp; "
                    "embedded NUL terminates comparison, not dispatch. Stable ASCII C-locale profile is explicit; "
                    "no Unicode lower/casefold or host environment lookup."
                ),
            ),
            (
                "mutation_contract",
                (
                    "Reparse raw payload; original AddVar resolves name once per WORD. Pure model coalesces "
                    "stable CRT/name calculations only, not actual calls. A updates precede B; ID0 or empty "
                    "vectors do not require map facts. Existing key OR needs no allocation; absent key requires "
                    "explicit normal-success insertion premise. Prior global maps never auto-clear per threat/record."
                ),
            ),
            (
                "lookup_contract",
                (
                    "Global mapA@+0/mapB@+0x10; size@+8 derived from complete entries, no ready bool. "
                    "Disable BYTE nonzero or empty A -> HRESULT bits80004004; B may be nonempty but unread. "
                    "A nonempty -> lookup A then B, hit value0 replaces0, miss preserves explicit prior QWORD. "
                    "Unknown bits stay raw and participate in OR, not rejected. Epochs must match reached maps."
                ),
            ),
            (
                "controller_contract",
                (
                    "Empty A requests GetBmController; signed HRESULT>=0 requests xchg BYTE+398,1 and "
                    "nonnull controller release. Missing facts retain conditional requests and selected normal-return "
                    "HRESULT, not observed completion; known success+NULL is outside normal pointer domain."
                ),
            ),
            (
                "caller_contract",
                (
                    "Only tokenized_path_1802C1B10; feature BYTE181272CD8=0 or negative GetEnvMatch HRESULT "
                    "skips query. Priors are0. Returned lookup HRESULT<0 -> vslot+20 fallback without mask; "
                    "HRESULT>=0/outA0 skips, nonzero requests vslot+18 r9=&outA; outB unused. Pure router accepts "
                    "explicit returned values; model-composed routing is conditional on normal return. Other two "
                    "variants/IEnvMatch wide paths/general detection/report/final verdict remain external."
                ),
            ),
        )
    )


def export_bm_env_var_map(parsed: BMEnvVarMap) -> ArtifactExport:
    """Export loader mapping/query metadata, not a standalone detector."""
    parsed = parse_bm_env_var_map(parsed.raw)
    sem = export_bm_env_var_map_semantics(parsed).to_json()
    document = {
        "format": "vdm.bm-env.shared-mapping-recipe.v1",
        "data": sem["data"],
        "claims": sem["claims"],
        "claim_evidence": sem["claim_evidence"],
        "runtime_inputs_resolved": False,
        "record_local_match": None,
        "final_verdict": None,
    }
    return ArtifactExport(
        "ready",
        (
            Artifact(
                "bm-env-map.json",
                "json",
                json.dumps(document, ensure_ascii=True, indent=2).encode("utf8")
                + b"\n",
            ),
        ),
    )


SPEC = FamilySpec(
    BM_ENV_VAR_MAP_TYPE,
    "BM_ENV_VAR_MAP",
    parse_bm_env_var_map,
    render_bm_env_var_map,
    exporter=export_bm_env_var_map,
    semantic_exporter=export_bm_env_var_map_semantics,
)
