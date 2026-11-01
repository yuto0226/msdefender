"""Lossless parser for REGKEY (0x63) records."""

import json
from dataclasses import dataclass
from typing import Final

from ..core import (
    Artifact,
    ArtifactExport,
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

REGKEY_TYPE: Final = 0x63
REGKEY_HIVES: Final = ("HKCR", "HKCU", "HKLM", "HKCC")
REGKEY_PREFIXES: Final = (
    "software\\microsoft\\windows\\currentversion\\run",
    "software\\microsoft\\windows\\currentversion\\explorer",
    "software\\microsoft\\windows\\currentversion",
    "software\\microsoft\\",
    "software\\classes\\clsid",
    "software\\classes\\interface",
    "software\\classes\\typelib",
    "software\\classes\\software\\microsoft\\windows\\currentversion\\explorer",
    "software\\classes",
    "software",
    "system\\currentcontrolset",
)


@dataclass(frozen=True, slots=True)
class RegKeyPayload:
    """Decoded boundaries and raw byte slices for a REGKEY payload."""

    raw: bytes
    key_type: int
    key_path_len: int
    key_path_raw: bytes
    key_path: str | None
    value_len: int
    value_raw: bytes
    value_utf8_preview: str | None
    tail_raw: bytes


def _decode_utf8(data: bytes) -> str | None:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _decode_printable_utf8_preview(data: bytes) -> str | None:
    if not data:
        return None
    decoded = _decode_utf8(data)
    if decoded is None or not decoded.isprintable():
        return None
    return decoded


def parse_regkey(payload: bytes) -> RegKeyPayload:
    """Parse REGKEY's two length-prefixed fields and retain all trailing bytes."""
    if len(payload) < 4:
        raise ValueError(f"truncated REGKEY header: need 4 bytes, have {len(payload)}")

    key_type = int.from_bytes(payload[0:2], "little")
    key_path_len = int.from_bytes(payload[2:4], "little")
    key_path_end = 4 + key_path_len
    if key_path_end > len(payload):
        raise ValueError(
            "truncated REGKEY key_path: "
            f"need {key_path_len} bytes, have {len(payload) - 4}"
        )

    value_len_offset = key_path_end
    if value_len_offset + 2 > len(payload):
        available = len(payload) - value_len_offset
        raise ValueError(f"truncated REGKEY value_len: need 2 bytes, have {available}")

    value_len = int.from_bytes(
        payload[value_len_offset : value_len_offset + 2], "little"
    )
    value_offset = value_len_offset + 2
    value_end = value_offset + value_len
    if value_end > len(payload):
        raise ValueError(
            f"truncated REGKEY value: need {value_len} bytes, "
            f"have {len(payload) - value_offset}"
        )

    key_path_raw = payload[4:key_path_end]
    key_path = _decode_utf8(key_path_raw)
    value_raw = payload[value_offset:value_end]
    return RegKeyPayload(
        raw=payload,
        key_type=key_type,
        key_path_len=key_path_len,
        key_path_raw=key_path_raw,
        key_path=key_path,
        value_len=value_len,
        value_raw=value_raw,
        value_utf8_preview=_decode_printable_utf8_preview(value_raw),
        tail_raw=payload[value_end:],
    )


def render_regkey(parsed: RegKeyPayload) -> FormatResult:
    key_type = f"0x{parsed.key_type:04x}"

    rows: list[tuple[str, str]] = [
        ("key_type", key_type),
        ("key_path_len", str(parsed.key_path_len)),
    ]
    if parsed.key_path is not None:
        rows.append(("key_path", parsed.key_path or "(empty)"))
    else:
        rows.append(("key_path_raw", parsed.key_path_raw.hex(" ") or "(empty)"))
        rows.append(("key_path_text", "invalid UTF-8; raw bytes preserved"))
    rows.extend((("value_len", str(parsed.value_len)),))
    if parsed.value_utf8_preview is not None:
        rows.append(("value_utf8_preview", parsed.value_utf8_preview))
    elif parsed.value_raw:
        rows.append(("value_raw", parsed.value_raw.hex(" ")))

    sections = [DisplaySection("Registry key", rows=tuple(rows))]
    if parsed.tail_raw:
        sections.append(
            DisplaySection(
                "Unclassified trailing bytes",
                rows=(("tail_len", str(len(parsed.tail_raw))),),
            )
        )
    return FormatResult(sections=tuple(sections))


def _project_receiver_fields(parsed: RegKeyPayload) -> JSONObject:
    effective_path = parsed.key_path_raw.split(b"\0", 1)[0]
    prefix_index = next(
        (
            index
            for index, prefix in enumerate(REGKEY_PREFIXES)
            if effective_path[: len(prefix)].lower() == prefix.encode("ascii").lower()
        ),
        None,
    )
    stored_path = (
        effective_path
        if prefix_index is None
        else effective_path[len(REGKEY_PREFIXES[prefix_index]) :]
    )
    separator = stored_path.find(b"\\\\")
    key_path = stored_path if separator < 0 else stored_path[:separator]
    value_name = None if separator < 0 else stored_path[separator + 2 :]
    storage = "asep" if value_name is None and parsed.value_raw else "general"
    return JSONObject(
        (
            (
                "hive",
                REGKEY_HIVES[parsed.key_type - 1]
                if 1 <= parsed.key_type <= len(REGKEY_HIVES)
                else None,
            ),
            ("ingest_prefix_index", prefix_index),
            ("prefix_index", prefix_index if storage == "general" else 0xFFFF),
            (
                "prefix",
                None if prefix_index is None else REGKEY_PREFIXES[prefix_index],
            ),
            ("stored_path_hex", stored_path.hex()),
            ("key_path_hex", key_path.hex()),
            ("value_name_hex", None if value_name is None else value_name.hex()),
            ("expected_content_hex", parsed.value_raw.hex()),
            ("storage_table", storage),
        )
    )


def export_regkey_semantics(parsed: RegKeyPayload) -> RuleSemantics:
    """Export the confirmed REGKEY receiver and candidate-matcher subset."""
    selector_accepted = 1 <= parsed.key_type <= 4
    receiver_fields = _project_receiver_fields(parsed)
    receiver_values = dict(receiver_fields.items)
    issues = [
        SemanticIssue(
            "final_verdict_unknown",
            "A successful registry resource match is a gated candidate, not a "
            "confirmed outer scan verdict.",
        ),
        SemanticIssue(
            "regkey_expansion_producer_external",
            "REG_SZ/REG_EXPAND_SZ offline patch and path equality are computed from "
            "explicit physical inputs or observations; seven-filter resolver outputs remain external.",
        ),
    ]
    if not selector_accepted:
        status = "ignored"
        issues.append(
            SemanticIssue(
                "receiver_ignored_selector",
                "The receiver returns success without registering selector values "
                "outside the accepted range 1 through 4.",
                (("selector", parsed.key_type),),
            )
        )
    elif parsed.key_path is None:
        status = "unsupported"
        issues.append(
            SemanticIssue(
                "invalid_utf8_path",
                "The path bytes are not valid UTF-8, so Store_UTF8_Reg processing "
                "cannot be represented faithfully.",
            )
        )
    elif parsed.tail_raw:
        status = "unsupported"
        issues.append(
            SemanticIssue(
                "regkey_trailing_bytes_semantics_unknown",
                "Trailing bytes are retained; their RecID/program meaning is not "
                "established by this semantic representation.",
                (("length", len(parsed.tail_raw)),),
            )
        )
    else:
        status = "confirmed_subset"

    return RuleSemantics(
        status=status,
        representation="regkey.registry-match-candidate.ir.v3",
        data=JSONObject(
            (
                ("type", "regkey"),
                ("raw_hex", parsed.raw.hex()),
                (
                    "selector",
                    JSONObject(
                        (
                            ("wire_offset", 0),
                            ("raw_u16", parsed.key_type),
                            ("registration_accepted", selector_accepted),
                            (
                                "hive",
                                REGKEY_HIVES[parsed.key_type - 1]
                                if selector_accepted
                                else None,
                            ),
                            (
                                "internal_value",
                                parsed.key_type - 1 if selector_accepted else None,
                            ),
                            ("mapping", "wire 1..4 -> internal 0..3"),
                        )
                    ),
                ),
                (
                    "path_field",
                    JSONObject(
                        (
                            ("wire_offset", 4),
                            ("length", parsed.key_path_len),
                            ("raw_hex", parsed.key_path_raw.hex()),
                            ("decoded_utf8", parsed.key_path),
                            (
                                "runtime_normalization",
                                receiver_fields,
                            ),
                        )
                    ),
                ),
                (
                    "value_field",
                    JSONObject(
                        (
                            ("length", parsed.value_len),
                            ("raw_hex", parsed.value_raw.hex()),
                            ("printable_utf8_preview", parsed.value_utf8_preview),
                            (
                                "runtime_role",
                                "expected registry value content",
                            ),
                        )
                    ),
                ),
                ("trailing_hex", parsed.tail_raw.hex()),
                ("query_recipe", _query_recipe_contract(selector_accepted)),
                ("resolved_path_comparison_profile", _resolved_path_profile()),
                ("offline_patch_recipe_profile", _offline_patch_profile()),
                (
                    "storage_routing",
                    JSONObject(
                        (
                            ("possible_tables", JSONArray(("general", "ASEP"))),
                            (
                                "record_assignment",
                                receiver_values["storage_table"],
                            ),
                        )
                    ),
                ),
                (
                    "matcher",
                    JSONObject(
                        (
                            (
                                "candidate_lookup",
                                "MatchResource -> reg_key_in_Registry",
                            ),
                            (
                                "roles",
                                "key path + optional value name + expected content",
                            ),
                            ("selector_to_hive_mapping", receiver_values["hive"]),
                        )
                    ),
                ),
            )
        ),
        evidence=(
            "mpengine 1.443.903.0 reg_key_DB_receiver",
            "mpengine 1.443.903.0 reg_key_DB_end",
            "mpengine 1.443.903.0 is_rkey_in_DB",
            "mpengine 1.443.903.0 is_rkey_in_asep_DB",
            "mpengine 1.443.903.0 reg_key_in_hive",
            "mpas.sig/mpav.sig REGKEY corpus invariants",
        ),
        profile="mpengine-1.443.903.0",
        issues=tuple(issues),
        claims=_regkey_claims(parsed, selector_accepted),
        claim_evidence=_regkey_evidence(),
    )


def _regkey_claims(
    parsed: RegKeyPayload, selector_accepted: bool
) -> tuple[SemanticClaim, ...]:
    return (
        SemanticClaim(
            id="regkey_offline_patch_instruction_profile",
            scope="runtime_consumer",
            statement=(
                "Under explicit per-call towupper EAX observations and disabled WPP, "
                "18 concrete outcomes from the original 226-byte direct patcher agree "
                "on status, full physical postpatch bytes and reached table/call/write "
                "traces. Six additional bounded unknown cases remain unknown, "
                "not engine-returned statuses."
            ),
            coverage="subset",
            evidence_refs=("regkey_offline_patch_instruction_test",),
            unknowns=(
                SemanticUnknown(
                    "runtime_consumer",
                    "The instruction profile executes only CallistoPatchPathFromOffline "
                    "with towupper hooks and WPP disabled, not host-native DLL, LUM or "
                    "member wrappers, CRT internals/locale, uint32 scan-cycle behavior, "
                    "arbitrary memory aliases, seven resolver services or final verdict.",
                ),
            ),
        ),
        SemanticClaim(
            id="regkey_offline_patch_values",
            scope="runtime_consumer",
            statement=(
                "Invocation-bound wrapper gates, physical WCHAR bytes, offline-relative "
                "BYTE window and independent engine CRT towupper observations compute "
                "patch status and at most one WCHAR write. The caller ignores patch status."
            ),
            coverage="subset",
            evidence_refs=("regkey_offline_patch_static",),
            unknowns=(
                SemanticUnknown(
                    "runtime_consumer",
                    "Wrapper state, physical image and CRT observations are explicit inputs; "
                    "seven-filter resolver services, report and final verdict remain external.",
                ),
            ),
        ),
        SemanticClaim(
            id="regkey_path_comparison_instruction_profile",
            scope="detection_predicate",
            statement=(
                "Under explicit ASCII CRT prefix-comparison and typed path-list "
                "service profiles, 145 concrete outcomes from original "
                "expand_path_cmp and GetFriendlyFileNameW instructions agree "
                "with the portable comparison, including ordered pair traces. "
                "Three additional bounded unreadable/out-of-profile cases "
                "remain unknown, not engine-returned booleans."
            ),
            coverage="subset",
            evidence_refs=("regkey_path_comparison_instruction_test",),
            unknowns=(
                SemanticUnknown(
                    "detection_predicate",
                    "CRT wcsncmp/_wcsnicmp, path-list services, cleanup and "
                    "security-cookie checks are explicit seams. Resolver and "
                    "offline producers, complete CRT locale behavior, NULL "
                    "dereference outcomes, registry I/O, report and final "
                    "verdict are not executed or established by this profile.",
                ),
            ),
        ),
        SemanticClaim(
            id="regkey_resolved_path_comparison",
            scope="detection_predicate",
            statement=(
                "After direct string mismatch, invocation-bound physical postpatch "
                "bytes and ordered resolver outputs permit actual Cartesian WCHAR "
                "comparison, including FriendlyFileName prefix handling, ASCII "
                "case and slash equivalence. Resolver statuses and missing facts "
                "remain distinct from empty successful lists."
            ),
            coverage="subset",
            evidence_refs=("regkey_path_comparison_static",),
            unknowns=(
                SemanticUnknown(
                    "detection_predicate",
                    "Offline patch and seven-filter resolver services are not run; "
                    "non-ASCII CRT UNC-prefix comparison requires an actual bound "
                    "observation. No registry event, report or final verdict follows.",
                ),
            ),
        ),
        SemanticClaim(
            id="regkey_wire_layout",
            scope="wire_layout",
            statement=(
                "REGKEY contains a u16 hive selector, a u16-length-prefixed UTF-8 "
                "path, a u16-length-prefixed expected-content field, and an optional "
                "RecID program tail."
            ),
            coverage="subset",
            evidence_refs=("regkey_receiver",),
            unknowns=(
                SemanticUnknown(
                    "wire_layout",
                    "The optional RecID program tail grammar remains unresolved.",
                ),
            ),
        ),
        SemanticClaim(
            id="regkey_dispatch_path",
            scope="loader_dispatch",
            statement="Type 0x63 is registered to reg_key_DB_receiver.",
            coverage="subset",
            evidence_refs=("regkey_dispatch",),
            unknowns=(
                SemanticUnknown(
                    "loader_dispatch",
                    "Outer database-selection and product enablement gates are not modeled.",
                ),
            ),
        ),
        SemanticClaim(
            id="regkey_receiver_projection",
            scope="receiver_transform",
            statement=(
                "Accepted selectors 1..4 map to HKCR/HKCU/HKLM/HKCC; the receiver "
                "strips the first matching prefix from an ordered 11-entry table, "
                "splits an optional value name at the first double backslash, and "
                "keeps the separate value field as expected content."
            ),
            coverage="subset" if selector_accepted else "unknown",
            evidence_refs=("regkey_receiver", "regkey_tables")
            if selector_accepted
            else (),
            unknowns=(
                SemanticUnknown(
                    "receiver_transform",
                    (
                        "This selector is accepted-and-ignored by the receiver."
                        if not selector_accepted
                        else "RecID program construction and allocation-failure state are not projected."
                    ),
                ),
            ),
        ),
        SemanticClaim(
            id="regkey_runtime_candidate",
            scope="runtime_consumer",
            statement=(
                "GetRegKeyFromRecord reconstructs hive/prefix/path, and "
                "reg_key_in_Registry expands logical-user keys before passing the "
                "key, optional value name, and expected content to ResutilsRegKeyInHive."
            ),
            coverage="subset" if selector_accepted else "unknown",
            evidence_refs=("regkey_consumer",) if selector_accepted else (),
            unknowns=(
                SemanticUnknown(
                    "runtime_consumer",
                    (
                        "Ignored selectors do not reach this registered-record consumer."
                        if not selector_accepted
                        else "ASEP requires actual caller bindings; registry/LUM state and expansion remain external."
                    ),
                ),
            ),
        ),
        SemanticClaim(
            id="regkey_typed_local_predicate",
            scope="detection_predicate",
            statement=(
                "A raw-authoritative query recipe and prebound registry snapshot "
                "support key/value existence, ASCII-only WCHAR comparison, exact "
                "binary bytes and unsigned decimal numeric predicates. Runtime "
                "type 5 formats the first byte shifted left 24, not a standard "
                "big-endian DWORD. Missing readable bytes or expansion are unknown."
            ),
            coverage="subset" if selector_accepted else "unknown",
            evidence_refs=("regkey_query_native",) if selector_accepted else (),
            unknowns=(
                SemanticUnknown(
                    "detection_predicate",
                    "Valid UTF-8 successful conversion and unchanged CRT locale profile only; "
                    "ASEP selection, actual LUM/root binding, expansion and final report are external.",
                ),
            ),
        ),
        SemanticClaim(
            id="regkey_detection_predicate",
            scope="detection_predicate",
            statement=(
                "MatchResource emits candidate metadata after the registry predicate "
                "matches and the selected signature/threat is not expired or disabled."
            ),
            coverage="subset" if selector_accepted else "unknown",
            evidence_refs=("regkey_candidate",) if selector_accepted else (),
            unknowns=(
                SemanticUnknown(
                    "detection_predicate",
                    (
                        "Ignored selectors have no registered matcher predicate."
                        if not selector_accepted
                        else "RecID validator effects and outer resource-search arbitration remain unresolved."
                    ),
                ),
            ),
        ),
        SemanticClaim(
            id="regkey_report_mapping",
            scope="report_mapping",
            statement="The registry candidate has no confirmed user-visible report mapping.",
            coverage="unknown",
            unknowns=(
                SemanticUnknown(
                    "report_mapping",
                    "No caller was followed from MatchResource output into report policy.",
                ),
            ),
        ),
        SemanticClaim(
            id="regkey_final_verdict",
            scope="final_verdict",
            statement="A REGKEY resource candidate is not a confirmed final verdict.",
            coverage="unknown",
            unknowns=(
                SemanticUnknown(
                    "final_verdict",
                    "Outer scan arbitration and final report policy remain unresolved.",
                ),
            ),
        ),
    )


def _regkey_evidence() -> tuple[SemanticEvidence, ...]:
    return (
        SemanticEvidence(
            id="regkey_offline_patch_instruction_test",
            axis="engine_equivalent_test",
            kind="engine_equivalent_test",
            source_ref="mpengine 1.443.903.0",
            locator=(
                "Original CallistoPatchPathFromOffline @ 0x1804A1DD0 (226 bytes), "
                "Unicorn 2.1.4; 18 concrete agreements plus 6 bounded unknown cases; "
                "tests/local_regkey_offline_instruction_differential_v1.py SHA256 "
                "8c45010ed7cc0dd38bc577eb5f2c42a03472a07d55b6f00a9367ee0b18879a44; "
                "tests/local_regkey_offline_instruction_differential_v1.json SHA256 "
                "ad01a117ec79d377536940ed9125875732c4a0e2aa07df8d96eb1317751cc2f9; "
                "per-call towupper raw EAX hooks, WPP disabled; no wrapper/host-native "
                "or resolver execution; docs/signature/REGKEY_offline_patcher_instruction_differential_private.md"
            ),
            supports=("regkey_offline_patch_instruction_profile",),
        ),
        SemanticEvidence(
            id="regkey_offline_patch_static",
            axis="consumer",
            kind="engine_static",
            source_ref="mpengine 1.443.903.0",
            locator=(
                "CallistoPatchPathFromOffline @ 0x1804A1DD0 (226 bytes); "
                "LUM_ResolveOfflineFile @ 0x180221A20 (49 bytes); "
                "CProfileMgr::ResolveOfflineFile @ 0x180D01240 (89 bytes); "
                "DLL SHA256 928e171c60a44bb326776d2a356412ae98d78469bdf8c94ebfbfa09f8ec4b4b3; "
                "docs/signature/REGKEY_offline_patch_value_contract_private.md"
            ),
            supports=("regkey_offline_patch_values",),
        ),
        SemanticEvidence(
            id="regkey_path_comparison_instruction_test",
            axis="engine_equivalent_test",
            kind="engine_equivalent_test",
            source_ref="mpengine 1.443.903.0",
            locator=(
                "Original expand_path_cmp @ 0x180523660 (468 bytes) and "
                "GetFriendlyFileNameW @ 0x18011790C (71 bytes), Unicorn 2.1.4; "
                "145 concrete agreements plus 3 bounded unknown cases; "
                "tests/local_regkey_paths_instruction_differential_v1.py SHA256 "
                "63e8a6ad94148ca2b36d3e65caf4750c0d0a227630354eb24418756217d3c7a6; "
                "tests/local_regkey_paths_instruction_differential_v2.json SHA256 "
                "edb539e1d0307e9758d94b31ffe3150a413783a25a05d715640d06e237eb3112; "
                "ASCII CRT/list/free/cookie seams; no resolver/offline producer execution; "
                "docs/signature/REGKEY_path_comparison_instruction_differential_private.md"
            ),
            supports=("regkey_path_comparison_instruction_profile",),
        ),
        SemanticEvidence(
            id="regkey_path_comparison_static",
            axis="consumer",
            kind="engine_static",
            source_ref="mpengine 1.443.903.0",
            locator=(
                "expand_path_cmp @ 0x180523660 (468 bytes); GetFriendlyFileNameW @ "
                "0x18011790C (71 bytes); ResutilsRegKeyInHive @ 0x1800BE408; "
                "DLL SHA256 928e171c60a44bb326776d2a356412ae98d78469bdf8c94ebfbfa09f8ec4b4b3; "
                "docs/signature/REGKEY_expansion_value_contract_private.md"
            ),
            supports=("regkey_resolved_path_comparison",),
        ),
        SemanticEvidence(
            id="regkey_query_native",
            axis="consumer",
            kind="engine_equivalent_test",
            source_ref="mpengine 1.443.903.0",
            locator=(
                "tests/local_regkey_query_native.py SHA256 "
                "c9bb5b795fb386bd65ae774f035ee12d95718884e9fcfeaa5dfd3dc79df3afb0; "
                "62 cases / 77 calls; tests/local_regkey_query_native.json SHA256 "
                "d8e0a03b2b5a5c97e8fa32625ff0656442b13301d1c26d6d8e109c15a285e0f2; "
                "current source bridge tests/local_regkey_query_bridge.py SHA256 "
                "c509880c005700eb581c25ef44973a2d0118f0ef8aaa04084d472a2cb4adb60c; "
                "receiver, GetRegKeyFromRecord and ResutilsRegKeyInHive original code; "
                "typed registry services, real host Win32 UTF-8 / C-locale UCRT oracles; "
                "docs/mpengine.dll/1.443.903.0/regkey_query_native_private.md"
            ),
            supports=("regkey_typed_local_predicate",),
        ),
        SemanticEvidence(
            id="regkey_receiver",
            axis="receiver",
            kind="engine_static",
            source_ref="mpengine 1.443.903.0",
            locator="reg_key_DB_receiver @ 0x180320BF0; Store_UTF8_Reg @ 0x180321440",
            supports=("regkey_wire_layout", "regkey_receiver_projection"),
        ),
        SemanticEvidence(
            id="regkey_tables",
            axis="receiver",
            kind="engine_static",
            source_ref="mpengine 1.443.903.0",
            locator="prefix table @ 0x180DD8600; hive table @ 0x180E65630",
            supports=("regkey_receiver_projection",),
        ),
        SemanticEvidence(
            id="regkey_dispatch",
            axis="dispatch",
            kind="engine_static",
            source_ref="mpengine 1.443.903.0",
            locator="register_DB_receiver_t_reg_key_record",
            supports=("regkey_dispatch_path",),
        ),
        SemanticEvidence(
            id="regkey_consumer",
            axis="consumer",
            kind="engine_static",
            source_ref="mpengine 1.443.903.0",
            locator=(
                "GetRegKeyFromRecord @ 0x180224628; reg_key_in_Registry @ "
                "0x180223A20; ResutilsRegKeyInHive @ 0x1800BE408"
            ),
            supports=("regkey_runtime_candidate",),
        ),
        SemanticEvidence(
            id="regkey_candidate",
            axis="consumer",
            kind="engine_static",
            source_ref="mpengine 1.443.903.0",
            locator="MatchResource @ 0x1802228A0",
            supports=("regkey_detection_predicate",),
        ),
    )


def _query_recipe_contract(applicable: bool) -> JSONObject:
    return JSONObject(
        (
            ("applicable", applicable),
            (
                "projector",
                "lib.vdm.regkey_match.project_regkey_query" if applicable else None,
            ),
            (
                "evaluator",
                "lib.vdm.regkey_match.evaluate_regkey" if applicable else None,
            ),
            (
                "recipe_type",
                "lib.vdm.regkey_match.RegKeyQueryRecipe" if applicable else None,
            ),
            (
                "snapshot_type",
                "lib.vdm.regkey_match.RegKeyQuerySnapshot" if applicable else None,
            ),
            (
                "value_type",
                "lib.vdm.regkey_match.RegKeyValueSnapshot" if applicable else None,
            ),
            (
                "asep_binding_type",
                "lib.vdm.regkey_match.RegKeyAsepBinding" if applicable else None,
            ),
            (
                "unsupported_error",
                "lib.vdm.regkey_match.UnsupportedRegKeyQuery" if applicable else None,
            ),
            (
                "scope",
                (
                    "Valid UTF-8 successful conversion; logical general key or actual "
                    "caller-resolved ASEP binding; prebound query statuses/type/physical bytes/declared "
                    "size are external. NULL differs from empty. Direct mismatch uses "
                    "invocation-bound postpatch bytes and resolved path lists, not an external bool. "
                    "No registry event or final verdict."
                ),
            ),
        )
    )


def _resolved_path_profile() -> JSONObject:
    return JSONObject(
        (
            ("representation", "regkey.resolved-path-comparison.v1"),
            ("evaluator", "lib.vdm.regkey_match.evaluate_regkey"),
            ("projector", "lib.vdm.regkey_paths.project_regkey_expansion"),
            ("snapshot_type", "lib.vdm.regkey_paths.RegKeyExpansionSnapshot"),
            ("list_type", "lib.vdm.regkey_paths.RegKeyResolvedPathList"),
            ("path_type", "lib.vdm.regkey_paths.RegKeyPathValue"),
            ("crt_observation_type", "lib.vdm.regkey_paths.RegKeyUncPrefixObservation"),
            ("error_type", "lib.vdm.regkey_paths.RegKeyPathSnapshotError"),
            ("runtime_inputs_resolved", False),
            ("record_local_match", None),
            ("final_verdict", None),
            ("direct_equal", "Lazy success; no expansion snapshot read."),
            (
                "binding",
                (
                    "Exact payload raw, physical original value and expected WCHAR content; "
                    "epoch identifies one invocation. Each resolver binds epoch, exact input "
                    "buffer, opaque profile identity and uint32(ctx_flags | 0x10)."
                ),
            ),
            (
                "snapshot_fields",
                JSONArray(
                    (
                        "epoch",
                        "payload_raw",
                        "original_value_utf16",
                        "expected_utf16",
                        "postpatch",
                        "profile_identity",
                        "context_flags",
                        "crt_profile_identity",
                        "left",
                        "right",
                        "offline_patch",
                    )
                ),
            ),
            (
                "physical_strings",
                (
                    "Immutable physical UTF-16LE bytes read by code unit through NUL; "
                    "no padding or truncation by declared size, no host Unicode decode. "
                    "expected_utf16 is NUL-free content. Path readable bytes None means unknown."
                ),
            ),
            (
                "postpatch",
                (
                    "Explicit observed bytes or local offline patch result from physical "
                    "inputs; caller ignores patch status. Known computed and observed bytes "
                    "must agree. No unchanged-buffer assumption or host patch service runs."
                ),
            ),
            (
                "resolver_order",
                (
                    "REG_EXPAND_SZ (2): left service first; REG_SZ (1): postpatch singleton. "
                    "Right service always follows. Exact status 0 is success; nonzero false; "
                    "None unknown. Empty successful list is false after status gates. "
                    "Ordered tuples are complete outputs; None is not empty. No services run here."
                ),
            ),
            (
                "comparison",
                (
                    "Left-major Cartesian pairs; FriendlyName right then left. Literal \\\\?\\ "
                    "prefix strips four WCHARs unless CRT _wcsnicmp first eight equals "
                    "\\\\?\\UNC\\. ASCII UNC subset is computed; non-ASCII classifier requires "
                    "actual CRT observation bound to bytes, invocation and CRT profile. "
                    "Final equality folds only ASCII a..z to A..Z and / to \\, through NUL. "
                    "No Unicode casefold, slash collapse, dot removal, prefix/basename comparison."
                ),
            ),
            (
                "outcomes",
                (
                    "Actual local equality, first matching pair and visited pairs retain candidate "
                    "bytes. First unknown reached read stops projection; match skips later pairs. "
                    "Missing facts yield None; malformed types or conflicting input/epoch/profile/flags "
                    "raise RegKeyPathSnapshotError, never silently no-match."
                ),
            ),
            (
                "unresolved",
                (
                    "Offline wrapper gates and engine CRT observations are explicit inputs; "
                    "seven ordered resolver filters/environment/filesystem outputs, registry "
                    "binding, outer report and final verdict remain external."
                ),
            ),
        )
    )


def _offline_patch_profile() -> JSONObject:
    return JSONObject(
        (
            ("representation", "regkey.offline-patch-values.v1"),
            ("projector", "lib.vdm.regkey_offline.project_regkey_offline_patch"),
            ("snapshot_type", "lib.vdm.regkey_offline.RegKeyOfflinePatchSnapshot"),
            ("memory_type", "lib.vdm.regkey_offline.RegKeyOfflineByteWindow"),
            (
                "crt_observation_type",
                "lib.vdm.regkey_offline.RegKeyTowupperObservation",
            ),
            ("result_type", "lib.vdm.regkey_offline.RegKeyOfflinePatchResult"),
            ("error_type", "lib.vdm.regkey_offline.RegKeyOfflineSnapshotError"),
            ("runtime_inputs_resolved", False),
            ("patch_status", None),
            ("postpatch_utf16", None),
            ("final_verdict", None),
            (
                "binding",
                (
                    "One invocation epoch, exact payload raw and physical original buffer. "
                    "CRT facts bind epoch/profile, previous index, call1 or call2 and input WCHAR. "
                    "No host Unicode folding or same-epoch stable-locale assumption."
                ),
            ),
            (
                "wrapper",
                (
                    "Manager absent:87; online:0; offline context absent:87; NULL offline data "
                    "or path:87; these branches read no path/table. Unknown reached gate stays unknown."
                ),
            ),
            (
                "physical_inputs",
                (
                    "offline_flags BYTE at +0x34 or physical window byte, conflicts rejected. "
                    "Bit0 skips path reads. Immutable offline-relative BYTE window supports "
                    "negative offsets. Mapping offset=zeroextend16(towupper_EAX)-12, -12..65523, "
                    "without A-Z guard. Outside supplied readable bytes is unknown, not zero."
                ),
            ),
            (
                "loop",
                (
                    "uint32 scan reads WCHAR through NUL. A noninitial colon followed by / or "
                    "backslash reads previous WCHAR: call1 AX -> map1, zero continues; nonzero "
                    "executes independent call2 AX -> map2, zeroextends BYTE to WCHAR and writes "
                    "previous position then returns0. Second map may be zero/different. No suffix "
                    "NUL read after write. No stable CRT locale inferred from epoch."
                ),
            ),
            (
                "outputs",
                (
                    "patch_status, postpatch physical bytes, changed, written_index, changed_position, "
                    "written_unit, fold_calls and table_reads are separate. Identical write still "
                    "returns0; zero can introduce NUL. Missing reached read is unknown; malformed "
                    "or conflicting facts raise RegKeyOfflineSnapshotError."
                ),
            ),
            (
                "integration",
                (
                    "ExpansionSnapshot.offline_patch may compute bytes or use independently "
                    "observed postpatch; known byte conflicts raise error. Caller ignores patch "
                    "status including87. Direct string equality skips patch facts. Seven ordered "
                    "resolver filters/environment/filesystem outputs remain external. No verdict."
                ),
            ),
        )
    )


def export_regkey(parsed: RegKeyPayload) -> ArtifactExport:
    """Export a query recipe manifest, not a registry event or detection rule."""
    parsed = parse_regkey(parsed.raw)
    semantics = export_regkey_semantics(parsed).to_json()
    manifest = {
        "format": "vdm.regkey.query-recipe.v1",
        "raw_hex": parsed.raw.hex(),
        "query_recipe": dict(_query_recipe_contract(1 <= parsed.key_type <= 4).items),
        "receiver_projection": dict(_project_receiver_fields(parsed).items),
        "resolved_path_comparison_profile": semantics["data"][
            "resolved_path_comparison_profile"
        ],
        "record_local_match": None,
        "offline_patch_recipe_profile": semantics["data"][
            "offline_patch_recipe_profile"
        ],
        "final_verdict": None,
        "claims": semantics["claims"],
        "claim_evidence": semantics["claim_evidence"],
    }
    return ArtifactExport(
        "ready",
        (
            Artifact(
                "regkey-query.json",
                "json",
                json.dumps(manifest, ensure_ascii=True, indent=2).encode("utf-8")
                + b"\n",
            ),
        ),
    )


SPEC = FamilySpec(
    REGKEY_TYPE,
    "REGKEY",
    parse_regkey,
    render_regkey,
    exporter=export_regkey,
    semantic_exporter=export_regkey_semantics,
)
