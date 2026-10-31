"""Lossless parser for Defender's shared file path signature family."""

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final, Literal

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
    SemanticJSONValue,
    SemanticUnknown,
)
from ..fpath_lookup import (
    CSIDL_INDEX_MISS,
    ORIGINAL_CSIDL_LOOKUP_PROFILE,
    lookup_original_csidl_index,
)

FPATH_TYPES: Final = MappingProxyType(
    {
        0x5F: "FILEPATH",
        0x60: "FOLDERNAME",
        0x71: "ASEP_FILEPATH",
        0x75: "ASEP_FOLDERNAME",
    }
)
FILEPATH_TYPES: Final = frozenset({0x5F, 0x71})
FOLDERNAME_TYPES: Final = frozenset({0x60, 0x75})
HEADER_SIZE: Final = 2


@dataclass(frozen=True, slots=True)
class FpathPayload:
    """Parsed fields for a FILEPATH family payload, retaining every byte."""

    raw: bytes
    type_byte: int
    csidl_value: int
    path_kind: Literal["filepath", "foldername"]
    path_region_raw: bytes
    path_bytes: bytes
    runtime_path_bytes: bytes
    nul_terminated: bool
    nul_offset: int | None
    pipe_offset: int | None
    tail_raw: bytes

    @property
    def path_text(self) -> str:
        """Return a reversible single-byte view without assuming UTF-16LE."""
        return self.path_bytes.decode("latin-1")


def _fpath_receiver_input_profile(parsed: FpathPayload) -> dict[str, object]:
    """Separate bounded wire bytes from the original receiver's input contract."""
    size = len(parsed.raw)
    is_folder = parsed.path_kind == "foldername"
    tail_offset = HEADER_SIZE + len(parsed.path_region_raw) + int(parsed.nul_terminated)
    uses_helper = parsed.nul_terminated and (is_folder or bool(parsed.tail_raw))
    scan_borrows_byte = is_folder and not parsed.nul_terminated
    return {
        "kind": "bounded_receiver_input_projection",
        "offset_unit": "payload_bytes",
        "wrapper_input": "original_payload_pointer_and_length_unchanged",
        "receiver": "folder_DB_receiver" if is_folder else "fpath_DB_receiver",
        "preconditions": [
            "csidl_lookup_succeeded",
            "receiver_reaches_the_described_scan_or_recid_selection_stage",
            "preceding_allocation_and_copy_complete_normally_where_required",
        ],
        "path_scan": {
            "external_read": (
                {"offset": size, "length": 1} if scan_borrows_byte else None
            ),
            "external_byte_must_be_readable": scan_borrows_byte,
            "upper_storage_readability_guarantee": (
                "unknown" if scan_borrows_byte else "not_required_by_path_scan"
            ),
            "external_value_affects_path_length_or_recid_route_under_readable": False,
        },
        "wire_tail": {
            "offset": tail_offset,
            "length": len(parsed.tail_raw),
            "raw_hex": parsed.tail_raw.hex(),
        },
        "recid_call": {
            "callee": "createrecidp" if uses_helper else "createrecid",
            "tail_argument": (
                {
                    "offset": tail_offset,
                    "declared_length": len(parsed.tail_raw) + int(is_folder),
                    "wire_available_length": len(parsed.tail_raw),
                    "outside_payload_length": int(is_folder),
                    "outside_payload_bytes": "unknown" if is_folder else "none",
                    "declared_span_is_bounded_by_payload": not is_folder,
                }
                if uses_helper
                else None
            ),
            "helper_prefix_external_read": (
                {"offset": size, "length": 1, "must_be_readable": True}
                if uses_helper and is_folder and not parsed.tail_raw
                else None
            ),
            "helper_guaranteed_no_name": uses_helper
            and is_folder
            and not parsed.tail_raw,
            "returned_recid_store_offset": 0x18,
            "recid_sentinel_effect": "return_32780_without_appending_record",
            "threatid_resolver_called_by_receiver": False,
            "name_projection": (
                "no_name_delegates_to_createrecid_under_prefix_readable"
                if uses_helper and is_folder and not parsed.tail_raw
                else "unmodeled"
                if uses_helper
                else "no_tail_helper"
            ),
            "runtime_identity": "unresolved",
        },
        "proof_scope": {
            "native": "original_receiver_scan_and_call_selection_slices",
            "allocation_and_copy_executed": False,
            "full_loader_acceptance": "unproven",
        },
    }


def _parse_size_constraint(raw: bytes) -> JSONObject:
    """Project the decimal grammar implemented by ``setSize``.

    Malformed strings stay explicit instead of approximating
    ``StrToULongHelper``'s partial-conversion behavior.
    """
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        text = ""

    lower = 0
    upper = 0
    form = "unmodeled"
    modeled = False
    if text.isdecimal():
        value = int(text, 10)
        if value <= 0xFFFFFFFF:
            lower = value
            upper = value
            form = "exact"
            modeled = True
    elif text.startswith("-") and text[1:].isdecimal():
        value = int(text[1:], 10)
        if value <= 0xFFFFFFFF:
            upper = value
            form = "maximum"
            modeled = True
    elif text.count("-") == 1:
        left, right = text.split("-", 1)
        if left.isdecimal() and (not right or right.isdecimal()):
            left_value = int(left, 10)
            right_value = int(right, 10) if right else 0
            if left_value <= 0xFFFFFFFF and right_value <= 0xFFFFFFFF:
                lower = left_value
                upper = 0xFFFFFFFF if right and right_value == 0 else right_value
                form = "range" if right else "lower_with_zero_upper"
                modeled = True

    return JSONObject(
        (
            ("raw_hex", raw.hex()),
            ("ascii", raw.decode("ascii", errors="replace")),
            ("form", form),
            ("modeled", modeled),
            ("minimum_u32", lower if modeled else None),
            ("maximum_u32", upper if modeled else None),
            ("bounds_inclusive", True if modeled else None),
        )
    )


def _fpath_csidl_lookup(parsed: FpathPayload) -> dict[str, object]:
    index = lookup_original_csidl_index(parsed.csidl_value)
    return {
        "profile_id": ORIGINAL_CSIDL_LOOKUP_PROFILE["id"],
        "selector_u16": parsed.csidl_value,
        "result_u32": index,
        "matched": index != CSIDL_INDEX_MISS,
        "row_index": None if index == CSIDL_INDEX_MISS else index,
        "state_assumption": "normal_readonly_original_key_state",
        "initialized_engine_executed": False,
        "runtime_expansion": "unresolved",
    }


def _fpath_match_profile(parsed: FpathPayload) -> dict[str, object]:
    """Return the engine-confirmed bounded path candidate contract."""
    is_asep = parsed.type_byte in {0x71, 0x75}
    is_file = parsed.path_kind == "filepath"
    return {
        "kind": "engine_confirmed_bounded_path_candidate",
        "storage_family": "asep" if is_asep else "standard",
        "resource_kind": parsed.path_kind,
        "path_input": (
            "csidl_expanded_prefix_plus_runtime_path"
            if is_asep
            else "resource_path_with_csidl"
        ),
        "runtime_path_bytes_are_fully_expanded": False,
        "csidl": {
            "required": True,
            "mapping": "CSIDL_2_ix_engine_binary_search",
            "entry_count": 49,
            "entry_stride": 0x28,
            "miss_sentinel": 0x7FFFFFFF,
            "lookup": _fpath_csidl_lookup(parsed),
            "expansion_prefix": "runtime_only_unresolved",
        },
        "path_matching": {
            "exact": {
                "consumer": ("filesystem_path_check" if is_asep else "fcmp_file_path"),
                "case": None if is_asep else "ascii_case_insensitive",
                "slash_equivalence_applies": None if is_asep else True,
                "slash_equivalence": None
                if is_asep
                else "forward_slash_equals_backslash",
                "terminal_separator": (
                    "runtime_filesystem_semantics_unresolved"
                    if is_asep
                    else "one_trailing_backslash_equals_end"
                ),
            },
            "wildcard": {
                "consumer": (
                    "fpath_on_disk_filesystem_enumeration"
                    if is_asep
                    else "MatchWildCardHelper_char_"
                ),
                "enabled_when": (
                    "runtime_filesystem_enumeration"
                    if is_asep
                    else "ResutilsStrHasWildcards(runtime_path_bytes)"
                ),
                "dialect": None if is_asep else "question_and_star",
                "question_mark": None if is_asep else "matches_one_character",
                "star": (
                    "runtime_filesystem_enumeration_semantics_unresolved"
                    if is_asep
                    else "matches_zero_or_more_characters_by_recursive_search"
                ),
                "case": None if is_asep else "ascii_case_insensitive",
                "terminal_separator": (
                    "runtime_filesystem_semantics_unresolved"
                    if is_asep
                    else "one_trailing_backslash_equals_end"
                ),
                "regex_or_yara_equivalence": None,
            },
            "wildcard_record_flag": "bit_31_of_csidl_index",
        },
        "size_constraint": {
            "source": "first_pipe_suffix" if is_file else "none",
            "runtime_check": "inclusive_u32_bounds",
            "unbounded_sentinel": {
                "minimum": 0,
                "maximum": 0xFFFFFFFF,
                "effect": "accept_without_filesystem_size_query",
            },
            "modeled_constraint": (
                None
                if not is_file or parsed.pipe_offset is None
                else dict(
                    _parse_size_constraint(
                        parsed.path_region_raw[parsed.pipe_offset + 1 :]
                    ).items
                )
            ),
        },
        "candidate_gates": [
            "csidl_match",
            "path_match_and_filesystem_resource_type",
            "size_constraint_if_present",
            "expiry_and_disabled_signature_or_threat_gates",
        ],
        "polarity": None,
        "final_verdict": None,
        "limitations": [
            "csidl_nonkey_fields_and_expansion_prefix_are_unmodeled",
            "resource_candidate_is_not_a_user_visible_report_or_final_verdict",
            "optional_recid_tail_semantics_are_unresolved",
        ],
    }


def _semantic_json(value: object) -> SemanticJSONValue:
    """Convert the shared JSON profile to the immutable semantic JSON types."""
    if isinstance(value, dict):
        if any(not isinstance(key, str) for key in value):
            raise TypeError("semantic profile object keys must be strings")
        return JSONObject(
            tuple((key, _semantic_json(item)) for key, item in value.items())
        )
    if isinstance(value, list):
        return JSONArray(tuple(_semantic_json(item) for item in value))
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    raise TypeError(f"unsupported semantic profile value: {type(value).__name__}")


def parse_fpath(payload: bytes, *, type_byte: int) -> FpathPayload:
    """Parse the type-specific path or folder record envelope losslessly."""
    try:
        FPATH_TYPES[type_byte]
    except KeyError as exc:
        raise ValueError(f"unsupported FPATH family type 0x{type_byte:02X}") from exc

    if len(payload) <= HEADER_SIZE:
        raise ValueError(
            "truncated FPATH path data: need at least 1 byte after the "
            f"{HEADER_SIZE}-byte header, have {len(payload) - HEADER_SIZE}"
        )

    csidl_value = int.from_bytes(payload[:HEADER_SIZE], "little")
    path_kind = "filepath" if type_byte in FILEPATH_TYPES else "foldername"
    path_and_tail = payload[HEADER_SIZE:]
    nul_offset = path_and_tail.find(b"\0")
    nul_terminated = nul_offset >= 0

    if nul_terminated:
        path_region_raw = path_and_tail[:nul_offset]
        tail_raw = path_and_tail[nul_offset + 1 :]
    else:
        path_region_raw = path_and_tail
        tail_raw = b""

    pipe_offset = path_region_raw.find(b"|") if path_kind == "filepath" else -1
    path_bytes = path_region_raw if pipe_offset < 0 else path_region_raw[:pipe_offset]
    runtime_path_bytes = path_bytes
    if (
        path_kind == "foldername"
        and runtime_path_bytes
        and not runtime_path_bytes.endswith(b"\\")
    ):
        runtime_path_bytes += b"\\"

    return FpathPayload(
        raw=payload,
        type_byte=type_byte,
        csidl_value=csidl_value,
        path_kind=path_kind,
        path_region_raw=path_region_raw,
        path_bytes=path_bytes,
        runtime_path_bytes=runtime_path_bytes,
        nul_terminated=nul_terminated,
        nul_offset=None if not nul_terminated else nul_offset,
        pipe_offset=None if pipe_offset < 0 else pipe_offset,
        tail_raw=tail_raw,
    )


def render_fpath(parsed: FpathPayload) -> FormatResult:
    """Render known path fields and opaque tail lengths as logger sections."""
    name = FPATH_TYPES[parsed.type_byte]
    lookup_index = lookup_original_csidl_index(parsed.csidl_value)
    path_rows = (
        ("csidl_value", f"0x{parsed.csidl_value:04X}"),
        (
            "csidl_lookup",
            "original-key profile: "
            + (
                "miss (0x7FFFFFFF)"
                if lookup_index == CSIDL_INDEX_MISS
                else f"row {lookup_index}"
            ),
        ),
        ("path_len", f"{len(parsed.path_bytes)} B"),
        (
            "path",
            json.dumps(parsed.path_text, ensure_ascii=True)
            if parsed.path_bytes
            else "(empty)",
        ),
        (
            "path_terminator",
            "NUL" if parsed.nul_terminated else "absent (payload boundary)",
        ),
    )

    if parsed.path_kind == "foldername":
        path_rows += (
            (
                "runtime_path",
                json.dumps(
                    parsed.runtime_path_bytes.decode("latin-1"),
                    ensure_ascii=True,
                ),
            ),
            ("normalization", "append '\\' when absent"),
        )

    if parsed.pipe_offset is not None:
        size_raw = parsed.path_region_raw[parsed.pipe_offset + 1 :]
        size_constraint = _parse_size_constraint(size_raw)
        size_values = dict(size_constraint.items)
        path_rows += (
            ("pipe_offset", str(parsed.pipe_offset)),
            ("size_dsl", size_raw.decode("ascii", errors="replace") or "(empty)"),
            (
                "size_bounds",
                (
                    f"{size_values['minimum_u32']}.."
                    f"{size_values['maximum_u32']} (inclusive)"
                    if size_values["modeled"]
                    else "unmodeled"
                ),
            ),
        )

    sections = [
        DisplaySection("Path", rows=path_rows),
        DisplaySection(
            "Opaque Tail",
            rows=(("tail_len", f"{len(parsed.tail_raw)} B"),),
        ),
        DisplaySection(
            "Record Type",
            rows=(("type", f"{name} (0x{parsed.type_byte:02X})"),),
        ),
    ]
    return FormatResult(sections=tuple(sections))


def export_fpath_artifact(parsed: FpathPayload) -> ArtifactExport:
    """Export a deterministic, lossless path observation manifest."""
    type_name = FPATH_TYPES[parsed.type_byte]
    is_asep = parsed.type_byte in {0x71, 0x75}
    path_offset = HEADER_SIZE
    pipe_suffix = (
        None
        if parsed.pipe_offset is None
        else parsed.path_region_raw[parsed.pipe_offset :]
    )
    manifest = {
        "schema": "vdm.fpath.artifact.v3",
        "record_type": {"byte": parsed.type_byte, "name": type_name},
        "family": "asep" if is_asep else "standard",
        "raw_hex": parsed.raw.hex(),
        "match_profile": _fpath_match_profile(parsed),
        "receiver_input_profile": _fpath_receiver_input_profile(parsed),
        "csidl": {
            "value": parsed.csidl_value,
            "raw_hex": parsed.raw[:HEADER_SIZE].hex(),
            "offset": 0,
            "lookup": _fpath_csidl_lookup(parsed),
        },
        "path": {
            "kind": parsed.path_kind,
            "raw_hex": parsed.path_region_raw.hex(),
            "offset": path_offset,
            "path_bytes_hex": parsed.path_bytes.hex(),
            "path_latin1": parsed.path_bytes.decode("latin-1"),
            "normalized_bytes_hex": parsed.runtime_path_bytes.hex(),
            "normalized_latin1": parsed.runtime_path_bytes.decode("latin-1"),
            "normalization": (
                "append_backslash_if_nonempty_and_missing"
                if parsed.path_kind == "foldername"
                else "none"
            ),
            "nul_terminated": parsed.nul_terminated,
            "nul_offset": (
                None if parsed.nul_offset is None else path_offset + parsed.nul_offset
            ),
            "pipe_suffix": (
                None
                if pipe_suffix is None
                else {
                    "offset": path_offset + parsed.pipe_offset,
                    "raw_hex": pipe_suffix.hex(),
                }
            ),
        },
        "recid_tail": {
            "raw_hex": parsed.tail_raw.hex(),
            "offset": (
                path_offset + len(parsed.path_region_raw) + int(parsed.nul_terminated)
            ),
        },
        "semantic_boundary": {
            "path_matching": "confirmed_subset",
            "final_verdict": "unknown",
            "csidl_runtime_expansion": "unknown",
            "pipe_suffix": "file_size_constraint_dsl",
            "recid_tail": "opaque_bytes_preserved",
            "path_encoding": "single_byte_latin1_view_is_reversible_not_text_semantics",
        },
    }
    data = (
        json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")
    digest = hashlib.sha256(parsed.raw).hexdigest()[:16]
    return ArtifactExport(
        "ready",
        artifacts=(
            Artifact(
                f"{parsed.type_byte:02x}-{digest}.json",
                "fpath_json_manifest",
                data,
            ),
        ),
    )


def _wire_field(kind: str, raw: bytes, offset: int) -> JSONObject:
    return JSONObject(
        (
            ("kind", kind),
            ("raw_span", JSONObject((("offset", offset), ("length", len(raw))))),
            ("raw_hex", raw.hex()),
        )
    )


def export_fpath_semantics(parsed: FpathPayload) -> RuleSemantics:
    """Export receiver and matcher behavior confirmed in the selected engine."""
    type_name = FPATH_TYPES[parsed.type_byte]
    is_asep = parsed.type_byte in {0x71, 0x75}
    path_offset = HEADER_SIZE
    path_end = path_offset + len(parsed.path_region_raw)
    size_dsl_raw = (
        None
        if parsed.pipe_offset is None
        else parsed.path_region_raw[parsed.pipe_offset + 1 :]
    )
    size_constraint = (
        None if size_dsl_raw is None else _parse_size_constraint(size_dsl_raw)
    )
    match_profile = _fpath_match_profile(parsed)
    issues = [
        SemanticIssue(
            "final_verdict_unknown",
            "The resource matcher yields a gated candidate, not the outer scan verdict.",
        ),
        SemanticIssue(
            "csidl_runtime_expansion_unknown",
            "The pinned original/read-only key-state lookup projects a numeric "
            "index or miss; runtime path expansion and other row fields remain unresolved.",
        ),
    ]
    if parsed.pipe_offset is not None:
        assert size_constraint is not None
        if not dict(size_constraint.items)["modeled"]:
            issues.append(
                SemanticIssue(
                    "size_dsl_conversion_unmodeled",
                    "setSize receives the bytes after '|', but malformed/partial "
                    "StrToULongHelper conversion is not projected.",
                    (
                        ("offset", path_offset + parsed.pipe_offset + 1),
                        ("length", len(size_dsl_raw or b"")),
                    ),
                )
            )
    receiver_input_profile = _fpath_receiver_input_profile(parsed)
    helper_called = parsed.nul_terminated and (
        parsed.path_kind == "foldername" or bool(parsed.tail_raw)
    )
    if parsed.tail_raw:
        issues.append(
            SemanticIssue(
                "receiver_recid_semantics_unmodeled",
                "The receiver calls createrecidp with the separately described "
                "input span; name construction and runtime identity are not projected.",
                (("length", len(parsed.tail_raw)),),
            )
        )
    evidence = (
        f"mpengine 1.443.903.0 {type_name} receiver registration and storage wrapper",
        "mpengine 1.443.903.0 type-specific FILEPATH/FOLDERNAME receiver path handling",
        (
            "mpengine 1.443.903.0 CSIDL_2_ix @ 0x180321810 bsearches 49 "
            "entries of stride 0x28 and returns 0x7fffffff on a miss"
        ),
    )
    return RuleSemantics(
        status=(
            "unsupported"
            if parsed.tail_raw
            or (
                size_constraint is not None
                and not dict(size_constraint.items)["modeled"]
            )
            else "confirmed_subset"
        ),
        representation="fpath.path-match-candidate.ir.v5",
        data=JSONObject(
            (
                ("type", type_name),
                ("raw_hex", parsed.raw.hex()),
                ("match_profile", _semantic_json(match_profile)),
                ("receiver_input_profile", _semantic_json(receiver_input_profile)),
                ("storage_family", "asep" if is_asep else "standard"),
                (
                    "csidl",
                    JSONObject(
                        (
                            ("value", parsed.csidl_value),
                            ("wire", _wire_field("csidl_value", parsed.raw[:2], 0)),
                            ("consumer", "CSIDL_2_ix"),
                            (
                                "mapping",
                                JSONObject(
                                    (
                                        ("kind", "engine_binary_search"),
                                        ("entry_count", 49),
                                        ("entry_stride", 0x28),
                                        ("miss_sentinel", 0x7FFFFFFF),
                                        (
                                            "lookup",
                                            _semantic_json(_fpath_csidl_lookup(parsed)),
                                        ),
                                    )
                                ),
                            ),
                        )
                    ),
                ),
                (
                    "path",
                    JSONObject(
                        (
                            ("kind", parsed.path_kind),
                            (
                                "wire",
                                _wire_field(
                                    "path_region", parsed.path_region_raw, path_offset
                                ),
                            ),
                            ("bytes_hex", parsed.path_bytes.hex()),
                            ("nul_terminated", parsed.nul_terminated),
                            (
                                "terminator",
                                None
                                if not parsed.nul_terminated
                                else _wire_field(
                                    "nul_terminator",
                                    parsed.raw[
                                        parsed.nul_offset
                                        + path_offset : parsed.nul_offset
                                        + path_offset
                                        + 1
                                    ],
                                    parsed.nul_offset + path_offset,
                                ),
                            ),
                            (
                                "runtime_bytes_hex",
                                parsed.runtime_path_bytes.hex(),
                            ),
                            (
                                "normalization",
                                "append_backslash_if_nonempty_and_missing"
                                if parsed.path_kind == "foldername"
                                else "none_confirmed",
                            ),
                            (
                                "wildcard_detection",
                                JSONObject(
                                    (
                                        ("consumer", "ResutilsStrHasWildcards"),
                                        ("input", "runtime_bytes"),
                                        (
                                            "stored_effect",
                                            "set_bit_31_of_csidl_index",
                                        ),
                                    )
                                ),
                            ),
                            ("size_constraint", size_constraint),
                        )
                    ),
                ),
                (
                    "receiver_tail",
                    JSONObject(
                        (
                            (
                                "wire",
                                _wire_field(
                                    "wire_tail",
                                    parsed.tail_raw,
                                    path_end + 1 if parsed.nul_terminated else path_end,
                                ),
                            ),
                            (
                                "receiver_path",
                                "createrecidp" if helper_called else "createrecid",
                            ),
                            ("meaning", None),
                        )
                    ),
                ),
            )
        ),
        evidence=evidence,
        profile="mpengine-1.443.903.0",
        issues=tuple(issues),
        claims=_fpath_claims(parsed),
        claim_evidence=_fpath_evidence(parsed),
    )


def _fpath_claims(parsed: FpathPayload) -> tuple[SemanticClaim, ...]:
    type_name = FPATH_TYPES[parsed.type_byte]
    is_asep = parsed.type_byte in {0x71, 0x75}
    is_file = parsed.path_kind == "filepath"
    receiver_detail = (
        "splits the first '|' and decodes the suffix into inclusive u32 file-size "
        "bounds"
        if is_file
        else "appends a trailing backslash to a non-empty folder path when absent"
    )
    consumer_detail = (
        "expands the configured CSIDL path and checks the resulting path on disk"
        if is_asep
        else "compares the supplied resource path using exact or wildcard matching"
    )
    return (
        SemanticClaim(
            id="fpath_wire_layout",
            scope="wire_layout",
            statement=(
                f"{type_name} contains a u16 CSIDL selector, a bounded narrow path, "
                "and optional NUL-separated wire tail bytes. The receiver's "
                "declared helper span is projected separately from these wire bytes."
            ),
            coverage="subset",
            evidence_refs=("fpath_receiver",),
            unknowns=(
                SemanticUnknown(
                    "wire_layout",
                    "Helper name construction and runtime identity are not projected.",
                ),
            ),
        ),
        SemanticClaim(
            id="fpath_dispatch_path",
            scope="loader_dispatch",
            statement=f"Type 0x{parsed.type_byte:02X} uses its type-specific receiver and table.",
            coverage="subset",
            evidence_refs=("fpath_dispatch",),
            unknowns=(
                SemanticUnknown(
                    "loader_dispatch",
                    "Outer database-selection and product enablement gates are not modeled.",
                ),
            ),
        ),
        SemanticClaim(
            id="fpath_receiver_projection",
            scope="receiver_transform",
            statement=f"The receiver resolves CSIDL, stores the path, and {receiver_detail}.",
            coverage="subset",
            evidence_refs=("fpath_receiver",),
            unknowns=(
                SemanticUnknown(
                    "receiver_transform",
                    "CSIDL nonkey fields, expansion and runtime RecID construction are not projected.",
                ),
            ),
        ),
        SemanticClaim(
            id="fpath_receiver_input_span",
            scope="receiver_transform",
            statement=(
                "Wrappers pass the original payload pointer and length unchanged. "
                "FILEPATH helper spans are bounded remaining bytes; FOLDERNAME "
                "declares one extra byte. Without NUL, the folder scan reads one "
                "external byte whose value does not affect path length or RecID "
                "route when readable. Receivers store RecID at +0x18 and reject "
                "its sentinel with 32780 without calling a threat-ID resolver."
            ),
            coverage="subset",
            evidence_refs=("fpath_receiver_span_static", "fpath_receiver_span_native"),
            unknowns=(
                SemanticUnknown(
                    "receiver_transform",
                    "Upper storage readability, borrowed tail byte values, allocation, "
                    "copy, full loader acceptance and runtime identity remain unproven.",
                ),
            ),
        ),
        SemanticClaim(
            id="fpath_original_csidl_lookup",
            scope="receiver_transform",
            statement=(
                "The pinned original/read-only key-state profile reproduces "
                "CSIDL_2_ix numeric index or 0x7fffffff miss using the original "
                "unsorted 49-key order and CRT binary search with even lower midpoint. "
                "Normal PE mapping/relocation preserves the read-only key spans."
            ),
            coverage="subset",
            evidence_refs=("fpath_csidl_lookup_static", "fpath_csidl_lookup_native"),
            unknowns=(
                SemanticUnknown(
                    "receiver_transform",
                    "Engine initialization was not executed; runtime expansion, "
                    "other row fields and any deliberate key mutation are outside this profile.",
                ),
            ),
        ),
        SemanticClaim(
            id="fpath_runtime_candidate",
            scope="runtime_consumer",
            statement=(
                f"MatchResource {consumer_detail}; FILEPATH size bounds are checked "
                "inclusively when present."
            ),
            coverage="subset",
            evidence_refs=("fpath_consumer",),
            unknowns=(
                SemanticUnknown(
                    "runtime_consumer",
                    "CSIDL expansion inputs and every resource-enumeration state transition are not modeled.",
                ),
            ),
        ),
        SemanticClaim(
            id="fpath_detection_predicate",
            scope="detection_predicate",
            statement=(
                "A path candidate is emitted only after path/on-disk matching, the "
                "inclusive size check, and disabled/expiry gates used by its branch."
            ),
            coverage="subset",
            evidence_refs=("fpath_consumer",),
            unknowns=(
                SemanticUnknown(
                    "detection_predicate",
                    "RecID validator effects and outer resource-search arbitration remain unresolved.",
                ),
            ),
        ),
        SemanticClaim(
            id="fpath_report_mapping",
            scope="report_mapping",
            statement="The candidate metadata has no confirmed user-visible report mapping.",
            coverage="unknown",
            unknowns=(
                SemanticUnknown(
                    "report_mapping",
                    "No caller was followed from MatchResource output into report policy.",
                ),
            ),
        ),
        SemanticClaim(
            id="fpath_final_verdict",
            scope="final_verdict",
            statement="A FILEPATH-family resource candidate is not a confirmed final verdict.",
            coverage="unknown",
            unknowns=(
                SemanticUnknown(
                    "final_verdict",
                    "Outer scan arbitration and final report policy remain unresolved.",
                ),
            ),
        ),
    )


def _fpath_evidence(parsed: FpathPayload) -> tuple[SemanticEvidence, ...]:
    receiver = (
        "fpath_DB_receiver @ 0x1803215DC; setSize @ 0x180B0B5CC"
        if parsed.path_kind == "filepath"
        else "folder_DB_receiver @ 0x18032126C"
    )
    dispatch = {
        0x5F: "file_path_DB_receiver @ 0x1803218B0",
        0x60: "folder_name_DB_receiver @ 0x180321140",
        0x71: "ASEP_file_path_DB_receiver @ 0x18051D810",
        0x75: "ASEP_folder_name_DB_receiver @ 0x180B0AC60",
    }[parsed.type_byte]
    consumer = (
        "MatchResource @ 0x1802228A0; get_expanded_path @ 0x180224330; "
        "fpath_on_disk @ 0x180224074; file_size_check @ 0x180223914"
        if parsed.type_byte in {0x71, 0x75}
        else "MatchResource @ 0x1802228A0; fpath_in_DB @ 0x1802233FC; "
        "fcmp_file_path @ 0x1803B0160; MatchWildCardHelper_char_ @ "
        "0x180223784; file_size_check @ 0x180223914"
    )
    return (
        SemanticEvidence(
            id="fpath_csidl_lookup_static",
            axis="receiver",
            kind="engine_static",
            source_ref="mpengine 1.443.903.0 original PE image",
            locator=(
                "CSIDL_2_ix @ 0x180321810; bsearch @ 0x1809387E0; "
                "fcmp_predef_path @ 0x1804E0FE0; g_predef_paths @ 0x180DB98D0, "
                "49 rows stride 0x28, unsigned WORD key +0x20; .rdata READ/non-WRITE "
                "and zero key-span relocation overlaps; tests/local_fpath_csidl_state_v1.json"
            ),
            supports=("fpath_original_csidl_lookup",),
        ),
        SemanticEvidence(
            id="fpath_csidl_lookup_native",
            axis="engine_equivalent_test",
            kind="engine_equivalent_test",
            source_ref="mpengine 1.443.903.0 original raw/read-only key-state helpers",
            locator=(
                "tests/local_fpath_csidl_raw_engine.py SHA256 "
                "32960de592956bfae87176506d5bae000ae1e8f73cd2b63128f95e6d7a6387c2; "
                "65536 uint16 selectors plus 37 selected controls, including 26 corpus "
                "selectors; original CSIDL_2_ix, full CRT search and comparator, no stubs; "
                "numeric returns and comparison traces match. Engine initialization, "
                "filesystem expansion and whole-loader acceptance were not executed."
            ),
            supports=("fpath_original_csidl_lookup",),
        ),
        SemanticEvidence(
            id="fpath_receiver_span_static",
            axis="receiver",
            kind="engine_static",
            source_ref="mpengine 1.443.903.0",
            locator=(
                "folder_DB_receiver @ 0x1803212EB..0x18032131D and "
                "0x1803213DD..0x1803213F5; fpath_DB_receiver @ "
                "0x18032166F..0x1803216B8 and 0x18032172F..0x18032179A; "
                "createrecidp @ 0x180323040 bounds name length by declared_length-1; "
                + dispatch
            ),
            supports=("fpath_receiver_input_span",),
        ),
        SemanticEvidence(
            id="fpath_receiver_span_native",
            axis="engine_equivalent_test",
            kind="engine_equivalent_test",
            source_ref="mpengine 1.443.903.0 original receiver slices",
            locator=(
                "tests/local_fpath_receiver_tail_slice.py SHA256 "
                "10b862bf6994065a25e734661db6391c555bafb876d216ad967188964d6a62df; "
                "43 tests / 64 result rows: 40 synthetic, 6 actual record controls, "
                "18 explicit external-byte 00/01/FF controls. Only scan and "
                "call-selection slices; allocation/copy and callees not executed; "
                "not full receiver or loader acceptance."
            ),
            supports=("fpath_receiver_input_span",),
        ),
        SemanticEvidence(
            id="fpath_receiver",
            axis="receiver",
            kind="engine_static",
            source_ref="mpengine 1.443.903.0",
            locator=receiver,
            supports=("fpath_wire_layout", "fpath_receiver_projection"),
        ),
        SemanticEvidence(
            id="fpath_dispatch",
            axis="dispatch",
            kind="engine_static",
            source_ref="mpengine 1.443.903.0",
            locator=dispatch,
            supports=("fpath_dispatch_path",),
        ),
        SemanticEvidence(
            id="fpath_consumer",
            axis="consumer",
            kind="engine_static",
            source_ref="mpengine 1.443.903.0",
            locator=consumer,
            supports=("fpath_runtime_candidate", "fpath_detection_predicate"),
        ),
    )


def _parser_for(type_byte: int) -> Callable[[bytes], FpathPayload]:
    def parser(payload: bytes) -> FpathPayload:
        return parse_fpath(payload, type_byte=type_byte)

    return parser


FPATH_SPECS = tuple(
    FamilySpec(
        type_byte,
        name,
        _parser_for(type_byte),
        render_fpath,
        exporter=(export_fpath_artifact if type_byte in {0x5F, 0x60, 0x71} else None),
        semantic_exporter=export_fpath_semantics,
    )
    for type_byte, name in FPATH_TYPES.items()
)
