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
    JSONObject,
    RuleSemantics,
    SemanticClaim,
    SemanticEvidence,
    SemanticIssue,
    SemanticUnknown,
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
    path_rows = (
        ("csidl_value", f"0x{parsed.csidl_value:04X}"),
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
        "schema": "vdm.fpath.artifact.v1",
        "record_type": {"byte": parsed.type_byte, "name": type_name},
        "family": "asep" if is_asep else "standard",
        "raw_hex": parsed.raw.hex(),
        "csidl": {
            "value": parsed.csidl_value,
            "raw_hex": parsed.raw[:HEADER_SIZE].hex(),
            "offset": 0,
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
            "csidl_runtime_mapping": "unknown",
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
    issues = [
        SemanticIssue(
            "final_verdict_unknown",
            "The resource matcher yields a gated candidate, not the outer scan verdict.",
        ),
        SemanticIssue(
            "csidl_table_entry_semantics_unknown",
            "CSIDL_2_ix maps the selector to an engine table index, but the "
            "selected row and runtime path-expansion semantics are unresolved.",
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
    if parsed.tail_raw:
        issues.append(
            SemanticIssue(
                "pcode_tail_not_exported",
                "Bytes after NUL are sent to createrecidp; their program and "
                "record-identity semantics are not exported.",
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
        representation="fpath.path-match-candidate.ir.v3",
        data=JSONObject(
            (
                ("type", type_name),
                ("raw_hex", parsed.raw.hex()),
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
                                        ("kind", "sorted_table_lookup"),
                                        ("entry_count", 49),
                                        ("entry_stride", 0x28),
                                        ("miss_sentinel", 0x7FFFFFFF),
                                        ("selected_index", "runtime_only"),
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
                    "pcode_tail",
                    JSONObject(
                        (
                            (
                                "wire",
                                _wire_field(
                                    "pcode_tail",
                                    parsed.tail_raw,
                                    path_end + 1 if parsed.nul_terminated else path_end,
                                ),
                            ),
                            (
                                "receiver_path",
                                "createrecidp" if parsed.tail_raw else "createrecid",
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
                "and an optional NUL-separated RecID program tail."
            ),
            coverage="subset",
            evidence_refs=("fpath_receiver",),
            unknowns=(
                SemanticUnknown(
                    "wire_layout",
                    "The optional RecID program tail grammar remains unresolved.",
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
                    "CSIDL table contents and RecID program construction are not projected.",
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
