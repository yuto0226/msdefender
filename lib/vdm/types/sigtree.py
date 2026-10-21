import json
from dataclasses import dataclass

from ..core import (
    Artifact,
    ArtifactExport,
    DisplaySection,
    FamilySpec,
    FormatResult,
    JSONArray,
    JSONObject,
    RuleSemantics,
    SemanticIssue,
)

_FIELD_FAMILIES = {
    0x30: "unknown",
    0x60: "generic attributes",
    0x70: "PE attributes",
}

_ENTRY_FLAG_BITS = (
    (0x0002, "ALWAYS_MATCH_A"),
    (0x0010, "EXT_BM_A"),
    (0x1000, "EXT_BM_B"),
)


@dataclass(frozen=True, slots=True)
class SigtreeParam:
    kind: str
    raw: bytes
    subtype: int | None = None


@dataclass(frozen=True, slots=True)
class SigtreeEntry:
    fixed_raw: bytes
    flags: int
    fid_lo: int
    fid_hi: int
    sub_lo: int
    sub_hi: int
    val_lo: int
    val_hi: int
    level_extra_raw: bytes
    param_b: SigtreeParam | None  # wire-first: fixed_raw[1], sub_hi
    param_a: SigtreeParam | None  # wire-second: fixed_raw[0], sub_lo


@dataclass(frozen=True, slots=True)
class SigtreePayload:
    raw: bytes
    entry_count: int
    format_level: int
    raw_header_2: int
    handler_index: int
    name_raw: bytes
    record_extra_raw: bytes
    entries: tuple[SigtreeEntry, ...]
    trailing_raw: bytes


def _take(payload: bytes, cursor: int, size: int, label: str) -> tuple[bytes, int]:
    end = cursor + size
    if end > len(payload):
        raise ValueError(f"truncated {label}")
    return payload[cursor:end], end


def _parse_param(
    payload: bytes,
    cursor: int,
    *,
    size_hint: int,
    flags: int,
    hash_enabled: bool,
    label: str,
) -> tuple[SigtreeParam | None, int]:
    if flags & 0x10:
        raw, cursor = _take(payload, cursor, size_hint, f"{label} BM data")
        kind = "special_extended" if flags & 0x04 else "bm_pattern"
        return SigtreeParam(kind=kind, raw=raw), cursor
    if not hash_enabled:
        return None, cursor

    subtype_raw, cursor = _take(payload, cursor, 1, f"{label} hash subtype")
    subtype = subtype_raw[0]
    if subtype == 1:
        data_size = size_hint * (2 if flags & 0x40 else 1)
    else:
        fixed_sizes = {2: 16, 3: 20, 4: 32}
        try:
            data_size = fixed_sizes[subtype]
        except KeyError as exc:
            raise ValueError(f"unsupported {label} hash subtype {subtype}") from exc
    data, cursor = _take(payload, cursor, data_size, f"{label} hash data")
    return SigtreeParam(
        kind="typed_hash", raw=subtype_raw + data, subtype=subtype
    ), cursor


def parse_sigtree(payload: bytes) -> SigtreePayload:
    if len(payload) < 5:
        raise ValueError("truncated SIGTREE header")

    entry_count, format_level, raw_header_2, handler_index = payload[:4]
    if format_level > 4:
        raise ValueError(f"unsupported SIGTREE format level {format_level}")
    if handler_index >= 7:
        raise ValueError(f"invalid SIGTREE handler index {handler_index}")

    name_end = payload.find(b"\0", 4, min(len(payload), 68))
    if name_end < 0:
        raise ValueError("unterminated SIGTREE name")
    name_raw = payload[4:name_end]
    cursor = name_end + 1

    record_extra_raw = b""
    if format_level >= 3:
        record_extra_raw, cursor = _take(payload, cursor, 4, "SIGTREE record extension")

    entries: list[SigtreeEntry] = []
    level_extra_size = 4 * min(format_level, 2)
    for index in range(entry_count):
        fixed_raw, cursor = _take(payload, cursor, 16, f"SIGTREE entry {index}")
        level_extra_raw, cursor = _take(
            payload,
            cursor,
            level_extra_size,
            f"SIGTREE entry {index} extension",
        )
        hash_gate_b = len(level_extra_raw) >= 3 and bool(level_extra_raw[2] & 1)
        hash_gate_a = len(level_extra_raw) >= 2 and bool(level_extra_raw[1] & 1)
        param_b, cursor = _parse_param(
            payload,
            cursor,
            size_hint=fixed_raw[7],
            flags=fixed_raw[1],
            hash_enabled=hash_gate_b,
            label=f"SIGTREE entry {index} param B",
        )
        param_a, cursor = _parse_param(
            payload,
            cursor,
            size_hint=fixed_raw[6],
            flags=fixed_raw[0],
            hash_enabled=hash_gate_a,
            label=f"SIGTREE entry {index} param A",
        )
        entries.append(
            SigtreeEntry(
                fixed_raw=fixed_raw,
                flags=int.from_bytes(fixed_raw[0:4], "little"),
                fid_lo=fixed_raw[4],
                fid_hi=fixed_raw[5],
                sub_lo=fixed_raw[6],
                sub_hi=fixed_raw[7],
                val_lo=int.from_bytes(fixed_raw[8:12], "little"),
                val_hi=int.from_bytes(fixed_raw[12:16], "little"),
                level_extra_raw=level_extra_raw,
                param_b=param_b,
                param_a=param_a,
            )
        )

    return SigtreePayload(
        raw=payload,
        entry_count=entry_count,
        format_level=format_level,
        raw_header_2=raw_header_2,
        handler_index=handler_index,
        name_raw=name_raw,
        record_extra_raw=record_extra_raw,
        entries=tuple(entries),
        trailing_raw=payload[cursor:],
    )


def render_sigtree(parsed: SigtreePayload) -> FormatResult:
    def preview(raw: bytes) -> str:
        if not raw:
            return "(empty)"
        shown = raw[:32].hex(" ")
        ellipsis = " …" if len(raw) > 32 else ""
        return f"{len(raw)} B [{shown}{ellipsis}]"

    def render_param(param: SigtreeParam) -> str:
        subtype = f" subtype={param.subtype}" if param.subtype is not None else ""
        return f"{param.kind}{subtype}, {preview(param.raw)}"

    def render_flags(value: int) -> str:
        names = [name for bit, name in _ENTRY_FLAG_BITS if value & bit]
        known_mask = sum(bit for bit, _ in _ENTRY_FLAG_BITS)
        unknown = value & ~known_mask
        if unknown:
            names.append(f"UNKNOWN_BITS({unknown:#010x})")
        annotation = f" ({' | '.join(names)})" if names else ""
        return f"{value:#010x}{annotation}"

    def render_width(value: int) -> str:
        return "full" if value == 0 else f"{value} B"

    sections: list[DisplaySection] = []
    for index, entry in enumerate(parsed.entries, 1):
        rows = [
            ("flags", render_flags(entry.flags)),
            (
                "field",
                (
                    f"{entry.fid_hi:#04x}:{entry.fid_lo:#04x} "
                    f"({_FIELD_FAMILIES.get(entry.fid_hi, 'unknown family')})"
                ),
            ),
            (
                "sub_widths",
                f"A={render_width(entry.sub_lo)}, B={render_width(entry.sub_hi)}",
            ),
            ("values", f"A={entry.val_lo:#010x}, B={entry.val_hi:#010x}"),
            ("fixed_raw", entry.fixed_raw.hex(" ")),
            ("level_extra_raw", entry.level_extra_raw.hex(" ") or "(empty)"),
        ]
        if entry.param_a is not None:
            rows.append(("param_A", render_param(entry.param_a)))
        if entry.param_b is not None:
            rows.append(("param_B", render_param(entry.param_b)))
        sections.append(DisplaySection(title=f"> Entry #{index}", rows=tuple(rows)))
    return FormatResult(
        fields=(
            ("entry_count", str(parsed.entry_count)),
            ("format_level", str(parsed.format_level)),
            (
                "handler_semantics",
                f"instance {parsed.handler_index}; reduction unresolved",
            ),
            ("entry_parameter_logic", "A and B when both are selected"),
            ("raw_header_2", f"{parsed.raw_header_2:#04x}"),
            ("handler_index", str(parsed.handler_index)),
            ("name_raw", parsed.name_raw.hex(" ") or "(empty)"),
            ("name", parsed.name_raw.decode("latin-1")),
            ("record_extra_raw", parsed.record_extra_raw.hex(" ") or "(empty)"),
            ("payload_consumption", f"{len(parsed.trailing_raw)} B unconsumed"),
            ("trailing_raw", preview(parsed.trailing_raw)),
        ),
        sections=tuple(sections),
    )


def _param_semantics(param: SigtreeParam | None) -> JSONObject | None:
    if param is None:
        return None
    receiver_decoder = (
        "BMGetInitData"
        if param.kind in {"bm_pattern", "special_extended"}
        else "read_sigattr_param_hash"
    )
    return JSONObject(
        (
            ("wire_kind", param.kind),
            ("subtype", param.subtype),
            ("raw_hex", param.raw.hex()),
            ("receiver_decoder", receiver_decoder),
            ("operand_semantics", "unknown"),
        )
    )


def _export_sigtree_semantics(
    parsed: SigtreePayload, *, record_type: int
) -> RuleSemantics:
    has_countdown_adjustment = any(
        entry.level_extra_raw and bool(entry.level_extra_raw[0] & 0x02)
        for entry in parsed.entries
    )
    entries = tuple(
        JSONObject(
            (
                ("index", index),
                ("wire_fixed_raw_hex", entry.fixed_raw.hex()),
                ("flags_raw_u32", entry.flags),
                ("fid_lo", entry.fid_lo),
                ("fid_hi", entry.fid_hi),
                ("sub_lo", entry.sub_lo),
                ("sub_hi", entry.sub_hi),
                ("val_lo_u32", entry.val_lo),
                ("val_hi_u32", entry.val_hi),
                ("wire_level_extra_raw_hex", entry.level_extra_raw.hex()),
                ("wire_param_b", _param_semantics(entry.param_b)),
                ("wire_param_a", _param_semantics(entry.param_a)),
            )
        )
        for index, entry in enumerate(parsed.entries)
    )
    data = JSONObject(
        (
            (
                "wire_tree",
                JSONObject(
                    (
                        ("record_type", record_type),
                        ("entry_count", parsed.entry_count),
                        ("format_level", parsed.format_level),
                        ("raw_header_2", parsed.raw_header_2),
                        ("handler_index", parsed.handler_index),
                        ("name_raw_hex", parsed.name_raw.hex()),
                        ("record_extra_raw_hex", parsed.record_extra_raw.hex()),
                        ("entries", JSONArray(entries)),
                        ("trailing_raw_hex", parsed.trailing_raw.hex()),
                        ("payload_raw_hex", parsed.raw.hex()),
                    )
                ),
            ),
            (
                "receiver_storage",
                JSONObject(
                    (
                        ("model", "runtime entry storage; exact allocation omitted"),
                        ("wire_fixed_0x00_0x03_to_runtime_0x04", "confirmed"),
                        ("wire_fixed_0x04_0x07_to_runtime_0x00", "confirmed"),
                        ("wire_val_lo_to_runtime_0x10", "confirmed"),
                        ("wire_val_hi_to_runtime_0x28", "confirmed"),
                        ("wire_level_extension_1_to_runtime_0x08", "when present"),
                        ("wire_level_extension_2_to_runtime_0x20", "when present"),
                    )
                ),
            ),
            (
                "runtime_evaluator",
                JSONObject(
                    (
                        ("graph_model", "named_attribute_dependency_dag"),
                        (
                            "named_attribute_lookup",
                            (
                                "equal_range by attribute type, name length, and "
                                "lowercase CRC"
                            ),
                        ),
                        (
                            "entry_parameter_combination",
                            "all selected parameters must match",
                        ),
                        (
                            "parameter_dispatch",
                            (
                                "BMSearchWorker, scalar/CRC equality, or strong-hash "
                                "path according to runtime flags"
                            ),
                        ),
                        (
                            "record_reduction",
                            JSONObject(
                                (
                                    ("model", "scan_time_countdown"),
                                    (
                                        "initial_countdown",
                                        parsed.raw_header_2,
                                    ),
                                    (
                                        "initial_countdown_source",
                                        "wire byte +0x02",
                                    ),
                                    (
                                        "reset_operation",
                                        (
                                            "ResetRecord copies record descriptor "
                                            "+0x02 to the per-record scan state"
                                        ),
                                    ),
                                    (
                                        "accepted_contribution_operation",
                                        (
                                            "an accepted ordinary entry contribution "
                                            "decrements the nonzero per-record "
                                            "countdown by one"
                                        ),
                                    ),
                                    (
                                        "duplicate_contribution_guard",
                                        (
                                            "per-entry scan state gates repeated "
                                            "contributions; exact flag-dependent "
                                            "group reset semantics remain incomplete"
                                        ),
                                    ),
                                    (
                                        "level_extension_adjustment_enabled",
                                        has_countdown_adjustment,
                                    ),
                                    (
                                        "level_extension_adjustment_source",
                                        (
                                            "record descriptor +0x0D bit 0 is set "
                                            "when any entry level-extension DWORD "
                                            "has bit 0x02"
                                        ),
                                    ),
                                    (
                                        "level_extension_gate_behavior",
                                        JSONObject(
                                            (
                                                (
                                                    "matching_flagged_entry",
                                                    (
                                                        "insert the attribute record "
                                                        "into a suppression set and "
                                                        "return without decrementing "
                                                        "the countdown"
                                                    ),
                                                ),
                                                (
                                                    "subsequent_contribution",
                                                    (
                                                        "return without a candidate "
                                                        "while the attribute record is "
                                                        "present in the suppression set"
                                                    ),
                                                ),
                                                (
                                                    "absence_path",
                                                    (
                                                        "the odd-count adjustment lets "
                                                        "the remaining ordinary "
                                                        "contributions complete the "
                                                        "record"
                                                    ),
                                                ),
                                                (
                                                    "portable_boolean_label",
                                                    (
                                                        "negated/unmatched guard shape; "
                                                        "exact flag-dependent grouping "
                                                        "remains incomplete"
                                                    ),
                                                ),
                                            )
                                        ),
                                    ),
                                    (
                                        "completion_expression",
                                        (
                                            "countdown_after = max(countdown_before "
                                            "- 1, 0); test_value = "
                                            "countdown_after - 1 when adjustment is "
                                            "enabled and countdown_after is odd, "
                                            "otherwise countdown_after; complete iff "
                                            "test_value == 0"
                                        ),
                                    ),
                                    (
                                        "format_level_0_simplification",
                                        (
                                            "complete iff the post-decrement "
                                            "countdown is zero"
                                        ),
                                    ),
                                    (
                                        "completion_candidate_state",
                                        1,
                                    ),
                                    (
                                        "incomplete_candidate_state",
                                        2,
                                    ),
                                    (
                                        "candidate_state_scope",
                                        (
                                            "refresh_cksig_data and its caller; not "
                                            "a final threat verdict"
                                        ),
                                    ),
                                )
                            ),
                        ),
                        (
                            "on_entry_match",
                            "refresh_cksig_data may emit a named attribute",
                        ),
                        (
                            "propagation",
                            (
                                "RuntimeAggregator::SetAttribute recursively invokes "
                                "siga_cksig"
                            ),
                        ),
                        (
                            "handler_instance_2_effect",
                            (
                                "when handler_index is 2, refresh_cksig_data has "
                                "BMLua reporting and telemetry branches"
                            ),
                        ),
                        (
                            "downstream_policy",
                            JSONObject(
                                (
                                    (
                                        "consumers",
                                        JSONArray(
                                            (
                                                (
                                                    "SignatureHasValidator / "
                                                    "ValidateSignatureWithPcode"
                                                ),
                                                "MpAggregateAttributeEx",
                                                "ShouldContinueScanning",
                                                "MpReportLowfiMatch",
                                                "HipsStreamScanCheck",
                                            )
                                        ),
                                    ),
                                    (
                                        "final_threat_verdict",
                                        "context_dependent_unknown",
                                    ),
                                )
                            ),
                        ),
                        ("yara_translation", "not established"),
                    )
                ),
            ),
        )
    )
    return RuleSemantics(
        status="unsupported" if parsed.trailing_raw else "confirmed_subset",
        representation="sigtree.wire_storage_evaluator.ir.v2",
        data=data,
        evidence=(
            "mpengine 1.443.903.0 SigtreeHandlerInstance::push",
            "mpengine 1.443.903.0 siga_cksig_impl and MatchParameter",
            "mpengine 1.443.903.0 refresh_cksig_data",
            "mpengine 1.443.903.0 SigtreeHandlerInstance::ResetRecord",
            "mpengine 1.443.903.0 RuntimeAggregator::SetAttribute",
        ),
        profile="mpengine-1.443.903.0",
        issues=(
            SemanticIssue(
                "sigtree_entry_state_flags_incomplete",
                "The countdown reduction is confirmed, but every flag-dependent "
                "entry grouping and reset case is not yet named.",
            ),
            SemanticIssue(
                "sigtree_final_policy_context_dependent",
                "A completed countdown produces a candidate state that still passes "
                "validator, aggregation, scan-policy, low-fidelity, and HIPS paths; "
                "it is not by itself a portable final threat verdict.",
            ),
            *(
                (
                    SemanticIssue(
                        "trailing_bytes_uninterpreted",
                        "Bytes after all parsed entries have no confirmed semantics.",
                        (("length", len(parsed.trailing_raw)),),
                    ),
                )
                if parsed.trailing_raw
                else ()
            ),
        ),
    )


def export_sigtree_semantics(parsed: SigtreePayload) -> RuleSemantics:
    return _export_sigtree_semantics(parsed, record_type=0x40)


def export_sigtree_ext_semantics(parsed: SigtreePayload) -> RuleSemantics:
    return _export_sigtree_semantics(parsed, record_type=0x41)


def export_sigtree_bm_semantics(parsed: SigtreePayload) -> RuleSemantics:
    return _export_sigtree_semantics(parsed, record_type=0xB3)


def _artifact_param(param: SigtreeParam | None) -> dict[str, object] | None:
    if param is None:
        return None
    return {
        "kind": param.kind,
        "subtype": param.subtype,
        "raw_length": len(param.raw),
        "raw_hex": param.raw.hex(),
        "operand_semantics": "unknown",
    }


def _export_sigtree_artifact(
    parsed: SigtreePayload, *, record_type: int
) -> ArtifactExport:
    """Export parsed SIGTREE structure without inventing a matcher language."""
    type_names = {0x40: "SIGTREE", 0x41: "SIGTREE_EXT", 0xB3: "SIGTREE_BM"}
    if record_type not in type_names:
        raise ValueError(f"unsupported SIGTREE record type {record_type:#04x}")

    entries: list[dict[str, object]] = []
    for index, entry in enumerate(parsed.entries):
        known_flags = 0x0002 | 0x0004 | 0x0010 | 0x0040 | 0x1000
        entries.append(
            {
                "index": index,
                "fixed_raw_hex": entry.fixed_raw.hex(),
                "flags_u32": entry.flags,
                "flags_raw_hex": entry.fixed_raw[:4].hex(),
                "flags_unclassified_bits": entry.flags & ~known_flags,
                "fid_lo": entry.fid_lo,
                "fid_hi": entry.fid_hi,
                "sub_lo": entry.sub_lo,
                "sub_hi": entry.sub_hi,
                "val_lo_u32": entry.val_lo,
                "val_hi_u32": entry.val_hi,
                "level_extra_raw_hex": entry.level_extra_raw.hex(),
                "parameter_a": _artifact_param(entry.param_a),
                "parameter_b": _artifact_param(entry.param_b),
                "parameter_combination": "all_selected_parameters_must_match",
            }
        )

    named_guard_indexes = [
        index
        for index, entry in enumerate(parsed.entries)
        if entry.level_extra_raw and entry.level_extra_raw[0] & 0x02
    ]
    unsupported_boundaries = [
        (
            "Parameter operands are preserved as bytes; their full portable "
            "semantics are unknown."
        ),
        "Entry grouping and all flag-dependent state reset cases are not fully named.",
        (
            "Named-attribute DAG edges require cross-record/runtime attribute "
            "resolution and are not synthesized here."
        ),
        (
            "A completed countdown is only a candidate state; final report "
            "policy is context-dependent."
        ),
        (
            "YARA translation is not established; no YARA or executable matcher "
            "is emitted."
        ),
    ]
    if parsed.trailing_raw:
        unsupported_boundaries.append(
            "Bytes remain after the parsed entries; their record semantics are unknown."
        )

    manifest = {
        "format": "vdm.sigtree.record.v1",
        "record": {
            "type": record_type,
            "type_hex": f"0x{record_type:02X}",
            "name": type_names[record_type],
            "scope": "record_local",
            "artifact_scope": "lossless_record_structure",
            "threat_association": "not_included",
            "portable_matcher": "not_emitted",
            "wire_parse_status": "partial" if parsed.trailing_raw else "complete",
        },
        "wire_envelope": {
            "payload_length": len(parsed.raw),
            "payload_raw_hex": parsed.raw.hex(),
            "entry_count": parsed.entry_count,
            "format_level": parsed.format_level,
            "initial_countdown": parsed.raw_header_2,
            "initial_countdown_raw_hex": parsed.raw[2:3].hex(),
            "handler_index": parsed.handler_index,
            "name_raw_hex": parsed.name_raw.hex(),
            "name_latin1": parsed.name_raw.decode("latin-1"),
            "record_extra_raw_hex": parsed.record_extra_raw.hex(),
            "entries": entries,
            "trailing_raw_hex": parsed.trailing_raw.hex(),
        },
        "graph": {
            "model": "named_attribute_dependency_dag",
            "node_name_raw_hex": parsed.name_raw.hex(),
            "dependency_edges": None,
            "edge_boundary": (
                "record-local payload does not resolve cross-record attribute edges"
            ),
        },
        "evaluator_shape": {
            "entry_parameter_combination": "all selected parameters must match",
            "reduction_model": "scan_time_countdown",
            "accepted_entry_contribution": "decrement nonzero countdown by one",
            "initial_countdown_source": "wire byte +0x02",
            "countdown_adjustment_enabled": bool(named_guard_indexes),
            "adjustment_entry_indexes": named_guard_indexes,
            "adjustment_shape": "negated_or_unmatched_guard; exact grouping unknown",
            "completion_expression": (
                "countdown_after=max(countdown_before-1,0); test_value="
                "countdown_after-1 iff adjustment is enabled and countdown_after "
                "is odd, else countdown_after; complete iff test_value==0"
            ),
            "final_verdict": "not_represented",
        },
        "unsupported_boundaries": unsupported_boundaries,
    }
    encoded = json.dumps(manifest, ensure_ascii=True, separators=(",", ":"))
    return ArtifactExport(
        "ready",
        artifacts=(
            Artifact(
                "sigtree.json",
                "sigtree_structural_manifest",
                (encoded + "\n").encode("utf-8"),
            ),
        ),
    )


def export_sigtree_artifact(parsed: SigtreePayload) -> ArtifactExport:
    return _export_sigtree_artifact(parsed, record_type=0x40)


def export_sigtree_ext_artifact(parsed: SigtreePayload) -> ArtifactExport:
    return _export_sigtree_artifact(parsed, record_type=0x41)


def export_sigtree_bm_artifact(parsed: SigtreePayload) -> ArtifactExport:
    return _export_sigtree_artifact(parsed, record_type=0xB3)


SIGTREE_SPEC = FamilySpec(
    0x40,
    "SIGTREE",
    parse_sigtree,
    render_sigtree,
    exporter=export_sigtree_artifact,
    semantic_exporter=export_sigtree_semantics,
)
SIGTREE_EXT_SPEC = FamilySpec(
    0x41,
    "SIGTREE_EXT",
    parse_sigtree,
    render_sigtree,
    exporter=export_sigtree_ext_artifact,
    semantic_exporter=export_sigtree_ext_semantics,
)
SIGTREE_BM_SPEC = FamilySpec(
    0xB3,
    "SIGTREE_BM",
    parse_sigtree,
    render_sigtree,
    exporter=export_sigtree_bm_artifact,
    semantic_exporter=export_sigtree_bm_semantics,
)
