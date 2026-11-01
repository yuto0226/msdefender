"""Typed parser for the standalone 0x95 PEBMPAT record."""

from dataclasses import dataclass

from ..bm import BmPattern, validate_bm_framing
from ..bm_semantic import BmSemanticContext, serialize_bm_pattern
from ..bm_yara import render_bm_yara
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

_PREVIEW = 64
_TEXT_PREVIEW = 512


def _candidate_matcher_projection(pattern_data: JSONObject | None) -> JSONObject:
    """Describe only the BMMatchPEMapper/BMSBufferReader candidate stage."""
    if pattern_data is None:
        return JSONObject(
            (
                ("status", "no_candidate"),
                ("reader", "BMSBufferReader"),
                ("operation_fidelity_counts", JSONObject(())),
                ("buffer_backward_scan_operations", JSONArray(())),
            )
        )

    pattern_fields = dict(pattern_data.items)
    operation_values = pattern_fields["operations"]
    operations = [dict(operation.items) for operation in operation_values.items]

    def fields(value: object) -> dict[str, object]:
        return dict(value.items) if isinstance(value, JSONObject) else {}

    fidelity_counts = {
        fidelity: sum(operation["fidelity"] == fidelity for operation in operations)
        for fidelity in ("exact", "conditional", "unsupported")
    }
    buffer_backward_scan_operations = [
        JSONObject(
            (
                ("offset", fields(operation["raw_span"])["offset"]),
                ("raw_id", operation["raw_id"]),
                ("dispatch", 0x09),
                (
                    "handler_address",
                    "0x1800EEA02",
                ),
                ("unconditional_rejection", False),
                (
                    "reason",
                    "BUFFER modes1/3 restore the worker-invocation entry snapshot; count, cursor and bounds can produce success or failure",
                ),
            )
        )
        for operation in operations
        if fields(operation.get("dispatch")).get("id") == 0x09
    ]
    remaining = fields(pattern_fields["remaining_raw"])
    framing_complete = (
        pattern_fields["ended"]
        and not pattern_fields["issues"].items
        and remaining["length"] == 0
    )
    if not framing_complete or fidelity_counts["unsupported"]:
        status = "unsupported"
    elif fidelity_counts["conditional"]:
        status = "conditional"
    else:
        status = "confirmed_subset"

    graph = fields(pattern_fields.get("execution_graph"))
    fidelity_basis = "flat_decoder_operations"
    end_tail_closed = bool(
        graph.get("root_end_tail_closed")
        and graph.get("structure_complete")
        and graph.get("fidelity") == "exact"
    )
    if (graph.get("has_rewrites") or end_tail_closed) and not (
        status == "confirmed_subset"
        and (graph.get("fidelity") == "conditional" or graph.get("class_choice_closed"))
    ):
        graph_fidelity = graph.get("fidelity")
        fidelity_basis = "execution_graph"
        status = {
            "exact": "confirmed_subset",
            "conditional": "conditional",
            "unsupported": "unsupported",
        }[graph_fidelity]

    return JSONObject(
        (
            ("status", status),
            (
                "scope",
                "BM candidate matching only; this is not trie eligibility, PE mapping, P-code validation, reporting, or a final threat/action verdict",
            ),
            ("reader", "BMSBufferReader via BMMatchPEMapper -> BMMatchEx2"),
            ("framing_complete", framing_complete),
            ("execution_graph_fidelity", graph.get("fidelity")),
            ("fidelity_basis", fidelity_basis),
            *(
                (
                    (
                        "end_tail_scope",
                        "same-start worker Boolean fragment only; keep the full physical pattern and length for receiver framing/derived flags, initializer raw-marker scans and mapper length guards; no whole-wrapper or receiver-acceptance equivalence",
                    ),
                )
                if end_tail_closed
                else ()
            ),
            ("byte_translation", "BM_MAP_ALL"),
            ("worker_flags", "(2 * !trie_flags_bit1) | 1"),
            ("worker_modes", JSONArray((1, 3))),
            ("pattern_preparation", "identity; original wire bytes"),
            ("match_offset_output_supplied", False),
            ("matches_vector_supplied", False),
            ("operation_fidelity_counts", JSONObject(tuple(fidelity_counts.items()))),
            (
                "buffer_backward_scan_operations",
                JSONArray(tuple(buffer_backward_scan_operations)),
            ),
            (
                "requirements",
                JSONArray(
                    (
                        "caller supplies the mapped subject window and start cursor",
                        (
                            "root END-tail qualification requires complete whole-body framing, a literal/raw01 prefix and no raw 90 1B bytes anywhere in the full physical pattern"
                            if end_tail_closed
                            else "mode1/3 equivalence requires complete single-segment framing and no raw 90 1B bytes in the full physical pattern"
                        ),
                        "conditional operations retain their serialized per-operation requirements",
                    )
                ),
            ),
        )
    )


@dataclass(frozen=True, slots=True)
class PEBMPat:
    """Lossless PEBMPAT fields and the receiver's BM insertion outcome."""

    raw: bytes
    flags: int
    name: bytes
    pattern_raw: bytes
    pattern: BmPattern | None
    receiver_result: str


def parse_pebmpat(payload: bytes) -> PEBMPat:
    """Parse exact PEBMPAT framing and validate its BM program."""
    if len(payload) < 4:
        raise ValueError("truncated PEBMPAT header")
    flags = payload[0]
    name_len = payload[1]
    pattern_len = int.from_bytes(payload[2:4], "little")
    expected = 4 + name_len + pattern_len
    if len(payload) != expected:
        raise ValueError("PEBMPAT size does not match its length fields")
    name_end = 4 + name_len
    name = payload[4:name_end]
    pattern_raw = payload[name_end:]
    pattern = None
    if flags & ~1:
        receiver_result = "no_op.unsupported_flags"
    elif len(payload) <= 4:
        receiver_result = "no_op.payload_length_le_4"
    else:
        sentinel = pattern_raw.find(b"\x90", 0, min(8, len(pattern_raw)))
        if 0 <= sentinel < 4:
            receiver_result = "error.first_90_before_offset_4"
        else:
            try:
                pattern = validate_bm_framing(pattern_raw, label="PEBMPAT")
            except ValueError as exc:
                receiver_result = f"error.{exc}"
            else:
                receiver_result = "added_candidate"
    return PEBMPat(payload, flags, name, pattern_raw, pattern, receiver_result)


def export_pebmpat_semantics(parsed: PEBMPat) -> RuleSemantics:
    """Export raw PEBMPAT framing and a non-authoritative BM decoder view."""
    # Derived dataclass fields are not authority for matcher-fidelity promotion.
    parsed = parse_pebmpat(parsed.raw)
    name_start = 4
    pattern_start = name_start + len(parsed.name)
    framing = JSONArray(
        (
            JSONObject(
                (
                    ("kind", "flags"),
                    ("raw_span", JSONObject((("offset", 0), ("length", 1)))),
                    ("raw_hex", parsed.raw[:1].hex()),
                )
            ),
            JSONObject(
                (
                    ("kind", "name_length"),
                    ("raw_span", JSONObject((("offset", 1), ("length", 1)))),
                    ("raw_hex", parsed.raw[1:2].hex()),
                )
            ),
            JSONObject(
                (
                    ("kind", "pattern_length"),
                    ("raw_span", JSONObject((("offset", 2), ("length", 2)))),
                    ("raw_hex", parsed.raw[2:4].hex()),
                )
            ),
            JSONObject(
                (
                    ("kind", "name"),
                    (
                        "raw_span",
                        JSONObject(
                            (("offset", name_start), ("length", len(parsed.name)))
                        ),
                    ),
                    ("raw_hex", parsed.name.hex()),
                )
            ),
            JSONObject(
                (
                    ("kind", "pattern"),
                    (
                        "raw_span",
                        JSONObject(
                            (
                                ("offset", pattern_start),
                                ("length", len(parsed.pattern_raw)),
                            )
                        ),
                    ),
                    ("raw_hex", parsed.pattern_raw.hex()),
                )
            ),
        )
    )
    issues = [
        SemanticIssue(
            "runtime_region_unknown",
            "ScanEx supplies a caller-selected guest-VA anchor to the trie and BM matcher, "
            "but no concrete candidate coordinate or backing bytes are observed. The "
            "direct-buffer and conditional file-backed VMM source provenance for this "
            "candidate remains unknown.",
        ),
        SemanticIssue(
            "pe_mapping_metadata_unknown",
            "Conditional x86/x64 file-backed translation paths are known, but this "
            "candidate's guest VA is not mapped to a concrete PE input coordinate.",
        ),
        SemanticIssue(
            "final_detection_policy_unknown",
            "A BM candidate still requires runtime matching and validation; final policy is not modeled.",
        ),
    ]
    pattern_data = None
    candidate_matcher = _candidate_matcher_projection(None)
    if parsed.pattern is not None:
        pattern_data, pattern_issues = serialize_bm_pattern(
            parsed.pattern,
            context=BmSemanticContext(
                "BUFFER",
                "identity",
                (1, 3),
                False,
                "identity",
                match_offset_output_supplied=False,
                matches_vector_supplied=False,
            ),
        )
        issues.extend(pattern_issues)
        candidate_matcher = _candidate_matcher_projection(pattern_data)
        matcher_status = dict(candidate_matcher.items)["status"]
        if matcher_status in ("conditional", "unsupported"):
            issues.append(
                SemanticIssue(
                    "bm_operand_semantics_incomplete",
                    "This candidate contains conditional or unsupported BM operations; see candidate_matcher and per-operation fidelity.",
                    (("candidate_matcher_status", matcher_status),),
                )
            )
    else:
        if parsed.receiver_result.startswith("no_op."):
            issues.append(
                SemanticIssue(
                    "receiver_no_op",
                    "The receiver accepts this record without adding a pattern candidate; raw bytes are retained.",
                    (("receiver_result", parsed.receiver_result),),
                )
            )
        else:
            issues.append(
                SemanticIssue(
                    "receiver_rejected",
                    "The receiver rejects this record and does not add a pattern candidate; raw bytes are retained.",
                    (("receiver_result", parsed.receiver_result),),
                )
            )
    data = JSONObject(
        (
            ("raw_hex", parsed.raw.hex()),
            ("framing", framing),
            ("flags", parsed.flags),
            ("unknown_flag_bits", parsed.flags & ~1),
            ("name_raw_hex", parsed.name.hex()),
            ("pattern_length", len(parsed.pattern_raw)),
            ("pattern_raw_hex", parsed.pattern_raw.hex()),
            ("receiver_result", parsed.receiver_result),
            (
                "mapping_strategy",
                JSONObject(
                    (
                        (
                            "coordinate",
                            (
                                "ScanEx scan_offset is caller-fed PE VMM guest address "
                                "on ordinary kvscanpage4sig path; trie prefix and BM "
                                "search use this start, with no trie-hit offset returned"
                            ),
                        ),
                        (
                            "upstream_coordinate_dataflow",
                            "kvscan4sig second argument -> VMM mmap64(addr,1024,1) -> kvscanpage4sig second argument -> PEBMPatScanner::Scan -> ScanEx; scan_PE_context::jmp_scan also calls kvscanpage4sig after VMM mmap",
                        ),
                        (
                            "sentinel_coordinate_path",
                            "kvscan4sig conditionally substitutes 0xFFFFFFFF; PEEmuMapper::mmap then maps self+0x10 + guest_offset + 1 subject to self+0x20 bound",
                        ),
                        (
                            "trie_reader",
                            JSONObject(
                                (
                                    (
                                        "callback",
                                        "PEMapper::mmap vtable slot 0, one byte per call",
                                    ),
                                    ("cursor_start", "ScanEx scan_offset"),
                                    ("cursor_step", 1),
                                    (
                                        "read_count_guard",
                                        "GetChar permits calls while count <= 0x1000",
                                    ),
                                    ("read_count_field_offset", 0x10),
                                    ("guest_va_field_offset", 0x08),
                                )
                            ),
                        ),
                        (
                            "bm_subject_reader",
                            JSONObject(
                                (
                                    (
                                        "mapping_callback",
                                        "BMMatchPEMapper gets pe_vars through mapper vtable slot 1 and calls __mmap_ex directly",
                                    ),
                                    (
                                        "matcher_reader",
                                        "BMMatchEx2 BMSBufferReader over the mapped contiguous pointer span",
                                    ),
                                    (
                                        "reader_callbacks",
                                        "BM worker reads mapped buffer bytes; it does not call ScanContext::GetChar",
                                    ),
                                    (
                                        "reader_cursor",
                                        "starts at mapped pointer + requested prefix in the primary-window branch",
                                    ),
                                    (
                                        "reader_end",
                                        "bounded by the mapped subject span",
                                    ),
                                )
                            ),
                        ),
                        (
                            "bm_primary_window",
                            JSONObject(
                                (
                                    ("prefix", "min(scan_offset, 2048)"),
                                    (
                                        "mapping_request",
                                        "__mmap_ex(pe_vars, scan_offset - prefix, prefix + 2048, 0x40000000)",
                                    ),
                                    (
                                        "prefix_fallback",
                                        "decrement prefix by 1 after mapping failure, through 0",
                                    ),
                                    (
                                        "minimum_mapping_length",
                                        "pattern_length; otherwise return false",
                                    ),
                                    (
                                        "subject_span",
                                        "[mapped_pointer, mapped_pointer + prefix + 2048)",
                                    ),
                                    ("search_start", "mapped_pointer + prefix"),
                                    ("search_length", 2048),
                                    (
                                        "search_range",
                                        "[scan_offset, scan_offset + 2048)",
                                    ),
                                )
                            ),
                        ),
                        ("primary_request_length", "prefix + 2048"),
                        ("primary_request_start", "mapper_address - prefix"),
                        ("bm_match_length_argument", 2048),
                        ("bm_match_start_argument", "mapped_pointer + prefix"),
                        (
                            "bm_start_argument_interpretation",
                            "mapped subject pointer plus requested prefix; backing file/RVA coordinate unknown",
                        ),
                        ("address_translation", None),
                        (
                            "address_translation_status",
                            (
                                "conditional x86 and x64 file-backed VMM interval translations "
                                "are recovered "
                                "below; a candidate-specific RVA/file mapping is not established"
                            ),
                        ),
                        (
                            "sentinel_mapping",
                            JSONObject(
                                (
                                    (
                                        "condition",
                                        "PEEmuMapper.self+0x18 == 0xFFFFFFFF",
                                    ),
                                    ("guest_offset", "x"),
                                    (
                                        "returned_pointer",
                                        "*(uint8_t **)(self+0x10) + x + 1",
                                    ),
                                    (
                                        "bounds_check",
                                        "x + 1 + length <= *(uint64_t *)(self+0x20)",
                                    ),
                                    ("buffer_provenance", None),
                                    ("rva_or_file_offset", None),
                                )
                            ),
                        ),
                        (
                            "x86_file_backed_vmm_mapping",
                            JSONObject(
                                (
                                    (
                                        "condition",
                                        "non-sentinel VMM path; file-backed image page branch",
                                    ),
                                    (
                                        "input_memory_offset",
                                        "guest_va - *(uint64_t *)(pe_vars+0x83798)",
                                    ),
                                    ("translator", "pe_mofs_to_fofs_ex"),
                                    ("interval_table_base_offset", 0x4040),
                                    ("interval_entry_stride", 0x28),
                                    (
                                        "interval_lower_bound_source",
                                        "*(uint32_t *)(row+0x00)",
                                    ),
                                    (
                                        "returned_file_position_formula",
                                        "u32(memory_offset + *(uint32_t *)(row+0x08) - *(uint32_t *)(row+0x00))",
                                    ),
                                    ("read_position_consumer", "UfsSeekRead"),
                                    ("read_destination", "VMM page buffer"),
                                    (
                                        "interval_index_output",
                                        "matching interval row index; concrete value unknown",
                                    ),
                                    ("read_length", None),
                                    ("row_field_names", None),
                                    ("actual_interval_row", None),
                                    ("candidate_va_to_rva", None),
                                )
                            ),
                        ),
                        (
                            "x64_file_backed_vmm_mapping",
                            JSONObject(
                                (
                                    (
                                        "condition",
                                        (
                                            "PEVAMap query returns an image region and the x64 loader "
                                            "selects the file-backed interval branch"
                                        ),
                                    ),
                                    (
                                        "input_memory_offset",
                                        "guest_va - *(uint64_t *)(pe_vars+0x83798)",
                                    ),
                                    ("interval_table_base_offset", 0x4040),
                                    ("interval_entry_stride", 0x28),
                                    (
                                        "guest_va_to_file_position_formula",
                                        (
                                            "memory_offset + *(uint32_t *)(row+0x08) "
                                            "- *(uint32_t *)(row+0x00)"
                                        ),
                                    ),
                                    ("read_position_consumer", "UfsSeekRead"),
                                    (
                                        "observed_readers",
                                        JSONArray(("VFS_Read", "UfsSeekRead")),
                                    ),
                                    ("row_field_names", None),
                                    ("actual_interval_row", None),
                                )
                            ),
                        ),
                        ("bm_byte_translation", "BM_MAP_ALL"),
                        (
                            "bm_match_flags",
                            "(2 * !trie_flags_bit1) | 1",
                        ),
                        ("match_offset_outputs_requested", False),
                        (
                            "fallback_requests",
                            "(scan_va, 2048), then (scan_va, 1); the fallback uses the mapped length",
                        ),
                        (
                            "bm_fallback_mappings",
                            JSONArray(
                                (
                                    JSONObject(
                                        (
                                            (
                                                "request",
                                                "__mmap_ex(pe_vars, scan_offset, 2048, 0x40000000)",
                                            ),
                                            ("subject_length", 2048),
                                            ("search_length", 2048),
                                            (
                                                "worker_flags",
                                                "(2 * !trie_flags_bit1) | 1",
                                            ),
                                        )
                                    ),
                                    JSONObject(
                                        (
                                            (
                                                "request",
                                                "__mmap_ex(pe_vars, scan_offset, 1, 0x40000000)",
                                            ),
                                            (
                                                "subject_length",
                                                "*(uint32_t *)(*(uint64_t *)(pe_vars + 699128) + 40)",
                                            ),
                                            ("search_length", "mapped subject length"),
                                            ("worker_flags", 1),
                                        )
                                    ),
                                )
                            ),
                        ),
                        (
                            "candidate_coordinate_status",
                            "ordinary path confirmed PE VMM guest address; sentinel path confirmed separately; candidate-specific section/RVA/file offset and runtime buffer provenance unknown",
                        ),
                        ("runtime_bytes_observed", False),
                        (
                            "candidate_search_guest_va",
                            "ScanEx scan_offset; runtime value supplied by caller",
                        ),
                        (
                            "candidate_search_range",
                            "[scan_offset, scan_offset + 2048) in the primary-window branch",
                        ),
                        (
                            "file_or_rva_translation",
                            "__mmap_ex has conditional x86/x64 file-backed VMM interval paths; no candidate-specific interval row or address-to-RVA/file-offset translation confirmed",
                        ),
                    )
                ),
            ),
            (
                "candidate_pipeline",
                JSONObject(
                    (
                        (
                            "matcher_stage",
                            "trie prefix candidate -> BMMatchPEMapper -> P-code validation",
                        ),
                        (
                            "post_bm_behavior",
                            (
                                "with SCAN_REPLY, ValidateSignatureWithPcode may "
                                "update recid/status; without it, a BM hit is returned "
                                "as a candidate entry"
                            ),
                        ),
                        (
                            "observed_status_routes",
                            JSONObject(
                                (
                                    ("3,6,8", "MpReportLowfiMatch"),
                                    ("10,11", "HipsManager::OnStreamDetection"),
                                    (
                                        "1,2",
                                        (
                                            "candidate-entry states when returned by "
                                            "P-code or when SCAN_REPLY is absent"
                                        ),
                                    ),
                                    (
                                        "0",
                                        "no report or candidate-entry branch in ScanEx",
                                    ),
                                )
                            ),
                        ),
                        (
                            "status_interpretation",
                            (
                                "ScanEx branch behavior only; status names and final "
                                "policy are not established"
                            ),
                        ),
                        ("pcode_context", "trie_flags_bit0 selects context 1 or 2"),
                        ("final_verdict", None),
                    )
                ),
            ),
            ("candidate_matcher", candidate_matcher),
            ("bm_pattern", pattern_data),
        )
    )
    matcher_status = dict(candidate_matcher.items)["status"]
    if parsed.receiver_result.startswith("no_op."):
        status = "ignored"
    elif parsed.pattern is None:
        status = "unsupported"
    else:
        status = (
            "confirmed_subset"
            if matcher_status == "confirmed_subset"
            else "unsupported"
        )

    if parsed.receiver_result == "added_candidate":
        receiver_statement = (
            "The checked flag, length, and BM-framing path accepts this payload "
            "for trie-candidate insertion."
        )
    elif parsed.receiver_result.startswith("no_op."):
        receiver_statement = (
            "AddNewPattern accepts this payload without storing a pattern candidate "
            f"({parsed.receiver_result})."
        )
    else:
        receiver_statement = (
            "AddNewPattern rejects this payload without storing a pattern candidate "
            f"({parsed.receiver_result})."
        )

    operation_raw_ids: set[int] = set()
    if pattern_data is not None:
        serialized = dict(pattern_data.items)
        operation_raw_ids = {
            raw_id
            for operation in serialized["operations"].items
            if isinstance((raw_id := dict(operation.items)["raw_id"]), int)
        }

    runtime_unknowns: list[SemanticUnknown] = []
    if parsed.pattern is None:
        runtime_unknowns.append(
            SemanticUnknown(
                "runtime_consumer",
                "This payload does not produce a validated BM candidate for the runtime matcher.",
            )
        )
    else:
        runtime_unknowns.extend(
            (
                SemanticUnknown(
                    "runtime_consumer",
                    "The candidate-specific guest address, mapped backing bytes, and trie eligibility are not observed.",
                ),
                SemanticUnknown(
                    "runtime_consumer",
                    "P-code validation and scan arbitration occur outside this BM candidate projection.",
                ),
            )
        )
        if 0x13 in operation_raw_ids and matcher_status != "confirmed_subset":
            runtime_unknowns.append(
                SemanticUnknown(
                    "runtime_consumer",
                    "Raw operation 0x13 is qualified only for null-backref BUFFER modes1/3 with identity/raw preparation and a single raw13 in the literal/raw01/END grammar; other compositions remain conditional.",
                )
            )
        if matcher_status in {"conditional", "unsupported"}:
            runtime_unknowns.append(
                SemanticUnknown(
                    "runtime_consumer",
                    "At least one decoded operation is conditional or unsupported in the candidate matcher projection.",
                )
            )

    mode_profile_applies = bool(
        parsed.pattern is not None
        and parsed.pattern.issue is None
        and parsed.pattern.ended
        and not parsed.pattern.remaining_raw
        and b"\x90\x1b" not in parsed.pattern.raw
    )
    mode_evidence_refs = (
        ("pebmpat_mode_equivalence_static", "pebmpat_mode_equivalence_native")
        if mode_profile_applies
        else ()
    )
    claims: list[SemanticClaim] = [
        SemanticClaim(
            id="pebmpat_wire_layout",
            scope="wire_layout",
            statement=(
                "The checked payload consists of flags, one-byte name length, "
                "little-endian pattern length, name bytes, and pattern bytes with "
                "exact total length."
            ),
            coverage="complete",
            evidence_refs=("pebmpat_add_pattern",),
        ),
        SemanticClaim(
            id="pebmpat_receiver_disposition",
            scope="receiver_transform",
            statement=receiver_statement,
            coverage="complete",
            evidence_refs=("pebmpat_add_pattern",),
        ),
        SemanticClaim(
            id="pebmpat_candidate_runtime",
            scope="runtime_consumer",
            statement=(
                "A stored candidate is consumed through BMMatchPEMapper, BMMatchEx2, "
                "and BMSBufferReader using a caller-selected PE mapping window."
            ),
            coverage=(
                "subset"
                if parsed.pattern is not None and matcher_status == "confirmed_subset"
                else "unknown"
            ),
            evidence_refs=(
                ("pebmpat_buffer_consumer", *mode_evidence_refs)
                if parsed.pattern is not None and matcher_status == "confirmed_subset"
                else ()
            ),
            unknowns=tuple(runtime_unknowns),
        ),
        SemanticClaim(
            id="pebmpat_detection_predicate",
            scope="detection_predicate",
            statement=(
                "The BM candidate result alone is not a complete PEBMPAT detection predicate."
            ),
            coverage="unknown",
            unknowns=(
                SemanticUnknown(
                    "detection_predicate",
                    "Trie eligibility, mapped runtime input, P-code validation, and other candidate paths are not composed into a complete predicate.",
                ),
            ),
        ),
        SemanticClaim(
            id="pebmpat_report_mapping",
            scope="report_mapping",
            statement="The observed ScanEx status branches do not establish report semantics.",
            coverage="unknown",
            unknowns=(
                SemanticUnknown(
                    "report_mapping",
                    "Status meanings and their outer policy/report mapping remain unresolved.",
                ),
            ),
        ),
        SemanticClaim(
            id="pebmpat_final_verdict",
            scope="final_verdict",
            statement="A PEBMPAT candidate result is not a confirmed final verdict.",
            coverage="unknown",
            unknowns=(
                SemanticUnknown(
                    "final_verdict",
                    "Outer scan arbitration, reporting, and action policy remain unresolved.",
                ),
            ),
        ),
    ]
    if 0x09 in operation_raw_ids:
        claims.append(
            SemanticClaim(
                id="pebmpat_buffer_backward_scan",
                scope="runtime_consumer",
                statement=(
                    "Decoded dispatch 0x09 selects the BUFFER backward-scan "
                    "handler at 0x1800EEA02. Modes1/3 restore the worker-entry "
                    "snapshot and apply byte-count/cursor/bounds logic; successful cases "
                    "disprove unconditional rejection. Full acceptance and "
                    "suffix behavior remain reader-specific and are not lowered."
                ),
                coverage="subset",
                evidence_refs=(
                    "pebmpat_backward_scan_consumer",
                    "pebmpat_backward_scan_counterexamples",
                    "pebmpat_backward_scan_transition_model",
                ),
                unknowns=(
                    SemanticUnknown(
                        "runtime_consumer",
                        "Suffix/capture composition, mode0/2 mapped-zero behavior "
                        "and outer candidate selection remain unmodeled; the "
                        "mode1/3 cursor transition alone is not full acceptance.",
                    ),
                ),
            )
        )

    if 0x13 in operation_raw_ids:
        claims.append(
            SemanticClaim(
                id="pebmpat_buffer_relative_instruction",
                scope="runtime_consumer",
                statement=(
                    "Raw13 decodes untranslated rel8/rel32 branch bytes from the "
                    "BUFFER subject, preserves the NEG ebx INT32_MIN target "
                    "exception and u64 wrap, then runs the mapped suffix at the "
                    "target. A failed suffix leaves the parent at that target. "
                    "The qualified single-raw13 literal/raw01/END composition "
                    "requires a complete finite contiguous BUFFER with declared "
                    "size equal to supplied storage length, and excludes captures, "
                    "other reader/mode profiles and PE mapping."
                ),
                coverage="subset",
                evidence_refs=("pebmpat_raw13_transition",),
                unknowns=(
                    SemanticUnknown(
                        "runtime_consumer",
                        "The primary transition profile excludes capture. "
                        "A separate 12-case producer observation does not close "
                        "the complete capture lifecycle. Arbitrary suffixes, "
                        "runtime mapping and caller arbitration remain outside "
                        "the qualified composition.",
                    ),
                ),
            )
        )
        claims.extend(
            (
                SemanticClaim(
                    id="pebmpat_raw13_capture_observation",
                    scope="runtime_consumer",
                    statement=(
                        "In 12 qualified producer cases, positive/zero rel8 "
                        "displacements saved [original_cursor,target) as 5/2 "
                        "bytes and kept the node after suffix failure. Negative "
                        "displacements skipped AddBackref despite capture enabled, "
                        "leaving an empty tree; raw1B then failed for missing "
                        "capture after a successful literal. next_id reached 2 "
                        "after that literal or stayed 1 on early literal failure."
                    ),
                    coverage="subset",
                    evidence_refs=("pebmpat_raw13_capture_probe",),
                    unknowns=(
                        SemanticUnknown(
                            "runtime_consumer",
                            "Initializer mode3, multiple keys/tree rotations, "
                            "destruction, complete caller lifecycle, allocation "
                            "failure/exceptions and captured bytes beyond supplied "
                            "backing are unverified; no capture evaluator is provided.",
                        ),
                    ),
                ),
                SemanticClaim(
                    id="pebmpat_raw13_actual_payloads",
                    scope="corpus_observation",
                    statement=(
                        "Eight cached actual PEBMPAT payloads (MPAS7/MPAV1) "
                        "were recovered and each has one AST raw13/dispatch13 "
                        "operation encoded as 90 13 without operands. This is "
                        "payload/AST coverage; the machine-code subject fixtures "
                        "remain five synthetic representatives."
                    ),
                    coverage="subset",
                    evidence_refs=("pebmpat_raw13_actual_payload_inventory",),
                    unknowns=(
                        SemanticUnknown(
                            "corpus_observation",
                            "MPAV was read at one pinned record rather than "
                            "walked; other database versions and runtime subjects "
                            "are outside this eight-payload inventory.",
                        ),
                    ),
                ),
            )
        )

    claim_evidence = [
        SemanticEvidence(
            id="pebmpat_add_pattern",
            axis="receiver",
            kind="engine_static",
            source_ref="mpengine 1.443.903.0",
            locator=(
                "PEBMPatScanner::AddNewPattern @ 0x1804701C0; "
                "BMGetPatternFlags @ 0x1800FEBF4"
            ),
            supports=("pebmpat_wire_layout", "pebmpat_receiver_disposition"),
        ),
    ]
    if 0x13 in operation_raw_ids:
        claim_evidence.extend(
            (
                SemanticEvidence(
                    id="pebmpat_raw13_capture_probe",
                    axis="engine_equivalent_test",
                    kind="engine_equivalent_test",
                    source_ref=(
                        "local_pebmpat13_capture_v1: 12 original-code Unicorn "
                        "cases, not host-native; initializer mode1, worker "
                        "modes1/3, identity map, single key ID0, rel8, null offset "
                        "outputs, valid supplied backing and allocation success. "
                        "Original initializer/worker producer/AddBackref/STL; "
                        "only a success-only guest operator new service seam. "
                        "Harness SHA256 "
                        "5928001c2a6b13bba77b75ed9881c4eb94091455d30623bfcac2a73d16e09562; "
                        "results SHA256 "
                        "2bc0eea6075ecf860106b5732af1b2480106b9d97bdc2e46c682691de8857b21"
                    ),
                    locator=(
                        "BMInitBackrefs @ 0x1800F0DC0; worker producer @ "
                        "0x1800EE2BD; raw13 AddBackref call @ 0x1800EEC44; "
                        "AddBackref @ 0x1800F01DC; guest new @ 0x18060E684"
                    ),
                    supports=("pebmpat_raw13_capture_observation",),
                ),
                SemanticEvidence(
                    id="pebmpat_raw13_actual_payload_inventory",
                    axis="corpus",
                    kind="corpus",
                    source_ref=(
                        "local_pebmpat13_fullactual_v1.json SHA256 "
                        "735a5ee604cd8c0badaf912fa26bf75eb38b3a71396bbc093c2987823aa77835; "
                        "one MPAS stream walk and one pinned MPAV seek; "
                        "MPAS7/MPAV1 actual payloads and ASTs, no engine execution"
                    ),
                    locator="eight recovered 0x95 payloads; AST raw_id=dispatch_id=0x13",
                    supports=("pebmpat_raw13_actual_payloads",),
                ),
            )
        )
        claim_evidence.append(
            SemanticEvidence(
                id="pebmpat_raw13_transition",
                axis="engine_equivalent_test",
                kind="engine_equivalent_test",
                source_ref=(
                    "mpengine 1.443.903.0 DLL SHA256 "
                    "928e171c60a44bb326776d2a356412ae98d78469bdf8c94ebfbfa09f8ec4b4b3; "
                    "local_pebmpat13_machinecode_v1: Unicorn x86-64 original "
                    "machine-code emulation, not host-native; 74 vectors x "
                    "modes1/3 = 148 calls, null backref context, no captures or "
                    "provider seams. Five actual payload representatives use "
                    "synthetic subjects; separate eight-payload AST recovery "
                    "does not expand these five machine-code subject fixtures. "
                    "Scratch CC preservation applies only to these 148 calls. "
                    "Harness SHA256 "
                    "9580562506ae0d686645f807a0262eeeb309b3c0896e0eb57e4dd06df66bb6ea; "
                    "results SHA256 "
                    "23301a66461ff014f014cdcc6c41d0c12e985427c4e86cbcc7c8cfa1b2cd82ec"
                ),
                locator=(
                    "BMMatchWorker_BMSBufferReader_ @ 0x1800EDB60; raw13 "
                    "handler @ 0x1800EEBB9; target update @ 0x1800EEC58; "
                    "negative displacement @ 0x1800EF2CA; recursive suffix "
                    "@ 0x1800EE9F0; static opcode/second-byte/rel8/rel32 size "
                    "gates @ 0x1800EEBC6/0x1800EF297/0x1800EEBE7/0x1800EF2B4 "
                    "establish finite-buffer read bounds; the probe's readable "
                    "A5 padding alone is not a declared-end read proof"
                ),
                supports=("pebmpat_buffer_relative_instruction",),
            )
        )
    if parsed.pattern is not None and matcher_status == "confirmed_subset":
        claim_evidence.append(
            SemanticEvidence(
                id="pebmpat_buffer_consumer",
                axis="consumer",
                kind="engine_static",
                source_ref="mpengine 1.443.903.0",
                locator=(
                    "PEBMPatScanner::ScanEx @ 0x1803D5A5C; "
                    "BMMatchPEMapper @ 0x1803D5E44; BMMatchEx2 @ 0x1800EC420"
                ),
                supports=("pebmpat_candidate_runtime",),
            )
        )
    if (
        parsed.pattern is not None
        and matcher_status == "confirmed_subset"
        and mode_profile_applies
    ):
        claim_evidence.append(
            SemanticEvidence(
                id="pebmpat_mode_equivalence_static",
                axis="consumer",
                kind="engine_static",
                source_ref="mpengine 1.443.903.0",
                locator=(
                    "BMMatchEx2 @ 0x1800EC420; "
                    "BMMatchWorker_BMSBufferReader_ @ 0x1800EDB60 "
                    "(2256 instructions) and range helper @ 0x1800F04C0 "
                    "(244 instructions): complete mode dataflow; initializer @ "
                    "0x1800F0DC0 scans physical bytes for 90 1B. Mode1/3 "
                    "Boolean neutrality requires BUFFER, identity map and raw "
                    "preparation, null match outputs, no physical 90 1B, and "
                    "fixed valid memory/resources; no other modes or captures"
                ),
                supports=("pebmpat_candidate_runtime",),
            )
        )
        claim_evidence.append(
            SemanticEvidence(
                id="pebmpat_mode_equivalence_native",
                axis="engine_equivalent_test",
                kind="engine_equivalent_test",
                source_ref=(
                    "Pinned DLL SHA256 "
                    "928e171c60a44bb326776d2a356412ae98d78469bdf8c94ebfbfa09f8ec4b4b3; "
                    "local_pebmpat_mode_extended_native: 3580 mode1/3 pairs "
                    "(7160 original worker executions), 14 actual libyara "
                    "compiles and 3580 matches; identity/raw preparation, null "
                    "backrefs, no physical 90 1B. Direct worker/helper only; "
                    "not BMMatchEx2 initialization, PE mapping, trie, validator "
                    "or final detection equivalence"
                ),
                locator=(
                    "worker @ 0x1800EDB60; range helper @ 0x1800F04C0; "
                    "fixed BUFFER/modes1,3 Boolean acceptance and reader-state comparison"
                ),
                supports=("pebmpat_candidate_runtime",),
            )
        )
    if 0x09 in operation_raw_ids:
        claim_evidence.append(
            SemanticEvidence(
                id="pebmpat_backward_scan_consumer",
                axis="consumer",
                kind="engine_static",
                source_ref="mpengine 1.443.903.0",
                locator=(
                    "g_bmOpcodeTable raw09 = 09 04 00; switch table @ "
                    "0x1800F0040 index 8 = RVA 0xEEA02; dedicated BUFFER "
                    "handler @ 0x1800EEA02, common failure exit @ 0x1800EDECB; "
                    "entry snapshot saves @ 0x1800EDBBB/0x1800EDBCA/0x1800EDBD9; "
                    "mode&4 snapshot update is excluded by modes1/3"
                ),
                supports=("pebmpat_buffer_backward_scan",),
            )
        )
        claim_evidence.append(
            SemanticEvidence(
                id="pebmpat_backward_scan_transition_model",
                axis="engine_equivalent_test",
                kind="engine_equivalent_test",
                source_ref=(
                    "Pinned DLL SHA256 "
                    "928e171c60a44bb326776d2a356412ae98d78469bdf8c94ebfbfa09f8ec4b4b3; "
                    "local_bm_raw09_model_engine: 2924 mode1/3 original-worker "
                    "comparisons for the literal/9090/raw01/raw09/END grammar, "
                    "with entry-snapshot register, Boolean, cursor and internal "
                    "scratch checks. Another 224 mode0/2 isolated transitions "
                    "do not extend the production byte-count model. "
                    "local_bm_raw09_u64_slice_engine adds 250 original-handler "
                    "arithmetic comparisons against the primitive and an "
                    "independent loop, including u64 wrap and initial bounds; "
                    "it stops before suffix execution. No general "
                    "BM program, FILE reader, capture or final-verdict equivalence"
                ),
                locator=(
                    "raw09 @ 0x1800EEA02..0x1800EEA7B; "
                    "mode1/3 suffix continuation @ 0x1800EE685"
                ),
                supports=("pebmpat_buffer_backward_scan",),
            )
        )
        claim_evidence.append(
            SemanticEvidence(
                id="pebmpat_backward_scan_counterexamples",
                axis="engine_equivalent_test",
                kind="engine_equivalent_test",
                source_ref=(
                    "Pinned DLL SHA256 "
                    "928e171c60a44bb326776d2a356412ae98d78469bdf8c94ebfbfa09f8ec4b4b3; "
                    "local_bm_alternatives_raw_engine::test_raw09_fresh_switch: "
                    "16 original BUFFER-worker cases, modes1/3, nonnull "
                    "internal scratch. Pattern 900900009000, subject 50, "
                    "cursor0 returns true; count1/cursor1 also returns true. "
                    "Switch index8 targets 0x1800EEA02. These are bounded "
                    "counterexamples, not a complete matcher or PE model"
                ),
                locator="BMMatchWorker_BMSBufferReader_ @ 0x1800EDB60",
                supports=("pebmpat_buffer_backward_scan",),
            )
        )

    return RuleSemantics(
        status=status,
        representation="pebmpat.pattern.ir.v14",
        data=data,
        evidence=(
            (
                "PEBMPatScanner::AddNewPattern framing and BMGetPatternFlags "
                "validation for mpengine 1.443.903.0"
            ),
            "PEBMPatScanner::ScanEx @ 0x1803D5A5C",
            "BMMatchPEMapper @ 0x1803D5E44",
            "BMMatchEx2 @ 0x1800EC420",
            "ScanContext::GetChar @ 0x180250F0C",
            "PEEmuMapper::mmap @ 0x180251080",
            "__mmap_ex @ 0x180035ED0",
            "VMM_x32_context::load_page @ 0x180040DD0",
            "pe_mofs_to_fofs_ex @ 0x1800E9DA0",
            (
                "pe_mofs_to_fofs_ex original-function probe: two synthetic selected-row "
                "cases return 0x634 and u32-wrap 0x134; no callee/provider stubs; "
                "does not verify caller mapping, metadata production, other branches or x64"
            ),
            "UfsSeekRead @ 0x18014A724",
            "VMM_x64_context::load_page @ 0x1800424D0 (x64 file-backed interval formula)",
        ),
        profile="mpengine-1.443.903.0",
        issues=tuple(issues),
        claims=tuple(claims),
        claim_evidence=tuple(claim_evidence),
    )


def _preview(raw: bytes) -> str:
    return raw[:_PREVIEW].hex(" ") + (" ..." if len(raw) > _PREVIEW else "")


def render_pebmpat(parsed: PEBMPat) -> FormatResult:
    """Render bounded raw fields and a conservative BM/YARA-like candidate."""
    yara = render_bm_yara(parsed.pattern) if parsed.pattern is not None else None
    rows = [
        ("flags", f"0x{parsed.flags:02X}"),
        ("flags_bit0_raw", str(parsed.flags & 1)),
        ("name_length", str(len(parsed.name))),
        ("name_raw", _preview(parsed.name)),
        ("name_preview", repr(parsed.name[:_TEXT_PREVIEW])),
        ("pattern_length", str(len(parsed.pattern_raw))),
        ("pattern_preview", _preview(parsed.pattern_raw)),
        ("receiver_result", parsed.receiver_result),
        (
            "bm_validation",
            "available" if parsed.pattern is not None else "not_available",
        ),
        (
            "bm_issue",
            f"{parsed.pattern.issue.code}@{parsed.pattern.issue.offset}"
            if parsed.pattern is not None and parsed.pattern.issue
            else "none",
        ),
    ]
    if yara is not None:
        rows.append(("bm_consumed", str(parsed.pattern.consumed)))
        rows.append(("bm_remaining_length", str(len(parsed.pattern.remaining_raw))))
        rows.append(("yara_fidelity", yara.fidelity.value))
    if yara is not None and yara.body:
        rows.append(("yara_like_preview", yara.body[:_TEXT_PREVIEW]))
    if yara is not None and yara.requirements:
        rows.append(("yara_requirements", "; ".join(yara.requirements)))
    rows.extend(
        (f"pattern_issue[{index}]", f"{issue.code}@{issue.offset}")
        for index, issue in enumerate(yara.diagnostics[:16] if yara else ())
    )
    if yara is not None and len(yara.diagnostics) > 16:
        rows.append(("remaining_issues", str(len(yara.diagnostics) - 16)))
    if yara is not None and yara.printable_preview:
        rows.append(("printable_preview", yara.printable_preview[:_TEXT_PREVIEW]))
    return FormatResult(sections=(DisplaySection("PEBMPAT", rows=tuple(rows)),))


SPEC = FamilySpec(
    0x95,
    "PEBMPAT",
    parse_pebmpat,
    render_pebmpat,
    semantic_exporter=export_pebmpat_semantics,
)
