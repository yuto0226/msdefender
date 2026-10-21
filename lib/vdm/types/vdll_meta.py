from dataclasses import dataclass

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

ITEM_PREVIEW_LIMIT = 16
TRAILING_PREVIEW_LIMIT = 32


@dataclass(frozen=True, slots=True)
class VdllMetaPayload:
    """Lossless fields shared by the known VDLL_META record families."""

    field0: int
    hash_key: int
    control: int
    count_flags: int
    field10: int
    items: tuple[int, ...]
    optional_value: int | None
    trailing: bytes
    raw: bytes

    @property
    def item_count(self) -> int:
        return len(self.items)


def parse_vdll_meta(payload: bytes) -> VdllMetaPayload:
    """Parse the common VDLL_META header, u16 items, and optional dword."""
    if len(payload) < 12:
        raise ValueError("truncated VDLL_META header")

    field0 = int.from_bytes(payload[0:4], "little")
    hash_key = int.from_bytes(payload[4:8], "little")
    control = payload[8]
    count_flags = payload[9]
    field10 = int.from_bytes(payload[10:12], "little")
    item_count = count_flags >> 3 if count_flags >= 8 else 0
    cursor = 12
    items_end = cursor + item_count * 2
    if items_end > len(payload):
        raise ValueError("truncated VDLL_META items")
    items = tuple(
        int.from_bytes(payload[offset : offset + 2], "little")
        for offset in range(cursor, items_end, 2)
    )
    cursor = items_end

    optional_value = None
    if len(payload) - cursor >= 4:
        optional_value = int.from_bytes(payload[cursor : cursor + 4], "little")
        cursor += 4
    elif cursor != len(payload):
        raise ValueError("truncated VDLL_META optional value")

    return VdllMetaPayload(
        field0=field0,
        hash_key=hash_key,
        control=control,
        count_flags=count_flags,
        field10=field10,
        items=items,
        optional_value=optional_value,
        trailing=payload[cursor:],
        raw=payload,
    )


def render_vdll_meta(parsed: VdllMetaPayload) -> FormatResult:
    preview_items = parsed.items[:ITEM_PREVIEW_LIMIT]
    items_preview = ", ".join(f"{item:#06x}" for item in preview_items)
    if len(parsed.items) > ITEM_PREVIEW_LIMIT:
        items_preview += f", … ({len(parsed.items) - ITEM_PREVIEW_LIMIT} more)"
    trailing_preview = parsed.trailing[:TRAILING_PREVIEW_LIMIT].hex(" ") or "(empty)"
    if len(parsed.trailing) > TRAILING_PREVIEW_LIMIT:
        trailing_preview += f" … ({len(parsed.trailing) - TRAILING_PREVIEW_LIMIT} more)"
    return FormatResult(
        fields=(
            ("field0", f"{parsed.field0:#010x}"),
            ("hash_key", f"{parsed.hash_key:#010x}"),
            ("control", f"{parsed.control:#04x}"),
            ("count_flags", f"{parsed.count_flags:#04x}"),
            ("item_count", str(parsed.item_count)),
            ("field10", f"{parsed.field10:#06x}"),
            ("items_preview", items_preview or "(empty)"),
            (
                "optional_value",
                "None"
                if parsed.optional_value is None
                else f"{parsed.optional_value:#010x}",
            ),
            ("trailing_length", str(len(parsed.trailing))),
            ("trailing_preview", trailing_preview),
        )
    )


def export_vdll_meta(
    parsed: VdllMetaPayload,
    *,
    type_byte: int,
    variant: str,
) -> RuleSemantics:
    """Export observed VDLL metadata fields without inventing rule semantics."""
    table_index = {0xB5: 0, 0xE1: 1, 0xE2: 2}.get(type_byte)
    host_selector = table_index if table_index is not None else None
    packed_lookup_value = ((parsed.optional_value or 0) << 32) | parsed.field0
    boundary_issues = (
        SemanticIssue(
            code="vdll_metadata_record_pairing_unknown",
            message=(
                (
                    "Host-selected global table lookup is confirmed, but this "
                    "metadata record is not paired one-to-one with a VDLL code record."
                )
                if table_index is not None
                else (
                    "This registered metadata table has no analyzed host-selected "
                    "linker route and is not paired one-to-one with a VDLL code record."
                )
            ),
        ),
        SemanticIssue(
            code="vdll_metadata_lookup_value_meaning_unknown",
            message=(
                "The linker consumes the packed 64-bit value as an import-address "
                "source, but its VA/RVA/flags representation is not established."
            ),
        ),
        SemanticIssue(
            code="vdll_metadata_final_verdict_unknown",
            message=(
                "Metadata insertion and linker lookup do not establish callback "
                "execution, scan matching, or final verdict causality."
            ),
        ),
    )
    data = JSONObject(
        (
            ("record_type", f"0x{type_byte:02X}"),
            ("variant", variant),
            (
                "wire_metadata",
                JSONObject(
                    (
                        ("field0", parsed.field0),
                        ("hash_key", parsed.hash_key),
                        ("control", parsed.control),
                        ("count_flags", parsed.count_flags),
                        ("item_count", parsed.item_count),
                        ("field10", parsed.field10),
                        ("items", JSONArray(tuple(parsed.items))),
                        ("optional_value", parsed.optional_value),
                        ("trailing_hex", parsed.trailing.hex()),
                    )
                ),
            ),
            (
                "receiver_storage",
                JSONObject(
                    (
                        ("table_scope", "type-specific VDLL metadata table"),
                        ("bucket_key", "hash_key modulo bucket_count"),
                        (
                            "insertion",
                            "prepend under hash_key modulo bucket_count",
                        ),
                        (
                            "internal_entry",
                            (
                                "receiver-created storage; exact reusable ABI is not "
                                "exported"
                            ),
                        ),
                        (
                            "duplicate_key_lookup_order",
                            None,
                        ),
                    )
                ),
            ),
            (
                "metadata_index_ir",
                JSONObject(
                    (
                        ("version", 4),
                        (
                            "host_routing",
                            JSONObject(
                                (
                                    ("host_selector", host_selector),
                                    ("table_index", table_index),
                                    ("registered_type", f"0x{type_byte:02X}"),
                                )
                            ),
                        ),
                        (
                            "key",
                            JSONObject(
                                (
                                    ("wire_field", "hash_key"),
                                    ("kind", "lookup_key"),
                                    ("bucket_formula", "hash_key % bucket_count"),
                                )
                            ),
                        ),
                        (
                            "chain",
                            JSONObject(
                                (
                                    ("bucket_head_width_bits", 16),
                                    ("empty_sentinel", 0xFFFF),
                                    (
                                        "insertion",
                                        (
                                            "new entry retains the previous bucket "
                                            "head and becomes the new head"
                                        ),
                                    ),
                                    ("duplicate_key_lookup_order", None),
                                )
                            ),
                        ),
                        (
                            "receiver_projection",
                            JSONObject(
                                (
                                    (
                                        "copied_fields",
                                        JSONArray(
                                            (
                                                "field0",
                                                "optional_value_or_zero",
                                                "hash_key",
                                                "control",
                                                "count_flags",
                                                "field10",
                                                "items",
                                            )
                                        ),
                                    ),
                                    (
                                        "storage_layout",
                                        "engine-internal and not a portable wire ABI",
                                    ),
                                )
                            ),
                        ),
                        (
                            "lookup_result",
                            JSONObject(
                                (
                                    ("width_bits", 64),
                                    ("packed_value", packed_lookup_value),
                                    ("low32_source", "field0"),
                                    ("high32_source", "optional_value_or_zero"),
                                    (
                                        "consumer_role",
                                        "linker_import_resolution_address_source",
                                    ),
                                    ("representation_meaning", None),
                                    ("representation_status", "unknown"),
                                )
                            ),
                        ),
                        (
                            "entry_pairing",
                            JSONObject(
                                (
                                    ("status", "not_established"),
                                    ("unique_code_record", None),
                                    ("pairing_key", None),
                                    (
                                        "bounded_negative",
                                        "metadata payload has no code-record slot/index; finalize consumes metadata as a hashed symbol-address source",
                                    ),
                                )
                            ),
                        ),
                        (
                            "receiver_ignored_trailing_length",
                            len(parsed.trailing),
                        ),
                        (
                            "final_verdict",
                            JSONObject((("status", "unknown"), ("value", None))),
                        ),
                    )
                ),
            ),
            (
                "vdll_code_linkage",
                JSONObject(
                    (
                        (
                            "finalize_host_table_index_map",
                            JSONArray(
                                (
                                    JSONObject(
                                        (
                                            ("host_selector", 0),
                                            ("table_index", 0),
                                            ("registered_type", "0xB5"),
                                        )
                                    ),
                                    JSONObject(
                                        (
                                            ("host_selector", 1),
                                            ("table_index", 1),
                                            ("registered_type", "0xE1"),
                                        )
                                    ),
                                    JSONObject(
                                        (
                                            ("host_selector", 2),
                                            ("table_index", 2),
                                            ("registered_type", "0xE2"),
                                        )
                                    ),
                                    JSONObject(
                                        (
                                            ("host_selector", 3),
                                            ("table_index", 3),
                                            ("registered_type", "0x93 (unnamed)"),
                                        )
                                    ),
                                    JSONObject(
                                        (
                                            ("host_selector", None),
                                            ("table_index", 4),
                                            ("registered_type", "0xE3"),
                                            (
                                                "finalize_reachability",
                                                "not selected by observed host selector values 0..3",
                                            ),
                                        )
                                    ),
                                )
                            ),
                        ),
                        (
                            "this_record_finalize_table_index",
                            {0xB5: 0, 0xE1: 1, 0xE2: 2}.get(type_byte),
                        ),
                        (
                            "type_mapped_by_get_meta_type_from_vtype",
                            table_index is not None,
                        ),
                        (
                            "entry_pairing",
                            (
                                "No unique VDLL_CODE record pairing is established "
                                "by this payload; receiver storage and finalize "
                                "symbol lookup expose no code-record identity key."
                            ),
                        ),
                        (
                            "linker_symbol_lookup",
                            (
                                "VDLL finalize maps host selectors 0/1/2/3 to global "
                                "metadata table indexes 0/1/2/3 and queries hashed "
                                "engine symbols there first; on miss it falls back "
                                "to the current code object's PE export index. This "
                                "does not establish unique wire-record pairing."
                            ),
                        ),
                    )
                ),
            ),
            (
                "runtime_loader",
                (
                    "The metadata receiver stores this record in a type-specific "
                    "global table. VDLL finalize uses host-selected table indexes "
                    "for hashed symbol resolution; code-object PE exports are a "
                    "separate fallback lookup. No unique metadata-to-code record "
                    "pairing is established."
                ),
            ),
            ("raw_hex", parsed.raw.hex()),
            ("detection_expression", None),
        )
    )
    claims = (
        SemanticClaim(
            id="vdll_meta_wire_framing",
            scope="wire_layout",
            statement=(
                "The receiver consumes the 12-byte header, count_flags-derived u16 "
                "items, and an optional u32 when at least four bytes remain; bytes "
                "after that optional value are ignored."
            ),
            coverage="complete",
            evidence_refs=("vdll_meta_receiver",),
        ),
        SemanticClaim(
            id="vdll_meta_dispatch",
            scope="loader_dispatch",
            statement=(
                f"Type 0x{type_byte:02X} is registered to the shared VDLL metadata "
                "receiver with its own metadata table context."
            ),
            coverage="complete",
            evidence_refs=("vdll_meta_registration",),
        ),
        SemanticClaim(
            id="vdll_meta_storage",
            scope="receiver_transform",
            statement=(
                "The receiver copies the consumed fields into an internal entry and "
                "prepends it to the bucket selected by hash_key modulo bucket_count."
            ),
            coverage="subset",
            evidence_refs=("vdll_meta_receiver",),
            unknowns=(
                SemanticUnknown(
                    "receiver_transform",
                    "The internal storage ABI and duplicate-key lookup selection are "
                    "not exported as portable semantics.",
                ),
            ),
        ),
        (
            SemanticClaim(
                id="vdll_meta_link_consumer",
                scope="runtime_consumer",
                statement=(
                    f"VDLL finalization for host selector {host_selector} queries "
                    f"metadata table {table_index} by import-symbol hash and uses a "
                    "hit's packed qword as the import-address source before the "
                    "current code object's PE-export fallback."
                ),
                coverage="subset",
                evidence_refs=("vdll_meta_linker",),
                unknowns=(
                    SemanticUnknown(
                        "runtime_consumer",
                        "This does not establish that this record is queried, that "
                        "the packed value's VA/RVA representation is known, or that "
                        "a resolved callback executes.",
                    ),
                ),
            )
            if table_index is not None
            else SemanticClaim(
                id="vdll_meta_link_consumer",
                scope="runtime_consumer",
                statement=(
                    f"No analyzed VDLL finalizer host selector routes to type "
                    f"0x{type_byte:02X}'s metadata table."
                ),
                coverage="unknown",
                unknowns=(
                    SemanticUnknown(
                        "runtime_consumer",
                        "A separate consumer for this registered table has not been "
                        "located.",
                    ),
                ),
            )
        ),
        SemanticClaim(
            id="vdll_meta_detection_predicate",
            scope="detection_predicate",
            statement="No record-specific detection predicate is established.",
            coverage="unknown",
            unknowns=(
                SemanticUnknown(
                    "detection_predicate",
                    "Metadata insertion and linker symbol resolution do not establish "
                    "a match condition.",
                ),
            ),
        ),
        SemanticClaim(
            id="vdll_meta_report_mapping",
            scope="report_mapping",
            statement="No candidate-to-report mapping is established.",
            coverage="unknown",
            unknowns=(
                SemanticUnknown(
                    "report_mapping",
                    "No policy or report path was closed for this metadata record.",
                ),
            ),
        ),
        SemanticClaim(
            id="vdll_meta_final_verdict",
            scope="final_verdict",
            statement="The final detection verdict is not established.",
            coverage="unknown",
            unknowns=(
                SemanticUnknown(
                    "final_verdict",
                    "No record-specific path to the host-visible verdict was observed.",
                ),
            ),
        ),
    )
    claim_evidence = (
        SemanticEvidence(
            id="vdll_meta_registration",
            axis="dispatch",
            kind="engine_static",
            source_ref="mpengine 1.443.903.0",
            locator="load_vdll_metadata @ 0x18048A27C",
            supports=("vdll_meta_dispatch",),
        ),
        SemanticEvidence(
            id="vdll_meta_receiver",
            axis="receiver",
            kind="engine_static",
            source_ref="mpengine 1.443.903.0",
            locator="vdll_metadata_receiver @ 0x1804C7B80",
            supports=("vdll_meta_wire_framing", "vdll_meta_storage"),
        ),
    ) + (
        (
            SemanticEvidence(
                id="vdll_meta_linker",
                axis="consumer",
                kind="engine_static",
                source_ref="mpengine 1.443.903.0",
                locator=(
                    "vdll_receiver_end @ 0x1800FF328; "
                    "get_meta_type_from_vtype @ 0x180D26DC8; "
                    "get_address_from_meta_id @ 0x1804DEB74"
                ),
                supports=("vdll_meta_link_consumer",),
            ),
        )
        if table_index is not None
        else ()
    )
    return RuleSemantics(
        status="confirmed_subset" if table_index is not None else "observed_only",
        representation="vdll_metadata_index_ir.v4",
        data=data,
        evidence=(
            (
                "mpengine 1.443.903.0 vdll_metadata_receiver @ 0x1804C7B80 "
                "consumes the bounded wire fields and inserts a receiver-created "
                "entry under hash_key modulo bucket_count."
            ),
            (
                "mpengine 1.443.903.0 load_vdll_metadata @ 0x18048A27C "
                "initializes the per-type metadata contexts and bucket counts."
            ),
            (
                "mpengine 1.443.903.0 get_meta_id @ 0x1804DEBAC searches the "
                "type-specific bucket chain by symbol hash; "
                "get_address_from_meta_id @ 0x1804DEB74 returns the entry's "
                "packed 64-bit lookup value."
            ),
            (
                "mpengine 1.443.903.0 vdll_receiver_end @ 0x1800FF328 uses the "
                "metadata lookup result as an import resolution address source"
            ),
            (
                "mpengine 1.443.903.0 get_meta_type_from_vtype @ 0x180D26DC8 "
                "maps host selectors 0/1/2 to metadata indexes 0/1/2, matching "
                "registered types 0xB5/0xE1/0xE2."
            ),
            (
                "The packed value representation, unique metadata-to-code pairing, "
                "callback execution, and final scan verdict remain unknown."
            ),
            (
                "The metadata receiver's observed role is table insertion; this "
                "confirmed subset covers receiver field projection and table lookup, "
                "not a portable internal layout, code-record pairing, or a detection "
                "verdict."
            ),
            (
                "Bounded negative: the wire metadata and analyzed resolution path "
                "contain no code-record slot/index or record identity join key."
            ),
        ),
        profile="mpengine-1.443.903.0",
        issues=boundary_issues
        + (
            (
                SemanticIssue(
                    code="receiver_ignored_trailing_bytes",
                    message=(
                        "Bytes after the optional value are preserved by this parser "
                        "but ignored by the analyzed receiver."
                    ),
                    details=(("length", len(parsed.trailing)),),
                ),
            )
            if parsed.trailing
            else ()
        ),
        claims=claims,
        claim_evidence=claim_evidence,
    )


def _semantic_exporter(type_byte: int, variant: str):
    def export(parsed: VdllMetaPayload) -> RuleSemantics:
        return export_vdll_meta(parsed, type_byte=type_byte, variant=variant)

    return export


FAMILY_SPECS = (
    FamilySpec(
        0xB5,
        "VDLL_META",
        parse_vdll_meta,
        render_vdll_meta,
        semantic_exporter=_semantic_exporter(0xB5, "unspecified architecture"),
    ),
    FamilySpec(
        0xE1,
        "VDLL_META_X64",
        parse_vdll_meta,
        render_vdll_meta,
        semantic_exporter=_semantic_exporter(0xE1, "x64"),
    ),
    FamilySpec(
        0xE2,
        "VDLL_META_ARM",
        parse_vdll_meta,
        render_vdll_meta,
        semantic_exporter=_semantic_exporter(0xE2, "ARM"),
    ),
    FamilySpec(
        0xE3,
        "VDLL_META_MSIL",
        parse_vdll_meta,
        render_vdll_meta,
        semantic_exporter=_semantic_exporter(0xE3, "MSIL / managed"),
    ),
)
