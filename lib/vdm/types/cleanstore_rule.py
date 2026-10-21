"""Corpus-supported structural profile for CLEANSTORE_RULE (0xC1).

The two envelope shapes here were recovered from the bundled mpas.sig corpus.
They are not an engine-validated semantic schema. The parser reports the
observed envelope fields without assigning semantic names to their values.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..core import (
    DisplaySection,
    FamilySpec,
    FormatResult,
    JSONArray,
    JSONObject,
    RuleSemantics,
    SemanticIssue,
)

MAX_FIELD_COUNT = 256
# Grammar-derived ceiling: at most MAX_FIELD_COUNT full fields, each with a
# u16-sized value and a 7-byte envelope. This is a parser resource bound, not
# an engine or VDM format limit.
MAX_PAYLOAD_SIZE = MAX_FIELD_COUNT * (0xFFFF + 7)
_PREVIEW_BYTES = 16
_MAX_RENDERED_FIELDS = 16


@dataclass(frozen=True, slots=True)
class CleanStoreField:
    """One field decoded using an observed 5-byte or 7-byte envelope."""

    offset: int
    header_size: int
    tag: int
    selector: int
    value_type: int | None
    data: bytes

    @property
    def size(self) -> int:
        return len(self.data)


@dataclass(frozen=True, slots=True)
class CleanStoreRule:
    """A C1 payload partitioned into corpus-observed fields."""

    raw: bytes
    fields: tuple[CleanStoreField, ...]


type _FieldEdge = tuple[int, int, int, int, int | None, int]


def _field_edges(payload: bytes, offset: int) -> tuple[_FieldEdge, ...]:
    edges: list[_FieldEdge] = []

    if offset + 7 <= len(payload) and payload[offset + 4] == 1:
        size = int.from_bytes(payload[offset + 5 : offset + 7], "little")
        data_start = offset + 7
        data_end = data_start + size
        if data_end <= len(payload):
            edges.append(
                (
                    data_end,
                    7,
                    int.from_bytes(payload[offset : offset + 2], "little"),
                    int.from_bytes(payload[offset + 2 : offset + 4], "little"),
                    payload[offset + 4],
                    size,
                )
            )

    if offset + 5 <= len(payload) and payload[offset + 4] == 0:
        size = payload[offset + 3]
        data_start = offset + 5
        data_end = data_start + size
        if data_end <= len(payload):
            edges.append(
                (
                    data_end,
                    5,
                    int.from_bytes(payload[offset : offset + 2], "little"),
                    payload[offset + 2],
                    None,
                    size,
                )
            )

    return tuple(edges)


def parse_cleanstore_rule(payload: bytes) -> CleanStoreRule:
    """Partition a C1 payload using the unique observed envelope parse.

    Full envelopes are ``u16 tag, u16 selector, u8 type, u16 size``. Compact
    envelopes are ``u16 tag, u8 selector, u8 size, u8 zero``. Both integers
    are little-endian. Field data follows each header immediately.

    The parser rejects incomplete or ambiguous partitions instead of guessing
    semantics or discarding unexplained bytes.
    """

    if not payload:
        raise ValueError("empty CLEANSTORE_RULE payload")
    if len(payload) > MAX_PAYLOAD_SIZE:
        raise ValueError(
            f"CLEANSTORE_RULE payload exceeds {MAX_PAYLOAD_SIZE} byte limit"
        )

    # Work backwards over the finite set of byte offsets. Each offset stores
    # only 0, 1, or 2 (meaning >1) suffix parses and one edge selector. This
    # gives O(n) time and two bytes of DP storage per payload byte.
    ways = bytearray(len(payload) + 1)
    choices = bytearray(len(payload) + 1)
    ways[len(payload)] = 1
    for offset in range(len(payload) - 1, -1, -1):
        total = 0
        unique_choice = 0
        for edge_index, edge in enumerate(_field_edges(payload, offset), start=1):
            end = edge[0]
            suffix_ways = ways[end]
            if suffix_ways:
                if total == 0 and suffix_ways == 1:
                    unique_choice = edge_index
                else:
                    unique_choice = 0
                total = min(2, total + suffix_ways)
        ways[offset] = total
        choices[offset] = unique_choice if total == 1 else 0

    if ways[0] == 0:
        raise ValueError("payload has no complete CLEANSTORE_RULE field partition")
    if ways[0] > 1:
        raise ValueError("payload has an ambiguous CLEANSTORE_RULE field partition")

    fields: list[CleanStoreField] = []
    offset = 0
    while offset < len(payload):
        edge_index = choices[offset]
        if edge_index == 0:
            raise ValueError("invalid CLEANSTORE_RULE partition state")
        try:
            end, header_size, tag, selector, value_type, size = _field_edges(
                payload, offset
            )[edge_index - 1]
        except IndexError as exc:
            raise ValueError("invalid CLEANSTORE_RULE partition state") from exc
        data_start = offset + header_size
        fields.append(
            CleanStoreField(
                offset=offset,
                header_size=header_size,
                tag=tag,
                selector=selector,
                value_type=value_type,
                data=payload[data_start : data_start + size],
            )
        )
        offset = end
        if len(fields) > MAX_FIELD_COUNT:
            raise ValueError(
                f"CLEANSTORE_RULE field count exceeds {MAX_FIELD_COUNT} limit"
            )
    return CleanStoreRule(raw=payload, fields=tuple(fields))


def _hex_preview(data: bytes) -> str:
    preview = data[:_PREVIEW_BYTES].hex(" ")
    return preview + (" …" if len(data) > _PREVIEW_BYTES else "")


def render_cleanstore_rule(parsed: CleanStoreRule) -> FormatResult:
    rows = [("field_count", str(len(parsed.fields)))]
    visible_fields = parsed.fields[:_MAX_RENDERED_FIELDS]
    rows.append(("fields_shown", str(len(visible_fields))))
    if len(visible_fields) < len(parsed.fields):
        rows.append(("fields_omitted", str(len(parsed.fields) - len(visible_fields))))
    for index, field in enumerate(visible_fields):
        prefix = f"field_{index}"
        rows.extend(
            (
                (f"{prefix}_offset", f"0x{field.offset:X}"),
                (f"{prefix}_header", f"{field.header_size} B"),
                (f"{prefix}_tag", f"0x{field.tag:04X}"),
                (f"{prefix}_selector", f"0x{field.selector:04X}"),
                (
                    f"{prefix}_type",
                    "compact/unspecified"
                    if field.value_type is None
                    else f"0x{field.value_type:02X}",
                ),
                (f"{prefix}_size", f"{field.size} B"),
                (f"{prefix}_data", _hex_preview(field.data)),
            )
        )
    section = DisplaySection("CLEANSTORE_RULE", rows=tuple(rows))
    return FormatResult(sections=(section,))


def export_cleanstore_rule_semantics(parsed: CleanStoreRule) -> RuleSemantics:
    """Export the corpus-observed wire partition without inferred semantics."""
    framing = []
    for field in parsed.fields:
        header = parsed.raw[field.offset : field.offset + field.header_size]
        framing.append(
            JSONObject(
                (
                    ("kind", "corpus_observed_field_envelope"),
                    (
                        "raw_span",
                        JSONObject(
                            (("offset", field.offset), ("length", field.header_size))
                        ),
                    ),
                    ("raw_hex", header.hex()),
                    ("tag_raw_hex", parsed.raw[field.offset : field.offset + 2].hex()),
                    (
                        "selector_raw_hex",
                        parsed.raw[
                            field.offset + 2 : field.offset
                            + field.header_size
                            - (3 if field.value_type is not None else 2)
                        ].hex(),
                    ),
                    (
                        "value_type_raw_hex",
                        None
                        if field.value_type is None
                        else parsed.raw[field.offset + 4 : field.offset + 5].hex(),
                    ),
                    (
                        "data_span",
                        JSONObject(
                            (
                                ("offset", field.offset + field.header_size),
                                ("length", field.size),
                            )
                        ),
                    ),
                    ("data_raw_hex", field.data.hex()),
                )
            )
        )

    unknown = JSONObject((("status", "unknown"), ("evidence", JSONArray(()))))
    issues = (
        SemanticIssue(
            "engine_semantics_unconfirmed",
            "The dynamic 0xC1 registration path, receiver, storage, runtime "
            "consumer, and final policy are not identified; the bounded direct-"
            "caller search does not exclude indirect or data-driven registration.",
        ),
        SemanticIssue(
            "corpus_profile_only",
            "The envelope partition is supported by the current corpus, not validated as an engine ABI.",
        ),
    )
    return RuleSemantics(
        status="observed_only",
        representation="cleanstore_rule.corpus_wire_profile.v2",
        data=JSONObject(
            (
                ("raw_hex", parsed.raw.hex()),
                ("raw_length", len(parsed.raw)),
                (
                    "wire",
                    JSONObject(
                        (
                            ("partition", JSONArray(tuple(framing))),
                            ("tail_disposition", "no_unparsed_tail"),
                        )
                    ),
                ),
                ("receiver", unknown),
                ("storage", unknown),
                ("runtime_consumer", unknown),
                ("final_policy", unknown),
                (
                    "registration_search_boundary",
                    JSONObject(
                        (
                            (
                                "checked",
                                "0xC1 immediate functions and direct regcntl callers",
                            ),
                            ("direct_intersection_found", False),
                            (
                                "register_for_database_records_callers_complete",
                                False,
                            ),
                            ("runtime_gktab_slot_observed", False),
                            ("indirect_or_data_driven_registration_excluded", False),
                        )
                    ),
                ),
                (
                    "corpus",
                    JSONObject(
                        (
                            ("stream", "mpas.sig"),
                            ("record_type", "0xC1"),
                            ("record_count", 61),
                            ("block", "!InfrastructureShared"),
                            ("threat_id", "0x7FFFFFF0"),
                            (
                                "payload_lengths",
                                JSONArray((49, 78, 86, 88, 90, 95, 103, 109)),
                            ),
                            ("mpav_record_count", 0),
                        )
                    ),
                ),
            )
        ),
        evidence=(
            (
                "The local mpas.sig corpus contains 61 records whose bytes are "
                "fully partitioned by this parser."
            ),
            (
                "mpengine 1.443.903.0 DispatchRecord at 0x1800FAF18 uses the "
                "dynamic gktab dispatcher; the type 0xC1 receiver slot remains "
                "unverified."
            ),
            (
                "The bounded negative audit intersected 0xC1 immediate functions "
                "with direct regcntl callers only; RegisterForDatabaseRecords, "
                "indirect, data-driven, and runtime slot paths remain open."
            ),
        ),
        profile="mpengine-1.443.903.0",
        issues=issues,
    )


SPEC = FamilySpec(
    0xC1,
    "CLEANSTORE_RULE",
    parse_cleanstore_rule,
    render_cleanstore_rule,
    semantic_exporter=export_cleanstore_rule_semantics,
)
