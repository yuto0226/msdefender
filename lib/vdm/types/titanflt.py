"""Lossless parser and bounded renderer for TITANFLT (0x30)."""

from dataclasses import dataclass
from typing import Final

from ..core import (
    FamilySpec,
    FormatResult,
    JSONArray,
    JSONObject,
    RuleSemantics,
    SemanticIssue,
)

TITANFLT_TYPE: Final = 0x30
_ENTRY_PREVIEW_COUNT: Final = 12
_ENTRY_PREVIEW_BYTES: Final = 40


@dataclass(frozen=True, slots=True)
class TitanFltPayload:
    """Lossless payload with optional corpus-only segment observations."""

    raw: bytes
    entries: tuple[bytes, ...]

    @property
    def entries_ascii(self) -> tuple[str, ...]:
        """Return entries as ASCII text while retaining their original bytes."""
        return tuple(entry.decode("ascii") for entry in self.entries)


def parse_titanflt(payload: bytes) -> TitanFltPayload:
    """Preserve arbitrary bytes; split only for the observed corpus profile."""
    if (
        payload
        and payload[-1] == 0
        and b"\x00" not in payload[:-1]
        and payload[:-1]
        and all(0x20 <= byte <= 0x7E for byte in payload[:-1])
    ):
        entries = tuple(payload[:-1].split(b"|"))
        if all(entries):
            return TitanFltPayload(raw=payload, entries=entries)

    return TitanFltPayload(raw=payload, entries=())


def render_titanflt(parsed: TitanFltPayload) -> FormatResult:
    """Render a bounded entry preview while preserving the complete raw model."""
    preview_entries: list[str] = []
    for entry in parsed.entries[:_ENTRY_PREVIEW_COUNT]:
        text = entry[:_ENTRY_PREVIEW_BYTES].decode("ascii")
        if len(entry) > _ENTRY_PREVIEW_BYTES:
            text += f"… ({len(entry) - _ENTRY_PREVIEW_BYTES} more bytes)"
        preview_entries.append(text)

    if len(parsed.entries) > _ENTRY_PREVIEW_COUNT:
        preview_entries.append(
            f"… ({len(parsed.entries) - _ENTRY_PREVIEW_COUNT} more entries)"
        )

    return FormatResult(
        fields=(
            (
                "corpus_profile_entry_count",
                str(len(parsed.entries)) if parsed.entries else "not observed",
            ),
            (
                "corpus_profile_entries_preview",
                " | ".join(preview_entries) if parsed.entries else "not observed",
            ),
            ("raw_len", str(len(parsed.raw))),
        )
    )


def export_titanflt_semantics(parsed: TitanFltPayload) -> RuleSemantics:
    """Export observed wire/corpus facts without assigning engine meaning."""
    cursor = 0
    segments = []
    separators = []
    for entry in parsed.entries:
        segments.append(
            JSONObject(
                (
                    ("kind", "corpus_observed_pipe_delimited_segment"),
                    (
                        "raw_span",
                        JSONObject((("offset", cursor), ("length", len(entry)))),
                    ),
                    ("raw_hex", entry.hex()),
                    ("observed_ascii", entry.decode("ascii")),
                )
            )
        )
        cursor += len(entry)
        if cursor < len(parsed.raw) - 1:
            separators.append(
                JSONObject((("offset", cursor), ("length", 1), ("raw_hex", "7c")))
            )
            cursor += 1  # The corpus profile parser validated this byte as '|'.

    corpus_profile_observed = bool(parsed.entries)
    profile_observation = (
        JSONObject(
            (
                ("status", "observed_in_current_corpus"),
                ("segments", JSONArray(tuple(segments))),
                ("separators", JSONArray(tuple(separators))),
                (
                    "terminal_nul",
                    JSONObject(
                        (
                            ("offset", len(parsed.raw) - 1),
                            ("length", 1),
                            ("raw_hex", "00"),
                        )
                    ),
                ),
                ("is_wire_grammar", False),
            )
        )
        if corpus_profile_observed
        else JSONObject(
            (
                ("status", "not_matching_observed_corpus_profile"),
                ("raw_hex", parsed.raw.hex()),
                ("is_wire_grammar", False),
            )
        )
    )
    receiver = JSONObject(
        (
            ("function", "RegisterForDatabaseRecords"),
            ("address", "0x180564BC0"),
            ("template_receiver", "ReceiveNewTemplate"),
            ("template_receiver_address", "0x1803224D0"),
            ("template_receiver_size", "0xB70"),
            ("selector", 0x30),
            ("registration_caller", "cksig_init_module"),
            ("registration_caller_address", "0x1805648A0"),
            ("registration_callsite", "0x180564A9F"),
            ("descriptor_address", "0x180E4DFF0"),
            ("instruction_word_count", 2),
            ("row_size", 0x10),
            (
                "descriptor",
                JSONObject(
                    (
                        ("opcode", "0x1005"),
                        ("destination_offset", 0),
                    )
                ),
            ),
            (
                "input_check",
                JSONObject(
                    (
                        ("required_bytes", 8),
                        ("available_bytes", len(parsed.raw)),
                        (
                            "result",
                            "rejected_before_copy"
                            if len(parsed.raw) < 8
                            else "sufficient_for_copy",
                        ),
                        ("error", 40964 if len(parsed.raw) < 8 else None),
                    )
                ),
            ),
        )
    )
    payload_short = len(parsed.raw) < 8
    row_dword = int.from_bytes(parsed.raw[:4], "little")
    object_store_selector = bool(row_dword & 0x40000000)
    normalized_object_id = (
        row_dword & 0xBFFFFFFF if object_store_selector else row_dword
    )
    wire_projection = (
        JSONObject(
            (
                ("status", "not_projected"),
                ("reason", "receiver_requires_eight_bytes_for_0x1005"),
            )
        )
        if payload_short
        else JSONObject(
            (
                (
                    "copy",
                    JSONObject(
                        (
                            (
                                "payload_span",
                                JSONObject((("offset", 0), ("length", 8))),
                            ),
                            ("row_offset", 0),
                            ("operation", "copy_qword"),
                        )
                    ),
                ),
                ("zeroed_span", JSONObject((("offset", 8), ("length", 8)))),
                (
                    "unconsumed_tail",
                    JSONObject((("offset", 8), ("length", len(parsed.raw) - 8))),
                ),
            )
        )
    )
    storage = JSONObject(
        (
            ("row_stride", 0x10),
            ("wire_projection", wire_projection),
        )
    )
    runtime_consumer = JSONObject(
        (
            ("status", "not_reached" if payload_short else "registered_pipeline"),
            *(
                (("reason", "receiver_rejected_before_row_creation"),)
                if payload_short
                else (
                    ("compile_function", "CompileVNFlts"),
                    ("compile_address", "0x1805B0370"),
                    ("compile_resolve_callsite", "0x1805B03DB"),
                    ("object_resolver", "kpopobject"),
                    ("regex_constructor", "Boost basic_regex<char> flags=0"),
                    ("filter_function", "CK_IsVnameFiltered"),
                    ("filter_address", "0x180BBADC4"),
                    (
                        "filter_operation",
                        "Boost regex_search(name, compiled_regex)",
                    ),
                    ("caller", "kvirinfo"),
                    ("caller_address", "0x180551320"),
                    ("caller_gate", "filter_names enabled"),
                    (
                        "packed_object_reference",
                        JSONObject(
                            (
                                (
                                    "payload_prefix_ascii",
                                    (
                                        parsed.raw[:8].decode("ascii")
                                        if all(
                                            0x20 <= byte <= 0x7E
                                            for byte in parsed.raw[:8]
                                        )
                                        else None
                                    ),
                                ),
                                ("row_dword_hex", parsed.raw[:4].hex()),
                                ("row_dword_value", row_dword),
                                ("raw_object_id", row_dword),
                                ("alternate_store_flag_bit30", object_store_selector),
                                (
                                    "store",
                                    "alternate" if object_store_selector else "primary",
                                ),
                                ("normalized_object_id", normalized_object_id),
                                ("packed_chunk_index", normalized_object_id >> 16),
                                ("packed_byte_offset", normalized_object_id & 0xFFFF),
                                ("resolution", "unconfirmed"),
                                (
                                    "resolution_limitation",
                                    "requires runtime gktab chunk tables and contents",
                                ),
                            )
                        ),
                    ),
                )
            ),
        )
    )
    reporting = JSONObject((("status", "unknown"),))
    return RuleSemantics(
        status="unsupported" if payload_short else "observed_only",
        representation="titanflt.packed_object_candidate.v4",
        data=JSONObject(
            (
                ("raw_hex", parsed.raw.hex()),
                ("raw_length", len(parsed.raw)),
                (
                    "corpus_profile_observation",
                    JSONObject(
                        (
                            ("profile", profile_observation),
                            ("not_wire_grammar", True),
                            ("raw_hex_always_preserved", True),
                        )
                    ),
                ),
                (
                    "profile_basis",
                    JSONObject(
                        (
                            ("record_type", "0x30"),
                            ("source", "current mpas.sig corpus"),
                            ("known_record_count", 1),
                            ("known_payload_length", 331),
                            ("mpav_record_count", 0),
                            ("input_identity_verified", False),
                            ("engine_loader_resolution", "unconfirmed"),
                        )
                    ),
                ),
                ("receiver", receiver),
                ("storage", storage),
                ("runtime_consumer", runtime_consumer),
                ("report", reporting),
            )
        ),
        evidence=(
            (
                "The current mpas.sig corpus contains one 0x30 record with a "
                "331-byte payload; mpav.sig contains none."
            ),
            (
                "The observed sample contains printable pipe-separated segments "
                "and a terminal NUL; this is not established as wire grammar."
            ),
            (
                "mpengine 1.443.903.0 cksig_init_module (0x1805648A0) calls "
                "RegisterForDatabaseRecords at 0x180564A9F for type 0x30, a "
                "16-byte row, and descriptor 0x180E4DFF0"
            ),
            (
                "mpengine 1.443.903.0 ReceiveNewTemplate (0x1803224D0) copies "
                "payload[0:8] to row[0:8] for descriptor opcode 0x1005"
            ),
            (
                "mpengine 1.443.903.0 CompileVNFlts (0x1805B0370) resolves row "
                "DWORD +0 through kpopobject at 0x1805B03DB and builds a Boost "
                "regex; CK_IsVnameFiltered (0x180BBADC4) checks names and is "
                "called by kvirinfo (0x180551320) when filter_names is enabled"
            ),
            *(
                (
                    "The 0x1005 receiver requires eight bytes and returns 0xA004 "
                    "before copying when the payload is shorter."
                    if payload_short
                    else f"The payload prefix normalizes to packed index "
                    f"0x{normalized_object_id >> 16:04X}:"
                    f"0x{normalized_object_id & 0xFFFF:04X}; its "
                    "resolution is unconfirmed, and payload bytes 8 onward are "
                    "not consumed by the registered template."
                ),
            ),
        ),
        profile="mpengine-1.443.903.0",
        issues=(
            *(
                (
                    SemanticIssue(
                        "receiver_input_too_short",
                        "The registered 0x1005 descriptor requires eight payload bytes and rejects this shorter input before copying.",
                    ),
                )
                if payload_short
                else (
                    SemanticIssue(
                        "packed_object_reference_unresolved",
                        "The payload prefix is copied as a packed kpopobject index, but its runtime resolution to regex bytes is unconfirmed.",
                    ),
                )
            ),
            SemanticIssue(
                "corpus_profile_only",
                "Pipe-delimited printable segments describe one corpus profile, not a validated wire grammar; the template consumes only the first eight payload bytes.",
            ),
        ),
    )


SPEC = FamilySpec(
    TITANFLT_TYPE,
    "TITANFLT",
    parse_titanflt,
    render_titanflt,
    semantic_exporter=export_titanflt_semantics,
)
