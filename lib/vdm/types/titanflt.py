"""Corpus-profile parser and bounded renderer for TITANFLT (0x30)."""

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
    """Lossless TITANFLT payload and its corpus-profile ASCII entries."""

    raw: bytes
    entries: tuple[bytes, ...]

    @property
    def entries_ascii(self) -> tuple[str, ...]:
        """Return entries as ASCII text while retaining their original bytes."""
        return tuple(entry.decode("ascii") for entry in self.entries)


def parse_titanflt(payload: bytes) -> TitanFltPayload:
    """Parse only the observed corpus profile; this is not an engine validator."""
    if not payload or payload[-1] != 0:
        raise ValueError("TITANFLT corpus profile requires exactly one terminal NUL")

    body = payload[:-1]
    if b"\x00" in body:
        raise ValueError("TITANFLT corpus profile does not allow embedded NUL")
    if not body:
        raise ValueError("TITANFLT corpus profile requires at least one entry")

    entries = tuple(body.split(b"|"))
    if any(not entry for entry in entries):
        raise ValueError("TITANFLT corpus profile does not allow an empty entry")
    if any(byte < 0x20 or byte > 0x7E for entry in entries for byte in entry):
        raise ValueError("TITANFLT corpus profile entries must use printable ASCII")

    return TitanFltPayload(raw=payload, entries=entries)


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
            ("entry_count", str(len(parsed.entries))),
            ("entries_preview", " | ".join(preview_entries)),
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

    terminator = JSONObject(
        (("offset", len(parsed.raw) - 1), ("length", 1), ("raw_hex", "00"))
    )
    receiver = JSONObject(
        (
            ("function", "RegisterForDatabaseRecords"),
            ("address", "0x180564BC0"),
            ("selector", 0x30),
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
                    ("object_resolver", "kpopobject"),
                    ("regex_constructor", "Boost basic_regex<char> flags=0"),
                    ("filter_function", "CK_IsVnameFiltered"),
                    ("filter_address", "0x180BBADC4"),
                    (
                        "filter_operation",
                        "Boost regex_search(name, compiled_regex)",
                    ),
                    ("caller", "kvirinfo"),
                    (
                        "packed_object_reference",
                        JSONObject(
                            (
                                (
                                    "payload_prefix_ascii",
                                    parsed.raw[:8].decode("ascii"),
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
        representation="titanflt.engine_registration.v3",
        data=JSONObject(
            (
                ("raw_hex", parsed.raw.hex()),
                ("raw_length", len(parsed.raw)),
                (
                    "wire",
                    JSONObject(
                        (
                            ("partition", JSONArray(tuple(segments))),
                            ("separators", JSONArray(tuple(separators))),
                            ("terminator", terminator),
                            ("tail_disposition", "corpus_profile_fully_partitioned"),
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
                "The payload is printable ASCII segments separated by pipe bytes, "
                "followed by one terminal NUL; this describes the corpus profile only."
            ),
            (
                "RegisterForDatabaseRecords registers type 0x30 with one 0x1005 "
                "descriptor; ReceiveNewTemplate copies payload[0:8] to row[0:8]."
            ),
            (
                "CompileVNFlts resolves row DWORD +0 through kpopobject and builds "
                "a Boost regex; CK_IsVnameFiltered checks names with regex_search."
            ),
            *(
                (
                    "The 0x1005 receiver requires eight bytes and returns 0xA004 "
                    "before copying when the payload is shorter."
                    if payload_short
                    else f"The payload prefix projects to packed index "
                    f"0x{row_dword >> 16:04X}:0x{row_dword & 0xFFFF:04X}; its "
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
                "Pipe-delimited printable segments describe corpus bytes only; the engine template consumes only the first eight payload bytes.",
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
