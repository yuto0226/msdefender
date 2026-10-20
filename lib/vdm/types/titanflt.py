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
    unknown = JSONObject(
        (
            ("status", "unknown"),
            ("evidence", JSONArray(())),
        )
    )
    return RuleSemantics(
        status="observed_only",
        representation="titanflt.corpus_wire_profile.v1",
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
                            ("tail_disposition", "no_unparsed_tail"),
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
                ("receiver", unknown),
                ("storage", unknown),
                ("runtime_consumer", unknown),
                ("report", unknown),
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
                "DispatchRecord uses dynamic gktab template/callback slots; the "
                "type 0x30 receiver, storage, runtime consumer, and report path "
                "remain unconfirmed."
            ),
        ),
        profile="mpengine-1.443.903.0",
        issues=(
            SemanticIssue(
                "engine_semantics_unconfirmed",
                "The type 0x30 receiver, storage, runtime consumer, and report path are not identified.",
            ),
            SemanticIssue(
                "corpus_profile_only",
                "The wire partition is supported by the current corpus and is not an engine acceptance contract.",
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
