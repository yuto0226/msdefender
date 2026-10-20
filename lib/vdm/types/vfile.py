"""Lossless receiver-framing view for VFILE (0x83) and VFILEEX (0xB2)."""

from dataclasses import dataclass
from typing import Final

from ..core import (
    DisplaySection,
    FamilySpec,
    FormatResult,
    JSONArray,
    JSONObject,
    RuleSemantics,
    SemanticIssue,
    SemanticJSONValue,
)

VFILE_TYPE: Final = 0x83
VFILEEX_TYPE: Final = 0xB2
_ENTRY_STRIDE: Final = 592
_ENTRY_PREFIX_SIZE: Final = 44
_ENTRY_PATH_FIELD_SIZE: Final = 0x208
_MAX_ENTRY_COUNT: Final = 0x6EB3E4
_PATH_PREVIEW_CHARS: Final = 80
_RAW_PREVIEW_BYTES: Final = 24
_TAIL_PREVIEW_BYTES: Final = 16


@dataclass(frozen=True, slots=True)
class VFilePayload:
    """Receiver-bounded field view; unconfirmed fields remain raw observations."""

    raw: bytes
    signature_type: int
    entry_count: int
    entries_raw: bytes
    entry_prefix_raw: bytes | None
    path_offset: int | None
    path_raw: bytes | None
    path_terminator: bytes | None
    path_terminated: bool | None
    tail_raw: bytes

    @property
    def path(self) -> str | None:
        """Decode the first entry's bounded UTF-16LE NUL-terminated candidate."""
        if not self.path_terminated or self.path_raw is None:
            return None
        return self.path_raw.decode("utf-16le", errors="surrogatepass")


def _parse(payload: bytes, signature_type: int) -> VFilePayload:
    if signature_type == VFILE_TYPE:
        prefix_size = 0
        entry_count = 1
    elif signature_type == VFILEEX_TYPE:
        if len(payload) < 4:
            raise ValueError(
                "VFILE receiver framing: truncated VFILEEX entry-count prefix; "
                "need 4 bytes"
            )
        prefix_size = 4
        entry_count = int.from_bytes(payload[:4], "little")
    else:
        raise ValueError(f"unsupported VFILE signature type: {signature_type:#x}")

    if entry_count > _MAX_ENTRY_COUNT:
        raise ValueError(
            "VFILE receiver framing: entry count exceeds receiver limit "
            f"({_MAX_ENTRY_COUNT:#x})"
        )

    entries_size = _ENTRY_STRIDE * entry_count
    tail_offset = prefix_size + entries_size
    if len(payload) <= tail_offset:
        raise ValueError(
            "VFILE receiver framing: receiver requires bytes beyond the entry "
            f"region ending at {tail_offset}; have {len(payload)}"
        )

    entries_raw = payload[prefix_size:tail_offset]
    first_entry = entries_raw[:_ENTRY_STRIDE] if entry_count else None
    if first_entry is None:
        entry_prefix_raw = None
        path_offset = None
        path_raw = None
        path_terminator = None
        path_terminated = None
    else:
        entry_prefix_raw = first_entry[:_ENTRY_PREFIX_SIZE]
        path_offset = prefix_size + _ENTRY_PREFIX_SIZE
        terminator_at = next(
            (
                offset
                for offset in range(0, _ENTRY_PATH_FIELD_SIZE, 2)
                if first_entry[
                    _ENTRY_PREFIX_SIZE + offset : _ENTRY_PREFIX_SIZE + offset + 2
                ]
                == b"\0\0"
            ),
            None,
        )
        path_terminated = terminator_at is not None
        path_raw = (
            first_entry[_ENTRY_PREFIX_SIZE : _ENTRY_PREFIX_SIZE + terminator_at]
            if path_terminated
            else first_entry[
                _ENTRY_PREFIX_SIZE : _ENTRY_PREFIX_SIZE + _ENTRY_PATH_FIELD_SIZE
            ]
        )
        path_terminator = b"\0\0" if path_terminated else b""
    tail_raw = payload[tail_offset:]

    return VFilePayload(
        raw=payload,
        signature_type=signature_type,
        entry_count=entry_count,
        entries_raw=entries_raw,
        entry_prefix_raw=entry_prefix_raw,
        path_offset=path_offset,
        path_raw=path_raw,
        path_terminator=path_terminator,
        path_terminated=path_terminated,
        tail_raw=tail_raw,
    )


def parse_vfile(payload: bytes) -> VFilePayload:
    """Parse the observed 0x83 receiver framing, not a complete engine schema."""
    return _parse(payload, VFILE_TYPE)


def parse_vfileex(payload: bytes) -> VFilePayload:
    """Parse the observed 0xB2 receiver framing with a u32 entry-count prefix."""
    return _parse(payload, VFILEEX_TYPE)


def _hex_preview(data: bytes, limit: int) -> str:
    preview = data[:limit].hex(" ").upper() or "(empty)"
    if len(data) > limit:
        preview += f" … (+{len(data) - limit} B)"
    return preview


def render_vfile(parsed: VFilePayload) -> FormatResult:
    """Render receiver-framing observations with bounded raw/string previews."""
    path = parsed.path
    path_preview = (
        "(no entries)"
        if parsed.entry_count == 0
        else "(no aligned NUL within bounded 520-byte field)"
        if path is None
        else ascii(path[:_PATH_PREVIEW_CHARS])
    )
    if path is not None and len(path) > _PATH_PREVIEW_CHARS:
        path_preview += f" … (+{len(path) - _PATH_PREVIEW_CHARS} more chars)"

    fields = [
        ("profile", "engine-confirmed VFILE/VFILEEX receiver framing"),
        ("signature_type", f"0x{parsed.signature_type:02X}"),
        ("payload_size", f"{len(parsed.raw)} B"),
        ("entry_count", str(parsed.entry_count)),
        ("entry_region_size", f"{len(parsed.entries_raw)} B"),
        ("tail_size", f"{len(parsed.tail_raw)} B"),
    ]
    section_rows = []
    if parsed.entry_count:
        fields.extend(
            (
                ("path_candidate_offset", f"0x{parsed.path_offset:X}"),
                ("path_chars", str(len(path)) if path is not None else "unknown"),
                ("path_raw_size", f"{len(parsed.path_raw)} B"),
                (
                    "path_terminated_within_520B",
                    str(parsed.path_terminated),
                ),
            )
        )
        section_rows.extend(
            (
                ("path_candidate", path_preview),
                ("path_raw_preview", _hex_preview(parsed.path_raw, _RAW_PREVIEW_BYTES)),
                (
                    "path_terminator_candidate",
                    parsed.path_terminator.hex(" ").upper()
                    if parsed.path_terminator is not None
                    else "",
                ),
                (
                    "entry_prefix_preview",
                    _hex_preview(parsed.entry_prefix_raw, _RAW_PREVIEW_BYTES),
                ),
            )
        )

    section_rows.append(
        ("tail_raw_preview", _hex_preview(parsed.tail_raw, _TAIL_PREVIEW_BYTES))
    )
    return FormatResult(
        fields=tuple(fields),
        sections=(
            DisplaySection("VFILE receiver-framed payload", tuple(section_rows)),
        ),
    )


def _span(offset: int, length: int) -> JSONObject:
    return JSONObject((("offset", offset), ("length", length)))


def export_vfile_semantics(parsed: VFilePayload) -> RuleSemantics:
    """Export confirmed receiver framing while preserving opaque entry bytes."""
    prefix_size = 4 if parsed.signature_type == VFILEEX_TYPE else 0
    entries: list[SemanticJSONValue] = []
    for index in range(parsed.entry_count):
        entry_offset = prefix_size + index * _ENTRY_STRIDE
        entry = parsed.entries_raw[index * _ENTRY_STRIDE : (index + 1) * _ENTRY_STRIDE]
        path_field = entry[
            _ENTRY_PREFIX_SIZE : _ENTRY_PREFIX_SIZE + _ENTRY_PATH_FIELD_SIZE
        ]
        terminator_at = next(
            (
                offset
                for offset in range(0, _ENTRY_PATH_FIELD_SIZE, 2)
                if path_field[offset : offset + 2] == b"\0\0"
            ),
            None,
        )
        path_candidate = (
            path_field if terminator_at is None else path_field[:terminator_at]
        )
        copied_field = JSONObject(
            (
                (
                    "raw_span",
                    _span(entry_offset + _ENTRY_PREFIX_SIZE, len(path_field)),
                ),
                ("raw_hex", path_field.hex()),
                ("receiver_copy_size", _ENTRY_PATH_FIELD_SIZE),
            )
        )
        path_object = JSONObject(
            (
                (
                    "raw_span",
                    _span(entry_offset + _ENTRY_PREFIX_SIZE, len(path_candidate)),
                ),
                ("raw_hex", path_candidate.hex()),
                ("nul_terminated_within_520_bytes", terminator_at is not None),
                (
                    "text_candidate",
                    path_candidate.decode("utf-16le", errors="surrogatepass")
                    if terminator_at is not None
                    else None,
                ),
            )
        )
        entries.append(
            JSONObject(
                (
                    ("index", index),
                    ("raw_span", _span(entry_offset, _ENTRY_STRIDE)),
                    ("raw_hex", entry.hex()),
                    ("prefix_raw_hex", entry[:_ENTRY_PREFIX_SIZE].hex()),
                    ("receiver_copied_field", copied_field),
                    ("path_candidate", path_object),
                )
            )
        )

    framing_items: list[tuple[str, SemanticJSONValue]] = [
        ("entry_stride", _ENTRY_STRIDE),
        ("entry_region", _span(prefix_size, len(parsed.entries_raw))),
        ("tail_required_nonempty", True),
    ]
    if parsed.signature_type == VFILEEX_TYPE:
        framing_items.append(
            (
                "count_prefix",
                JSONObject(
                    (
                        ("raw_span", _span(0, 4)),
                        ("raw_hex", parsed.raw[:4].hex()),
                        ("value", parsed.entry_count),
                    )
                ),
            )
        )
    else:
        framing_items.append(("entry_count", 1))

    confirmed_routes = ["offline_receiver"]
    persistence_details = "offline storage serialization is not confirmed for this type"
    if parsed.signature_type == VFILEEX_TYPE:
        confirmed_routes.append("offline_storage_serialization_and_cached_load")
        persistence_details = (
            "receiver-end writes deduplicated DATA/LINK chunks to compressed offline "
            "storage; cached-end reads the storage and calls vfs_global_vfileinit"
        )

    data = JSONObject(
        (
            ("type", "vfile" if parsed.signature_type == VFILE_TYPE else "vfileex"),
            ("signature_type", parsed.signature_type),
            ("raw_hex", parsed.raw.hex()),
            ("framing", JSONObject(tuple(framing_items))),
            ("entry_count", parsed.entry_count),
            ("entries", JSONArray(tuple(entries))),
            (
                "tail",
                JSONObject(
                    (
                        (
                            "raw_span",
                            _span(
                                prefix_size + len(parsed.entries_raw),
                                len(parsed.tail_raw),
                            ),
                        ),
                        ("raw_hex", parsed.tail_raw.hex()),
                        ("consumer", "kstoreex"),
                        ("framing_semantics", "unknown"),
                    )
                ),
            ),
            (
                "persistence",
                JSONObject(
                    (
                        ("confirmed_routes", JSONArray(tuple(confirmed_routes))),
                        ("details", persistence_details),
                    )
                ),
            ),
            ("scan_time_matcher", None),
            ("report_consumer", None),
        )
    )
    return RuleSemantics(
        status="observed_only",
        representation="vfile.receiver_framing.v1",
        data=data,
        evidence=(
            "mpengine 1.443.903.0 vfileAndVfileexReceiver @ 0x1802C8A58",
            "mpengine 1.443.903.0 VFILE/VFILEEX offline receiver registrations",
            "mpengine 1.443.903.0 VFILEEX offline and cached receiver-end routines",
        ),
        profile="mpengine-1.443.903.0",
        issues=(
            SemanticIssue(
                "scan_time_matcher_report_unlocated",
                "The scan-time matcher and report consumer for VFILE/VFILEEX have "
                "not been located; receiver and persistence behavior do not establish "
                "scan-time detection semantics.",
            ),
            SemanticIssue(
                "tail_framing_unknown",
                "Bytes after the fixed-stride entry region are retained as raw tail; "
                "their internal framing is unknown.",
                (("length", len(parsed.tail_raw)),),
            ),
        ),
    )


VFILE_SPEC = FamilySpec(
    VFILE_TYPE,
    "VFILE",
    parse_vfile,
    render_vfile,
    semantic_exporter=export_vfile_semantics,
)
VFILEEX_SPEC = FamilySpec(
    VFILEEX_TYPE,
    "VFILEEX",
    parse_vfileex,
    render_vfile,
    semantic_exporter=export_vfile_semantics,
)

__all__ = [
    "VFILEEX_SPEC",
    "VFILEEX_TYPE",
    "VFILE_SPEC",
    "VFILE_TYPE",
    "VFilePayload",
    "export_vfile_semantics",
    "parse_vfile",
    "parse_vfileex",
    "render_vfile",
]
