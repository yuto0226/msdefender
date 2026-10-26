"""Lossless receiver-framing view for VFILE (0x83) and VFILEEX (0xB2)."""

import json
from dataclasses import dataclass
from typing import Final

from ..core import (
    Artifact,
    ArtifactExport,
    ArtifactWarning,
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

VFILE_TYPE: Final = 0x83
VFILEEX_TYPE: Final = 0xB2
_ENTRY_STRIDE: Final = 592
_ENTRY_PREFIX_SIZE: Final = 44
_ENTRY_PATH_FIELD_SIZE: Final = 0x208
_RUNTIME_PATH_CONTENT_SIZE: Final = _ENTRY_PATH_FIELD_SIZE - 2
_MAX_ENTRY_COUNT: Final = 0x6EB3E4
_PATH_PREVIEW_CHARS: Final = 80
_RAW_PREVIEW_BYTES: Final = 24
_TAIL_PREVIEW_BYTES: Final = 16
_INITIAL_DATA_ARTIFACT: Final = "initial_data.bin"
_INPUT_METADATA_ARTIFACT: Final = "virtual_file_input.json"


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
    def runtime_path_raw(self) -> bytes | None:
        """Return content before the receiver's forced NUL, preserving wire fields.

        ``path_raw`` and ``path_terminator`` describe the wire field. The receiver
        copies 520 bytes to runtime +8, then overwrites runtime +526..527 with NUL.
        Consequently only the first 518 copied bytes can contribute name content.
        """
        if self.path_raw is None:
            return None
        return self.path_raw[:_RUNTIME_PATH_CONTENT_SIZE]

    @property
    def path(self) -> str | None:
        """Decode effective runtime name content, including any lone surrogate."""
        raw = self.runtime_path_raw
        return None if raw is None else raw.decode("utf-16le", errors="surrogatepass")


@dataclass(frozen=True, slots=True)
class _EntryNameProjection:
    wire_field: bytes
    wire_content: bytes
    wire_terminator_offset: int | None
    runtime_content: bytes
    portable_text: str | None


def _project_entry_name(entry: bytes) -> _EntryNameProjection:
    field = entry[_ENTRY_PREFIX_SIZE : _ENTRY_PREFIX_SIZE + _ENTRY_PATH_FIELD_SIZE]
    terminator_at = next(
        (
            offset
            for offset in range(0, _ENTRY_PATH_FIELD_SIZE, 2)
            if field[offset : offset + 2] == b"\0\0"
        ),
        None,
    )
    wire_content = field if terminator_at is None else field[:terminator_at]
    runtime_content = wire_content[:_RUNTIME_PATH_CONTENT_SIZE]
    try:
        portable_text = runtime_content.decode("utf-16le")
    except UnicodeDecodeError:
        portable_text = None
    return _EntryNameProjection(
        field, wire_content, terminator_at, runtime_content, portable_text
    )


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
        name = _project_entry_name(first_entry)
        path_terminated = name.wire_terminator_offset is not None
        path_raw = name.wire_content
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
        else "(runtime path unavailable)"
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
                ("runtime_path_raw_size", f"{len(parsed.runtime_path_raw)} B"),
                (
                    "wire_path_terminated_within_520B",
                    str(parsed.path_terminated),
                ),
            )
        )
        section_rows.extend(
            (
                ("path_candidate", path_preview),
                ("path_raw_preview", _hex_preview(parsed.path_raw, _RAW_PREVIEW_BYTES)),
                (
                    "wire_path_terminator_candidate",
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
    supplied_length = len(parsed.tail_raw) & 0xFFFFFFFF
    source_is_u32_vdm_payload = len(parsed.raw) <= 0xFFFFFFFF
    entries: list[SemanticJSONValue] = []
    text_issues: list[SemanticIssue] = []
    for index in range(parsed.entry_count):
        entry_offset = prefix_size + index * _ENTRY_STRIDE
        entry = parsed.entries_raw[index * _ENTRY_STRIDE : (index + 1) * _ENTRY_STRIDE]
        name = _project_entry_name(entry)
        path_field = name.wire_field
        terminator_at = name.wire_terminator_offset
        path_candidate = name.wire_content
        runtime_content = name.runtime_content
        runtime_text = name.portable_text
        if runtime_text is None:
            text_issues.append(
                SemanticIssue(
                    "runtime_path_utf16_not_well_formed",
                    "The receiver's effective name contains unpaired UTF-16 code "
                    "units. Raw runtime bytes are retained, but no Unicode text "
                    "projection is emitted; this does not mean engine rejection.",
                    (("entry_index", index),),
                )
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
                ("wire_nul_terminated_within_520_bytes", terminator_at is not None),
                ("runtime_content_raw_hex", runtime_content.hex()),
                ("runtime_utf16_well_formed", runtime_text is not None),
                (
                    "runtime_content_wire_span",
                    _span(entry_offset + _ENTRY_PREFIX_SIZE, len(runtime_content)),
                ),
                (
                    "text_candidate",
                    runtime_text,
                ),
                (
                    "runtime_forced_nul_offset_in_copied_field",
                    _RUNTIME_PATH_CONTENT_SIZE,
                ),
                (
                    "runtime_use",
                    (
                        "candidate path input for retained entries reaching "
                        "VfsFileData::addFile"
                    ),
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
                    ("initial_data_reference_if_newly_retained", "tail"),
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
            "receiver-end writes retained, deduplicated DATA/LINK chunks to "
            "compressed offline storage; cached-end reads retained entries and "
            "calls vfs_global_vfileinit"
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
                "portable_subset",
                JSONObject(
                    (
                        ("name_field_offset_within_entry", _ENTRY_PREFIX_SIZE),
                        ("name_field_size", _ENTRY_PATH_FIELD_SIZE),
                        ("runtime_name_content_limit", _RUNTIME_PATH_CONTENT_SIZE),
                        ("encoding", "UTF-16LE"),
                        (
                            "runtime_terminator",
                            (
                                "receiver overwrites the final copied UTF-16 code unit "
                                "at field offset 518 with NUL"
                            ),
                        ),
                        (
                            "consumer",
                            (
                                "retained entries reaching VfsFileData::addFile build "
                                "the VirtualFS tree"
                            ),
                        ),
                        (
                            "content_source",
                            (
                                "initial shared virtual-file data: supplied tail bytes "
                                "after successful fresh receiver storage"
                            ),
                        ),
                    )
                ),
            ),
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
                        ("role", "initial_shared_virtual_file_data"),
                        ("source_is_u32_vdm_payload", source_is_u32_vdm_payload),
                        ("storage_flags", 4),
                        ("receiver_supplied_length", supplied_length),
                        (
                            "receiver_length_operation",
                            "u32(data_size - entry_region_size)",
                        ),
                        ("initial_content_length", supplied_length),
                        (
                            "full_tail_byte_equivalence",
                            True if source_is_u32_vdm_payload else None,
                        ),
                        (
                            "profile_requirement",
                            (
                                "u32-bounded source VDM payload and successful fresh offline "
                                "load with non-null kstoreex(flags=4) result"
                            ),
                        ),
                        ("newly_retained_entries_share_pointer_and_length", True),
                        ("runtime_data_pointer_offset", 0x210),
                        ("runtime_data_length_offset", 0x218),
                        ("later_content_immutability", None),
                        ("os_file_equivalence", None),
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
    claims = [
        SemanticClaim(
            id="vfile_wire_layout",
            scope="wire_layout",
            statement=(
                "The receiver reads "
                + (
                    "a u32 entry count followed by "
                    if parsed.signature_type == VFILEEX_TYPE
                    else ""
                )
                + f"{_ENTRY_STRIDE}-byte entries and requires a non-empty tail."
            ),
            coverage="subset",
            evidence_refs=("vfile_receiver",),
            unknowns=(
                SemanticUnknown(
                    "wire_layout",
                    "The producer interpretation of the ignored 44-byte entry prefix "
                    "and 28-byte entry suffix remains unresolved.",
                ),
            ),
        ),
        SemanticClaim(
            id="vfile_dispatch_path",
            scope="loader_dispatch",
            statement=(
                f"The offline loader registers type 0x{parsed.signature_type:02X} "
                "to the shared VFILE/VFILEEX receiver route."
            ),
            coverage="subset",
            evidence_refs=("vfile_dispatch",),
            unknowns=(
                SemanticUnknown(
                    "loader_dispatch",
                    "Outer database selection and product enablement gates are not modeled.",
                ),
            ),
        ),
        SemanticClaim(
            id="vfile_receiver_projection",
            scope="receiver_transform",
            statement=(
                "The receiver copies each retained entry's bounded 520-byte UTF-16LE "
                "name field, overwrites its last code unit with NUL (at most 518 "
                "content bytes). For a u32-bounded source VDM payload and "
                "successful fresh offline load, kstoreex "
                "flags 4 preserves supplied tail bytes and unsigned 32-bit length "
                "without decoding, headers or added NUL. All newly retained entries "
                "share that stored pointer and length as initial virtual-file data."
            ),
            coverage="subset",
            evidence_refs=(
                "vfile_receiver",
                "vfile_initial_data_static",
                "vfile_initial_data_native",
            ),
            unknowns=(
                SemanticUnknown(
                    "receiver_transform",
                    "Entry retention, prior same-name entries, cross-record storage "
                    "sharing, later writes and cached/global load lifecycle are not "
                    "projected. Initial data is not an OS-file identity or "
                    "maliciousness assertion.",
                ),
            ),
        ),
        SemanticClaim(
            id="vfile_runtime_vfs_insertion",
            scope="runtime_consumer",
            statement=(
                "For entries retained by the receiver or VFILEEX cache route, "
                "VfsFileData::addFile inserts the normalized path and ByteStream into "
                "the VirtualFS tree."
            ),
            coverage="subset",
            evidence_refs=("vfile_consumer",),
            unknowns=(
                SemanticUnknown(
                    "runtime_consumer",
                    "VirtualFS lookup behavior and consumers of the inserted files are "
                    "not traced.",
                ),
            ),
        ),
        SemanticClaim(
            id="vfile_detection_predicate",
            scope="detection_predicate",
            statement=(
                "No scan-time detection predicate is established by this VFS "
                "construction path."
            ),
            coverage="unknown",
            unknowns=(
                SemanticUnknown(
                    "detection_predicate",
                    "The matcher or emulation logic that queries the constructed "
                    "VirtualFS is unlocated.",
                ),
            ),
        ),
        SemanticClaim(
            id="vfile_report_mapping",
            scope="report_mapping",
            statement=(
                "VFILE/VFILEEX data has no confirmed direct mapping to a threat report."
            ),
            coverage="unknown",
            unknowns=(
                SemanticUnknown(
                    "report_mapping",
                    "No consumer was followed from a VirtualFS lookup to report policy.",
                ),
            ),
        ),
        SemanticClaim(
            id="vfile_final_verdict",
            scope="final_verdict",
            statement="VirtualFS insertion is not a confirmed final scan verdict.",
            coverage="unknown",
            unknowns=(
                SemanticUnknown(
                    "final_verdict",
                    "Outer scan arbitration and final report policy remain unresolved.",
                ),
            ),
        ),
    ]
    claim_evidence = [
        SemanticEvidence(
            id="vfile_dispatch",
            axis="dispatch",
            kind="engine_static",
            source_ref="mpengine 1.443.903.0",
            locator="VFILE/VFILEEX offline receiver registrations",
            supports=("vfile_dispatch_path",),
        ),
        SemanticEvidence(
            id="vfile_receiver",
            axis="receiver",
            kind="engine_static",
            source_ref="mpengine 1.443.903.0",
            locator=(
                "vfileAndVfileexReceiver @ 0x1802C8A58; memmove 520 bytes "
                "to runtime +8 at 0x1802C8B2C; forced WORD NUL at runtime "
                "+526 at 0x1802C8B31"
            ),
            supports=("vfile_wire_layout", "vfile_receiver_projection"),
        ),
        SemanticEvidence(
            id="vfile_initial_data_static",
            axis="receiver",
            kind="engine_static",
            source_ref="mpengine 1.443.903.0",
            locator=(
                "receiver 0x1802C8AA8/0x1802C8AB3 truncates supplied size to u32; "
                "kstoreex 0x1803AC26C -> kpushobjectex 0x1800FC300 -> "
                "kstore_copy_buff 0x1800FC594: memmove calls 0x1800FC6AE/"
                "0x1800FC77E, flags-4 alignment 0x1800FC764; "
                "kpopobjectex 0x1800F9520 returns block base + handle offset"
            ),
            supports=("vfile_receiver_projection",),
        ),
        SemanticEvidence(
            id="vfile_initial_data_native",
            axis="receiver",
            kind="engine_equivalent_test",
            source_ref=(
                "Pinned DLL SHA256 "
                "928e171c60a44bb326776d2a356412ae98d78469bdf8c94ebfbfa09f8ec4b4b3; "
                "local_kstoreex_vfile_probe executes original store/push/copy/pop, "
                "XXH, memmove and memcmp with only a VirtualAlloc OS seam and "
                "artificial initialized store; sizes 1/3/4096/4097/65537/263936 "
                "preserve exact bytes and lengths, including aligned dedup, "
                "unaligned copy, no-hash and new-block allocation paths"
            ),
            locator=(
                "kstoreex flags=4 success paths; no allocation-failure, hash-table "
                "growth, old-block search or full VFS lifecycle execution"
            ),
            supports=("vfile_receiver_projection",),
        ),
        SemanticEvidence(
            id="vfile_consumer",
            axis="consumer",
            kind="engine_static",
            source_ref="mpengine 1.443.903.0",
            locator=(
                "populateVfsWithVfiles @ 0x18019FF7C; "
                "VfsFileData::addFile @ 0x18019E640"
            ),
            supports=("vfile_runtime_vfs_insertion",),
        ),
    ]
    if parsed.signature_type == VFILEEX_TYPE:
        claims.append(
            SemanticClaim(
                id="vfileex_persistence_route",
                scope="receiver_transform",
                statement=(
                    "The VFILEEX receiver-end serializes retained, deduplicated "
                    "DATA/LINK entries; cached-end reloads retained entries through "
                    "vfs_global_vfileinit before addFile."
                ),
                coverage="subset",
                evidence_refs=("vfileex_persistence",),
                unknowns=(
                    SemanticUnknown(
                        "receiver_transform",
                        "The retention/deduplication predicate and compressed storage "
                        "encoding are not projected.",
                    ),
                ),
            )
        )
        claim_evidence.append(
            SemanticEvidence(
                id="vfileex_persistence",
                axis="receiver",
                kind="engine_static",
                source_ref="mpengine 1.443.903.0",
                locator="VFILEEX offline and cached receiver-end routines",
                supports=("vfileex_persistence_route",),
            )
        )
    return RuleSemantics(
        status="confirmed_subset",
        representation="vfile.receiver_vfs_entry.ir.v5",
        data=data,
        evidence=(
            "mpengine 1.443.903.0 vfileAndVfileexReceiver @ 0x1802C8A58",
            "mpengine 1.443.903.0 VFILE/VFILEEX offline receiver registrations",
            "mpengine 1.443.903.0 VFILEEX offline and cached receiver-end routines",
            "mpengine 1.443.903.0 populateVfsWithVfiles @ 0x18019FF7C",
            "mpengine 1.443.903.0 VfsFileData::addFile @ 0x18019E640",
        ),
        profile="mpengine-1.443.903.0",
        issues=(
            *text_issues,
            SemanticIssue(
                "scan_time_matcher_report_unlocated",
                "The runtime VFS file-construction consumer is located, but the "
                "specific scan-time matcher and report consumer for VFILE/VFILEEX "
                "remain unknown; this data flow does not establish scan-time "
                "detection semantics.",
            ),
            SemanticIssue(
                "initial_virtual_file_data_scope",
                "The supplied tail is initial shared virtual-file data on successful "
                "fresh receiver loads. Later writes, cached/global load lifecycle "
                "and OS-file identity are outside the byte-preservation proof.",
                (("length", len(parsed.tail_raw)),),
            ),
        ),
        claims=tuple(claims),
        claim_evidence=tuple(claim_evidence),
    )


def export_vfile_artifacts(parsed: VFilePayload) -> ArtifactExport:
    """Export initial shared input and conditional names, never host-path files."""
    if len(parsed.raw) > 0xFFFFFFFF:
        return ArtifactExport(
            "unsupported",
            reason="VFILE initial-data export requires a u32-bounded source VDM payload",
        )

    prefix_size = 4 if parsed.signature_type == VFILEEX_TYPE else 0
    candidates: list[dict[str, object]] = []
    warnings = [
        ArtifactWarning(
            "virtual_file_input_scope",
            "Initial emulation input only. Name candidates are conditional on "
            "new retention; global name priority, cross-record storage identity, later writes, "
            "OS-file equivalence and detection policy are not modeled.",
        )
    ]
    for index in range(parsed.entry_count):
        entry = parsed.entries_raw[index * _ENTRY_STRIDE : (index + 1) * _ENTRY_STRIDE]
        name = _project_entry_name(entry)
        candidates.append(
            {
                "entry_index": index,
                "entry_raw_offset": prefix_size + index * _ENTRY_STRIDE,
                "runtime_name_utf16le_hex": name.runtime_content.hex(),
                "portable_text": name.portable_text,
                "runtime_utf16_well_formed": name.portable_text is not None,
                "data_artifact_if_newly_retained": _INITIAL_DATA_ARTIFACT,
            }
        )
        if name.portable_text is None:
            warnings.append(
                ArtifactWarning(
                    "runtime_path_utf16_not_well_formed",
                    "Raw runtime name units are retained in metadata, but no "
                    "Unicode text projection is emitted; this is not engine rejection.",
                    (("entry_index", index),),
                )
            )
    if not candidates:
        warnings.append(
            ArtifactWarning(
                "virtual_file_data_unassigned",
                "The record has no name candidates; exported bytes are unassigned "
                "data, not evidence that a runtime file was retained.",
            )
        )

    metadata = {
        "schema": "vfile.initial_shared_input.v1",
        "role": "emulation_input_not_detector",
        "source_type": parsed.signature_type,
        "source_type_name": "VFILEEX"
        if parsed.signature_type == VFILEEX_TYPE
        else "VFILE",
        "engine_profile": "mpengine-1.443.903.0",
        "source_payload_length": len(parsed.raw),
        "source_entry_count": parsed.entry_count,
        "profile_requirement": (
            "u32-bounded source VDM payload and successful fresh offline "
            "load with non-null kstoreex(flags=4) result"
        ),
        "initial_data": {
            "artifact": _INITIAL_DATA_ARTIFACT,
            "length": len(parsed.tail_raw),
            "record_relative_offset": prefix_size + len(parsed.entries_raw),
            "role": "initial_shared_virtual_file_data",
            "sharing": "one blob for all conditionally newly retained candidates",
        },
        "data_assignment": (
            "conditional_newly_retained_candidates" if candidates else "unassigned_data"
        ),
        "wire_name_candidates": candidates,
        "unknowns": [
            "global name retention and prior-entry priority",
            "cross-record storage identity and deduplication",
            "later writes, cached/global load lifecycle and OS-file equivalence",
            "scan-time matcher, report policy and final verdict",
        ],
    }
    encoded = (json.dumps(metadata, ensure_ascii=False, indent=2) + "\n").encode(
        "utf-8"
    )
    return ArtifactExport(
        "ready",
        artifacts=(
            Artifact(
                _INITIAL_DATA_ARTIFACT, "emulation_input_not_detector", parsed.tail_raw
            ),
            Artifact(_INPUT_METADATA_ARTIFACT, "virtual_file_input_manifest", encoded),
        ),
        warnings=tuple(warnings),
    )


VFILE_SPEC = FamilySpec(
    VFILE_TYPE,
    "VFILE",
    parse_vfile,
    render_vfile,
    exporter=export_vfile_artifacts,
    semantic_exporter=export_vfile_semantics,
)
VFILEEX_SPEC = FamilySpec(
    VFILEEX_TYPE,
    "VFILEEX",
    parse_vfileex,
    render_vfile,
    exporter=export_vfile_artifacts,
    semantic_exporter=export_vfile_semantics,
)

__all__ = [
    "VFILEEX_SPEC",
    "VFILEEX_TYPE",
    "VFILE_SPEC",
    "VFILE_TYPE",
    "VFilePayload",
    "export_vfile_artifacts",
    "export_vfile_semantics",
    "parse_vfile",
    "parse_vfileex",
    "render_vfile",
]
