"""Parser and concise renderer for PESTATIC (0x87) payloads."""

import json
from dataclasses import dataclass
from typing import Final

from ..core import (
    Artifact,
    ArtifactExport,
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
    semantic_json_to_data,
)
from ..recid import RecIdTail, parse_recid_tail

PESTATIC_TYPE: Final = 0x87
BASE_SIZE: Final = 16
CRC_PARAMETERS: Final = {
    "width": 32,
    "polynomial": 0x04C11DB7,
    "reflected_polynomial": 0xEDB88320,
    "refin": True,
    "refout": True,
    "initial_value": 0xFFFFFFFF,
    "final_xor": 0,
}


def _byte_predicate_recipe() -> JSONObject:
    return JSONObject(
        (
            ("callable", "lib.vdm.pestatic_match.evaluate_pestatic"),
            ("context_decoder", "lib.vdm.pestatic_match.decode_pestatic_section"),
            ("context_type", "lib.vdm.pestatic_match.PeStaticSectionContext"),
            ("selection_type", "lib.vdm.pestatic_match.PeStaticSourceSelection"),
            ("result_type", "lib.vdm.pestatic_match.PeStaticMatch"),
            ("stage_type", "lib.vdm.pestatic_match.PeStaticStageResult"),
            ("unsupported_error", "lib.vdm.pestatic_match.UnsupportedPeStaticContext"),
            (
                "input_start",
                "raw normalized pe_vars section caller fields +2150/+4048, base +83798, optional header adjustment; not a standard PE parser",
            ),
            (
                "source_binding",
                "explicit file complete current UFS bytes, or complete available mapped-address window and base",
            ),
            (
                "execution",
                "one cold immutable-source attempt; lazy prefix64/prefix512/content, later stages None after mismatch; no automatic file/mmap OR",
            ),
            (
                "constructor_seed",
                "consumed=0; running_crc=FFFFFFFF, confirmed original check_by_addr initialization",
            ),
            ("file_read_chunk_bytes", 2048),
            (
                "content_bound",
                "record content_size, not whole-file or section size; prefix64/512 not clipped to content_size",
            ),
            (
                "sentinel_match",
                "incomplete prefix reads may match sentinels; read_complete, error and matched remain separate",
            ),
            (
                "unknown_boundary",
                "negative HRESULT, arbitrary short-read scheduling, unknown mapper/source binding, warm/mutable caches, full store/EX/NID/report/final verdict",
            ),
        )
    )


@dataclass(frozen=True, slots=True)
class PeStaticPayload:
    raw: bytes
    crc_first_64: int
    crc_first_512: int
    content_crc: int
    content_size: int
    recid_tail: RecIdTail | None


def parse_pestatic(payload: bytes) -> PeStaticPayload:
    """Parse the fixed PESTATIC wire prefix and optional shared RecID tail."""
    if len(payload) < BASE_SIZE:
        raise ValueError(
            f"truncated PESTATIC header: need {BASE_SIZE} bytes, have {len(payload)}"
        )

    return PeStaticPayload(
        raw=payload,
        crc_first_64=int.from_bytes(payload[0:4], "little"),
        crc_first_512=int.from_bytes(payload[4:8], "little"),
        content_crc=int.from_bytes(payload[8:12], "little"),
        content_size=int.from_bytes(payload[12:16], "little"),
        recid_tail=parse_recid_tail(payload[BASE_SIZE:]),
    )


def _printable_object(data: bytes) -> str | None:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if text and all(char.isprintable() for char in text):
        return text
    return None


def render_pestatic(parsed: PeStaticPayload) -> FormatResult:
    sections = [
        DisplaySection(
            "PE Fingerprints",
            rows=(
                ("crc_first_64", f"0x{parsed.crc_first_64:08X}"),
                ("crc_first_512", f"0x{parsed.crc_first_512:08X}"),
                ("content_crc", f"0x{parsed.content_crc:08X}"),
                ("content_size", f"{parsed.content_size} B"),
            ),
        )
    ]

    if parsed.recid_tail is not None:
        tail = parsed.recid_tail
        identity_rows = [
            ("recid_tail_len", f"{len(tail.raw)} B"),
            ("object_length_limit", f"{tail.length_limit} B"),
            ("effective_object_len", f"{len(tail.object_raw)} B"),
        ]
        if tail.has_object:
            preview = _printable_object(tail.object_raw)
            identity_rows.append(
                ("object_preview", preview if preview is not None else "(nonprintable)")
            )
        else:
            identity_rows.append(("object", "absent"))
        if tail.trailing_raw:
            identity_rows.append(("trailing_len", f"{len(tail.trailing_raw)} B"))
        sections.append(DisplaySection("Record Identity", rows=tuple(identity_rows)))

    return FormatResult(sections=tuple(sections))


def export_pestatic(parsed: PeStaticPayload) -> ArtifactExport:
    """Export the staged fingerprint record as lossless data, not a matcher."""
    tail = parsed.recid_tail
    tail_data: dict[str, object] | None = None
    if tail is not None:
        tail_data = {
            "raw_hex": tail.raw.hex(),
            "raw_offset": BASE_SIZE,
            "declared_length": tail.length_limit,
            "object_raw_hex": tail.object_raw.hex(),
            "object_registered": tail.has_object,
            "trailing_raw_hex": tail.trailing_raw.hex(),
            "bounded_object_truncated": tail.length_limit > len(tail.raw) - 1,
            "object_meaning": "unknown",
        }

    manifest = {
        "format": "vdm.pestatic.record.v2",
        "record": {
            "type": PESTATIC_TYPE,
            "type_hex": f"0x{PESTATIC_TYPE:02X}",
            "name": "PESTATIC",
            "scope": "record_local",
            "threat_association": "not_included",
            "portable_matcher": "not_emitted",
            "matcher_boundary": (
                "Staged fingerprint candidate only; provider-selected input start "
                "and file bytes are runtime-dependent"
            ),
        },
        "payload_length": len(parsed.raw),
        "byte_predicate_recipe": semantic_json_to_data(_byte_predicate_recipe()),
        "payload_raw_hex": parsed.raw.hex(),
        "fingerprints": {
            "crc_first_64": {
                "value": parsed.crc_first_64,
                "raw_hex": parsed.raw[0:4].hex(),
                "input_length": 64,
                "algorithm": "mpengine.CRC_1",
                "parameters": CRC_PARAMETERS,
            },
            "crc_first_512": {
                "value": parsed.crc_first_512,
                "raw_hex": parsed.raw[4:8].hex(),
                "input_length": 512,
                "algorithm": "mpengine.CRC_1",
                "parameters": CRC_PARAMETERS,
            },
            "content_crc": {
                "value": parsed.content_crc,
                "raw_hex": parsed.raw[8:12].hex(),
                "input_length": parsed.content_size,
                "algorithm": "mpengine.CRC_0",
                "parameters": CRC_PARAMETERS,
            },
            "content_size": {
                "value": parsed.content_size,
                "raw_hex": parsed.raw[12:16].hex(),
            },
        },
        "recid_alias": tail_data,
    }
    encoded = json.dumps(manifest, ensure_ascii=True, separators=(",", ":"))
    return ArtifactExport(
        "ready",
        artifacts=(
            Artifact(
                "pestatic.json",
                "pestatic_record_manifest",
                (encoded + "\n").encode("utf-8"),
            ),
        ),
    )


def _raw_field(kind: str, raw: bytes, offset: int) -> JSONObject:
    return JSONObject(
        (
            ("kind", kind),
            ("raw_span", JSONObject((("offset", offset), ("length", len(raw))))),
            ("raw_hex", raw.hex()),
        )
    )


def _crc_stage(
    order: int,
    kind: str,
    algorithm: str,
    expected: int,
    field_offset: int,
    input_length: int,
) -> JSONObject:
    return JSONObject(
        (
            ("order", order),
            ("kind", kind),
            ("source_start", "provider_selected_start"),
            ("input_length", input_length),
            ("algorithm", algorithm),
            ("algorithm_parameters", JSONObject(tuple(CRC_PARAMETERS.items()))),
            ("expected", expected),
            (
                "expected_raw_span",
                JSONObject((("offset", field_offset), ("length", 4))),
            ),
        )
    )


def _tail_data(tail: RecIdTail | None) -> JSONObject | None:
    if tail is None:
        return None
    object_offset = BASE_SIZE + 1
    trailing_offset = object_offset + len(tail.object_raw)
    return JSONObject(
        (
            (
                "raw_span",
                JSONObject((("offset", BASE_SIZE), ("length", len(tail.raw)))),
            ),
            ("raw_hex", tail.raw.hex()),
            ("length_limit", tail.length_limit),
            (
                "length_limit_raw_span",
                JSONObject((("offset", BASE_SIZE), ("length", 1))),
            ),
            ("effective_object_length", len(tail.object_raw)),
            ("has_object", tail.has_object),
            (
                "receiver_effect",
                "createrecidpc_result_is_resolved_to_stored_threat_id",
            ),
            ("object_producer_meaning", None),
            ("object_raw_hex", tail.object_raw.hex()),
            (
                "object_raw_span",
                JSONObject(
                    (("offset", object_offset), ("length", len(tail.object_raw)))
                ),
            ),
            ("trailing_raw_hex", tail.trailing_raw.hex()),
            (
                "trailing_raw_span",
                JSONObject(
                    (("offset", trailing_offset), ("length", len(tail.trailing_raw)))
                ),
            ),
        )
    )


def export_pestatic_semantics(parsed: PeStaticPayload) -> RuleSemantics:
    """Export the verified staged fingerprint candidate, not a final verdict."""
    tail_raw = parsed.recid_tail.raw if parsed.recid_tail is not None else b""
    framing = JSONArray(
        (
            _raw_field("crc_first_64", parsed.raw[0:4], 0),
            _raw_field("crc_first_512", parsed.raw[4:8], 4),
            _raw_field("content_crc", parsed.raw[8:12], 8),
            _raw_field("content_size", parsed.raw[12:16], 12),
            _raw_field("recid_alias_tail", tail_raw, BASE_SIZE),
        )
    )
    stages = JSONArray(
        (
            _crc_stage(
                0,
                "prefix_64_candidate",
                "mpengine.CRC_1",
                parsed.crc_first_64,
                0,
                64,
            ),
            _crc_stage(
                1,
                "prefix_512_candidate",
                "mpengine.CRC_1",
                parsed.crc_first_512,
                4,
                512,
            ),
            _crc_stage(
                2,
                "content_candidate",
                "mpengine.CRC_0",
                parsed.content_crc,
                8,
                parsed.content_size,
            ),
        )
    )
    issues: list[SemanticIssue] = []
    status = "confirmed_subset"
    if parsed.recid_tail is not None and parsed.recid_tail.has_object:
        status = "unsupported"
        issues.append(
            SemanticIssue(
                "recid_object_meaning_unknown",
                "The receiver uses the bounded object to construct RecID metadata, "
                "but its producer-side meaning is unknown.",
                (("length", len(parsed.recid_tail.object_raw)),),
            )
        )
    if (
        parsed.recid_tail is not None
        and parsed.recid_tail.length_limit > len(parsed.recid_tail.raw) - 1
    ):
        status = "unsupported"
        issues.append(
            SemanticIssue(
                "recid_object_truncated",
                "The bounded RecID object is shorter than its declared length.",
                (
                    ("declared_length", parsed.recid_tail.length_limit),
                    ("available_length", len(parsed.recid_tail.raw) - 1),
                ),
            )
        )
    if parsed.recid_tail is not None and parsed.recid_tail.trailing_raw:
        status = "unsupported"
        issues.append(
            SemanticIssue(
                "recid_trailing_bytes_uninterpreted",
                "Bytes after the bounded RecID alias are retained without semantics.",
                (("length", len(parsed.recid_tail.trailing_raw)),),
            )
        )

    data = JSONObject(
        (
            ("raw_hex", parsed.raw.hex()),
            ("framing", framing),
            ("type", "staged_pe_fingerprint_candidate"),
            ("source_start", "provider_selected_start"),
            ("stages", stages),
            ("byte_predicate_recipe", _byte_predicate_recipe()),
            ("content_size", parsed.content_size),
            ("recid_tail", _tail_data(parsed.recid_tail)),
            ("final_verdict", "not_represented"),
        )
    )
    return RuleSemantics(
        status=status,
        representation="pestatic.staged_fingerprint.ir.v2",
        data=data,
        evidence=(
            (
                "mpengine 1.443.903.0 PESTATIC RecordPush, Lookup, and "
                "PeStaticHashProvider::CompareValues data flow"
            ),
            (
                "mpengine 1.443.903.0 CRC_0/CRC_1 and table @ 0x180DBC0D0: "
                "reflected polynomial 0xEDB88320, init 0xFFFFFFFF, raw return"
            ),
        ),
        profile="mpengine-1.443.903.0",
        issues=tuple(issues),
        claims=(
            SemanticClaim(
                id="pestatic_bound_byte_predicate",
                scope="detection_predicate",
                statement="For the normalized section caller, raw runtime-context fields derive mapped/file starts; one explicitly bound cold immutable source supports lazy prefix64/prefix512/content CRC comparisons, including native incomplete-read sentinel matches. The helper returns only a record-local fingerprint candidate.",
                coverage="subset",
                evidence_refs=("pestatic_provider_native_projection",),
                unknowns=(
                    SemanticUnknown(
                        "final_verdict",
                        "Complete VMM/OS initialization, negative HRESULTs, arbitrary short-read scheduling, warm/mutable caches, multi-record/EX fallback and report/verdict policies remain outside the projection.",
                    ),
                ),
            ),
            SemanticClaim(
                id="pestatic_wire_layout",
                scope="wire_layout",
                statement=(
                    "PESTATIC contains four little-endian DWORD fields followed "
                    "by an optional bounded RecID tail."
                ),
                coverage="complete",
                evidence_refs=("pestatic_receiver",),
            ),
            SemanticClaim(
                id="pestatic_loader_dispatch",
                scope="loader_dispatch",
                statement="The analyzed store registration binds type 0x87 to PESTATIC.",
                coverage="subset",
                evidence_refs=("pestatic_dispatch",),
                unknowns=(
                    SemanticUnknown(
                        "loader_dispatch",
                        "Other database profiles and engine versions are not covered.",
                    ),
                ),
            ),
            SemanticClaim(
                id="pestatic_receiver_projection",
                scope="receiver_transform",
                statement=(
                    "RecordPush copies the four DWORDs into a 20-byte runtime entry; "
                    "a present tail is converted to RecID metadata and its derived "
                    "threat ID is stored in the fifth DWORD."
                ),
                coverage="subset",
                evidence_refs=("pestatic_receiver",),
                unknowns=(
                    SemanticUnknown(
                        "receiver_transform",
                        "The producer meaning of the optional tail object is unknown.",
                    ),
                ),
            ),
            SemanticClaim(
                id="pestatic_crc_consumer",
                scope="runtime_consumer",
                statement=(
                    "The analyzed lookup supports CRC_1 comparisons over 64 and "
                    "512 bytes and a CRC_0 comparison over the record content length."
                ),
                coverage="subset",
                evidence_refs=("pestatic_consumer",),
                unknowns=(
                    SemanticUnknown(
                        "runtime_consumer",
                        "Runtime source-start selection and all caller contexts are not closed.",
                    ),
                ),
            ),
            SemanticClaim(
                id="pestatic_local_predicate",
                scope="detection_predicate",
                statement=(
                    "At the local lookup boundary, a candidate is accepted only "
                    "after the analyzed mode-0, mode-1, and mode-2 CRC comparisons succeed."
                ),
                coverage="subset",
                evidence_refs=("pestatic_consumer",),
                unknowns=(
                    SemanticUnknown(
                        "detection_predicate",
                        "Bloom selection, caller context, and outer scan gates are not a portable predicate.",
                    ),
                ),
            ),
            SemanticClaim(
                id="pestatic_report_branch",
                scope="report_mapping",
                statement=(
                    "The analyzed matched-entry branch can set detection data for "
                    "ordinary threats or aggregate attribute entries."
                ),
                coverage="subset",
                evidence_refs=("pestatic_report",),
                unknowns=(
                    SemanticUnknown(
                        "report_mapping",
                        "ShouldContinueScanning and outer reply arbitration remain unresolved.",
                    ),
                ),
            ),
            SemanticClaim(
                id="pestatic_final_verdict",
                scope="final_verdict",
                statement="A PESTATIC candidate does not by itself establish the final product verdict.",
                coverage="unknown",
                unknowns=(
                    SemanticUnknown(
                        "final_verdict",
                        "The service/UI/remediation verdict path has not been followed to completion.",
                    ),
                ),
            ),
        ),
        claim_evidence=(
            SemanticEvidence(
                id="pestatic_provider_native_projection",
                axis="consumer",
                kind="engine_equivalent_test",
                source_ref="Pinned mpengine 1.443.903.0 original caller/constructor/ordinary Lookup/equal_range/provider/CRCOnFile/CRC and MakeSigSha; ReadAt/mmap byte services and explicit namespace/NID/report/EX services, no digest seam.",
                locator="tests/local_pestatic_provider_native.py SHA256 e488833a20ce2ae4679b9a126ce2b031d6ef4bbfe49fa464f2e3c374e0853508 (41 cases); current bridge tests/local_pestatic_provider_differential.py SHA256 1f21f6360465780f0ca8f86186226b4d9ee9fe7348fae6fc151d2afafe1e7e33 (108 cases, including 2 additional original section-caller controls); docs/mpengine.dll/1.443.903.0/pestatic_provider_native_private.md",
                supports=("pestatic_bound_byte_predicate",),
            ),
            SemanticEvidence(
                id="pestatic_dispatch",
                axis="dispatch",
                kind="engine_static",
                source_ref="mpengine 1.443.903.0",
                locator="PESTATIC store registration and RecordPush binding",
                supports=("pestatic_loader_dispatch",),
            ),
            SemanticEvidence(
                id="pestatic_receiver",
                axis="receiver",
                kind="engine_static",
                source_ref="mpengine 1.443.903.0",
                locator="PESTATIC RecordPush @ 0x180435A44",
                supports=("pestatic_wire_layout", "pestatic_receiver_projection"),
            ),
            SemanticEvidence(
                id="pestatic_consumer",
                axis="consumer",
                kind="engine_static",
                source_ref="mpengine 1.443.903.0",
                locator=(
                    "Store::Lookup @ 0x180137728; Subtype::Lookup @ 0x180136E38; "
                    "PeStaticHashProvider::CompareValues @ 0x1803B6CCC"
                ),
                supports=("pestatic_crc_consumer", "pestatic_local_predicate"),
            ),
            SemanticEvidence(
                id="pestatic_report",
                axis="report",
                kind="engine_static",
                source_ref="mpengine 1.443.903.0",
                locator="PESTATIC Subtype::Lookup @ 0x180136E38 matched-entry branches",
                supports=("pestatic_report_branch",),
            ),
        ),
    )


SPEC = FamilySpec(
    PESTATIC_TYPE,
    "PESTATIC",
    parse_pestatic,
    render_pestatic,
    exporter=export_pestatic,
    semantic_exporter=export_pestatic_semantics,
)
