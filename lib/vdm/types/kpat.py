"""Lossless typed models for kernel pattern records 0xBB and 0xBC."""

from dataclasses import dataclass

from ..core import (
    DisplaySection,
    FamilySpec,
    FormatResult,
    JSONObject,
    RuleSemantics,
    SemanticClaim,
    SemanticEvidence,
    SemanticIssue,
    SemanticUnknown,
)

_PREVIEW = 64
_TEXT_PREVIEW = 512


@dataclass(frozen=True, slots=True)
class KpatPayload:
    raw: bytes
    prefix_size: int
    key: bytes
    pattern_raw: bytes
    name_raw: bytes | None
    suffix: bytes

    @property
    def name(self) -> bytes | None:
        """Name bytes only when the runtime would retain a nonempty C name."""
        if self.name_raw is None or not self.name_raw or self.name_raw[0] == 0:
            return None
        return self.name_raw.split(b"\0", 1)[0]


def parse_kpat(payload: bytes) -> KpatPayload:
    """Parse KPAT prefix framing while keeping opaque pattern and suffix bytes."""
    if not payload:
        raise ValueError("truncated KPAT prefix size")
    prefix_size = payload[0]
    if prefix_size < 8:
        raise ValueError("KPAT prefix size must be at least 8")
    prefix_end = prefix_size + 1
    if len(payload) < prefix_end:
        raise ValueError("truncated KPAT key/pattern prefix")
    key = payload[1:9]
    pattern_raw = payload[9:prefix_end]
    cursor = prefix_end
    name_raw = None
    if cursor < len(payload):
        name_len = payload[cursor]
        cursor += 1
        if cursor + name_len > len(payload):
            raise ValueError("truncated KPAT name")
        name_raw = payload[cursor : cursor + name_len]
        cursor += name_len
    return KpatPayload(
        payload, prefix_size, key, pattern_raw, name_raw, payload[cursor:]
    )


def parse_kpatex(payload: bytes) -> KpatPayload:
    """Parse KPATEX framing without assigning unverified matcher semantics."""
    return parse_kpat(payload)


def _preview(raw: bytes) -> str:
    return raw[:_PREVIEW].hex(" ") + (" ..." if len(raw) > _PREVIEW else "")


def _render(parsed: KpatPayload, *, extended: bool) -> FormatResult:
    rows = [
        ("prefix_size", str(parsed.prefix_size)),
        ("key", parsed.key.hex(" ")),
        ("pattern_length", str(len(parsed.pattern_raw))),
        ("pattern_preview", _preview(parsed.pattern_raw)),
        (
            "name_length",
            "absent" if parsed.name_raw is None else str(len(parsed.name_raw)),
        ),
        (
            "name_raw",
            "absent" if parsed.name_raw is None else _preview(parsed.name_raw),
        ),
        (
            "name_preview",
            "anonymous" if parsed.name is None else repr(parsed.name[:_TEXT_PREVIEW]),
        ),
        ("suffix_length", str(len(parsed.suffix))),
        ("suffix_preview", _preview(parsed.suffix)),
    ]
    if extended:
        rows.append(
            (
                "pattern_semantics",
                "BMMatchEx2 path after successful BM finalization",
            )
        )
    return FormatResult(
        sections=(DisplaySection("KPATEX" if extended else "KPAT", rows=tuple(rows)),)
    )


def render_kpat(parsed: KpatPayload) -> FormatResult:
    return _render(parsed, extended=False)


def render_kpatex(parsed: KpatPayload) -> FormatResult:
    return _render(parsed, extended=True)


def _export_semantics(
    parsed: KpatPayload, *, record_type: str, extended: bool
) -> RuleSemantics:
    """Export bounded load and candidate semantics without claiming acceptance."""
    claim_prefix = record_type.lower()
    name_length_offset = parsed.prefix_size + 1
    name_offset = name_length_offset + (parsed.name_raw is not None)
    suffix_offset = name_offset + (len(parsed.name_raw) if parsed.name_raw else 0)
    issues = [
        SemanticIssue(
            "load_acceptance_not_observed",
            "Offline parsing does not establish that ReceiveNewTemplate and the "
            "tsig finalizer accepted this individual record.",
        ),
        SemanticIssue(
            "final_verdict_unknown",
            "The registered template projects this record into the matcher row, "
            "but complete candidate validation and final report policy remain unknown.",
        ),
    ]
    status = "confirmed_subset"
    if extended:
        matcher = JSONObject(
            (
                ("kind", "bm_match_ex2"),
                ("registration_group", "second tsig row group"),
                ("flags_source", "BMGetPatternFlags"),
                ("match_function", "BMMatchEx2"),
                ("match_map", "BM_MAP_ALL"),
                ("loaded_row_matcher", "BM token matcher with row flags"),
                ("wire_payload_projection", "confirmed"),
                (
                    "pattern_input_equivalence",
                    "conditional_on_receiver_and_bm_finalizer_success",
                ),
                ("load_gate", "BMGetPatternFlags must succeed"),
            )
        )
        matcher_evidence = (
            "mpengine 1.443.903.0 pattsearch_init registers type 0x4BC in the second tsig row group",
            "mpengine 1.443.903.0 tsig_push_end calls BMGetPatternFlags for the second group and stores row flags",
            "mpengine 1.443.903.0 kpatsearchex calls BMMatchEx2 with BM_MAP_ALL and the loaded row flags",
        )
    else:
        matcher = JSONObject(
            (
                ("kind", "wildcard_raw_byte_compare"),
                ("registration_group", "first tsig row group"),
                ("comparison", "bytewise pattern/subject comparison"),
                ("wildcard_byte", 0x90),
                ("wildcard_behavior", "matches any one subject byte"),
                ("wire_payload_projection", "confirmed"),
                (
                    "pattern_input_equivalence",
                    "conditional_on_receiver_and_finalizer_success",
                ),
                ("load_gate", "tsig finalizer and trie build must succeed"),
            )
        )
        matcher_evidence = (
            "mpengine 1.443.903.0 pattsearch_init registers type 0x4BB in the first tsig row group",
            "mpengine 1.443.903.0 tsig_push_end adds the first-group pattern object to FilteredTrie without BMGetPatternFlags",
            "mpengine 1.443.903.0 kpatsearchex byte-compares first-group candidates; pattern byte 0x90 matches any subject byte",
        )
    data = JSONObject(
        (
            ("record_type", record_type),
            ("raw_hex", parsed.raw.hex()),
            ("prefix_size", parsed.prefix_size),
            ("prefix_size_raw_hex", parsed.raw[:1].hex()),
            ("key_offset", 1),
            ("key_raw_hex", parsed.key.hex()),
            ("pattern_offset", 9),
            ("pattern_length_observed", len(parsed.pattern_raw)),
            ("pattern_raw_hex", parsed.pattern_raw.hex()),
            ("name_length_offset", name_length_offset),
            (
                "name_length_raw_hex",
                parsed.raw[name_length_offset : name_length_offset + 1].hex()
                if parsed.name_raw is not None
                else "",
            ),
            ("name_offset", name_offset),
            ("name_raw_hex", (parsed.name_raw or b"").hex()),
            ("suffix_offset", suffix_offset),
            ("suffix_raw_hex", parsed.suffix.hex()),
            ("runtime_matcher", matcher),
            ("runtime_matcher_scope", "successfully_loaded_candidate_subset"),
            (
                "runtime_matcher_association",
                "conditional_on_receiver_and_finalizer_success",
            ),
            ("wire_payload_projection", "confirmed"),
        )
    )
    wire_claim_id = f"{claim_prefix}_wire_projection"
    dispatch_claim_id = f"{claim_prefix}_loader_dispatch"
    receiver_claim_id = f"{claim_prefix}_receiver_transform"
    consumer_claim_id = f"{claim_prefix}_candidate_matcher"
    predicate_claim_id = f"{claim_prefix}_candidate_predicate"
    report_claim_id = f"{claim_prefix}_report_mapping"
    verdict_claim_id = f"{claim_prefix}_final_verdict"

    if extended:
        consumer_statement = (
            "After the receiver succeeds and tsig_push_end accepts the pattern with "
            "BMGetPatternFlags, kpatsearchex passes the loaded pattern and derived "
            "row flags to BMMatchEx2 with BM_MAP_ALL."
        )
        predicate_statement = (
            "For a successfully finalized KPATEX row, BMGetPatternFlags acceptance "
            "is a load-time gate and BMMatchEx2 success is only a candidate match."
        )
    else:
        consumer_statement = (
            "After the receiver and tsig finalizer succeed, kpatsearchex compares "
            "the loaded pattern bytewise and treats pattern byte 0x90 as one-byte "
            "wildcard."
        )
        predicate_statement = (
            "For a successfully finalized KPAT row, the bytewise wildcard comparison "
            "is only a candidate match before ValidateKpatMatch."
        )

    claims = (
        SemanticClaim(
            id=wire_claim_id,
            scope="wire_layout",
            statement=(
                "The payload prefix contains an 8-byte key followed by "
                "prefix_size - 8 pattern bytes, then an optional length-prefixed name; "
                "remaining suffix bytes are outside these parsed fields."
            ),
            coverage="complete",
            evidence_refs=("kpat_receiver_descriptor",),
        ),
        SemanticClaim(
            id=dispatch_claim_id,
            scope="loader_dispatch",
            statement=(
                f"pattsearch_init registers wire type "
                f"{'0xBC' if extended else '0xBB'} into the "
                f"{'second' if extended else 'first'} tsig row group with the shared "
                "template descriptor and tsig_push_end finalizer."
            ),
            coverage="complete",
            evidence_refs=("kpat_registration",),
        ),
        SemanticClaim(
            id=receiver_claim_id,
            scope="receiver_transform",
            statement=(
                "On successful ReceiveNewTemplate completion, key, pattern bytes, "
                "pattern length, and optional name recid are projected into a 0x14-byte "
                "tsig row; suffix bytes do not enter those row fields."
            ),
            coverage="subset",
            evidence_refs=("kpat_receiver_descriptor",),
            unknowns=(
                SemanticUnknown(
                    "receiver_transform",
                    "The offline parser does not execute receiver allocation, object, "
                    "or record-ID failure paths for this individual payload.",
                ),
            ),
        ),
        SemanticClaim(
            id=consumer_claim_id,
            scope="runtime_consumer",
            statement=consumer_statement,
            coverage="subset",
            evidence_refs=("kpat_candidate_consumer",),
            unknowns=(
                SemanticUnknown(
                    "runtime_consumer",
                    "FilteredTrie candidate generation and the 8-byte key's complete "
                    "selection role are not reconstructed as a portable matcher.",
                ),
                SemanticUnknown(
                    "runtime_consumer",
                    "Parser acceptance and synthetic payloads do not prove that the "
                    "engine receiver and finalizer loaded a row.",
                ),
            ),
        ),
        SemanticClaim(
            id=predicate_claim_id,
            scope="detection_predicate",
            statement=predicate_statement,
            coverage="subset",
            evidence_refs=("kpat_candidate_consumer",),
            unknowns=(
                SemanticUnknown(
                    "detection_predicate",
                    "ValidateKpatMatch p-code, continuation, aggregation, HIPS, and "
                    "low-fidelity reporting branches are not a closed predicate.",
                ),
            ),
        ),
        SemanticClaim(
            id=report_claim_id,
            scope="report_mapping",
            statement="KPAT candidate-to-report mapping is unresolved.",
            coverage="unknown",
            unknowns=(
                SemanticUnknown(
                    "report_mapping",
                    "The complete ValidateKpatMatch report and aggregation policy has "
                    "not been reconstructed.",
                ),
            ),
        ),
        SemanticClaim(
            id=verdict_claim_id,
            scope="final_verdict",
            statement="A KPAT or KPATEX candidate match is not a confirmed verdict.",
            coverage="unknown",
            unknowns=(
                SemanticUnknown(
                    "final_verdict",
                    "Outer scan arbitration and the final detection result remain "
                    "unresolved.",
                ),
            ),
        ),
    )
    claim_evidence = (
        SemanticEvidence(
            id="kpat_registration",
            axis="dispatch",
            kind="engine_static",
            source_ref="mpengine 1.443.903.0",
            locator="pattsearch_init @ 0x1805653B8",
            supports=(dispatch_claim_id,),
        ),
        SemanticEvidence(
            id="kpat_receiver_descriptor",
            axis="receiver",
            kind="engine_static",
            source_ref="mpengine 1.443.903.0",
            locator=(
                "ReceiveNewTemplate descriptor @ 0x180F67150; row offsets "
                "+0x00/+0x08/+0x0C/+0x10"
            ),
            supports=(wire_claim_id, receiver_claim_id),
        ),
        SemanticEvidence(
            id="kpat_candidate_consumer",
            axis="consumer",
            kind="engine_static",
            source_ref="mpengine 1.443.903.0",
            locator=(
                "tsig_push_end @ 0x1804F51E0; kpatsearchex; "
                "ValidateKpatMatch @ 0x1805FE27C"
            ),
            supports=(consumer_claim_id, predicate_claim_id),
        ),
    )
    return RuleSemantics(
        status=status,
        representation="kpat.runtime_matcher_subset.ir.v5",
        data=data,
        evidence=(
            *matcher_evidence,
            "mpengine 1.443.903.0 descriptor 0x180F67150 maps prefix-derived pattern length to row +0x10 and the following pattern span to the object index at row +0x0C",
            "mpengine 1.443.903.0 ReceiveNewTemplate opcode sequence also maps key to row +0 and optional length-prefixed name to recid at row +8",
            "ReceiveNewTemplate ends after registered descriptors without requiring payload exhaustion; trailing bytes do not enter the matcher row",
            "ValidateKpatMatch may validate/report candidates; complete verdict policy remains unresolved",
        ),
        profile="mpengine-1.443.903.0",
        issues=tuple(issues),
        claims=claims,
        claim_evidence=claim_evidence,
    )


def export_kpat_semantics(parsed: KpatPayload) -> RuleSemantics:
    return _export_semantics(parsed, record_type="KPAT", extended=False)


def export_kpatex_semantics(parsed: KpatPayload) -> RuleSemantics:
    return _export_semantics(parsed, record_type="KPATEX", extended=True)


KPAT_SPEC = FamilySpec(
    0xBB,
    "KPAT",
    parse_kpat,
    render_kpat,
    semantic_exporter=export_kpat_semantics,
)
KPATEX_SPEC = FamilySpec(
    0xBC,
    "KPATEX",
    parse_kpatex,
    render_kpatex,
    semantic_exporter=export_kpatex_semantics,
)
