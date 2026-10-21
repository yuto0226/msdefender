"""Typed, lossless parser for BOOT (0x44) payloads."""

from dataclasses import dataclass
from typing import Final, Literal

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

BOOT_TYPE: Final = 0x44
_FIELD_SIZE: Final = 32
_PREVIEW_SIZE: Final = 32


@dataclass(frozen=True, slots=True)
class BootPayload:
    """A current 32-byte template descriptor or preserved legacy bytes."""

    raw: bytes
    variant: Literal["current", "legacy_opaque"]
    receiver_acceptance: Literal[
        "accepted_by_current_template", "rejected_by_current_template"
    ]
    identity_raw: bytes | None
    identity: str | None
    descriptor_raw: bytes | None
    selector_raw: int | None
    selector_domain: Literal["ordinary", "special_32", "wrapped_unknown"] | None
    runtime_compare_span: tuple[int, int] | None
    pattern_raw: bytes | None
    wildcard_count: int | None
    special_prefix: bytes | None
    special_check_length: int | None
    special_crc32: int | None
    trailing_raw: bytes


def parse_boot(payload: bytes) -> BootPayload:
    """Parse a bounded identity + fixed descriptor, retaining all raw bytes.

    Payloads without a complete descriptor are preserved as legacy opaque data;
    observed legacy corpus variants are not rejected by this parser.
    """
    identity_end = payload.find(b"\0")
    if identity_end < 0 or len(payload) < identity_end + 1 + _FIELD_SIZE:
        return BootPayload(
            raw=payload,
            variant="legacy_opaque",
            receiver_acceptance="rejected_by_current_template",
            identity_raw=None,
            identity=None,
            descriptor_raw=None,
            selector_raw=None,
            selector_domain=None,
            runtime_compare_span=None,
            pattern_raw=None,
            wildcard_count=None,
            special_prefix=None,
            special_check_length=None,
            special_crc32=None,
            trailing_raw=b"",
        )

    field_start = identity_end + 1
    field_end = field_start + _FIELD_SIZE
    identity_raw = payload[:identity_end]
    field = payload[field_start:field_end]
    selector = field[0]
    if selector == 0x20:
        selector_domain = "special_32"
        runtime_compare_span = None
        pattern_raw = None
        wildcard_count = None
        special_prefix = field[2:10]
        special_check_length = int.from_bytes(field[10:12], "little")
        special_crc32 = int.from_bytes(field[12:16], "little")
    elif 4 <= selector <= 31:
        selector_domain = "ordinary"
        runtime_compare_span = (0, selector)
        pattern_raw = field[1 : 1 + selector]
        wildcard_count = pattern_raw[4:].count(b"\x90")
        special_prefix = None
        special_check_length = None
        special_crc32 = None
    else:
        # The matcher compares a fixed dword plus a wrapped secondary span.
        # The descriptor only supplies 31 bytes after selector; do not invent
        # the bytes the runtime may read beyond that stored body.
        selector_domain = "wrapped_unknown"
        runtime_compare_span = (0, 4 + ((selector - 4) & 0x1F))
        pattern_raw = None
        wildcard_count = None
        special_prefix = None
        special_check_length = None
        special_crc32 = None

    return BootPayload(
        raw=payload,
        variant="current",
        receiver_acceptance="accepted_by_current_template",
        identity_raw=identity_raw,
        identity=identity_raw.decode("utf-8", errors="replace"),
        descriptor_raw=field,
        selector_raw=selector,
        selector_domain=selector_domain,
        runtime_compare_span=runtime_compare_span,
        pattern_raw=pattern_raw,
        wildcard_count=wildcard_count,
        special_prefix=special_prefix,
        special_check_length=special_check_length,
        special_crc32=special_crc32,
        trailing_raw=payload[field_end:],
    )


def _preview(raw: bytes) -> str:
    preview = raw[:_PREVIEW_SIZE].hex(" ")
    return preview + (" ..." if len(raw) > _PREVIEW_SIZE else "")


def render_boot(parsed: BootPayload) -> FormatResult:
    """Render bounded metadata and previews without inferring engine acceptance."""
    rows: list[tuple[str, str]] = [
        ("variant", parsed.variant),
        ("receiver_acceptance", parsed.receiver_acceptance),
        ("payload_length", f"{len(parsed.raw)} B"),
    ]
    if parsed.variant == "legacy_opaque":
        rows.extend(
            (
                ("raw_preview", _preview(parsed.raw)),
                (
                    "interpretation",
                    "current template rejects with 0xA004; preserved opaque",
                ),
            )
        )
        return FormatResult(sections=(DisplaySection("BOOT", rows=tuple(rows)),))

    assert parsed.identity_raw is not None and parsed.descriptor_raw is not None
    rows.extend(
        (
            ("identity_length", f"{len(parsed.identity_raw)} B"),
            (
                "identity",
                repr(parsed.identity[:256] if parsed.identity is not None else ""),
            ),
            ("descriptor_length", f"{len(parsed.descriptor_raw)} B"),
            (
                "selector_raw",
                f"0x{parsed.selector_raw:02X}"
                if parsed.selector_raw is not None
                else "unknown",
            ),
            ("selector_domain", parsed.selector_domain or "unknown"),
            (
                "runtime_compare_span",
                f"candidate+{parsed.runtime_compare_span[0]}, "
                f"{parsed.runtime_compare_span[1]} B"
                if parsed.runtime_compare_span is not None
                else "unknown",
            ),
            ("trailing_length", f"{len(parsed.trailing_raw)} B"),
            ("trailing_preview", _preview(parsed.trailing_raw) or "(empty)"),
            (
                "receiver_note",
                "descriptor shape recognized by the current engine template",
            ),
        )
    )
    if parsed.selector_domain == "special_32":
        assert parsed.special_prefix is not None
        rows.extend(
            (
                ("special_prefix", _preview(parsed.special_prefix)),
                ("special_check_length", str(parsed.special_check_length)),
                (
                    "special_crc32",
                    f"0x{parsed.special_crc32:08X}"
                    if parsed.special_crc32 is not None
                    else "unknown",
                ),
            )
        )
    elif parsed.selector_domain == "ordinary":
        rows.extend(
            (
                (
                    "pattern_length",
                    str(len(parsed.pattern_raw))
                    if parsed.pattern_raw is not None
                    else "unknown",
                ),
                ("pattern_preview", _preview(parsed.pattern_raw or b"")),
                (
                    "0x90_wildcard_count",
                    str(parsed.wildcard_count)
                    if parsed.wildcard_count is not None
                    else "unknown",
                ),
            )
        )
    else:
        assert parsed.descriptor_raw is not None
        available_body_length = len(parsed.descriptor_raw) - 1
        compare_length = (
            parsed.runtime_compare_span[1]
            if parsed.runtime_compare_span is not None
            else 0
        )
        rows.extend(
            (
                (
                    "runtime_note",
                    "wrapped selector; span is binary-derived, selector meaning unknown",
                ),
                ("available_descriptor_body", f"{available_body_length} B"),
                (
                    "unavailable_compare_bytes",
                    f"{max(0, compare_length - available_body_length)} B",
                ),
                ("descriptor_preview", _preview(parsed.descriptor_raw)),
            )
        )
    return FormatResult(sections=(DisplaySection("BOOT", rows=tuple(rows)),))


def _wire_span(name: str, raw: bytes, offset: int) -> JSONObject:
    return JSONObject(
        (
            ("name", name),
            ("raw_span", JSONObject((("offset", offset), ("length", len(raw))))),
            ("raw_hex", raw.hex()),
        )
    )


def _ordinary_pattern_atoms(pattern: bytes) -> JSONArray:
    return JSONArray(
        tuple(
            JSONObject(
                (
                    ("offset", offset),
                    (
                        "kind",
                        "wildcard" if offset >= 4 and value == 0x90 else "exact",
                    ),
                    ("value", None if offset >= 4 and value == 0x90 else value),
                )
            )
            for offset, value in enumerate(pattern)
        )
    )


def export_boot_semantics(parsed: BootPayload) -> RuleSemantics:
    """Export receiver-confirmed BOOT probe details without a verdict."""
    issues = [
        SemanticIssue(
            "outer_verdict_unknown",
            "A BOOT probe result does not establish a final detection verdict.",
        ),
    ]
    identity_end = parsed.raw.find(b"\0")
    framing: list[JSONObject] = []
    unsupported = parsed.variant != "current"
    if parsed.variant == "current":
        assert identity_end >= 0 and parsed.descriptor_raw is not None
        field_offset = identity_end + 1
        field = parsed.descriptor_raw
        framing.extend(
            (
                _wire_span("identity", parsed.identity_raw or b"", 0),
                _wire_span("identity_terminator", b"\0", identity_end),
                _wire_span("descriptor", field, field_offset),
                _wire_span("trailing", parsed.trailing_raw, field_offset + len(field)),
            )
        )
        if parsed.selector_domain == "ordinary":
            assert parsed.pattern_raw is not None and parsed.selector_raw is not None
            selector_raw = field[:1]
            pattern_offset = field_offset + 1
            rule = JSONObject(
                (
                    ("kind", "candidate_byte_probe"),
                    ("selector_raw", parsed.selector_raw),
                    ("selector", _wire_span("selector", selector_raw, field_offset)),
                    (
                        "runtime_compare_span",
                        JSONObject((("offset", 0), ("length", parsed.selector_raw))),
                    ),
                    (
                        "pattern",
                        _wire_span("pattern", parsed.pattern_raw, pattern_offset),
                    ),
                    ("comparison", _ordinary_pattern_atoms(parsed.pattern_raw)),
                    ("candidate_end_bound", "offset + length < buffer_length"),
                )
            )
        elif parsed.selector_domain == "special_32":
            assert parsed.selector_raw is not None
            rule = JSONObject(
                (
                    ("kind", "special_crc_probe"),
                    ("selector_raw", parsed.selector_raw),
                    ("flags_raw", field[1]),
                    (
                        "special_header",
                        _wire_span("special_header", field[:2], field_offset),
                    ),
                    (
                        "prefix",
                        _wire_span(
                            "prefix", parsed.special_prefix or b"", field_offset + 2
                        ),
                    ),
                    (
                        "check_length_raw",
                        _wire_span("check_length", field[10:12], field_offset + 10),
                    ),
                    ("check_length", parsed.special_check_length),
                    (
                        "crc32_raw",
                        _wire_span("crc32", field[12:16], field_offset + 12),
                    ),
                    ("crc32", parsed.special_crc32),
                    ("crc_algorithm", "mpengine.CRC_1"),
                    ("candidate_end_bound", "offset + check_length < buffer_length"),
                )
            )
        else:
            unsupported = True
            issues.append(
                SemanticIssue(
                    "wrapped_selector_semantics_unknown",
                    "The matcher branch arithmetic produces this wrapped span, "
                    "but selectors outside 4..32 have no confirmed valid wire "
                    "domain or predicate semantics.",
                    (("selector_raw", parsed.selector_raw),),
                )
            )
            rule = JSONObject(
                (
                    ("kind", "opaque_wrapped_probe"),
                    ("selector_raw", parsed.selector_raw),
                    (
                        "runtime_compare_span",
                        JSONArray(parsed.runtime_compare_span or ()),
                    ),
                    (
                        "branch_arithmetic_status",
                        "observed_machine_behavior_not_validated_wire_semantics",
                    ),
                    ("descriptor_raw_hex", field.hex()),
                )
            )
        if parsed.trailing_raw:
            issues.append(
                SemanticIssue(
                    "receiver_ignored_trailing",
                    "The current template receiver ignores bytes after the fixed descriptor.",
                    (("length", len(parsed.trailing_raw)),),
                )
            )
    else:
        rule = JSONObject((("kind", "opaque_legacy"),))
        framing.append(_wire_span("payload", parsed.raw, 0))
        issues.append(
            SemanticIssue(
                "legacy_shape_unrecognized",
                "The observed legacy shape is opaque; do not infer legacy fields.",
            )
        )
        issues.append(
            SemanticIssue(
                "current_template_rejects_shape",
                "mpengine 1.443.903.0 ReceiveNewTemplate returns 0xA004 for this "
                "missing-NUL or short-descriptor shape; DispatchRecords propagates "
                "the error and DispatchRecord has no receiver fallback.",
                (
                    ("current_template_error_code", 40964),
                    ("current_template_error_hex", "0xA004"),
                    ("dispatch_fallback", False),
                ),
            )
        )

    is_current = parsed.variant == "current"
    has_supported_matcher = parsed.selector_domain in {"ordinary", "special_32"}
    has_wrapped_matcher = parsed.selector_domain == "wrapped_unknown"

    if is_current:
        wire_claim = SemanticClaim(
            id="boot_wire_projection",
            scope="wire_layout",
            statement=(
                "For this current-template payload, the first NUL terminates the "
                "identity, the next 32 bytes form the descriptor, and any suffix "
                "is outside the template projection."
            ),
            coverage="complete",
            evidence_refs=("boot_receiver",),
        )
        receiver_statement = (
            "The current receiver creates a 36-byte row from a derived record ID "
            "and the 32-byte descriptor; it does not require the payload suffix "
            "to be exhausted."
        )
        receiver_coverage = "subset"
        receiver_unknowns = (
            SemanticUnknown(
                "receiver_transform",
                "Record-ID derivation, allocation, and storage failure paths are not projected.",
            ),
        )
    else:
        wire_claim = SemanticClaim(
            id="boot_wire_projection",
            scope="wire_layout",
            statement="The preserved legacy payload has no confirmed field grammar.",
            coverage="unknown",
            unknowns=(
                SemanticUnknown(
                    "wire_layout",
                    "Current-template rejection does not identify a historical layout.",
                ),
            ),
        )
        receiver_statement = (
            "The current receiver rejects this missing-NUL or short-descriptor "
            "shape with 0xA004 before incrementing the BOOT row count."
        )
        receiver_coverage = "complete"
        receiver_unknowns = ()

    if has_supported_matcher:
        matcher_statement = (
            "bootsigsearch consumes the loaded row as an ordinary exact/NOP-wildcard "
            "candidate probe."
            if parsed.selector_domain == "ordinary"
            else "bootsigsearch consumes the loaded row as an 8-byte prefix plus "
            "CRC_1 candidate probe."
        )
        predicate_statement = (
            "A candidate satisfies the BOOT matcher only when the ordinary byte "
            "comparison passes its strict end bound and ShouldContinueScanning "
            "returns false."
            if parsed.selector_domain == "ordinary"
            else "A candidate satisfies the BOOT matcher only when the prefix and "
            "CRC_1 checks pass their strict end bounds and ShouldContinueScanning "
            "returns false."
        )
        matcher_claim = SemanticClaim(
            id="boot_candidate_matcher",
            scope="runtime_consumer",
            statement=matcher_statement,
            coverage="subset",
            evidence_refs=("boot_consumer",),
            unknowns=(
                SemanticUnknown(
                    "runtime_consumer",
                    "The outer boot-buffer acquisition and invocation contexts are not modeled.",
                ),
            ),
        )
        predicate_claim = SemanticClaim(
            id="boot_candidate_predicate",
            scope="detection_predicate",
            statement=predicate_statement,
            coverage="subset",
            evidence_refs=("boot_consumer",),
            unknowns=(
                SemanticUnknown(
                    "detection_predicate",
                    "Candidate acceptance is not a complete threat detection condition.",
                ),
            ),
        )
    elif has_wrapped_matcher:
        matcher_claim = SemanticClaim(
            id="boot_candidate_matcher",
            scope="runtime_consumer",
            statement=(
                "The current matcher executes the ordinary branch with a wrapped "
                "secondary length for this selector."
            ),
            coverage="subset",
            evidence_refs=("boot_consumer",),
            unknowns=(
                SemanticUnknown(
                    "runtime_consumer",
                    "The selector is outside the confirmed wire domain and the row "
                    "does not provide every byte that the wrapped span may read.",
                ),
            ),
        )
        predicate_claim = SemanticClaim(
            id="boot_candidate_predicate",
            scope="detection_predicate",
            statement="No portable candidate predicate is established for this selector.",
            coverage="unknown",
            unknowns=(
                SemanticUnknown(
                    "detection_predicate",
                    "Wrapped-selector intent and valid input semantics are unresolved.",
                ),
            ),
        )
    else:
        matcher_claim = SemanticClaim(
            id="boot_candidate_matcher",
            scope="runtime_consumer",
            statement=(
                "This rejected payload does not enter bootsigsearch through the "
                "confirmed current template path."
            ),
            coverage="unknown",
            unknowns=(
                SemanticUnknown(
                    "runtime_consumer",
                    "Historical versions, platform initialization, and independent "
                    "consumers of this legacy shape were not established.",
                ),
            ),
        )
        predicate_claim = SemanticClaim(
            id="boot_candidate_predicate",
            scope="detection_predicate",
            statement="No match predicate is established for the opaque legacy payload.",
            coverage="unknown",
            unknowns=(
                SemanticUnknown(
                    "detection_predicate",
                    "The legacy grammar and any associated matcher are unresolved.",
                ),
            ),
        )

    claims = (
        wire_claim,
        SemanticClaim(
            id="boot_dispatch_path",
            scope="loader_dispatch",
            statement=(
                "When boot_init_module is active, type 0x44 is registered as a "
                "template record and DispatchRecord routes it to ReceiveNewTemplate."
            ),
            coverage="subset",
            evidence_refs=("boot_dispatch",),
            unknowns=(
                SemanticUnknown(
                    "loader_dispatch",
                    "Outer auto-initialization platform gates were not established.",
                ),
            ),
        ),
        SemanticClaim(
            id="boot_receiver_disposition",
            scope="receiver_transform",
            statement=receiver_statement,
            coverage=receiver_coverage,
            evidence_refs=("boot_receiver",),
            unknowns=receiver_unknowns,
        ),
        matcher_claim,
        predicate_claim,
        SemanticClaim(
            id="boot_report_mapping",
            scope="report_mapping",
            statement="BOOT candidate identity to product report mapping is unresolved.",
            coverage="unknown",
            unknowns=(
                SemanticUnknown(
                    "report_mapping",
                    "ShouldContinueScanning and caller policy were not reduced to a "
                    "portable report mapping.",
                ),
            ),
        ),
        SemanticClaim(
            id="boot_final_verdict",
            scope="final_verdict",
            statement="A BOOT candidate result is not a confirmed final verdict.",
            coverage="unknown",
            unknowns=(
                SemanticUnknown(
                    "final_verdict",
                    "Boot-format checks, removal policy, report arbitration, and cure "
                    "outcomes remain outside this payload rule.",
                ),
            ),
        ),
    )

    claim_evidence = [
        SemanticEvidence(
            id="boot_dispatch",
            axis="dispatch",
            kind="engine_static",
            source_ref="mpengine 1.443.903.0",
            locator=("boot_init_module @ 0x180C385B0; DispatchRecord @ 0x1800FAF18"),
            supports=("boot_dispatch_path",),
        ),
        SemanticEvidence(
            id="boot_receiver",
            axis="receiver",
            kind="engine_static",
            source_ref="mpengine 1.443.903.0",
            locator=(
                "ReceiveNewTemplate @ 0x1803224D0 with BOOT descriptor "
                "{0x1016, 0, 0x2020, 4}"
            ),
            supports=(
                ("boot_wire_projection", "boot_receiver_disposition")
                if is_current
                else ("boot_receiver_disposition",)
            ),
        ),
    ]
    if is_current:
        claim_evidence.append(
            SemanticEvidence(
                id="boot_consumer",
                axis="consumer",
                kind="engine_static",
                source_ref="mpengine 1.443.903.0",
                locator="bootsigsearch @ 0x180192E10",
                supports=(
                    ("boot_candidate_matcher", "boot_candidate_predicate")
                    if has_supported_matcher
                    else ("boot_candidate_matcher",)
                ),
            )
        )

    return RuleSemantics(
        status="unsupported" if unsupported else "confirmed_subset",
        representation="boot.candidate_probe.ir.v2",
        data=JSONObject(
            (
                ("raw_hex", parsed.raw.hex()),
                ("framing", JSONArray(tuple(framing))),
                (
                    "identity_raw_hex",
                    parsed.identity_raw.hex()
                    if parsed.identity_raw is not None
                    else None,
                ),
                (
                    "current_template_shape_disposition",
                    "rejected_with_0xA004"
                    if parsed.variant == "legacy_opaque"
                    else "matches_current_template_shape",
                ),
                (
                    "current_template_error_code",
                    40964 if parsed.variant == "legacy_opaque" else None,
                ),
                ("selector_domain", parsed.selector_domain),
                ("rule", rule),
                ("trailing_raw_hex", parsed.trailing_raw.hex()),
            )
        ),
        evidence=(
            "BOOT receiver selector span, modulo-wrap, and special CRC path",
            "BOOT identity and cure caller path",
        ),
        profile="mpengine-1.443.903.0",
        issues=tuple(issues),
        claims=claims,
        claim_evidence=tuple(claim_evidence),
    )


BOOT_SPEC = FamilySpec(
    BOOT_TYPE,
    "BOOT",
    parse_boot,
    render_boot,
    semantic_exporter=export_boot_semantics,
)
