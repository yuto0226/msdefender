"""Typed model for observed KVIR32 records (type 0x20)."""

from dataclasses import dataclass
from typing import Final

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

KVIR32_TYPE: Final = 0x20
_PREFIX_SIZE: Final = 16
_EXTENSION_MARKER: Final = 0x21
_DATA_PREVIEW_SIZE: Final = 64


@dataclass(frozen=True, slots=True)
class Kvir32Payload:
    raw: bytes
    opaque_prefix: bytes
    extension_marker: int | None
    extension_data: bytes | None


def parse_kvir32(payload: bytes) -> Kvir32Payload:
    """Parse the fixed opaque prefix and the observed optional extension."""
    if len(payload) < _PREFIX_SIZE:
        raise ValueError(
            f"truncated KVIR32 prefix: need {_PREFIX_SIZE} bytes, have {len(payload)}"
        )

    opaque_prefix = payload[:_PREFIX_SIZE]
    remainder = payload[_PREFIX_SIZE:]
    if not remainder:
        return Kvir32Payload(payload, opaque_prefix, None, None)

    if len(remainder) < 2:
        raise ValueError("truncated KVIR32 extension header")

    declared_size = remainder[0]
    marker = remainder[1]
    if marker != _EXTENSION_MARKER:
        raise ValueError(f"unexpected KVIR32 extension marker 0x{marker:02X}")
    if declared_size == 0:
        raise ValueError("invalid KVIR32 extension size 0")

    # In the observed corpus profile, declared_size counts the bytes after
    # the size byte, including the 0x21 marker. This is not an engine rule.
    expected_size = declared_size + 1
    if len(remainder) != expected_size:
        raise ValueError(
            "KVIR32 extension size mismatch: "
            f"declared {declared_size}, expected {expected_size} bytes, "
            f"have {len(remainder)}"
        )

    return Kvir32Payload(
        raw=payload,
        opaque_prefix=opaque_prefix,
        extension_marker=marker,
        extension_data=remainder[2:],
    )


def _hex_preview(data: bytes) -> str:
    preview = data[:_DATA_PREVIEW_SIZE].hex(" ")
    if len(data) > _DATA_PREVIEW_SIZE:
        preview += " ..."
    return preview or "(empty)"


def render_kvir32(parsed: Kvir32Payload) -> FormatResult:
    rows = [("opaque_prefix", parsed.opaque_prefix.hex(" "))]
    if parsed.extension_marker is not None:
        assert parsed.extension_data is not None
        rows.extend(
            (
                ("extension_marker", f"0x{parsed.extension_marker:02X}"),
                ("extension_data_length", str(len(parsed.extension_data))),
                ("extension_data", _hex_preview(parsed.extension_data)),
            )
        )
    return FormatResult(sections=(DisplaySection("KVIR32", rows=tuple(rows)),))


def export_kvir32_semantics(parsed: Kvir32Payload) -> RuleSemantics:
    """Export the observed framing and complete bytes without inferred meaning."""
    data = JSONObject(
        (
            ("record_type", "KVIR32"),
            ("raw_hex", parsed.raw.hex()),
            (
                "observed_profile",
                "16-byte prefix with optional 0x21 extension framing",
            ),
            ("opaque_prefix_hex", parsed.opaque_prefix.hex()),
            ("extension_present", parsed.extension_marker is not None),
            (
                "following_size_raw",
                parsed.raw[_PREFIX_SIZE]
                if parsed.extension_marker is not None
                else None,
            ),
            ("extension_marker_raw", parsed.extension_marker),
            (
                "extension_data_raw_hex",
                parsed.extension_data.hex()
                if parsed.extension_data is not None
                else None,
            ),
            (
                "extension_data_length",
                len(parsed.extension_data)
                if parsed.extension_data is not None
                else None,
            ),
            (
                "evidence_axes",
                JSONObject(
                    (
                        ("wire", "corpus_observed_profile_only"),
                        ("receiver", "unresolved_dynamic_gktab_slot"),
                        ("runtime_consumer", "unknown"),
                        ("policy", "unknown"),
                        ("report", "unknown"),
                    )
                ),
            ),
            (
                "registration_search_boundary",
                JSONObject(
                    (
                        (
                            "checked",
                            "direct RegisterForDatabaseRecords and regcntl caller evidence",
                        ),
                        ("type_specific_callsite_found", False),
                        ("runtime_gktab_slot_observed", False),
                        ("indirect_or_data_driven_registration_excluded", False),
                    )
                ),
            ),
        )
    )
    return RuleSemantics(
        status="observed_only",
        representation="kvir32.observed_framing.v2",
        data=data,
        evidence=(
            (
                "The local mpas.sig/mpav.sig corpus contains 6,595 type 0x20 "
                "records matching the 16-byte prefix and optional extension profile."
            ),
            (
                "mpengine 1.443.903.0 DispatchRecord at 0x1800FAF18 uses the "
                "dynamic gktab dispatcher; no type 0x20 receiver or payload "
                "consumer was confirmed by the bounded static audit."
            ),
        ),
        profile="mpengine-1.443.903.0",
        issues=(
            SemanticIssue(
                "payload_semantics_unknown",
                "KVIR32 bytes are preserved as observed framing; type-specific "
                "receiver bounds, storage, consumer, policy, and report behavior "
                "remain unresolved.",
                (
                    (
                        "unresolved_axes",
                        "receiver_bounds,storage,runtime_consumer,policy,report",
                    ),
                ),
            ),
        ),
        claims=(
            SemanticClaim(
                id="kvir32_corpus_profile",
                scope="corpus_observation",
                statement=(
                    "The current local corpus contains 6,595 type 0x20 records "
                    "matching the parser's observed framing profile."
                ),
                coverage="subset",
                evidence_refs=("kvir32_corpus",),
                unknowns=(
                    SemanticUnknown(
                        "corpus_observation",
                        "This profile is not an engine ABI or cross-version guarantee.",
                    ),
                ),
            ),
            SemanticClaim(
                id="kvir32_dispatch_boundary",
                scope="loader_dispatch",
                statement=(
                    "DispatchRecord uses dynamic gktab slots, but the bounded audit "
                    "did not resolve the type 0x20 slot."
                ),
                coverage="subset",
                evidence_refs=("kvir32_dispatch",),
                unknowns=(
                    SemanticUnknown(
                        "loader_dispatch",
                        "Indirect, data-driven, or runtime registration remains possible.",
                    ),
                ),
            ),
            SemanticClaim(
                id="kvir32_runtime_consumer",
                scope="runtime_consumer",
                statement="The type-specific runtime consumer is unresolved.",
                coverage="unknown",
                unknowns=(
                    SemanticUnknown(
                        "runtime_consumer",
                        "Receiver, storage, and consumer dataflow are not established.",
                    ),
                ),
            ),
            SemanticClaim(
                id="kvir32_detection_predicate",
                scope="detection_predicate",
                statement="No KVIR32 detection predicate is established.",
                coverage="unknown",
                unknowns=(
                    SemanticUnknown(
                        "detection_predicate",
                        "The bounded evidence stops at generic dispatch.",
                    ),
                ),
            ),
            SemanticClaim(
                id="kvir32_final_verdict",
                scope="final_verdict",
                statement="No KVIR32 final-verdict path is established.",
                coverage="unknown",
                unknowns=(
                    SemanticUnknown(
                        "final_verdict",
                        "Policy, report, and verdict consumers are unresolved.",
                    ),
                ),
            ),
        ),
        claim_evidence=(
            SemanticEvidence(
                id="kvir32_corpus",
                axis="corpus",
                kind="corpus",
                source_ref="mpas.sig + mpav.sig",
                locator="type 0x20 corpus count: 6,595",
                supports=("kvir32_corpus_profile",),
            ),
            SemanticEvidence(
                id="kvir32_dispatch",
                axis="dispatch",
                kind="engine_static",
                source_ref="mpengine 1.443.903.0",
                locator="DispatchRecord @ 0x1800FAF18; bounded type-slot audit",
                supports=("kvir32_dispatch_boundary",),
            ),
        ),
    )


SPEC: Final = FamilySpec(
    KVIR32_TYPE,
    "KVIR32",
    parse_kvir32,
    render_kvir32,
    semantic_exporter=export_kvir32_semantics,
)
