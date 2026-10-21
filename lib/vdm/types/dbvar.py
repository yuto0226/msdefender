"""Parser and bounded renderer for DBVAR (0x5B) payloads."""

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

DBVAR_TYPE: Final = 0x5B
_VALUE_PREVIEW_SIZE: Final = 32


@dataclass(frozen=True, slots=True)
class DbVarPayload:
    """Lossless DBVAR fields; names remain raw bytes for exact round trips."""

    raw: bytes
    name_len: int
    name_raw: bytes
    value_len: int
    value_raw: bytes
    trailing: bytes

    @property
    def name(self) -> str:
        """Decode a display-friendly name while preserving ``name_raw``."""
        return self.name_raw.decode("utf-8", errors="replace")


def parse_dbvar(payload: bytes) -> DbVarPayload:
    """Parse the canonical name/value envelope and preserve trailing bytes.

    The offline parser validates both declared byte ranges regardless of
    registry state. Bytes after the declared value are retained verbatim.
    """
    if len(payload) < 1:
        raise ValueError("truncated DBVAR header: need 1-byte name length")

    name_len = payload[0]
    name_end = 1 + name_len
    value_length_end = name_end + 4
    if len(payload) < value_length_end:
        raise ValueError(
            f"truncated DBVAR name/value-length header: need {value_length_end} "
            f"bytes, have {len(payload)}"
        )

    value_len = int.from_bytes(payload[name_end:value_length_end], "little")
    value_end = value_length_end + value_len
    if len(payload) < value_end:
        raise ValueError(
            f"truncated DBVAR value: need {value_len} bytes, "
            f"have {len(payload) - value_length_end}"
        )

    return DbVarPayload(
        raw=payload,
        name_len=name_len,
        name_raw=payload[1:name_end],
        value_len=value_len,
        value_raw=payload[value_length_end:value_end],
        trailing=payload[value_end:],
    )


def render_dbvar(parsed: DbVarPayload) -> FormatResult:
    """Render metadata and a fixed-size hex preview of the potentially large value."""
    preview = parsed.value_raw[:_VALUE_PREVIEW_SIZE].hex(" ")
    if parsed.value_len > _VALUE_PREVIEW_SIZE:
        preview += f" … ({parsed.value_len - _VALUE_PREVIEW_SIZE} more bytes)"
    name_display = ascii(parsed.name)
    sections = (
        DisplaySection(
            "Database Variable",
            rows=(
                ("name_len", str(parsed.name_len)),
                ("name_raw", parsed.name_raw.hex(" ")),
                ("name", name_display),
                ("value_len", str(parsed.value_len)),
                ("value_preview", preview),
                ("trailing_len", str(len(parsed.trailing))),
            ),
        ),
    )
    return FormatResult(sections=sections)


def export_dbvar_semantics(parsed: DbVarPayload) -> RuleSemantics:
    """Export the confirmed receiver lookup/update behavior for DBVAR."""
    return RuleSemantics(
        status="confirmed_subset",
        representation="dbvar.named_raw_value.v1",
        data=JSONObject(
            (
                ("type", "dbvar"),
                ("raw_hex", parsed.raw.hex()),
                (
                    "name",
                    JSONObject(
                        (
                            ("length", parsed.name_len),
                            ("raw_hex", parsed.name_raw.hex()),
                        )
                    ),
                ),
                (
                    "lookup",
                    JSONObject(
                        (
                            ("requires_equal_byte_length", True),
                            ("comparison", "ascii_case_insensitive"),
                            ("non_ascii_bytes", "exact_byte_compare"),
                        )
                    ),
                ),
                (
                    "declared_value",
                    JSONObject(
                        (
                            ("length", parsed.value_len),
                            ("raw_hex", parsed.value_raw.hex()),
                            ("semantics", "unknown"),
                        )
                    ),
                ),
                (
                    "receiver",
                    JSONObject(
                        (
                            (
                                "unknown_name",
                                JSONObject(
                                    (
                                        ("result", "success"),
                                        ("value_length_validated", False),
                                    )
                                ),
                            ),
                            (
                                "existing_nonempty_storage",
                                JSONObject(
                                    (
                                        ("result", "success"),
                                        ("overwrite", False),
                                        ("value_length_validated", False),
                                    )
                                ),
                            ),
                            (
                                "matching_empty_storage",
                                JSONObject(
                                    (
                                        ("value_length_validated", True),
                                        (
                                            "copy_data_input",
                                            "declared_value.raw_hex",
                                        ),
                                        (
                                            "copy_data_success",
                                            "replaces_data_pointer_and_size",
                                        ),
                                        ("copy_data_success_result", 0),
                                        ("copy_data_allocation_failure", 0x8007),
                                        ("copy_data_error", "propagated"),
                                        ("trailing_bytes", "ignored"),
                                    )
                                ),
                            ),
                        )
                    ),
                ),
                ("trailing_hex", parsed.trailing.hex()),
            )
        ),
        evidence=(
            "mpengine 1.443.903.0 ReceiveDatabaseVar",
            "mpengine 1.443.903.0 DBVarEntry::CopyData",
            "mpas.sig corpus: 2,190 DBVAR records across 497 names",
            "mpas.sig corpus: declared lengths match payloads; no trailing bytes",
            "mpav.sig corpus: no DBVAR records",
        ),
        profile="mpengine-1.443.903.0",
        issues=(
            SemanticIssue(
                "dbvar_consumer_semantics_unknown",
                "The raw value is stored as bytes, but the purpose and meaning "
                "of each named database variable are not established.",
            ),
        ),
        claims=(
            SemanticClaim(
                id="dbvar_receiver_update",
                scope="receiver_transform",
                statement=(
                    "The receiver performs an exact-length ASCII-insensitive name "
                    "lookup and copies the declared bytes only into empty storage."
                ),
                coverage="subset",
                evidence_refs=("dbvar_receiver",),
                unknowns=(
                    SemanticUnknown(
                        "receiver_transform",
                        "Behavior for other variable states or database combinations "
                        "has not been closed.",
                    ),
                ),
            ),
            SemanticClaim(
                id="dbvar_detection_predicate",
                scope="detection_predicate",
                statement="The stored DBVAR value is not a confirmed detection predicate.",
                coverage="unknown",
                unknowns=(
                    SemanticUnknown(
                        "detection_predicate",
                        "Named value consumers and their business meanings are unresolved.",
                    ),
                ),
            ),
            SemanticClaim(
                id="dbvar_final_verdict",
                scope="final_verdict",
                statement="DBVAR does not establish a final verdict.",
                coverage="unknown",
                unknowns=(
                    SemanticUnknown(
                        "final_verdict",
                        "No value-consumer-to-report path has been followed.",
                    ),
                ),
            ),
        ),
        claim_evidence=(
            SemanticEvidence(
                id="dbvar_receiver",
                axis="receiver",
                kind="engine_static",
                source_ref="mpengine 1.443.903.0",
                locator="ReceiveDatabaseVar; DBVarEntry::CopyData",
                supports=("dbvar_receiver_update",),
            ),
        ),
    )


SPEC = FamilySpec(
    DBVAR_TYPE,
    "DBVAR",
    parse_dbvar,
    render_dbvar,
    semantic_exporter=export_dbvar_semantics,
)
