"""Engine-validated parser for UFSP_DISABLE (0x88)."""

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
)

UFSP_DISABLE_TYPE: Final = 0x88
PAYLOAD_SIZE: Final = 4


@dataclass(frozen=True, slots=True)
class UfspDisablePayload:
    """Plugin ID removed from the registered-plugin collection."""

    raw: bytes
    plugin_id: int
    trailing_raw: bytes


def parse_ufsp_disable(payload: bytes) -> UfspDisablePayload:
    """Parse the engine template's DWORD and preserve accepted suffix bytes."""
    if len(payload) < PAYLOAD_SIZE:
        raise ValueError(
            f"truncated UFSP_DISABLE plugin ID: need {PAYLOAD_SIZE} bytes, "
            f"have {len(payload)}"
        )
    return UfspDisablePayload(
        raw=payload,
        plugin_id=int.from_bytes(payload[:PAYLOAD_SIZE], "little"),
        trailing_raw=payload[PAYLOAD_SIZE:],
    )


def render_ufsp_disable(parsed: UfspDisablePayload) -> FormatResult:
    """Render the exact-ID removal semantics confirmed in the engine."""
    rows = [
        ("plugin_id", f"0x{parsed.plugin_id:08X}"),
        ("effect", "remove exact ID from registered plugins"),
    ]
    if parsed.trailing_raw:
        rows.append(("trailing_raw", parsed.trailing_raw.hex(" ")))
    return FormatResult(
        sections=(
            DisplaySection(
                "UFSP_DISABLE",
                rows=tuple(rows),
            ),
        )
    )


def _wire_span(kind: str, raw: bytes, offset: int) -> JSONObject:
    return JSONObject(
        (
            ("kind", kind),
            ("raw_span", JSONObject((("offset", offset), ("length", len(raw))))),
            ("raw_hex", raw.hex()),
        )
    )


def export_ufsp_disable_semantics(parsed: UfspDisablePayload) -> RuleSemantics:
    """Export the exact plugin-ID removal operation and lossless wire spans."""
    issues = [
        SemanticIssue(
            "outer_policy_unknown",
            "Exact removal from the registered-plugin collection is confirmed; "
            "the resulting scan behavior and final report policy are not.",
        ),
        SemanticIssue(
            "plugin_id_business_name_unknown",
            "The numeric plugin ID is matched exactly, but its product-facing "
            "name is not established by this dataflow.",
            (("plugin_id", parsed.plugin_id),),
        ),
    ]
    if parsed.trailing_raw:
        issues.append(
            SemanticIssue(
                "receiver_ignored_suffix",
                "The receiver accepts bytes after the plugin ID and ignores them.",
                (("length", len(parsed.trailing_raw)),),
            )
        )

    return RuleSemantics(
        status="confirmed_subset",
        representation="ufsp_disable.plugin_removal.ir.v2",
        data=JSONObject(
            (
                ("raw_hex", parsed.raw.hex()),
                (
                    "framing",
                    JSONArray(
                        (
                            _wire_span("plugin_id", parsed.raw[:PAYLOAD_SIZE], 0),
                            _wire_span(
                                "receiver_ignored_suffix",
                                parsed.trailing_raw,
                                PAYLOAD_SIZE,
                            ),
                        )
                    ),
                ),
                (
                    "operation",
                    JSONObject(
                        (
                            ("kind", "remove_registered_plugin"),
                            (
                                "lookup",
                                JSONObject(
                                    (
                                        ("kind", "exact"),
                                        ("plugin_id", parsed.plugin_id),
                                        ("plugin_id_raw_hex", parsed.raw[:4].hex()),
                                        ("wildcard", False),
                                    )
                                ),
                            ),
                        )
                    ),
                ),
                ("record_role", "loader_policy_state_update"),
                ("content_match_predicate", False),
                ("special_all_plugins_sentinel", False),
                ("suffix_disposition", "accepted_and_ignored"),
                ("final_scan_policy", "unknown"),
            )
        ),
        evidence=(
            "Ufs_init_module @ 0x180B44A80 registers type 0x88 as a DWORD row",
            "DisableUfsPluginPushEnd @ 0x18055CF20 removes only exact ComparePluginIDs matches",
            "ComparePluginIDs @ 0x180534CA0 has no 0xFFFFFFFF wildcard branch",
        ),
        profile="mpengine-1.443.903.0",
        issues=tuple(issues),
    )


SPEC = FamilySpec(
    UFSP_DISABLE_TYPE,
    "UFSP_DISABLE",
    parse_ufsp_disable,
    render_ufsp_disable,
    semantic_exporter=export_ufsp_disable_semantics,
)
