"""Lossless parsers for removal policy records."""

import json
from dataclasses import dataclass
from typing import Final

from ..core import (
    DisplaySection,
    FamilySpec,
    FormatResult,
    JSONObject,
    RuleSemantics,
    SemanticIssue,
)

REMOVAL_POLICY_TYPE: Final = 0x6A
REMOVAL_POLICY_BY_NAME_TYPE: Final = 0x98
_NAME_PREVIEW_LIMIT: Final = 128
_BYTE_PREVIEW_LIMIT: Final = 64

# The observed consumer resolves a threat ID first, then falls back to a
# regular-expression name lookup. Policy bits remain opaque here.


@dataclass(frozen=True, slots=True)
class RemovalPolicyByName:
    raw: bytes
    name_len: int
    name_raw: bytes
    name_preview_raw: bytes
    name_preview: str
    policy: int
    trailing_raw: bytes


@dataclass(frozen=True, slots=True)
class RemovalPolicy:
    raw: bytes
    threat_id: int
    policy: int
    trailing_raw: bytes


def _hex_preview(raw: bytes) -> str:
    preview = raw[:_BYTE_PREVIEW_LIMIT].hex(" ")
    return (preview or "(empty)") + (" ..." if len(raw) > _BYTE_PREVIEW_LIMIT else "")


def parse_removal_policy_by_name(payload: bytes) -> RemovalPolicyByName:
    """Parse a byte-length-prefixed name and 32-bit policy value."""
    if len(payload) < 1:
        raise ValueError(
            "truncated REMOVAL_POLICY_BY_NAME name_len: need 1 byte, have 0"
        )
    name_len = payload[0]
    policy_offset = 1 + name_len
    if len(payload) < policy_offset + 4:
        raise ValueError(
            "truncated REMOVAL_POLICY_BY_NAME policy: "
            f"need 4 bytes at offset {policy_offset}, "
            f"have {max(0, len(payload) - policy_offset)}"
        )

    name_raw = payload[1:policy_offset]
    nul = name_raw.find(b"\0")
    c_string_raw = name_raw if nul < 0 else name_raw[:nul]
    preview_raw = c_string_raw[:_NAME_PREVIEW_LIMIT]
    return RemovalPolicyByName(
        raw=payload,
        name_len=name_len,
        name_raw=name_raw,
        name_preview_raw=preview_raw,
        name_preview=preview_raw.decode("utf-8", errors="replace"),
        policy=int.from_bytes(payload[policy_offset : policy_offset + 4], "little"),
        trailing_raw=payload[policy_offset + 4 :],
    )


def render_removal_policy_by_name(parsed: RemovalPolicyByName) -> FormatResult:
    rows = [
        ("name_len", str(parsed.name_len)),
        ("name_preview", json.dumps(parsed.name_preview, ensure_ascii=False)),
        ("name_raw", _hex_preview(parsed.name_raw)),
        ("policy", f"0x{parsed.policy:08X}"),
    ]
    nul = parsed.name_raw.find(b"\0")
    c_string_len = len(parsed.name_raw) if nul < 0 else nul
    if c_string_len > len(parsed.name_preview_raw):
        rows.append(("name_preview_truncated", "yes (128 B limit)"))
    if parsed.trailing_raw:
        rows.append(("trailing_raw", _hex_preview(parsed.trailing_raw)))
    return FormatResult(
        sections=(DisplaySection("Removal policy by name", rows=tuple(rows)),)
    )


def parse_removal_policy(payload: bytes) -> RemovalPolicy:
    """Parse the threat ID and 32-bit policy value."""
    if len(payload) < 8:
        raise ValueError(f"truncated REMOVAL_POLICY: need 8 bytes, have {len(payload)}")
    return RemovalPolicy(
        raw=payload,
        threat_id=int.from_bytes(payload[:4], "little"),
        policy=int.from_bytes(payload[4:8], "little"),
        trailing_raw=payload[8:],
    )


def render_removal_policy(parsed: RemovalPolicy) -> FormatResult:
    rows = [
        ("threat_id", f"0x{parsed.threat_id:08X}"),
        ("policy", f"0x{parsed.policy:08X}"),
    ]
    if parsed.trailing_raw:
        rows.append(("trailing_raw", _hex_preview(parsed.trailing_raw)))
    return FormatResult(sections=(DisplaySection("Removal policy", rows=tuple(rows)),))


def _wire_field(kind: str, raw: bytes, offset: int) -> JSONObject:
    return JSONObject(
        (
            ("kind", kind),
            ("raw_span", JSONObject((("offset", offset), ("length", len(raw))))),
            ("raw_hex", raw.hex()),
        )
    )


def export_removal_policy_semantics(parsed: RemovalPolicy) -> RuleSemantics:
    """Export the confirmed threat-ID lookup while keeping policy bits opaque."""
    issues = [
        SemanticIssue(
            "policy_bits_opaque",
            "The policy DWORD is returned verbatim, but individual product bits are unnamed.",
        )
    ]
    if parsed.trailing_raw:
        issues.append(
            SemanticIssue(
                "trailing_bytes_uninterpreted",
                "Bytes after the confirmed eight-byte row are not consumed by the lookup.",
                (("length", len(parsed.trailing_raw)),),
            )
        )
    return RuleSemantics(
        status="unsupported" if parsed.trailing_raw else "confirmed_subset",
        representation="removal_policy.lookup.ir.v1",
        data=JSONObject(
            (
                ("type", "threat_id_exact_lookup"),
                ("raw_hex", parsed.raw.hex()),
                (
                    "threat_id",
                    JSONObject(
                        (
                            ("value", parsed.threat_id),
                            ("wire", _wire_field("threat_id", parsed.raw[:4], 0)),
                        )
                    ),
                ),
                (
                    "result",
                    JSONObject(
                        (
                            ("type", "opaque_policy_u32"),
                            ("value", parsed.policy),
                            ("wire", _wire_field("policy", parsed.raw[4:8], 4)),
                        )
                    ),
                ),
                ("priority", "before_name_rules"),
                (
                    "trailing",
                    _wire_field("trailing", parsed.trailing_raw, 8),
                ),
            )
        ),
        evidence=(
            "mpengine 1.443.903.0 GetThreatRemovalPolicy exact threat-ID lookup",
        ),
        profile="mpengine-1.443.903.0",
        issues=tuple(issues),
    )


def export_removal_policy_by_name_semantics(
    parsed: RemovalPolicyByName,
) -> RuleSemantics:
    """Export the confirmed regex-search and allow/deny mask contribution."""
    nul = parsed.name_raw.find(b"\0")
    pattern_raw = parsed.name_raw if nul < 0 else parsed.name_raw[:nul]
    policy_offset = 1 + parsed.name_len
    deny = bool(parsed.policy & 0x80000000)
    mask = parsed.policy & 0x7FFFFFFF if deny else parsed.policy
    issues = [
        SemanticIssue(
            "policy_bits_opaque",
            "Mask reduction is confirmed, but individual product bits are unnamed.",
        ),
        SemanticIssue(
            "regex_compile_failure_policy_unknown",
            "The engine's fallback for an invalid Boost regex is not confirmed.",
        ),
    ]
    if parsed.trailing_raw:
        issues.append(
            SemanticIssue(
                "trailing_bytes_uninterpreted",
                "Bytes after the confirmed name and policy fields are not interpreted.",
                (("length", len(parsed.trailing_raw)),),
            )
        )
    return RuleSemantics(
        status="unsupported" if parsed.trailing_raw else "confirmed_subset",
        representation="removal_policy.lookup.ir.v1",
        data=JSONObject(
            (
                ("type", "threat_name_regex_lookup"),
                ("raw_hex", parsed.raw.hex()),
                ("match_mode", "regex_search"),
                ("regex_engine", "boost_basic_regex_char"),
                ("name_length", parsed.name_len),
                ("name_length_wire", _wire_field("name_length", parsed.raw[:1], 0)),
                ("pattern_wire_raw_hex", parsed.name_raw.hex()),
                ("pattern_c_string_raw_hex", pattern_raw.hex()),
                (
                    "pattern_wire",
                    _wire_field("name", parsed.name_raw, 1),
                ),
                (
                    "contribution",
                    JSONObject(
                        (
                            ("bucket", "deny" if deny else "allow"),
                            ("mask", mask),
                            ("raw_policy", parsed.policy),
                            (
                                "wire",
                                _wire_field(
                                    "policy",
                                    parsed.raw[policy_offset : policy_offset + 4],
                                    policy_offset,
                                ),
                            ),
                        )
                    ),
                ),
                ("reduction", "allow_or & ~deny_or"),
                ("priority", "after_threat_id_lookup"),
                (
                    "trailing",
                    _wire_field("trailing", parsed.trailing_raw, policy_offset + 4),
                ),
            )
        ),
        evidence=(
            "mpengine 1.443.903.0 GetThreatRemovalPolicy regex and mask reduction",
        ),
        profile="mpengine-1.443.903.0",
        issues=tuple(issues),
    )


REMOVAL_POLICY_SPEC = FamilySpec(
    REMOVAL_POLICY_TYPE,
    "REMOVAL_POLICY",
    parse_removal_policy,
    render_removal_policy,
    semantic_exporter=export_removal_policy_semantics,
)
REMOVAL_POLICY_BY_NAME_SPEC = FamilySpec(
    REMOVAL_POLICY_BY_NAME_TYPE,
    "REMOVAL_POLICY_BY_NAME",
    parse_removal_policy_by_name,
    render_removal_policy_by_name,
    semantic_exporter=export_removal_policy_by_name_semantics,
)
REMOVAL_POLICY_SPECS = (REMOVAL_POLICY_SPEC, REMOVAL_POLICY_BY_NAME_SPEC)
