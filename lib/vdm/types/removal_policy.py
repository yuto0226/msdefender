"""Lossless parsers for removal policy records."""

import json
from dataclasses import dataclass
from typing import Final

from ..core import DisplaySection, FamilySpec, FormatResult

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


REMOVAL_POLICY_SPEC = FamilySpec(
    REMOVAL_POLICY_TYPE,
    "REMOVAL_POLICY",
    parse_removal_policy,
    render_removal_policy,
)
REMOVAL_POLICY_BY_NAME_SPEC = FamilySpec(
    REMOVAL_POLICY_BY_NAME_TYPE,
    "REMOVAL_POLICY_BY_NAME",
    parse_removal_policy_by_name,
    render_removal_policy_by_name,
)
REMOVAL_POLICY_SPECS = (REMOVAL_POLICY_SPEC, REMOVAL_POLICY_BY_NAME_SPEC)
