"""Lossless parser and bounded renderer for HOSTSENTRY (0x64) payloads."""

import json
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

HOSTSENTRY_TYPE: Final = 0x64
ADDRESS_NULL_SENTINEL: Final = b"NULL"
PREVIEW_LIMIT: Final = 64


@dataclass(frozen=True, slots=True)
class HostsentryPayload:
    """Parsed HOSTSENTRY strings with their complete declared spans retained."""

    raw: bytes
    address_raw: bytes
    hostname_raw: bytes
    trailing_raw: bytes

    @property
    def address_c_string(self) -> bytes:
        """Return the address bytes before its first NUL, if present."""
        return self.address_raw.split(b"\0", 1)[0]

    @property
    def hostname_c_string(self) -> bytes:
        """Return the hostname bytes before its first NUL, if present."""
        return self.hostname_raw.split(b"\0", 1)[0]

    @property
    def address_null_sentinel(self) -> bool:
        """Match the handler's case-insensitive C-string ``NULL`` sentinel."""
        return self.address_c_string.lower() == ADDRESS_NULL_SENTINEL.lower()

    @property
    def wildcard_hostname(self) -> bool:
        """Whether the hostname C-string starts with the observed ``*.`` prefix."""
        return self.hostname_c_string.startswith(b"*.")


def _read_string_span(payload: bytes, cursor: int, label: str) -> tuple[bytes, int]:
    if cursor >= len(payload):
        raise ValueError(f"truncated HOSTSENTRY {label} length")
    length = payload[cursor]
    cursor += 1
    if length < 2:
        raise ValueError(f"HOSTSENTRY {label} length must be at least 2")
    end = cursor + length
    if end > len(payload):
        raise ValueError(f"truncated HOSTSENTRY {label}: need {length} bytes")
    span = payload[cursor:end]
    if span[-1] != 0:
        raise ValueError(f"HOSTSENTRY {label} span must end with NUL")
    return span, end


def parse_hostsentry(payload: bytes) -> HostsentryPayload:
    """Parse two length-prefixed, NUL-terminated strings and retain any tail."""
    address_raw, cursor = _read_string_span(payload, 0, "address")
    hostname_raw, cursor = _read_string_span(payload, cursor, "hostname")
    return HostsentryPayload(
        raw=payload,
        address_raw=address_raw,
        hostname_raw=hostname_raw,
        trailing_raw=payload[cursor:],
    )


def _bounded_hex(data: bytes) -> str:
    shown = data[:PREVIEW_LIMIT].hex(" ").upper()
    if len(data) > PREVIEW_LIMIT:
        return f"{shown} … ({len(data) - PREVIEW_LIMIT} B omitted)"
    return shown or "(empty)"


def _byte_preview(data: bytes) -> str:
    return json.dumps(data.decode("latin-1"), ensure_ascii=True)


def render_hostsentry(parsed: HostsentryPayload) -> FormatResult:
    """Render semantic flags and bounded byte previews without decoding assumptions."""
    return FormatResult(
        sections=(
            DisplaySection(
                "HOSTS Entry",
                rows=(
                    ("address_length", f"{len(parsed.address_raw)} B"),
                    (
                        "address_preview",
                        _byte_preview(parsed.address_c_string[:PREVIEW_LIMIT]),
                    ),
                    ("address_raw", _bounded_hex(parsed.address_raw)),
                    (
                        "address_null_sentinel",
                        str(parsed.address_null_sentinel).lower(),
                    ),
                    ("hostname_length", f"{len(parsed.hostname_raw)} B"),
                    (
                        "hostname_preview",
                        _byte_preview(parsed.hostname_c_string[:PREVIEW_LIMIT]),
                    ),
                    ("hostname_raw", _bounded_hex(parsed.hostname_raw)),
                    ("wildcard_hostname", str(parsed.wildcard_hostname).lower()),
                    ("trailing_length", f"{len(parsed.trailing_raw)} B"),
                    ("trailing_raw", _bounded_hex(parsed.trailing_raw)),
                ),
            ),
        )
    )


def _wire_field(kind: str, raw: bytes, offset: int) -> JSONObject:
    return JSONObject(
        (
            ("kind", kind),
            ("raw_span", JSONObject((("offset", offset), ("length", len(raw))))),
            ("raw_hex", raw.hex()),
        )
    )


def _hosts_domain_suffix(hostname: bytes) -> tuple[int, bytes] | None:
    """Return GetHostsDomain's confirmed slice start and bytes, if valid."""
    last_dot = hostname.rfind(b".")
    if last_dot < 0 or last_dot == len(hostname) - 1:
        return None
    previous_dot = hostname.rfind(b".", 0, last_dot)
    start = previous_dot + 1 if previous_dot >= 0 else 0
    return start, hostname[start:]


def export_hostsentry_semantics(parsed: HostsentryPayload) -> RuleSemantics:
    """Export confirmed insertion/lookup behavior without naming report results."""
    address_length = len(parsed.address_raw)
    hostname_length_offset = 1 + address_length
    hostname_offset = hostname_length_offset + 1
    trailing_offset = hostname_offset + len(parsed.hostname_raw)
    address_c_string = parsed.address_c_string
    hostname_c_string = parsed.hostname_c_string
    wildcard = parsed.wildcard_hostname
    hosts_domain = _hosts_domain_suffix(hostname_c_string[2:]) if wildcard else None
    address_key = (
        JSONObject((("kind", "constant"), ("value", 0xFFFFFFFF)))
        if parsed.address_null_sentinel
        else JSONObject(
            (
                ("kind", "crc_lower_string_a"),
                ("input_hex", address_c_string.hex()),
            )
        )
    )
    issues = [
        SemanticIssue(
            "report_state_business_meaning_unknown",
            "At the observed kcrce_scanfile callsite, context byte +1 is initialized to 1 and makes a match return 0x29; its business/report label remains unknown.",
        ),
        SemanticIssue(
            "final_scan_report_policy_unknown",
            "The observed path maps callback 0x29 to a nonzero enumerator result "
            "and then to scanresult 0xFE; the final SCAN_REPLY/report meaning of "
            "that control-flow value is not established.",
        ),
        SemanticIssue(
            "hosts_file_format_and_scope_unknown",
            "The observed callback path does not establish an operating-system hosts-file format or broader hostname policy.",
        ),
    ]
    if parsed.trailing_raw:
        issues.append(
            SemanticIssue(
                "trailing_bytes_meaning_unknown",
                "Trailing bytes are accepted and included in record identity, but are not parsed as fields.",
                (("length", len(parsed.trailing_raw)),),
            )
        )
    if wildcard and hosts_domain is None:
        issues.append(
            SemanticIssue(
                "wildcard_domain_key_invalid",
                "GetHostsDomain rejects a wildcard hostname without a dot or with an empty final label.",
            )
        )

    hostname_index = (
        JSONObject(
            (
                ("kind", "wildcard_tree"),
                ("tree", "qword_18128A710"),
                ("domain_key_operation", "GetHostsDomain(hostname_after_star_dot)"),
                ("invalid_domain_key_result", 32770),
                (
                    "insertion_result",
                    "rejected" if hosts_domain is None else "eligible",
                ),
                (
                    "tree_key_hex",
                    None if hosts_domain is None else hosts_domain[1].hex(),
                ),
                (
                    "stored_mapped_string_hex",
                    None
                    if hosts_domain is None
                    else hostname_c_string[2 : 2 + hosts_domain[0]].hex(),
                ),
                ("stored_mapped_string_case", "payload_slice_preserved"),
                (
                    "callback_lookup",
                    "GetHostsDomain(query_hostname), lowercase_for_tree_lookup, then suffix comparison",
                ),
                ("callback_suffix_comparison", "_strnicmp"),
            )
        )
        if wildcard
        else JSONObject(
            (
                ("kind", "exact_crc_map"),
                ("map", "HostsDomain"),
                ("key_operation", "CRCLowerStringA(hostname_c_string)"),
            )
        )
    )
    return RuleSemantics(
        status=(
            "unsupported"
            if parsed.trailing_raw or (wildcard and hosts_domain is None)
            else "confirmed_subset"
        ),
        representation="hostsentry.map-lookup.ir.v4",
        data=JSONObject(
            (
                ("type", "HOSTSENTRY"),
                ("raw_hex", parsed.raw.hex()),
                (
                    "address",
                    JSONObject(
                        (
                            (
                                "wire_length",
                                _wire_field("address_length", parsed.raw[:1], 0),
                            ),
                            (
                                "wire_span",
                                _wire_field("address_span", parsed.address_raw, 1),
                            ),
                            ("c_string_hex", address_c_string.hex()),
                            ("null_sentinel", parsed.address_null_sentinel),
                            (
                                "domain",
                                JSONObject(
                                    (
                                        ("wire_value", "NUL-terminated byte string"),
                                        (
                                            "engine_interpretation",
                                            "case-insensitive NULL sentinel or CRCLowerStringA key",
                                        ),
                                        ("syntax_validation_observed", False),
                                        ("semantic_domain", "unknown"),
                                    )
                                ),
                            ),
                            ("map_key", address_key),
                        )
                    ),
                ),
                (
                    "hostname",
                    JSONObject(
                        (
                            (
                                "wire_length",
                                _wire_field(
                                    "hostname_length",
                                    parsed.raw[hostname_length_offset:hostname_offset],
                                    hostname_length_offset,
                                ),
                            ),
                            (
                                "wire_span",
                                _wire_field(
                                    "hostname_span",
                                    parsed.hostname_raw,
                                    hostname_offset,
                                ),
                            ),
                            ("c_string_hex", hostname_c_string.hex()),
                            ("classification", "wildcard" if wildcard else "exact"),
                            ("index", hostname_index),
                        )
                    ),
                ),
                (
                    "record_identity",
                    JSONObject(
                        (
                            (
                                "input",
                                _wire_field("complete_payload", parsed.raw, 0),
                            ),
                            ("consumer", "CRC/SHA helpers and createrecid"),
                            ("record_id_value", None),
                        )
                    ),
                ),
                (
                    "map_value",
                    JSONObject(
                        (
                            ("address_key", address_key),
                            ("record_id", "created_from_complete_payload"),
                            (
                                "wildcard_extra",
                                "payload_slice_mapped_string" if wildcard else None,
                            ),
                        )
                    ),
                ),
                (
                    "hosts_file_consumer",
                    JSONObject(
                        (
                            ("enumerator", "MPEnumHostsEntries"),
                            ("callback", "hosts_callback"),
                            (
                                "callback_match_outputs",
                                JSONArray(("matched_byte", "record_id")),
                            ),
                            ("callback_returns", JSONArray((0, 0x29))),
                            (
                                "enumerator_special_branches",
                                JSONArray((0x29, 0x64)),
                            ),
                            (
                                "caller_context_seed",
                                JSONObject(
                                    (
                                        ("caller", "kcrce_scanfile"),
                                        ("callsite", "0x18011FE43"),
                                        (
                                            "context_storage",
                                            "stack-local result buffer",
                                        ),
                                        ("result_byte_0_initial", 0),
                                        ("result_byte_1_initial", 1),
                                        (
                                            "result_byte_1_source",
                                            "r13d = 1 at 0x18011FC21; stored at 0x18011FE3F",
                                        ),
                                    )
                                ),
                            ),
                            (
                                "callback_observed_effects",
                                JSONObject(
                                    (
                                        (
                                            "match_flag_write",
                                            "result_byte_0 = 1 on match",
                                        ),
                                        (
                                            "record_id_write",
                                            "result_dword_4 = matched_record_id",
                                        ),
                                        (
                                            "return_gate",
                                            "return 0x29 when preexisting result_byte_1 != 0; otherwise return 0",
                                        ),
                                        (
                                            "outer_verdict",
                                            (
                                                "unknown; kcrce_scanfile maps a nonzero "
                                                "enumerator return to scanresult 0xFE, "
                                                "but final SCAN_REPLY/report meaning is "
                                                "not established"
                                            ),
                                        ),
                                    )
                                ),
                            ),
                        )
                    ),
                ),
                (
                    "trailing",
                    _wire_field("trailing", parsed.trailing_raw, trailing_offset),
                ),
            )
        ),
        evidence=(
            (
                "mpengine 1.443.903.0 hosts_push (0x18059E170) bounded spans, "
                "record identity, and map insertion"
            ),
            (
                "mpengine 1.443.903.0 hosts_callback (0x1804E9580) "
                "exact/wildcard lookup, result writes, and return gate"
            ),
            (
                "mpengine 1.443.903.0 MPEnumHostsEntries (0x1804270AC) "
                "0x29/0x64 callback branches and result consumption"
            ),
            (
                "mpengine 1.443.903.0 kcrce_scanfile (0x18011FBC0) "
                "callback context seed and nonzero enumerator result mapping"
            ),
            (
                "mpengine 1.443.903.0 GetHostsDomain (0x18059E480) "
                "hostname slicing behavior"
            ),
        ),
        profile="mpengine-1.443.903.0",
        issues=tuple(issues),
    )


SPEC = FamilySpec(
    HOSTSENTRY_TYPE,
    "HOSTSENTRY",
    parse_hostsentry,
    render_hostsentry,
    semantic_exporter=export_hostsentry_semantics,
)
