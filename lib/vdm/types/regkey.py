"""Lossless parser for REGKEY (0x63) records."""

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

REGKEY_TYPE: Final = 0x63


@dataclass(frozen=True, slots=True)
class RegKeyPayload:
    """Decoded boundaries and raw byte slices for a REGKEY payload."""

    raw: bytes
    key_type: int
    key_path_len: int
    key_path_raw: bytes
    key_path: str | None
    value_len: int
    value_raw: bytes
    value_utf8_preview: str | None
    tail_raw: bytes


def _decode_utf8(data: bytes) -> str | None:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _decode_printable_utf8_preview(data: bytes) -> str | None:
    if not data:
        return None
    decoded = _decode_utf8(data)
    if decoded is None or not decoded.isprintable():
        return None
    return decoded


def parse_regkey(payload: bytes) -> RegKeyPayload:
    """Parse REGKEY's two length-prefixed fields and retain all trailing bytes."""
    if len(payload) < 4:
        raise ValueError(f"truncated REGKEY header: need 4 bytes, have {len(payload)}")

    key_type = int.from_bytes(payload[0:2], "little")
    key_path_len = int.from_bytes(payload[2:4], "little")
    key_path_end = 4 + key_path_len
    if key_path_end > len(payload):
        raise ValueError(
            "truncated REGKEY key_path: "
            f"need {key_path_len} bytes, have {len(payload) - 4}"
        )

    value_len_offset = key_path_end
    if value_len_offset + 2 > len(payload):
        available = len(payload) - value_len_offset
        raise ValueError(f"truncated REGKEY value_len: need 2 bytes, have {available}")

    value_len = int.from_bytes(
        payload[value_len_offset : value_len_offset + 2], "little"
    )
    value_offset = value_len_offset + 2
    value_end = value_offset + value_len
    if value_end > len(payload):
        raise ValueError(
            f"truncated REGKEY value: need {value_len} bytes, "
            f"have {len(payload) - value_offset}"
        )

    key_path_raw = payload[4:key_path_end]
    key_path = _decode_utf8(key_path_raw)
    value_raw = payload[value_offset:value_end]
    return RegKeyPayload(
        raw=payload,
        key_type=key_type,
        key_path_len=key_path_len,
        key_path_raw=key_path_raw,
        key_path=key_path,
        value_len=value_len,
        value_raw=value_raw,
        value_utf8_preview=_decode_printable_utf8_preview(value_raw),
        tail_raw=payload[value_end:],
    )


def render_regkey(parsed: RegKeyPayload) -> FormatResult:
    key_type = f"0x{parsed.key_type:04x}"

    rows: list[tuple[str, str]] = [
        ("key_type", key_type),
        ("key_path_len", str(parsed.key_path_len)),
    ]
    if parsed.key_path is not None:
        rows.append(("key_path", parsed.key_path or "(empty)"))
    else:
        rows.append(("key_path_raw", parsed.key_path_raw.hex(" ") or "(empty)"))
        rows.append(("key_path_text", "invalid UTF-8; raw bytes preserved"))
    rows.extend((("value_len", str(parsed.value_len)),))
    if parsed.value_utf8_preview is not None:
        rows.append(("value_utf8_preview", parsed.value_utf8_preview))
    elif parsed.value_raw:
        rows.append(("value_raw", parsed.value_raw.hex(" ")))

    sections = [DisplaySection("Registry key", rows=tuple(rows))]
    if parsed.tail_raw:
        sections.append(
            DisplaySection(
                "Unclassified trailing bytes",
                rows=(("tail_len", str(len(parsed.tail_raw))),),
            )
        )
    return FormatResult(sections=tuple(sections))


def export_regkey_semantics(parsed: RegKeyPayload) -> RuleSemantics:
    """Export the confirmed REGKEY wire fields without guessing selector meaning."""
    selector_accepted = 1 <= parsed.key_type <= 4
    issues = [
        SemanticIssue(
            "regkey_selector_names_unknown",
            "The receiver stores selectors 1 through 4 as internal values 0 through 3; "
            "the binary does not establish symbolic names or hive identities.",
        ),
        SemanticIssue(
            "regkey_prefix_table_unexpanded",
            "Store_UTF8_Reg strips the first matching entry from an 11-entry, "
            "case-insensitive prefix table; the table strings are not named here.",
        ),
        SemanticIssue(
            "regkey_expansion_comparator_unknown",
            "REG_SZ/REG_EXPAND_SZ may use expand_path_cmp after direct comparison; "
            "that helper's expansion rules are not modeled.",
        ),
    ]
    if not selector_accepted:
        status = "ignored"
        issues.append(
            SemanticIssue(
                "receiver_ignored_selector",
                "The receiver returns success without registering selector values "
                "outside the accepted range 1 through 4.",
                (("selector", parsed.key_type),),
            )
        )
    elif parsed.key_path is None:
        status = "unsupported"
        issues.append(
            SemanticIssue(
                "invalid_utf8_path",
                "The path bytes are not valid UTF-8, so Store_UTF8_Reg processing "
                "cannot be represented faithfully.",
            )
        )
    elif parsed.tail_raw:
        status = "unsupported"
        issues.append(
            SemanticIssue(
                "regkey_trailing_bytes_semantics_unknown",
                "Trailing bytes are retained; their RecID/program meaning is not "
                "established by this semantic representation.",
                (("length", len(parsed.tail_raw)),),
            )
        )
    else:
        status = "confirmed_subset"

    return RuleSemantics(
        status=status,
        representation="regkey.registry_matcher_subset.v2",
        data=JSONObject(
            (
                ("type", "regkey"),
                ("raw_hex", parsed.raw.hex()),
                (
                    "selector",
                    JSONObject(
                        (
                            ("wire_offset", 0),
                            ("raw_u16", parsed.key_type),
                            ("registration_accepted", selector_accepted),
                            ("semantic_name", None),
                            (
                                "internal_value",
                                parsed.key_type - 1 if selector_accepted else None,
                            ),
                            ("hive_mapping", "not-established"),
                        )
                    ),
                ),
                (
                    "path_field",
                    JSONObject(
                        (
                            ("wire_offset", 4),
                            ("length", parsed.key_path_len),
                            ("raw_hex", parsed.key_path_raw.hex()),
                            ("decoded_utf8", parsed.key_path),
                            (
                                "runtime_normalization",
                                "strip-first-case-insensitive-prefix; split-at-first-double-backslash",
                            ),
                        )
                    ),
                ),
                (
                    "value_field",
                    JSONObject(
                        (
                            ("length", parsed.value_len),
                            ("raw_hex", parsed.value_raw.hex()),
                            ("printable_utf8_preview", parsed.value_utf8_preview),
                            (
                                "runtime_role",
                                "registry value name (when path splits); otherwise absent",
                            ),
                        )
                    ),
                ),
                ("trailing_hex", parsed.tail_raw.hex()),
                (
                    "storage_routing",
                    JSONObject(
                        (
                            ("possible_tables", JSONArray(("general", "ASEP"))),
                            (
                                "record_assignment",
                                "ASEP when no double-backslash separator is found and a value field exists; general otherwise",
                            ),
                        )
                    ),
                ),
                (
                    "matcher",
                    JSONObject(
                        (
                            ("candidate_lookup", "confirmed"),
                            (
                                "comparison",
                                (
                                    "REG_SZ/EXPAND_SZ case-insensitive text "
                                    "(then expansion helper); REG_BINARY exact bytes; "
                                    "DWORD/BIG_ENDIAN decimal text"
                                ),
                            ),
                            ("selector_to_hive_mapping", None),
                        )
                    ),
                ),
            )
        ),
        evidence=(
            "mpengine 1.443.903.0 reg_key_DB_receiver",
            "mpengine 1.443.903.0 reg_key_DB_end",
            "mpengine 1.443.903.0 is_rkey_in_DB",
            "mpengine 1.443.903.0 is_rkey_in_asep_DB",
            "mpengine 1.443.903.0 reg_key_in_hive",
            "mpas.sig/mpav.sig REGKEY corpus invariants",
        ),
        profile="mpengine-1.443.903.0",
        issues=tuple(issues),
    )


SPEC = FamilySpec(
    REGKEY_TYPE,
    "REGKEY",
    parse_regkey,
    render_regkey,
    semantic_exporter=export_regkey_semantics,
)
