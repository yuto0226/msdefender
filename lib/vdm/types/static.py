"""Parser and concise renderer for STATIC (0x67) payloads."""

from dataclasses import dataclass
from enum import IntEnum
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
from ..recid import RecIdTail, parse_recid_tail

STATIC_TYPE: Final = 0x67
HEADER_SIZE: Final = 18
ALLOW_LARGER_MASK: Final = 0x0001
MODE_MASK: Final = 0x7000
IGNORED_FLAGS_MASK: Final = 0x8FFE


class StaticHashMode(IntEnum):
    MD5 = 0
    SHA1 = 1
    CRC_0 = 2
    SHA1_PREFIX4 = 3
    SHA256 = 4


_HASH_LENGTHS: Final = {
    StaticHashMode.MD5: 16,
    StaticHashMode.SHA1: 20,
    StaticHashMode.CRC_0: 4,
    StaticHashMode.SHA1_PREFIX4: 4,
    StaticHashMode.SHA256: 32,
}


@dataclass(frozen=True, slots=True)
class StaticPayload:
    raw: bytes
    first_page_crc: int
    tail_page_crc: int
    prefix_crc: int
    file_size: int
    flags: int
    allow_larger: bool
    mode_value: int
    mode: StaticHashMode | None
    hash_raw: bytes
    recid_tail: RecIdTail | None
    opaque_raw: bytes

    @property
    def ignored_flags(self) -> int:
        return self.flags & IGNORED_FLAGS_MASK


def parse_static(payload: bytes) -> StaticPayload:
    """Parse a STATIC payload while retaining every input byte."""
    if len(payload) < HEADER_SIZE:
        raise ValueError(
            f"truncated STATIC header: need {HEADER_SIZE} bytes, have {len(payload)}"
        )

    first_page_crc = int.from_bytes(payload[0:4], "little")
    tail_page_crc = int.from_bytes(payload[4:8], "little")
    prefix_crc = int.from_bytes(payload[8:12], "little")
    file_size = int.from_bytes(payload[12:16], "little")
    flags = int.from_bytes(payload[16:18], "little")
    mode_value = (flags >> 12) & 0x7
    allow_larger = bool(flags & ALLOW_LARGER_MASK)

    try:
        mode = StaticHashMode(mode_value)
    except ValueError:
        return StaticPayload(
            raw=payload,
            first_page_crc=first_page_crc,
            tail_page_crc=tail_page_crc,
            prefix_crc=prefix_crc,
            file_size=file_size,
            flags=flags,
            allow_larger=allow_larger,
            mode_value=mode_value,
            mode=None,
            hash_raw=b"",
            recid_tail=None,
            opaque_raw=payload[HEADER_SIZE:],
        )

    hash_size = _HASH_LENGTHS[mode]
    hash_end = HEADER_SIZE + hash_size
    if len(payload) < hash_end:
        raise ValueError(
            f"truncated STATIC {mode.name} hash: need {hash_size} bytes, "
            f"have {len(payload) - HEADER_SIZE}"
        )
    return StaticPayload(
        raw=payload,
        first_page_crc=first_page_crc,
        tail_page_crc=tail_page_crc,
        prefix_crc=prefix_crc,
        file_size=file_size,
        flags=flags,
        allow_larger=allow_larger,
        mode_value=mode_value,
        mode=mode,
        hash_raw=payload[HEADER_SIZE:hash_end],
        recid_tail=parse_recid_tail(payload[hash_end:]),
        opaque_raw=b"",
    )


def _printable_object(data: bytes) -> str | None:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if text and all(char.isprintable() for char in text):
        return text
    return None


def render_static(parsed: StaticPayload) -> FormatResult:
    if parsed.allow_larger:
        file_size = f">= {parsed.file_size} B"
    else:
        file_size = f"{parsed.file_size} B (exact)"

    if parsed.mode is None:
        hash_display = "unavailable"
    elif parsed.mode is StaticHashMode.CRC_0:
        hash_display = f"0x{int.from_bytes(parsed.hash_raw, 'little'):08X}"
    else:
        hash_display = parsed.hash_raw.hex()

    flag_parts = ["allow_larger" if parsed.allow_larger else "exact"]
    if parsed.ignored_flags:
        flag_parts.append(f"loader_ignored=0x{parsed.ignored_flags:04X}")

    hash_mode = (
        f"{parsed.mode.name}({parsed.mode_value})"
        if parsed.mode is not None
        else f"UNSUPPORTED({parsed.mode_value})"
    )
    policy_rows = (
        ("file_size", file_size),
        ("flags", f"{', '.join(flag_parts)} (0x{parsed.flags:04X})"),
        ("hash_mode", hash_mode),
    )
    fingerprint_rows = [
        ("first_page_crc", f"0x{parsed.first_page_crc:08X}"),
        ("tail_page_crc", f"0x{parsed.tail_page_crc:08X}"),
        ("prefix_crc", f"0x{parsed.prefix_crc:08X}"),
        ("hash", hash_display),
    ]
    if parsed.mode is None:
        fingerprint_rows.append(("opaque_len", f"{len(parsed.opaque_raw)} B"))

    sections = [
        DisplaySection("Match Policy", rows=policy_rows),
        DisplaySection("File Fingerprints", rows=tuple(fingerprint_rows)),
    ]
    if parsed.mode is not None and parsed.recid_tail is not None:
        tail = parsed.recid_tail
        identity_rows = [
            ("recid_tail_len", f"{len(tail.raw)} B"),
            ("object_length_limit", f"{tail.length_limit} B"),
            ("effective_object_len", f"{len(tail.object_raw)} B"),
        ]
        if tail.has_object:
            preview = _printable_object(tail.object_raw)
            if preview is not None:
                identity_rows.append(("object_preview", preview))
            else:
                identity_rows.append(("object_preview", "(nonprintable)"))
        else:
            identity_rows.append(("object", "absent"))
        if tail.trailing_raw:
            identity_rows.append(("trailing_len", f"{len(tail.trailing_raw)} B"))
        sections.append(DisplaySection("Record Identity", rows=tuple(identity_rows)))
    return FormatResult(sections=tuple(sections))


def _wire_field(kind: str, raw: bytes, offset: int) -> JSONObject:
    return JSONObject(
        (
            ("kind", kind),
            ("raw_span", JSONObject((("offset", offset), ("length", len(raw))))),
            ("raw_hex", raw.hex()),
        )
    )


def _recid_tail_semantics(tail: RecIdTail | None, offset: int) -> JSONObject | None:
    if tail is None:
        return None
    object_offset = offset + 1
    trailing_offset = object_offset + len(tail.object_raw)
    return JSONObject(
        (
            ("wire", _wire_field("recid_tail", tail.raw, offset)),
            ("length_limit", tail.length_limit),
            (
                "object",
                _wire_field("opaque_object", tail.object_raw, object_offset),
            ),
            ("object_present", tail.has_object),
            (
                "trailing",
                _wire_field("tail_surplus", tail.trailing_raw, trailing_offset),
            ),
            ("producer_meaning", None),
        )
    )


def export_static_semantics(parsed: StaticPayload) -> RuleSemantics:
    """Export the confirmed STATIC receiver and staged hash-match subset."""
    issues = [
        SemanticIssue(
            "final_match_not_determined",
            "This record alone cannot determine a match; file bytes and runtime "
            "conditions are required.",
        ),
        SemanticIssue(
            "allow_larger_gates_incomplete",
            "Larger-file matches also depend on threat exceptions and "
            "valid-signature checks.",
        ),
    ]
    mode = parsed.mode
    if mode is None:
        return RuleSemantics(
            status="unsupported",
            representation="static.match.ir.v1",
            data=JSONObject(
                (
                    ("type", "STATIC"),
                    ("raw_hex", parsed.raw.hex()),
                    ("mode_value", parsed.mode_value),
                    ("hash", None),
                    (
                        "opaque_after_header",
                        _wire_field("opaque", parsed.opaque_raw, HEADER_SIZE),
                    ),
                )
            ),
            evidence=(
                "mpengine 1.443.903.0 staticrec_t::Load modes 5-7 assertion path",
                (
                    "mpengine 1.443.903.0 StaticHashProvider::CompareValues rejects "
                    "modes 5-7"
                ),
            ),
            profile="mpengine-1.443.903.0",
            issues=(
                SemanticIssue(
                    "unsupported_hash_mode",
                    "Modes 5 through 7 are not accepted for complete STATIC hash "
                    "matching.",
                    (("mode", parsed.mode_value),),
                ),
            ),
        )

    hash_size = len(parsed.hash_raw)
    hash_offset = HEADER_SIZE
    tail_offset = hash_offset + hash_size
    unresolved = parsed.ignored_flags
    if unresolved:
        issues.append(
            SemanticIssue(
                "loader_ignored_flag_bits",
                "These flag bits are ignored by the STATIC loader; no semantic "
                "names are assigned.",
                (("value", unresolved),),
            )
        )
    if mode in {StaticHashMode.SHA1_PREFIX4, StaticHashMode.SHA256}:
        issues.append(
            SemanticIssue(
                "mode_not_observed_in_corpus",
                "This mode is confirmed by current-binary code paths but has no "
                "mpas.sig or mpav.sig sample.",
                (("mode", int(mode)),),
            )
        )
    if parsed.allow_larger:
        issues.append(
            SemanticIssue(
                "larger_file_match_is_conditional",
                "allow_larger permits a size mismatch through an early stage only; "
                "later conditions still apply.",
            )
        )
    if parsed.recid_tail is not None and parsed.recid_tail.has_object:
        issues.append(
            SemanticIssue(
                "recid_object_meaning_unknown",
                "The bounded object is passed to createrecidpc, but its producer "
                "meaning is unknown.",
            )
        )
    if (
        parsed.recid_tail is not None
        and parsed.recid_tail.length_limit > len(parsed.recid_tail.raw) - 1
    ):
        issues.append(
            SemanticIssue(
                "recid_object_truncated",
                "The RecID object is shorter than its declared length.",
                (
                    ("declared_length", parsed.recid_tail.length_limit),
                    ("available_length", len(parsed.recid_tail.raw) - 1),
                ),
            )
        )
    if parsed.recid_tail is not None and parsed.recid_tail.trailing_raw:
        issues.append(
            SemanticIssue(
                "recid_tail_surplus_uninterpreted",
                "Bytes beyond the length-limited RecID object are retained without "
                "semantics.",
                (("length", len(parsed.recid_tail.trailing_raw)),),
            )
        )

    hash_data: JSONObject
    if mode is StaticHashMode.CRC_0:
        hash_data = JSONObject(
            (
                ("algorithm", "CRC_0"),
                ("wire", _wire_field("crc_u32le", parsed.hash_raw, hash_offset)),
                ("value", int.from_bytes(parsed.hash_raw, "little")),
            )
        )
    else:
        algorithm = {
            StaticHashMode.MD5: "MD5",
            StaticHashMode.SHA1: "SHA1",
            StaticHashMode.SHA1_PREFIX4: "SHA1_prefix4",
            StaticHashMode.SHA256: "SHA256",
        }[mode]
        hash_data = JSONObject(
            (
                ("algorithm", algorithm),
                ("wire", _wire_field("hash_bytes", parsed.hash_raw, hash_offset)),
                ("value_hex", parsed.hash_raw.hex()),
            )
        )

    recid_unsupported = parsed.recid_tail is not None and (
        parsed.recid_tail.has_object
        or bool(parsed.recid_tail.trailing_raw)
        or parsed.recid_tail.length_limit > len(parsed.recid_tail.raw) - 1
    )
    return RuleSemantics(
        status="unsupported" if recid_unsupported else "confirmed_subset",
        representation="static.match.ir.v1",
        data=JSONObject(
            (
                ("type", "STATIC"),
                ("raw_hex", parsed.raw.hex()),
                (
                    "header",
                    JSONObject(
                        (
                            (
                                "first_page_crc",
                                JSONObject(
                                    (
                                        ("value", parsed.first_page_crc),
                                        (
                                            "wire",
                                            _wire_field(
                                                "first_4096_crc_u32le",
                                                parsed.raw[0:4],
                                                0,
                                            ),
                                        ),
                                    )
                                ),
                            ),
                            (
                                "tail_page_crc",
                                JSONObject(
                                    (
                                        ("value", parsed.tail_page_crc),
                                        (
                                            "wire",
                                            _wire_field(
                                                "tail_4096_crc_u32le",
                                                parsed.raw[4:8],
                                                4,
                                            ),
                                        ),
                                    )
                                ),
                            ),
                            (
                                "prefix_crc",
                                JSONObject(
                                    (
                                        ("value", parsed.prefix_crc),
                                        (
                                            "wire",
                                            _wire_field(
                                                "prefix_crc_u32le",
                                                parsed.raw[8:12],
                                                8,
                                            ),
                                        ),
                                    )
                                ),
                            ),
                            (
                                "file_size",
                                JSONObject(
                                    (
                                        ("value", parsed.file_size),
                                        (
                                            "wire",
                                            _wire_field(
                                                "file_size_u32le",
                                                parsed.raw[12:16],
                                                12,
                                            ),
                                        ),
                                        (
                                            "comparison",
                                            "at_least"
                                            if parsed.allow_larger
                                            else "exact",
                                        ),
                                    )
                                ),
                            ),
                        )
                    ),
                ),
                (
                    "flags",
                    JSONObject(
                        (
                            (
                                "wire",
                                _wire_field("flags_u16le", parsed.raw[16:18], 16),
                            ),
                            ("allow_larger", parsed.allow_larger),
                            ("mode", int(mode)),
                            ("loader_ignored_bits", unresolved),
                        )
                    ),
                ),
                ("hash", hash_data),
                (
                    "match_pipeline",
                    JSONArray(
                        (
                            "first_page_crc_candidate_key",
                            "prefix_crc_up_to_min(file_size, 65536)",
                            "tail_crc_of_last_up_to_4096_bytes_zero_padded_when_short",
                            "file_size_policy",
                            "mode_specific_hash_validation",
                        )
                    ),
                ),
                (
                    "recid_tail",
                    _recid_tail_semantics(parsed.recid_tail, tail_offset),
                ),
            )
        ),
        evidence=(
            "mpengine 1.443.903.0 staticrec_t::Load mode lengths and hash storage",
            (
                "mpengine 1.443.903.0 StaticHashProvider::CompareValues staged "
                "CRC/size/hash flow"
            ),
            "mpengine 1.443.903.0 GetHashes mode-to-algorithm mapping",
            "mpas.sig/mpav.sig corpus: modes 0-2 observed; modes 3-4 absent",
        ),
        profile="mpengine-1.443.903.0",
        issues=tuple(issues),
    )


SPEC = FamilySpec(
    STATIC_TYPE,
    "STATIC",
    parse_static,
    render_static,
    semantic_exporter=export_static_semantics,
)
