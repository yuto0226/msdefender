"""Lossless parsers for the MACRO_PCODE record families."""

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

MACRO_PCODE_TYPE: Final = 0x42
MACRO_PCODE64_TYPE: Final = 0xCF
MACRO_PCODE_NAME_PREVIEW_LIMIT: Final = 32
MACRO_PCODE_TAIL_PREVIEW_LIMIT: Final = 32


@dataclass(frozen=True, slots=True)
class MacroPcodePayload:
    """Three normalized header values and the complete NUL-delimited tail."""

    fields: tuple[int, int, int]
    wire_width: int
    tail: bytes
    name_bytes: bytes
    suffix: bytes


def _parse_macro_pcode(payload: bytes, type_byte: int) -> MacroPcodePayload:
    if type_byte == MACRO_PCODE_TYPE:
        width = 4
    elif type_byte == MACRO_PCODE64_TYPE:
        width = 8
    else:
        raise ValueError(f"unsupported MACRO_PCODE type 0x{type_byte:02X}")

    header_size = width * 3
    if len(payload) < header_size:
        raise ValueError(
            "truncated MACRO_PCODE header: "
            f"need {header_size} bytes, have {len(payload)}"
        )

    fields = tuple(
        int.from_bytes(payload[offset : offset + width], "little")
        for offset in range(0, header_size, width)
    )
    tail = payload[header_size:]
    if tail:
        nul_offset = tail.find(b"\0")
        if nul_offset < 0:
            raise ValueError("invalid MACRO_PCODE tail: missing NUL terminator")
        name_bytes = tail[:nul_offset]
        suffix = tail[nul_offset + 1 :]
    else:
        name_bytes = b""
        suffix = b""

    return MacroPcodePayload(
        fields=(fields[0], fields[1], fields[2]),
        wire_width=width,
        tail=tail,
        name_bytes=name_bytes,
        suffix=suffix,
    )


def parse_macro_pcode(payload: bytes) -> MacroPcodePayload:
    """Parse the 32-bit MACRO_PCODE (0x42) record."""
    return _parse_macro_pcode(payload, MACRO_PCODE_TYPE)


def parse_macro_pcode64(payload: bytes) -> MacroPcodePayload:
    """Parse the 64-bit MACRO_PCODE64 (0xCF) record."""
    return _parse_macro_pcode(payload, MACRO_PCODE64_TYPE)


def render_macro_pcode(parsed: MacroPcodePayload) -> FormatResult:
    """Render fixed-width normalized fields and bounded tail previews."""
    rows = [
        (f"field{index}", f"0x{value:0{parsed.wire_width * 2}x}")
        for index, value in enumerate(parsed.fields)
    ]
    name_preview = parsed.name_bytes[:MACRO_PCODE_NAME_PREVIEW_LIMIT]
    rows.extend(
        (
            ("wire_width", str(parsed.wire_width)),
            ("tail_length", str(len(parsed.tail))),
            ("name_preview", name_preview.hex(" ")),
            (
                "name_omitted_bytes",
                str(len(parsed.name_bytes) - len(name_preview)),
            ),
            ("suffix_length", str(len(parsed.suffix))),
        )
    )
    if parsed.tail:
        rows.append(
            (
                "tail_preview",
                parsed.tail[:MACRO_PCODE_TAIL_PREVIEW_LIMIT].hex(" "),
            )
        )
    return FormatResult(sections=(DisplaySection("MACRO_PCODE", rows=tuple(rows)),))


def export_macro_pcode_semantics(parsed: MacroPcodePayload) -> RuleSemantics:
    """Export neutral header fields and the confirmed RME key/report path."""
    header_size = parsed.wire_width * 3
    type_byte = MACRO_PCODE_TYPE if parsed.wire_width == 4 else MACRO_PCODE64_TYPE
    header_raw = b"".join(
        value.to_bytes(parsed.wire_width, "little") for value in parsed.fields
    )
    fields = JSONArray(
        tuple(
            JSONObject(
                (
                    ("name", f"field{index}"),
                    ("value", value),
                    ("raw_hex", value.to_bytes(parsed.wire_width, "little").hex()),
                    ("offset", index * parsed.wire_width),
                )
            )
            for index, value in enumerate(parsed.fields)
        )
    )
    issues = [
        SemanticIssue(
            "header_field_names_unknown",
            "The three header values participate in signature keys, but their "
            "individual business names are not confirmed.",
        ),
        SemanticIssue(
            "scan_policy_unknown",
            "ShouldContinueScanning receives a candidate and signature "
            "metadata; its policy meaning is not exported.",
        ),
        SemanticIssue(
            "final_verdict_unknown",
            "The observed RME lookup/report path does not establish a final "
            "host-visible verdict.",
        ),
    ]
    if parsed.suffix:
        issues.append(
            SemanticIssue(
                "nul_suffix_semantics_unknown",
                "Bytes after the first NUL are passed through but have no "
                "confirmed semantic role.",
                (("length", len(parsed.suffix)),),
            )
        )

    recid_construction = (
        JSONObject(
            (
                ("kind", "createrecid"),
                ("extra_id", 0xFFFFFFFF),
                ("identity_source", "outer_threat_and_signature_ids"),
            )
        )
        if not parsed.tail
        else JSONObject(
            (
                ("kind", "createrecidz"),
                ("tail_raw_hex", parsed.tail.hex()),
                ("tail_length", len(parsed.tail)),
                ("interned_prefix_raw_hex", parsed.name_bytes.hex()),
                ("nul_suffix_raw_hex", parsed.suffix.hex()),
                ("nul_suffix_role", "unknown"),
            )
        )
    )

    return RuleSemantics(
        status="unsupported" if parsed.suffix else "confirmed_subset",
        representation="macro_pcode.signature_key.ir.v1",
        data=JSONObject(
            (
                ("type_byte", type_byte),
                ("raw_hex", (header_raw + parsed.tail).hex()),
                ("wire_width", parsed.wire_width),
                ("header_length", header_size),
                ("header_raw_hex", header_raw.hex()),
                ("fields", fields),
                (
                    "native_entry",
                    JSONObject(
                        (
                            ("kind", "pcode_virrec"),
                            ("stride", 0x20),
                            (
                                "header_field_offsets",
                                JSONArray((0, 8, 16)),
                            ),
                            ("recid_offset", 0x18),
                            ("width_selector_offset", 0x1C),
                            ("width_selector", 0 if parsed.wire_width == 4 else 1),
                        )
                    ),
                ),
                ("tail_raw_hex", parsed.tail.hex()),
                ("tail_length", len(parsed.tail)),
                ("interned_prefix_raw_hex", parsed.name_bytes.hex()),
                ("nul_suffix_raw_hex", parsed.suffix.hex()),
                ("recid_construction", recid_construction),
                (
                    "signature_keys",
                    JSONObject(
                        (
                            (
                                "sha",
                                JSONObject(
                                    (
                                        ("algorithm", "MakeSigSha"),
                                        ("type_byte", type_byte),
                                        ("header_length", header_size),
                                        ("header_raw_hex", header_raw.hex()),
                                        ("value", "not_computed"),
                                    )
                                ),
                            ),
                            (
                                "sequence",
                                JSONObject(
                                    (
                                        ("algorithm", "CRC_1"),
                                        ("type_byte", type_byte),
                                        ("header_length", header_size),
                                        ("header_raw_hex", header_raw.hex()),
                                        ("tag_encoding", "unknown"),
                                        ("value", "not_computed"),
                                    )
                                ),
                            ),
                        )
                    ),
                ),
                (
                    "rme_lookup",
                    JSONObject(
                        (
                            ("kind", "exact_ordered_key_lookup"),
                            ("search", "bsearch_and_adjacent_equal_key_scan"),
                            (
                                "comparators",
                                JSONArray(("pcodevirrec_cmp", "pcodevirrec_cmp2")),
                            ),
                            (
                                "key_regions",
                                JSONArray(
                                    (
                                        JSONObject((("offset", 8), ("length", 8))),
                                        JSONObject((("offset", 0), ("length", 8))),
                                    )
                                ),
                            ),
                        )
                    ),
                ),
                (
                    "report_path",
                    JSONArray(
                        (
                            "RME::find_pcrc",
                            "ShouldContinueScanning",
                            "RME::O97Scan",
                            "RME::reportvirus",
                        )
                    ),
                ),
                ("scan_policy", "unknown"),
                ("final_verdict", "unknown"),
            )
        ),
        evidence=(
            (
                "macro_pcode_push and macro_pcode64_push preserve three 32-bit or "
                "64-bit header values"
            ),
            (
                "pcode_virrec::GetSigSha uses MakeSigSha over type and "
                "width-specific header bytes"
            ),
            (
                "pcode_virrec::GetSigSeq uses CRC_1 over the width-specific header "
                "and type/length tag"
            ),
            (
                "RME::find_pcrc uses ordered safecrc comparisons and passes "
                "candidate RecID/SigSeq/SigSha to ShouldContinueScanning"
            ),
        ),
        profile="mpengine-1.443.903.0",
        issues=tuple(issues),
    )


MACRO_PCODE_SPEC = FamilySpec(
    MACRO_PCODE_TYPE,
    "MACRO_PCODE",
    parse_macro_pcode,
    render_macro_pcode,
    semantic_exporter=export_macro_pcode_semantics,
)
MACRO_PCODE64_SPEC = FamilySpec(
    MACRO_PCODE64_TYPE,
    "MACRO_PCODE64",
    parse_macro_pcode64,
    render_macro_pcode,
    semantic_exporter=export_macro_pcode_semantics,
)
MACRO_PCODE_SPECS = (MACRO_PCODE_SPEC, MACRO_PCODE64_SPEC)
