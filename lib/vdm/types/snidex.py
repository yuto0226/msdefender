"""Typed models for extended SNID hash records 0xE5 and 0xE6."""

import hashlib
import json
from dataclasses import dataclass
from typing import Final

from ..core import (
    Artifact,
    ArtifactExport,
    DisplaySection,
    FamilySpec,
    FormatResult,
    JSONObject,
    RuleSemantics,
    SemanticIssue,
)

SNIDEX_TYPE: Final = 0xE5
SNIDEX2_TYPE: Final = 0xE6
_TEXT_PREVIEW: Final = 256


@dataclass(frozen=True, slots=True)
class SnidExPayload:
    type: int
    raw: bytes
    key_blocks: tuple[bytes, ...]
    category_value: int
    recid_input_raw: bytes

    @property
    def object_raw(self) -> bytes | None:
        """Return the exact bytes interned by ``createrecidz``, when present."""
        if not self.recid_input_raw or self.recid_input_raw[0] == 0:
            return None
        nul = self.recid_input_raw.find(b"\0")
        return self.recid_input_raw if nul < 0 else self.recid_input_raw[: nul + 1]

    @property
    def ignored_trailing_raw(self) -> bytes:
        """Return bytes after the first NUL that the receiver does not intern."""
        if not self.recid_input_raw:
            return b""
        nul = self.recid_input_raw.find(b"\0")
        return b"" if nul < 0 else self.recid_input_raw[nul + 1 :]


def parse_snidex(payload: bytes, type_byte: int = SNIDEX_TYPE) -> SnidExPayload:
    """Parse fixed opaque hash chunks, category, and optional label bytes."""
    if type_byte not in {SNIDEX_TYPE, SNIDEX2_TYPE}:
        raise ValueError(f"unsupported SNIDEX type 0x{type_byte:02X}")
    hash_count = 2 if type_byte == SNIDEX_TYPE else 4
    prefix_size = hash_count * 16 + 1
    if len(payload) < prefix_size:
        raise ValueError(
            f"truncated SNIDEX fixed prefix: need {prefix_size} bytes, "
            f"have {len(payload)}"
        )
    key_blocks = tuple(
        payload[offset : offset + 16] for offset in range(0, hash_count * 16, 16)
    )
    return SnidExPayload(
        type=type_byte,
        raw=payload,
        key_blocks=key_blocks,
        category_value=payload[hash_count * 16],
        recid_input_raw=payload[prefix_size:],
    )


def _parser_for(type_byte: int):
    return lambda payload: parse_snidex(payload, type_byte)


def _text_preview(raw: bytes) -> str | None:
    if raw.endswith(b"\0"):
        raw = raw[:-1]
    try:
        text = raw[:_TEXT_PREVIEW].decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not text or not all(character.isprintable() for character in text):
        return None
    return repr(text) + (" ..." if len(raw) > _TEXT_PREVIEW else "")


def render_snidex(parsed: SnidExPayload) -> FormatResult:
    rows = [
        ("type", f"0x{parsed.type:02X}"),
        ("key_blocks", str(len(parsed.key_blocks))),
    ]
    rows.extend(
        (f"key_block[{index}]", value.hex(" "))
        for index, value in enumerate(parsed.key_blocks)
    )
    object_raw = parsed.object_raw
    identity_preview = _text_preview(object_raw) if object_raw is not None else None
    rows.extend(
        (
            ("category_value", f"0x{parsed.category_value:02X} (semantics unresolved)"),
            ("recid_input_length", str(len(parsed.recid_input_raw))),
            (
                "interned_object_length",
                "none" if object_raw is None else f"{len(object_raw)} B",
            ),
            (
                "identity_text_preview",
                identity_preview if identity_preview is not None else "unavailable",
            ),
            ("receiver_ignored_length", str(len(parsed.ignored_trailing_raw))),
        )
    )
    title = "SNIDEX2" if parsed.type == SNIDEX2_TYPE else "SNIDEX"
    return FormatResult(sections=(DisplaySection(title, rows=tuple(rows)),))


def export_snidex_semantics(parsed: SnidExPayload) -> RuleSemantics:
    """Export confirmed matching/report structure without naming opaque keys."""
    prefix_size = len(parsed.key_blocks) * 16 + 1
    raw_key = b"".join(parsed.key_blocks)
    record_name = "SNIDEX2" if parsed.type == SNIDEX2_TYPE else "SNIDEX"
    if parsed.type == SNIDEX2_TYPE:
        report_path = JSONObject(
            (
                (
                    "attribute_name",
                    JSONObject(
                        (
                            (
                                "without_reply",
                                "return_state_1_and_optionally_write_out_recid",
                            ),
                            (
                                "with_reply",
                                "MpAggregateAttributeEx_then_ShouldContinueScanning",
                            ),
                        )
                    ),
                ),
                (
                    "ordinary_name",
                    JSONObject(
                        (
                            ("gate", "nid64search_type_108_by_sequence"),
                            (
                                "gate_nonzero",
                                (
                                    "state_2; with reply SetDetectionData then "
                                    "ShouldContinueScanning"
                                ),
                            ),
                            (
                                "gate_zero",
                                (
                                    "state_1; with reply SetDetectionData then "
                                    "ShouldContinueScanning and delayed-detection gate"
                                ),
                            ),
                        )
                    ),
                ),
            )
        )
    else:
        report_path = JSONObject(
            (
                (
                    "attribute_name",
                    JSONObject(
                        (
                            ("without_reply", "return_nonzero_match_state"),
                            ("with_reply", "write_out_recid"),
                        )
                    ),
                ),
                (
                    "ordinary_name",
                    JSONObject(
                        (
                            ("gate", "nid64search_type_108_by_sequence"),
                            ("gate_result_zero", "ordinary_match_state"),
                            ("gate_result_nonzero", "alternate_match_state"),
                            ("reply_present", "write_out_recid"),
                        )
                    ),
                ),
            )
        )
    recid = JSONObject(
        (
            ("input_raw_hex", parsed.recid_input_raw.hex()),
            (
                "mode",
                "outer_threat_and_sig_ids"
                if not parsed.recid_input_raw
                else "createrecidz_then_resolve_threat_and_sig_ids",
            ),
            (
                "interned_object_raw_hex",
                None if parsed.object_raw is None else parsed.object_raw.hex(),
            ),
            ("ignored_after_first_nul_hex", parsed.ignored_trailing_raw.hex()),
            (
                "first_nul_included_in_object",
                bool(parsed.object_raw and parsed.object_raw.endswith(b"\0")),
            ),
        )
    )

    return RuleSemantics(
        status="confirmed_subset",
        representation="snidex.exact_match_entry.v2",
        data=JSONObject(
            (
                ("type", record_name),
                ("raw_hex", parsed.raw.hex()),
                (
                    "wire_entry",
                    JSONObject(
                        (
                            ("raw_key_hex", raw_key.hex()),
                            ("raw_key_length", len(raw_key)),
                            ("category_byte", parsed.category_value),
                            ("category_offset", len(raw_key)),
                            ("recid_input_offset", prefix_size),
                            ("recid", recid),
                        )
                    ),
                ),
                (
                    "lookup",
                    JSONObject(
                        (
                            (
                                "prefilter",
                                "four_bloom_bit_probes_if_filter_nonempty",
                            ),
                            ("candidate_range", "std_equal_range_by_query_selector"),
                            ("exact_raw_key_compare", "memcmp"),
                            ("exact_raw_key_length", len(raw_key)),
                            ("exact_category_compare", "single_byte_equality"),
                            ("exact_category_value", parsed.category_value),
                            ("query_selector_width", 32),
                            ("provider_selector_source", "unknown"),
                            ("raw_key_generation", "unknown"),
                            ("raw_key_byte_order", "unknown"),
                        )
                    ),
                ),
                (
                    "matched_entry_report_path",
                    JSONObject(
                        (
                            ("resolve_threat_name", True),
                            ("read_signature_sequence", True),
                            (
                                "signature_sha_input",
                                f"type_0x{parsed.type:02x}_plus_wire_prefix_{prefix_size}_bytes",
                            ),
                            ("report_path", report_path),
                            ("final_verdict", "unknown"),
                        )
                    ),
                ),
            )
        ),
        evidence=(
            (
                "mpengine 1.443.903.0 SNIDEX Lookup 0x180477668 and "
                "RecordPush 0x180540574"
            ),
            (
                "mpengine 1.443.903.0 SNIDEX2 Lookup 0x18052EFB0 and "
                "RecordPush 0x18055B540"
            ),
            "mpengine 1.443.903.0 createrecidz",
            "mpengine 1.443.903.0 nid64searchrecidex",
            "mpas.sig corpus: 123 SNIDEX and 50 SNIDEX2 records",
            "mpav.sig corpus: no SNIDEX or SNIDEX2 records",
        ),
        profile="mpengine-1.443.903.0",
        issues=(
            SemanticIssue(
                "snidex_key_inputs_unknown",
                "Lookup confirms a 32-bit selector, exact raw-key comparison, "
                "and exact category-byte comparison, but this bounded caller "
                "search did not locate the selector/key producer. Hash family, "
                "normalization, byte order, category meaning, and final scan "
                "verdict remain unknown.",
            ),
        ),
    )


def export_snidex_artifact(parsed: SnidExPayload) -> ArtifactExport:
    """Export opaque exact-match key blocks and metadata as raw observations."""
    prefix_size = len(parsed.key_blocks) * 16 + 1
    manifest = {
        "schema": "vdm.snidex.artifact.v1",
        "record_type": {
            "byte": parsed.type,
            "name": "SNIDEX2" if parsed.type == SNIDEX2_TYPE else "SNIDEX",
        },
        "raw_hex": parsed.raw.hex(),
        "key_blocks": [
            {"index": index, "offset": index * 16, "raw_hex": block.hex()}
            for index, block in enumerate(parsed.key_blocks)
        ],
        "category": {
            "offset": len(parsed.key_blocks) * 16,
            "raw_hex": bytes((parsed.category_value,)).hex(),
            "value": parsed.category_value,
        },
        "recid_input": {
            "offset": prefix_size,
            "raw_hex": parsed.recid_input_raw.hex(),
            "interned_object_raw_hex": (
                None if parsed.object_raw is None else parsed.object_raw.hex()
            ),
            "receiver_ignored_after_nul_raw_hex": parsed.ignored_trailing_raw.hex(),
        },
        "matcher_boundary": {
            "confirmed_operation": "exact_raw_key_and_category_byte_comparison",
            "key_generation": "unknown",
            "provider_selector": "unknown",
            "recid_or_pcode_effect": "unknown",
            "final_report_or_verdict": "unknown",
        },
    }
    data = (
        json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")
    digest = hashlib.sha256(parsed.raw).hexdigest()[:16]
    return ArtifactExport(
        "ready",
        artifacts=(
            Artifact(f"{parsed.type:02x}-{digest}.json", "snidex_json_manifest", data),
        ),
    )


SNIDEX_SPEC = FamilySpec(
    SNIDEX_TYPE,
    "SNIDEX",
    _parser_for(SNIDEX_TYPE),
    render_snidex,
    exporter=export_snidex_artifact,
    semantic_exporter=export_snidex_semantics,
)
SNIDEX2_SPEC = FamilySpec(
    SNIDEX2_TYPE,
    "SNIDEX2",
    _parser_for(SNIDEX2_TYPE),
    render_snidex,
    exporter=export_snidex_artifact,
    semantic_exporter=export_snidex_semantics,
)
SNIDEX_SPECS: Final = (SNIDEX_SPEC, SNIDEX2_SPEC)
