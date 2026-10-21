"""Typed parser for THREAT_UPDATE_STATUS (0xC3) records."""

from dataclasses import dataclass
from typing import Final

from ..core import (
    FamilySpec,
    FormatResult,
    JSONArray,
    JSONObject,
    RuleSemantics,
    SemanticIssue,
)

_NAME_PREVIEW_BYTES = 64
_NAME_PREVIEW_CHARS = 96
_TAIL_PREVIEW_BYTES = 32
THREAT_UPDATE_STATUS_TYPE: Final = 0xC3


@dataclass(frozen=True, slots=True)
class ThreatUpdateStatusPayload:
    """Lossless bytes plus safely decoded view of a 0xC3 payload."""

    raw: bytes
    name_len: int
    name_raw: bytes
    name: str
    word_08: int
    word_0c: int
    trailing_raw: bytes


def _safe_name(raw: bytes) -> str:
    decoded = raw.decode("utf-8", errors="replace")
    safe: list[str] = []
    for char in decoded:
        codepoint = ord(char)
        if char == "\\":
            safe.append("\\\\")
        elif char.isprintable():
            safe.append(char)
        elif codepoint <= 0xFF:
            safe.append(f"\\x{codepoint:02x}")
        else:
            safe.append(f"\\u{codepoint:04x}")
    return "".join(safe)


def _take(payload: bytes, cursor: int, size: int, label: str) -> tuple[bytes, int]:
    end = cursor + size
    if end > len(payload):
        raise ValueError(f"truncated {label}")
    return payload[cursor:end], end


def parse_threat_update_status(payload: bytes) -> ThreatUpdateStatusPayload:
    """Parse the engine template: u8-length bytes followed by two u32 words.

    The engine stops after its three template instructions and does not require
    the cursor to equal the payload end, so remaining bytes are preserved.
    """
    length_raw, cursor = _take(payload, 0, 1, "name length")
    name_len = length_raw[0]
    name_raw, cursor = _take(payload, cursor, name_len, "name")
    word_08_raw, cursor = _take(payload, cursor, 4, "word_08")
    word_0c_raw, cursor = _take(payload, cursor, 4, "word_0c")

    return ThreatUpdateStatusPayload(
        raw=payload,
        name_len=name_len,
        name_raw=name_raw,
        name=_safe_name(name_raw),
        word_08=int.from_bytes(word_08_raw, "little"),
        word_0c=int.from_bytes(word_0c_raw, "little"),
        trailing_raw=payload[cursor:],
    )


def render_threat_update_status(
    parsed: ThreatUpdateStatusPayload,
) -> FormatResult:
    """Render bounded previews and leave both status words explicitly unknown."""
    name_hex = parsed.name_raw[:_NAME_PREVIEW_BYTES].hex(" ")
    if len(parsed.name_raw) > _NAME_PREVIEW_BYTES:
        name_hex += f" … ({len(parsed.name_raw) - _NAME_PREVIEW_BYTES} more bytes)"

    name_preview = parsed.name[:_NAME_PREVIEW_CHARS]
    if len(parsed.name) > _NAME_PREVIEW_CHARS:
        name_preview += f" … ({len(parsed.name) - _NAME_PREVIEW_CHARS} more chars)"

    tail_hex = parsed.trailing_raw[:_TAIL_PREVIEW_BYTES].hex(" ")
    if len(parsed.trailing_raw) > _TAIL_PREVIEW_BYTES:
        tail_hex += f" … ({len(parsed.trailing_raw) - _TAIL_PREVIEW_BYTES} more bytes)"

    return FormatResult(
        fields=(
            ("name_len", str(parsed.name_len)),
            ("name_raw", name_hex or "(empty)"),
            ("name_safe", name_preview or "(empty)"),
            ("word_08", f"{parsed.word_08:#010x} (semantics unknown)"),
            ("word_0c", f"{parsed.word_0c:#010x} (semantics unknown)"),
            ("trailing_len", f"{len(parsed.trailing_raw)} B"),
            ("trailing_raw", tail_hex or "(empty)"),
            ("raw_len", f"{len(parsed.raw)} B"),
        )
    )


def export_threat_update_status_semantics(
    parsed: ThreatUpdateStatusPayload,
) -> RuleSemantics:
    """Export confirmed framing and receiver storage without guessing policy."""
    has_trailing = bool(parsed.trailing_raw)
    issues = [
        SemanticIssue(
            "dword_value_domains_unresolved",
            "A bounded consumer uses the first DWORD as a mask operand and ORs "
            "the second into an output DWORD, but neither value domain nor "
            "product-level meaning is confirmed.",
            (("fields", "word_08, word_0c"),),
        ),
        SemanticIssue(
            "metadata_only_effect_unproven",
            "The receiver stores the DWORDs in a per-type row, but the bounded "
            "static trace does not prove that their product effect is limited "
            "to metadata updates.",
            (("row_offsets", "0x08, 0x0C"),),
        ),
    ]
    if has_trailing:
        issues.append(
            SemanticIssue(
                "unconsumed_trailing_bytes",
                "The registered receiver accepts bytes after the two DWORDs, but "
                "their interpretation is unconfirmed; only the prefix is exported.",
                (("trailing_length", len(parsed.trailing_raw)),),
            )
        )
    issues.append(
        SemanticIssue(
            "final_policy_unresolved",
            "The bounded consumer dataflow does not establish the final product policy or verdict.",
            (("consumer", "ThreatUpdateStatus"),),
        )
    )

    return RuleSemantics(
        # confirmed_subset covers the fully consumed projection and bounded
        # consumer dataflow; an unconsumed suffix remains unsupported.
        status="unsupported" if has_trailing else "confirmed_subset",
        representation="vdm.threat_update_status.receiver_observation.v3",
        profile="mpengine-1.443.903.0",
        evidence=(
            (
                "mpengine 1.443.903.0 SigDataInit at 0x1809AEE24 registers "
                "type 0xC3 with a 0x16-byte row and three template fields."
            ),
            (
                "mpengine 1.443.903.0 ReceiveNewTemplate at 0x1803224D0 "
                "decodes one length-prefixed byte string and two little-endian "
                "DWORDs into row offsets 0x00, 0x08, and 0x0C."
            ),
            (
                "mpengine 1.443.903.0 DispatchRecord at 0x1800FAF18 and "
                "FastDispatchRecord at 0x1805CD7BC are confirmed generic callers "
                "of ReceiveNewTemplate. ThreatUpdateStatus at 0x1809B0FF8 "
                "reads the indexed row: row+0x08 is ANDed with input_context+0x08; "
                "on regex match and nonzero intersection, row+0x0C is ORed into "
                "output_context+0x0C. ksignalupper at 0x180279E98 calls it at "
                "0x18027A6D5 and returns its MP_ERROR result."
            ),
            (
                "mpengine 1.443.903.0 SigDataInit at 0x1809AEE24 registers "
                "the type 0xC3 template from 0x180EEC9D0; template execution "
                "does not establish metadata-only product behavior."
            ),
            (
                "The local mpas.sig corpus contains three type 0xC3 records; "
                "these samples corroborate observed values only and do not define "
                "the two DWORDs' value domains or product-level effect."
            ),
        ),
        issues=tuple(issues),
        data=JSONObject(
            (
                ("record_type", f"0x{THREAT_UPDATE_STATUS_TYPE:02X}"),
                ("raw_payload_hex", parsed.raw.hex()),
                ("payload_length", len(parsed.raw)),
                (
                    "wire_framing",
                    (
                        "u8 name_length; name_length bytes; u32_le value_0; "
                        "u32_le value_1"
                    ),
                ),
                ("name_length", parsed.name_len),
                ("name_raw_hex", parsed.name_raw.hex()),
                ("name_safe", parsed.name),
                (
                    "receiver_row_observation",
                    JSONObject(
                        (
                            (
                                "offset_0x00",
                                (
                                    "pointer returned by kstore(name_raw, name_length, 0); "
                                    "the pointed-to bytes are preserved as name_raw_hex"
                                ),
                            ),
                            ("offset_0x08_raw_u32", parsed.word_08),
                            ("offset_0x0c_raw_u32", parsed.word_0c),
                            (
                                "row_stride",
                                (
                                    "0x16 bytes; bytes at offsets 0x10..0x15 are not "
                                    "assigned by this template"
                                ),
                            ),
                        )
                    ),
                ),
                ("word_08", parsed.word_08),
                ("word_0c", parsed.word_0c),
                (
                    "consumer_trace",
                    JSONObject(
                        (
                            ("registration_address", "0x1809AEE24"),
                            ("template_handler_address", "0x1803224D0"),
                            (
                                "dispatchers",
                                JSONArray(("0x1800FAF18", "0x1805CD7BC")),
                            ),
                            ("dedicated_value_consumer", "confirmed_bounded_consumer"),
                            ("consumer_address", "0x1809B0FF8"),
                            (
                                "name_gate",
                                "row+0x00 regex must match the resolved threat name",
                            ),
                            ("mask_operand", "row+0x08 & input_context+0x08"),
                            (
                                "or_contribution",
                                "row+0x0C is ORed into output_context+0x0C",
                            ),
                            ("caller_address", "0x180279E98"),
                            ("caller_site", "0x18027A6D5"),
                            ("metadata_only_effect", "not_proven"),
                            (
                                "search_scope",
                                (
                                    "one indexed-row consumer confirmed; other "
                                    "consumers and product-level meaning unresolved"
                                ),
                            ),
                        )
                    ),
                ),
                (
                    "value_semantics",
                    "bounded use confirmed: first DWORD is a mask operand and second DWORD is an OR contribution; value domains and product-level meaning remain unresolved",
                ),
                (
                    "trailing",
                    JSONObject(
                        (
                            ("length", len(parsed.trailing_raw)),
                            ("raw_hex", parsed.trailing_raw.hex()),
                            (
                                "interpretation",
                                "accepted_by_template_loop_not_stored_by_its_fields",
                            ),
                        )
                    ),
                ),
            )
        ),
    )


SPEC = FamilySpec(
    THREAT_UPDATE_STATUS_TYPE,
    "THREAT_UPDATE_STATUS",
    parse_threat_update_status,
    render_threat_update_status,
    semantic_exporter=export_threat_update_status_semantics,
)
