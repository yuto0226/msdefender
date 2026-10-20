"""Lossless TRUSTED_PUBLISHER framing and bounded key interpretation."""

import hashlib
import json
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final, Literal

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
from ._certificate_key import parse_certificate_key

TRUSTED_PUBLISHER_TYPE: Final = 0x70

_KEY_TYPES = MappingProxyType({1: "HASH", 2: "BY", 3: "TO", 4: "BADHASH", 5: "TEAMID"})


@dataclass(frozen=True, slots=True)
class TrustedPublisher:
    raw: bytes
    key_len: int
    key_data: bytes
    mode: Literal["binary", "string"]
    key_type: int
    prefix: str | None
    prefix_raw: bytes
    key_material_raw: bytes
    key_text: str | None
    text_raw: bytes
    terminator_raw: bytes
    string_trailing_raw: bytes
    decode_error: str | None
    recid_tail_raw: bytes
    recid_tail: RecIdTail | None


def parse_trusted_publisher(payload: bytes) -> TrustedPublisher:
    """Parse the WORD-sized key and retain opaque or malformed key contents.

    Load at 0x18032039C rejects keys shorter than two bytes. Its string GetKey
    overload scans for NUL without a length; this parser stays within key_len.
    UTF-16LE is confirmed by wcsnicmp and the wide-string GetKey overload.
    """
    if len(payload) < 2:
        raise ValueError(
            f"truncated TRUSTED_PUBLISHER key_len: need 2 bytes, have {len(payload)}"
        )
    key_len = int.from_bytes(payload[:2], "little")
    if key_len < 2:
        raise ValueError(
            f"invalid TRUSTED_PUBLISHER key_len: need at least 2, have {key_len}"
        )
    key_end = 2 + key_len
    if key_end > len(payload):
        raise ValueError(
            "truncated TRUSTED_PUBLISHER key_data: "
            f"need {key_len} bytes, have {len(payload) - 2}"
        )

    key_data = payload[2:key_end]
    recid_tail_raw = payload[key_end:]
    key = parse_certificate_key(key_data)

    # The signature hash covers payload[:key_end], excluding this RecID tail;
    # Load also ORs (key_end << 40) and 0x7000000000 into its CRC result. Key
    # material itself is not universally a digest (see both GetKey overloads).
    return TrustedPublisher(
        raw=payload,
        key_len=key_len,
        key_data=key_data,
        mode=key.mode,
        key_type=key.key_type,
        prefix=key.prefix,
        prefix_raw=key.prefix_raw,
        key_material_raw=key.material_raw,
        key_text=key.text,
        text_raw=key.text_raw,
        terminator_raw=key.terminator_raw,
        string_trailing_raw=key.trailing_raw,
        decode_error=key.decode_error,
        recid_tail_raw=recid_tail_raw,
        recid_tail=parse_recid_tail(recid_tail_raw),
    )


def render_trusted_publisher(parsed: TrustedPublisher) -> FormatResult:
    label = _KEY_TYPES.get(parsed.key_type)
    key_type = f"0x{parsed.key_type:02x}"
    if label is not None:
        key_type += f" ({label})"
    fields = (
        ("key_len", str(parsed.key_len)),
        ("mode", parsed.mode),
        ("key_type", key_type),
    )
    rows = list(fields)
    if parsed.mode == "binary":
        rows.append(("key_material_raw", parsed.key_material_raw.hex(" ") or "(empty)"))
    if parsed.mode == "string":
        rows.append(("prefix", parsed.prefix or "(none; defaults to TO)"))
        if parsed.key_text is not None:
            rows.append(("key_text", json.dumps(parsed.key_text, ensure_ascii=False)))
        else:
            rows.append(("decode_error", f"invalid UTF-16LE: {parsed.decode_error}"))
            rows.append(("text_raw", parsed.text_raw.hex(" ") or "(empty)"))
        rows.append(
            (
                "terminator",
                "NUL"
                if parsed.terminator_raw
                else "(missing within key_len; engine reads an unbounded string)",
            )
        )
        if parsed.string_trailing_raw:
            rows.append(("string_trailing_len", f"{len(parsed.string_trailing_raw)} B"))
    sections = [DisplaySection("Publisher key", rows=tuple(rows))]
    if parsed.recid_tail_raw:
        sections.append(
            DisplaySection(
                "RecID tail",
                rows=(("recid_tail_len", f"{len(parsed.recid_tail_raw)} B"),),
            )
        )
    return FormatResult(sections=tuple(sections))


def export_trusted_publisher_semantics(parsed: TrustedPublisher) -> RuleSemantics:
    """Export the confirmed normalized-key lookup without claiming trust policy."""
    type_name = _KEY_TYPES.get(parsed.key_type)
    unsupported_reasons: list[SemanticIssue] = []
    if type_name is None:
        unsupported_reasons.append(
            SemanticIssue(
                "unknown_key_type",
                "The receiver's meaning for this key type is not confirmed.",
                (("key_type", parsed.key_type),),
            )
        )
    if parsed.decode_error is not None:
        unsupported_reasons.append(
            SemanticIssue(
                "invalid_utf16le",
                "The string key cannot be decoded as UTF-16LE; text semantics are unavailable.",
            )
        )
    if parsed.mode == "string" and not parsed.terminator_raw:
        unsupported_reasons.append(
            SemanticIssue(
                "unbounded_wide_string",
                "The engine's wide GetKey call can read beyond key_len when the "
                "key material has no NUL terminator.",
            )
        )
    if parsed.recid_tail_raw:
        unsupported_reasons.append(
            SemanticIssue(
                "recid_gate_not_exported",
                "The optional createrecidp program and its post-lookup gate are "
                "preserved but not executable in the portable IR.",
            )
        )

    issues = [
        SemanticIssue(
            "policy_effect_unknown",
            "An accepted publisher-key lookup does not by itself establish the "
            "final IsTrustedFile or scan verdict policy.",
        ),
        *unsupported_reasons,
    ]
    unsupported = bool(unsupported_reasons)
    key_descriptor_items: list[tuple[str, str | int | None]] = [
        ("kind", parsed.mode),
        ("key_type", parsed.key_type),
        ("key_type_name", type_name),
    ]
    if parsed.mode == "binary":
        key_descriptor_items.append(
            ("key_material_raw_hex", parsed.key_material_raw.hex())
        )
    else:
        key_descriptor_items.extend(
            (
                ("prefix", parsed.prefix),
                ("text", parsed.key_text),
                ("text_raw_hex", parsed.text_raw.hex()),
                ("terminator_raw_hex", parsed.terminator_raw.hex()),
                ("string_trailing_raw_hex", parsed.string_trailing_raw.hex()),
            )
        )

    normalized_key: bytes | None = None
    if type_name is not None and parsed.mode == "binary":
        if parsed.key_type in {1, 4} and len(parsed.key_material_raw) == 20:
            adjusted = bytearray(parsed.key_material_raw)
            adjusted[0] = (adjusted[0] + parsed.key_type) & 0xFF
            normalized_key = bytes(adjusted)
            normalization = "copy_digest_then_add_type_to_first_byte"
        else:
            normalized_key = hashlib.sha1(
                bytes((parsed.key_type,)) + parsed.key_material_raw
            ).digest()
            normalization = "sha1(type_byte || binary_material)"
    elif (
        type_name is not None
        and parsed.mode == "string"
        and parsed.key_text is not None
        and parsed.key_type not in {1, 4}
    ):
        normalized_key = hashlib.sha1(
            bytes((parsed.key_type,)) + parsed.key_text.encode("utf-8")
        ).digest()
        normalization = "sha1(type_byte || utf8(text))"
    elif parsed.mode == "string" and parsed.key_type in {1, 4}:
        normalization = "hex_decode_then_binary_GetKey"
    else:
        normalization = "unknown"

    return RuleSemantics(
        status="unsupported" if unsupported else "confirmed_subset",
        representation="trusted_publisher.normalized_lookup.ir.v1",
        data=JSONObject(
            (
                ("raw_hex", parsed.raw.hex()),
                (
                    "framing",
                    JSONArray(
                        (
                            JSONObject(
                                (
                                    ("kind", "key_len"),
                                    ("offset", 0),
                                    ("length", 2),
                                    ("raw_hex", parsed.raw[:2].hex()),
                                )
                            ),
                            JSONObject(
                                (
                                    ("kind", "key_data"),
                                    ("offset", 2),
                                    ("length", parsed.key_len),
                                    ("raw_hex", parsed.key_data.hex()),
                                )
                            ),
                            JSONObject(
                                (
                                    ("kind", "recid_tail"),
                                    ("offset", 2 + parsed.key_len),
                                    ("length", len(parsed.recid_tail_raw)),
                                    ("raw_hex", parsed.recid_tail_raw.hex()),
                                )
                            ),
                        )
                    ),
                ),
                ("key_descriptor", JSONObject(tuple(key_descriptor_items))),
                (
                    "normalization",
                    JSONObject(
                        (
                            ("engine_call", "GetKey"),
                            ("operation", normalization),
                            (
                                "normalized_key_hex",
                                None
                                if normalized_key is None
                                else normalized_key.hex(),
                            ),
                        )
                    ),
                ),
                ("match_operation", "exact_normalized_key_lookup"),
                (
                    "post_lookup_gate",
                    "nid64searchrecid(133, 0, matched_sig_id)",
                ),
                ("policy_effect", "unknown"),
            )
        ),
        evidence=(
            "TRUSTED_PUBLISHER parser bounds key_len and key_data",
            "mpengine 1.443.903.0 trustedpublisher_t::Load",
            "mpengine 1.443.903.0 GetKey overloads and key-type dispatch",
            "mpengine 1.443.903.0 CheckPublisher exact store lookup",
        ),
        profile="mpengine-1.443.903.0",
        issues=tuple(issues),
    )


SPEC = FamilySpec(
    TRUSTED_PUBLISHER_TYPE,
    "TRUSTED_PUBLISHER",
    parse_trusted_publisher,
    render_trusted_publisher,
    semantic_exporter=export_trusted_publisher_semantics,
)
