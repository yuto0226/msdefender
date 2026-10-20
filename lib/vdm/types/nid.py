import json
from collections.abc import Callable
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

NID_TYPE: Final = 0x55
SNID_TYPE: Final = 0x7E
NID64_TYPE: Final = 0xCE

_FAMILY_NAMES = MappingProxyType(
    {
        NID_TYPE: "NID",
        SNID_TYPE: "SNID",
        NID64_TYPE: "NID64",
    }
)

# These records have the same shape but use different identifier widths.
# Names intentionally describe only confirmed wire semantics.
_KEY_WIDTHS = MappingProxyType(
    {
        NID_TYPE: 4,
        SNID_TYPE: 20,
        NID64_TYPE: 8,
    }
)


@dataclass(frozen=True, slots=True)
class NidPayload:
    raw: bytes
    type_byte: int
    key_raw: bytes
    metadata_raw: int
    recid_input_raw: bytes
    identity_kind: Literal["none", "object", "unnamed", "raw"]
    object_raw: bytes | None
    ignored_trailing_raw: bytes

    @property
    def identity_text(self) -> str | None:
        """Return a display-only text view without asserting a wire encoding."""
        data = self.object_raw
        if data is None:
            return None
        if data.endswith(b"\0"):
            data = data[:-1]
        if not data or b"\0" in data:
            return None
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            return None
        return text if all(character.isprintable() for character in text) else None


def parse_nid(payload: bytes, *, type_byte: int) -> NidPayload:
    """Parse the fixed key prefix and preserve the following metadata byte."""
    try:
        key_width = _KEY_WIDTHS[type_byte]
    except KeyError as exc:
        raise ValueError(f"unsupported NID family type 0x{type_byte:02X}") from exc

    header_size = key_width + 1
    if len(payload) < header_size:
        raise ValueError(
            f"truncated {_FAMILY_NAMES[type_byte]} header: "
            f"need {header_size} bytes, have {len(payload)}"
        )

    recid_input_raw = payload[header_size:]
    object_raw: bytes | None = None
    ignored_trailing_raw = b""
    if not recid_input_raw:
        identity_kind: Literal["none", "object", "unnamed", "raw"] = "none"
    elif recid_input_raw[0] == 0:
        identity_kind = "unnamed"
        ignored_trailing_raw = recid_input_raw[1:]
    else:
        identity_kind = "object"
        nul = recid_input_raw.find(b"\0")
        if nul < 0:
            object_raw = recid_input_raw
        else:
            object_raw = recid_input_raw[: nul + 1]
            ignored_trailing_raw = recid_input_raw[nul + 1 :]

    return NidPayload(
        raw=payload,
        type_byte=type_byte,
        key_raw=payload[:key_width],
        metadata_raw=payload[key_width],
        recid_input_raw=recid_input_raw,
        identity_kind=identity_kind,
        object_raw=object_raw,
        ignored_trailing_raw=ignored_trailing_raw,
    )


def render_nid(parsed: NidPayload) -> FormatResult:
    if len(parsed.key_raw) in (4, 8):
        key_width = len(parsed.key_raw) * 2 + 2
        key = f"{int.from_bytes(parsed.key_raw, 'little'):#0{key_width}x}"
    else:
        key = parsed.key_raw.hex()

    fields = [
        ("key", key),
        ("key_raw", parsed.key_raw.hex(" ")),
        ("metadata_raw", f"0x{parsed.metadata_raw:02x}"),
    ]
    if parsed.type_byte == NID_TYPE:
        fields.append(("key_match", "exact 4-byte key; exact metadata byte"))
    elif parsed.type_byte == SNID_TYPE:
        fields.append(("key_match", "exact 20-byte key; exact metadata byte"))
    elif parsed.type_byte == NID64_TYPE:
        fields.append(("key_match", "exact 8-byte key; exact metadata byte"))
    fields.append(("record_identity", parsed.identity_kind))
    identity_text = parsed.identity_text
    if identity_text is not None:
        fields.extend(
            (
                ("identity_text", json.dumps(identity_text, ensure_ascii=False)),
                ("recid_input_raw", parsed.recid_input_raw.hex(" ")),
            )
        )
        if parsed.type_byte in (NID_TYPE, SNID_TYPE, NID64_TYPE):
            fields.append(
                (
                    "identity_role",
                    "interned RecID name; runtime checks IsAttribute()",
                )
            )
    elif parsed.recid_input_raw:
        fields.append(("recid_input_raw", parsed.recid_input_raw.hex(" ")))
    if parsed.object_raw is not None:
        fields.append(("interned_object_length", f"{len(parsed.object_raw)} B"))
    if parsed.ignored_trailing_raw:
        fields.append(("receiver_ignored_raw", parsed.ignored_trailing_raw.hex(" ")))
    return FormatResult(
        sections=(DisplaySection("Network Identifier", rows=tuple(fields)),)
    )


def _raw_field(kind: str, raw: bytes, offset: int) -> JSONObject:
    return JSONObject(
        (
            ("kind", kind),
            (
                "raw_span",
                JSONObject((("offset", offset), ("length", len(raw)))),
            ),
            ("raw_hex", raw.hex()),
        )
    )


def export_nid_semantics(parsed: NidPayload) -> RuleSemantics:
    """Export the receiver-confirmed exact lookup tuple and lossless framing."""
    key_width = _KEY_WIDTHS[parsed.type_byte]
    identity_offset = key_width + 1
    identity_length = len(parsed.recid_input_raw) - len(parsed.ignored_trailing_raw)
    identity_raw = parsed.recid_input_raw[:identity_length]

    framing = JSONArray(
        (
            _raw_field("key", parsed.key_raw, 0),
            _raw_field("metadata", parsed.raw[key_width : key_width + 1], key_width),
            _raw_field("record_identity", identity_raw, identity_offset),
            _raw_field(
                "receiver_ignored_trailing",
                parsed.ignored_trailing_raw,
                identity_offset + identity_length,
            ),
        )
    )
    issues: list[SemanticIssue] = [
        SemanticIssue(
            "key_derivation_unknown",
            "The lookup key is retained as exact bytes without assigning a hash "
            "or derivation algorithm.",
        ),
        SemanticIssue(
            "outer_verdict_unknown",
            "A successful table lookup is not exported as a final detection verdict.",
        ),
    ]
    unsupported = False
    if parsed.identity_kind == "raw":
        unsupported = True
        issues.append(
            SemanticIssue(
                "unknown_identity_kind",
                "The record identity bytes have no confirmed receiver semantics.",
            )
        )
    if parsed.ignored_trailing_raw:
        unsupported = True
        issues.append(
            SemanticIssue(
                "receiver_ignored_trailing",
                "Bytes after the bounded record identity are ignored by the receiver.",
                (("length", len(parsed.ignored_trailing_raw)),),
            )
        )

    return RuleSemantics(
        status="unsupported" if unsupported else "confirmed_subset",
        representation="nid.exact_lookup.ir.v1",
        data=JSONObject(
            (
                ("raw_hex", parsed.raw.hex()),
                ("framing", framing),
                ("type_byte", parsed.type_byte),
                ("family", _FAMILY_NAMES[parsed.type_byte]),
                ("key_width", key_width),
                (
                    "lookup",
                    JSONObject(
                        (
                            ("kind", "exact"),
                            ("key_raw_hex", parsed.key_raw.hex()),
                            ("metadata_raw", parsed.metadata_raw),
                        )
                    ),
                ),
                (
                    "record_identity",
                    JSONObject(
                        (
                            ("kind", parsed.identity_kind),
                            ("raw_hex", identity_raw.hex()),
                        )
                    ),
                ),
                (
                    "receiver_ignored_trailing_raw_hex",
                    parsed.ignored_trailing_raw.hex(),
                ),
            )
        ),
        evidence=(
            "NID-family receiver and exact lookup paths in mpengine 1.443.903.0",
        ),
        profile="mpengine-1.443.903.0",
        issues=tuple(issues),
    )


def _parser_for(type_byte: int) -> Callable[[bytes], NidPayload]:
    def parser(payload: bytes) -> NidPayload:
        return parse_nid(payload, type_byte=type_byte)

    return parser


NID_SPECS = tuple(
    FamilySpec(
        type_byte,
        name,
        _parser_for(type_byte),
        render_nid,
        semantic_exporter=export_nid_semantics,
    )
    for type_byte, name in _FAMILY_NAMES.items()
)
