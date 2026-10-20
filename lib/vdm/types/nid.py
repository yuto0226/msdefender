import json
from collections.abc import Callable
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final, Literal

from ..core import DisplaySection, FamilySpec, FormatResult

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

_SELECTOR_NAMES = MappingProxyType(
    {
        0x3A: "NID_LOWFI_SIG",
        0x50: "NID_FPCHECK_EXCLUDED_SIGNATURE",
        0x57: "NID_FILTER_TRUSTED_LOWFI",
        0x5C: "NID_NONCACHED_LOWFI",
        0x5E: "NID_EXTENDED_REPORT",
        0x67: "NID_INCLUDE_DNS_CACHE_INFO",
        0x6A: "NID_LOWFI_CACHE_PER_TRIGGER",
        0x6E: "NID_FILEQUERY_ONLY",
        0x7B: "NID_SMS_THREAT",
    }
)


@dataclass(frozen=True, slots=True)
class NidPayload:
    raw: bytes
    type_byte: int
    key_raw: bytes
    selector: int
    recid_input_raw: bytes
    identity_kind: Literal["none", "object", "unnamed", "direct"]
    object_raw: bytes | None
    ignored_trailing_raw: bytes

    @property
    def identity_text(self) -> str | None:
        """Return a display-only text view without asserting a wire encoding."""
        data = self.object_raw
        if data is None and self.identity_kind == "direct":
            data = self.recid_input_raw
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
    """Parse the family key, exact-match selector, and optional label."""
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
        identity_kind: Literal["none", "object", "unnamed", "direct"] = "none"
    elif type_byte == NID64_TYPE:
        identity_kind = "direct"
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
        selector=payload[key_width],
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

    selector_name = _SELECTOR_NAMES.get(parsed.selector, "name unresolved")

    fields = [
        ("key", key),
        ("key_raw", parsed.key_raw.hex(" ")),
        ("selector", f"0x{parsed.selector:02x} ({selector_name})"),
    ]
    if parsed.type_byte == SNID_TYPE:
        fields.extend(
            (
                ("key_match", "exact 20-byte key; first DWORD indexed"),
                ("selector_match", "exact byte"),
            )
        )
    fields.append(("record_identity", parsed.identity_kind))
    identity_text = parsed.identity_text
    if identity_text is not None:
        fields.extend(
            (
                ("identity_text", json.dumps(identity_text, ensure_ascii=False)),
                ("recid_input_raw", parsed.recid_input_raw.hex(" ")),
            )
        )
        if parsed.type_byte == SNID_TYPE:
            fields.append(
                (
                    "identity_role",
                    (
                        "record name; !# prefix routes to attribute aggregation"
                        if identity_text.startswith("!#")
                        else "record name"
                    ),
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


def _parser_for(type_byte: int) -> Callable[[bytes], NidPayload]:
    def parser(payload: bytes) -> NidPayload:
        return parse_nid(payload, type_byte=type_byte)

    return parser


NID_SPECS = tuple(
    FamilySpec(type_byte, name, _parser_for(type_byte), render_nid)
    for type_byte, name in _FAMILY_NAMES.items()
)
