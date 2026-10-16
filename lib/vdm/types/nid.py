import json
from collections.abc import Callable
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final

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
    label_raw: bytes
    label: str | None
    trailing_raw: bytes


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

    label_raw = b""
    label = None
    trailing_raw = b""
    if len(payload) > header_size:
        nul = payload.find(b"\0", header_size)
        if nul < 0:
            label_raw = payload[header_size:]
        else:
            label_raw = payload[header_size:nul]
            trailing_raw = payload[nul + 1 :]
        if label_raw:
            label = label_raw.decode("utf-8", errors="replace")

    return NidPayload(
        raw=payload,
        type_byte=type_byte,
        key_raw=payload[:key_width],
        selector=payload[key_width],
        label_raw=label_raw,
        label=label,
        trailing_raw=trailing_raw,
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
    if parsed.label is not None:
        fields.extend(
            (
                ("label", json.dumps(parsed.label, ensure_ascii=False)),
                ("label_raw", parsed.label_raw.hex(" ") or "(empty)"),
            )
        )
    if parsed.trailing_raw:
        fields.append(("trailing_raw", parsed.trailing_raw.hex(" ")))
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
