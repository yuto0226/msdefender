import json
from collections.abc import Callable
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final

from ..core import FamilySpec, FormatResult

NID_TYPE: Final = 0x55
SNID_TYPE: Final = 0x7E

_FAMILY_NAMES = MappingProxyType(
    {
        NID_TYPE: "NID",
        SNID_TYPE: "SNID",
    }
)

# The two records have the same shape but use different identifier widths.
# Names intentionally describe only confirmed wire semantics.
_KEY_WIDTHS = MappingProxyType(
    {
        NID_TYPE: 4,
        SNID_TYPE: 20,
    }
)


@dataclass(frozen=True, slots=True)
class NidPayload:
    raw: bytes
    type_byte: int
    key_raw: bytes
    metadata: int
    label_raw: bytes
    label: str | None
    trailing_raw: bytes


def parse_nid(payload: bytes, *, type_byte: int) -> NidPayload:
    """Parse the NID/SNID key, unresolved metadata byte, and optional label."""
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
        metadata=payload[key_width],
        label_raw=label_raw,
        label=label,
        trailing_raw=trailing_raw,
    )


def render_nid(parsed: NidPayload) -> FormatResult:
    if len(parsed.key_raw) == 4:
        key = f"{int.from_bytes(parsed.key_raw, 'little'):#010x}"
    else:
        key = parsed.key_raw.hex()

    fields = [
        ("key", key),
        ("key_raw", parsed.key_raw.hex(" ")),
        ("metadata", f"0x{parsed.metadata:02x} (semantics unresolved)"),
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
    return FormatResult(fields=tuple(fields))


def _parser_for(type_byte: int) -> Callable[[bytes], NidPayload]:
    def parser(payload: bytes) -> NidPayload:
        return parse_nid(payload, type_byte=type_byte)

    return parser


NID_SPECS = tuple(
    FamilySpec(type_byte, name, _parser_for(type_byte), render_nid)
    for type_byte, name in _FAMILY_NAMES.items()
)
