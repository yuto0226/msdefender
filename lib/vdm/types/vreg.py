"""Lossless parser and concise renderer for VREG (0xB0) payloads."""

import json
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final

from ..core import DisplaySection, FamilySpec, FormatResult

VREG_TYPE: Final = 0xB0
MAX_KEY_UNITS: Final = 0x100
MAX_NAME_UNITS: Final = 0x108

_HIVE_LABELS = MappingProxyType(
    {
        0: "HKCR (HKEY_CLASSES_ROOT)",
        1: "HKCU (HKEY_CURRENT_USER)",
        2: "HKLM (HKEY_LOCAL_MACHINE)",
        3: "HKU (HKEY_USERS)",
        4: "HKEY_PERFORMANCE_DATA",
        5: "HKCC (HKEY_CURRENT_CONFIG)",
    }
)

# WinNT.h REG_* constants.  Values are presentation labels only: the engine
# accepts unknown values and does not validate the data size against the type.
_VALUE_TYPE_LABELS = MappingProxyType(
    {
        0: "REG_NONE",
        1: "REG_SZ",
        2: "REG_EXPAND_SZ",
        3: "REG_BINARY",
        4: "REG_DWORD",
        5: "REG_DWORD_BIG_ENDIAN",
        6: "REG_LINK",
        7: "REG_MULTI_SZ",
        8: "REG_RESOURCE_LIST",
        9: "REG_FULL_RESOURCE_DESCRIPTOR",
        10: "REG_RESOURCE_REQUIREMENTS_LIST",
        11: "REG_QWORD",
    }
)


@dataclass(frozen=True, slots=True)
class VregPayload:
    raw: bytes
    hive: int
    key_units: int
    key_raw: bytes
    key_wire: str
    key: str
    value_type: int
    name_units: int
    name_raw: bytes
    name_wire: str
    name: str
    data_size: int
    data_raw: bytes
    trailing_raw: bytes

    @property
    def creates_key_only(self) -> bool:
        return self.data_size == 0


def _effective_string(wire: str) -> str:
    return wire.partition("\0")[0]


def parse_vreg(payload: bytes) -> VregPayload:
    """Parse the engine's length-prefixed VREG wire layout."""
    if len(payload) < 8:
        raise ValueError(f"truncated VREG header: need 8 bytes, have {len(payload)}")

    hive = payload[0]
    key_units = int.from_bytes(payload[1:3], "little")
    if key_units >= MAX_KEY_UNITS:
        raise ValueError(
            f"invalid VREG key_units: need < {MAX_KEY_UNITS}, have {key_units}"
        )

    key_end = 3 + 2 * key_units
    if len(payload) < key_end:
        raise ValueError(
            "truncated VREG key: "
            f"need {2 * key_units} bytes, have {max(0, len(payload) - 3)}"
        )

    name_header_end = key_end + 3
    if len(payload) < name_header_end:
        raise ValueError(
            "truncated VREG value header: "
            f"need 3 bytes, have {max(0, len(payload) - key_end)}"
        )

    value_type = payload[key_end]
    name_units = int.from_bytes(payload[key_end + 1 : name_header_end], "little")
    if name_units >= MAX_NAME_UNITS:
        raise ValueError(
            f"invalid VREG name_units: need < {MAX_NAME_UNITS}, have {name_units}"
        )

    name_offset = name_header_end
    name_end = name_offset + 2 * name_units
    data_size_end = name_end + 2
    if len(payload) < data_size_end:
        raise ValueError(
            "truncated VREG name/data_size: "
            f"need {2 * name_units + 2} bytes, "
            f"have {max(0, len(payload) - name_offset)}"
        )

    data_size = int.from_bytes(payload[name_end:data_size_end], "little")
    data_end = data_size_end + data_size
    if len(payload) < data_end:
        raise ValueError(
            f"truncated VREG data: need {data_size} bytes, "
            f"have {max(0, len(payload) - data_size_end)}"
        )

    key_raw = payload[3:key_end]
    name_raw = payload[name_offset:name_end]
    key_wire = key_raw.decode("utf-16le", errors="surrogatepass")
    name_wire = name_raw.decode("utf-16le", errors="surrogatepass")
    return VregPayload(
        raw=payload,
        hive=hive,
        key_units=key_units,
        key_raw=key_raw,
        key_wire=key_wire,
        key=_effective_string(key_wire),
        value_type=value_type,
        name_units=name_units,
        name_raw=name_raw,
        name_wire=name_wire,
        name=_effective_string(name_wire),
        data_size=data_size,
        data_raw=payload[data_size_end:data_end],
        trailing_raw=payload[data_end:],
    )


def _quoted(text: str) -> str:
    # ensure_ascii keeps lone UTF-16 surrogates safe for terminal encoders.
    return json.dumps(text, ensure_ascii=True)


def _enum_value(value: int, labels: Mapping[int, str]) -> str:
    label = labels.get(value)
    return (
        f"{label} (0x{value:02X})" if label is not None else f"unknown (0x{value:02X})"
    )


def _string_rows(
    label: str,
    units: int,
    wire: str,
    effective: str,
) -> list[tuple[str, str]]:
    rows = [(f"{label}_units", str(units)), (label, _quoted(effective))]
    if wire not in {effective, effective + "\0"}:
        rows.append((f"{label}_wire", _quoted(wire)))
    return rows


def _hex_preview(data: bytes, limit: int = 32) -> str:
    preview = data[:limit].hex(" ") or "(empty)"
    if len(data) > limit:
        return f"{preview} … (+{len(data) - limit} B)"
    return preview


def _reg_sz_preview(data: bytes) -> str | None:
    if len(data) % 2:
        return None
    text = data.decode("utf-16le", errors="surrogatepass")
    effective = _effective_string(text)
    if any(not (char.isprintable() or char in "\t\r\n") for char in effective):
        return None
    return _quoted(effective)


def render_vreg(parsed: VregPayload) -> FormatResult:
    key_rows = [
        ("hive", _enum_value(parsed.hive, _HIVE_LABELS)),
        *_string_rows("key", parsed.key_units, parsed.key_wire, parsed.key),
    ]

    value_rows = [
        ("name_units", str(parsed.name_units)),
        ("name", "(default)" if not parsed.name else _quoted(parsed.name)),
    ]
    if parsed.name_wire not in {parsed.name, parsed.name + "\0"}:
        value_rows.append(("name_wire", _quoted(parsed.name_wire)))
    value_rows.extend(
        (
            ("value_type", _enum_value(parsed.value_type, _VALUE_TYPE_LABELS)),
            ("data_size", f"{parsed.data_size} B"),
        )
    )
    if parsed.creates_key_only:
        value_rows.append(("operation", "create key only (engine skips SetValue)"))
    else:
        if parsed.value_type == 1:
            preview = _reg_sz_preview(parsed.data_raw)
            if preview is not None:
                value_rows.append(("text", preview))
        elif parsed.value_type == 4 and parsed.data_size == 4:
            value_rows.append(
                ("dword", f"0x{int.from_bytes(parsed.data_raw, 'little'):08X}")
            )
        value_rows.append(("data_raw", _hex_preview(parsed.data_raw)))

    sections = [
        DisplaySection("Target Key", rows=tuple(key_rows)),
        DisplaySection("Value Data", rows=tuple(value_rows)),
    ]
    if parsed.trailing_raw:
        sections.append(
            DisplaySection(
                "Ignored Trailing Bytes",
                rows=(
                    ("trailing_len", f"{len(parsed.trailing_raw)} B"),
                    ("trailing_raw", _hex_preview(parsed.trailing_raw)),
                    ("engine_behavior", "ignored"),
                ),
            )
        )
    return FormatResult(sections=tuple(sections))


SPEC = FamilySpec(VREG_TYPE, "VREG", parse_vreg, render_vreg)
