"""Lossless parser and bounded renderer for DEFAULTS (0x58) payloads."""

import json
from dataclasses import dataclass
from typing import Final

from ..core import DisplaySection, FamilySpec, FormatResult

DEFAULTS_TYPE: Final = 0x58
_PREVIEW_BYTES: Final = 64
_PREVIEW_SUBRECORDS: Final = 16


@dataclass(frozen=True, slots=True)
class DefaultsSubrecord:
    """One DEFAULTS item, including any bytes its consumer does not use."""

    raw: bytes
    stride: int
    data_size: int
    field_08: int
    field_09: int
    field_0a: int
    name_raw: bytes
    data_raw: bytes
    trailing_raw: bytes

    @property
    def name(self) -> str:
        """Decode the stored UTF-16LE name while retaining ``name_raw``."""
        return self.name_raw[:-2].decode("utf-16le", errors="replace")


@dataclass(frozen=True, slots=True)
class DefaultsPayload:
    """Parsed DEFAULTS header, primary name, subrecords, and complete tail."""

    raw: bytes
    first_subrecord_offset: int
    subrecord_count: int
    field_06: int
    field_08: int
    flags_0a: int
    primary_name_raw: bytes
    primary_gap_raw: bytes
    subrecords: tuple[DefaultsSubrecord, ...]
    trailing_raw: bytes
    ignored_body: bool = False

    @property
    def primary_name(self) -> str:
        """Decode the primary UTF-16LE name while retaining its original bytes."""
        return self.primary_name_raw[:-2].decode("utf-16le", errors="replace")


def _find_utf16_nul(payload: bytes, start: int, end: int, label: str) -> int:
    for offset in range(start, end - 1, 2):
        if payload[offset : offset + 2] == b"\0\0":
            return offset + 2
    raise ValueError(f"missing UTF-16LE NUL terminator for {label}")


def parse_defaults(
    payload: bytes, *, parse_ignored_body: bool = False
) -> DefaultsPayload:
    """Parse DEFAULTS, mirroring the receiver's flag-controlled early return.

    Set ``parse_ignored_body`` to inspect the structural bytes even when the
    native receiver would return success without parsing that body.
    """
    length = len(payload)
    if length < 0x0E:
        raise ValueError("truncated DEFAULTS header: need at least 14 bytes")

    first_subrecord_offset = int.from_bytes(payload[0:4], "little")
    if first_subrecord_offset > length:
        raise ValueError(
            "DEFAULTS first subrecord offset exceeds payload length: "
            f"{first_subrecord_offset} > {length}"
        )

    subrecord_count = int.from_bytes(payload[4:6], "little")
    field_06 = int.from_bytes(payload[6:8], "little")
    field_08 = int.from_bytes(payload[8:10], "little")
    flags_0a = int.from_bytes(payload[10:12], "little")

    ignored_body = (flags_0a & 6) not in (0, 4)
    if ignored_body and not parse_ignored_body:
        return DefaultsPayload(
            raw=payload,
            first_subrecord_offset=first_subrecord_offset,
            subrecord_count=subrecord_count,
            field_06=field_06,
            field_08=field_08,
            flags_0a=flags_0a,
            primary_name_raw=b"",
            primary_gap_raw=b"",
            subrecords=(),
            trailing_raw=payload[12:],
            ignored_body=True,
        )

    primary_end = _find_utf16_nul(payload, 12, first_subrecord_offset, "primary name")
    if first_subrecord_offset < primary_end:
        raise ValueError("DEFAULTS first subrecord offset precedes primary name end")

    cursor = first_subrecord_offset
    subrecords: list[DefaultsSubrecord] = []
    for index in range(subrecord_count):
        if cursor + 4 > length:
            raise ValueError(f"truncated DEFAULTS subrecord {index}: missing stride")
        stride = int.from_bytes(payload[cursor : cursor + 4], "little")
        subrecord_end = cursor + stride
        if subrecord_end > length:
            raise ValueError(
                f"DEFAULTS subrecord {index} exceeds payload bounds: "
                f"end {subrecord_end} > {length}"
            )

        # Access fixed fields in parser order after the stride bounds check.
        if stride < 12:
            raise ValueError(
                f"truncated DEFAULTS subrecord {index} header: stride {stride}"
            )
        data_size = int.from_bytes(payload[cursor + 4 : cursor + 8], "little")
        field_08 = payload[cursor + 8]
        field_09 = payload[cursor + 9]
        field_0a = int.from_bytes(payload[cursor + 10 : cursor + 12], "little")

        name_start = cursor + 12
        name_end = _find_utf16_nul(
            payload, name_start, subrecord_end, f"subrecord {index} name"
        )
        data_end = name_end + data_size
        if data_end > subrecord_end:
            raise ValueError(
                f"DEFAULTS subrecord {index} data exceeds stride: "
                f"need {data_size} bytes after name, have {subrecord_end - name_end}"
            )

        subrecords.append(
            DefaultsSubrecord(
                raw=payload[cursor:subrecord_end],
                stride=stride,
                data_size=data_size,
                field_08=field_08,
                field_09=field_09,
                field_0a=field_0a,
                name_raw=payload[name_start:name_end],
                data_raw=payload[name_end:data_end],
                trailing_raw=payload[data_end:subrecord_end],
            )
        )
        cursor = subrecord_end

    return DefaultsPayload(
        raw=payload,
        first_subrecord_offset=first_subrecord_offset,
        subrecord_count=subrecord_count,
        field_06=field_06,
        field_08=field_08,
        flags_0a=flags_0a,
        primary_name_raw=payload[12:primary_end],
        primary_gap_raw=payload[primary_end:first_subrecord_offset],
        subrecords=tuple(subrecords),
        trailing_raw=payload[cursor:],
    )


def _hex_preview(data: bytes, limit: int = _PREVIEW_BYTES) -> str:
    preview = data[:limit].hex(" ").upper()
    if len(data) > limit:
        preview += f" … ({len(data) - limit} more bytes)"
    return preview or "(empty)"


def _string_preview(raw: bytes) -> str:
    text = raw[:-2].decode("utf-16le", errors="replace")
    return json.dumps(text[:_PREVIEW_BYTES], ensure_ascii=True)


def render_defaults(parsed: DefaultsPayload) -> FormatResult:
    """Render bounded metadata and previews without losing parser data."""
    rows = []
    for index, item in enumerate(parsed.subrecords[:_PREVIEW_SUBRECORDS]):
        rows.append(
            (
                f"subrecord_{index:02d}",
                (
                    f"stride={item.stride} data_size={item.data_size} "
                    f"fields={item.field_08:02X}/{item.field_09:02X}/"
                    f"{item.field_0a:04X} name={_string_preview(item.name_raw)} "
                    f"data={_hex_preview(item.data_raw)} "
                    f"tail={_hex_preview(item.trailing_raw)}"
                ),
            )
        )

    return FormatResult(
        fields=(
            ("first_subrecord_offset", str(parsed.first_subrecord_offset)),
            ("subrecord_count", str(parsed.subrecord_count)),
            ("field_06", f"0x{parsed.field_06:04X}"),
            ("field_08", f"0x{parsed.field_08:04X}"),
            ("flags_0a", f"0x{parsed.flags_0a:04X}"),
            ("ignored_body", str(parsed.ignored_body).lower()),
            ("primary_name", _string_preview(parsed.primary_name_raw)),
            ("primary_name_raw", _hex_preview(parsed.primary_name_raw)),
            ("primary_gap_len", str(len(parsed.primary_gap_raw))),
            ("primary_gap_raw", _hex_preview(parsed.primary_gap_raw)),
            ("subrecords_omitted", str(max(0, len(parsed.subrecords) - len(rows)))),
            ("trailing_len", str(len(parsed.trailing_raw))),
            ("trailing_raw", _hex_preview(parsed.trailing_raw)),
            ("raw_len", str(len(parsed.raw))),
        ),
        sections=(DisplaySection("DEFAULTS subrecords", rows=tuple(rows)),),
    )


SPEC = FamilySpec(DEFAULTS_TYPE, "DEFAULTS", parse_defaults, render_defaults)
