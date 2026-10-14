"""Parser and concise renderer for STATIC (0x67) payloads."""

from dataclasses import dataclass
from enum import IntEnum
from typing import Final

from ..core import DisplaySection, FamilySpec, FormatResult

STATIC_TYPE: Final = 0x67
HEADER_SIZE: Final = 18
ALLOW_LARGER_MASK: Final = 0x0001
MODE_MASK: Final = 0x7000
IGNORED_FLAGS_MASK: Final = 0x8FFE


class StaticHashMode(IntEnum):
    MD5 = 0
    SHA1 = 1
    CRC_0 = 2
    SHA1_PREFIX4 = 3
    SHA256 = 4


_HASH_LENGTHS: Final = {
    StaticHashMode.MD5: 16,
    StaticHashMode.SHA1: 20,
    StaticHashMode.CRC_0: 4,
    StaticHashMode.SHA1_PREFIX4: 4,
    StaticHashMode.SHA256: 32,
}


@dataclass(frozen=True, slots=True)
class StaticRecIdTail:
    """Lossless tail bytes and the engine's bounded type-1 object view."""

    raw: bytes
    length_prefix: int
    object_raw: bytes
    trailing_raw: bytes
    has_object: bool


@dataclass(frozen=True, slots=True)
class StaticPayload:
    raw: bytes
    first_page_crc: int
    tail_page_crc: int
    prefix_crc: int
    file_size: int
    flags: int
    allow_larger: bool
    mode_value: int
    mode: StaticHashMode | None
    hash_raw: bytes
    recid_tail: StaticRecIdTail | None
    opaque_raw: bytes

    @property
    def ignored_flags(self) -> int:
        return self.flags & IGNORED_FLAGS_MASK


def _parse_recid_tail(raw: bytes) -> StaticRecIdTail | None:
    if not raw:
        return None
    length_prefix = raw[0]
    object_end = min(length_prefix, len(raw) - 1)
    object_raw = raw[1 : 1 + object_end]
    trailing_raw = raw[1 + object_end :]
    # Engine creates a RecID without a type-1 object for an empty or zero-first
    # object, while the original prefix and bytes remain available in `raw`.
    has_object = bool(object_raw) and object_raw[0] != 0
    return StaticRecIdTail(
        raw=raw,
        length_prefix=length_prefix,
        object_raw=object_raw,
        trailing_raw=trailing_raw,
        has_object=has_object,
    )


def parse_static(payload: bytes) -> StaticPayload:
    """Parse a STATIC payload while retaining every input byte."""
    if len(payload) < HEADER_SIZE:
        raise ValueError(
            f"truncated STATIC header: need {HEADER_SIZE} bytes, have {len(payload)}"
        )

    first_page_crc = int.from_bytes(payload[0:4], "little")
    tail_page_crc = int.from_bytes(payload[4:8], "little")
    prefix_crc = int.from_bytes(payload[8:12], "little")
    file_size = int.from_bytes(payload[12:16], "little")
    flags = int.from_bytes(payload[16:18], "little")
    mode_value = (flags >> 12) & 0x7
    allow_larger = bool(flags & ALLOW_LARGER_MASK)

    try:
        mode = StaticHashMode(mode_value)
    except ValueError:
        return StaticPayload(
            raw=payload,
            first_page_crc=first_page_crc,
            tail_page_crc=tail_page_crc,
            prefix_crc=prefix_crc,
            file_size=file_size,
            flags=flags,
            allow_larger=allow_larger,
            mode_value=mode_value,
            mode=None,
            hash_raw=b"",
            recid_tail=None,
            opaque_raw=payload[HEADER_SIZE:],
        )

    hash_size = _HASH_LENGTHS[mode]
    hash_end = HEADER_SIZE + hash_size
    if len(payload) < hash_end:
        raise ValueError(
            f"truncated STATIC {mode.name} hash: need {hash_size} bytes, "
            f"have {len(payload) - HEADER_SIZE}"
        )
    return StaticPayload(
        raw=payload,
        first_page_crc=first_page_crc,
        tail_page_crc=tail_page_crc,
        prefix_crc=prefix_crc,
        file_size=file_size,
        flags=flags,
        allow_larger=allow_larger,
        mode_value=mode_value,
        mode=mode,
        hash_raw=payload[HEADER_SIZE:hash_end],
        recid_tail=_parse_recid_tail(payload[hash_end:]),
        opaque_raw=b"",
    )


def _printable_object(data: bytes) -> str | None:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if text and all(char.isprintable() for char in text):
        return text
    return None


def render_static(parsed: StaticPayload) -> FormatResult:
    if parsed.allow_larger:
        file_size = f">= {parsed.file_size} B"
    else:
        file_size = f"{parsed.file_size} B (exact)"

    if parsed.mode is None:
        hash_display = "unavailable"
    elif parsed.mode is StaticHashMode.CRC_0:
        hash_display = f"0x{int.from_bytes(parsed.hash_raw, 'little'):08X}"
    else:
        hash_display = parsed.hash_raw.hex()

    flag_parts = ["allow_larger" if parsed.allow_larger else "exact"]
    if parsed.ignored_flags:
        flag_parts.append(f"loader_ignored=0x{parsed.ignored_flags:04X}")

    hash_mode = (
        f"{parsed.mode.name}({parsed.mode_value})"
        if parsed.mode is not None
        else f"UNSUPPORTED({parsed.mode_value})"
    )
    policy_rows = (
        ("file_size", file_size),
        ("flags", f"{', '.join(flag_parts)} (0x{parsed.flags:04X})"),
        ("hash_mode", hash_mode),
    )
    fingerprint_rows = [
        ("first_page_crc", f"0x{parsed.first_page_crc:08X}"),
        ("tail_page_crc", f"0x{parsed.tail_page_crc:08X}"),
        ("prefix_crc", f"0x{parsed.prefix_crc:08X}"),
        ("hash", hash_display),
    ]
    if parsed.mode is None:
        fingerprint_rows.append(("opaque_len", f"{len(parsed.opaque_raw)} B"))

    sections = [
        DisplaySection("Match Policy", rows=policy_rows),
        DisplaySection("File Fingerprints", rows=tuple(fingerprint_rows)),
    ]
    if parsed.mode is not None and parsed.recid_tail is not None:
        tail = parsed.recid_tail
        identity_rows = [
            ("recid_tail_len", f"{len(tail.raw)} B"),
            ("object_length_limit", f"{tail.length_prefix} B"),
            ("effective_object_len", f"{len(tail.object_raw)} B"),
        ]
        if tail.has_object:
            preview = _printable_object(tail.object_raw)
            if preview is not None:
                identity_rows.append(("object_preview", preview))
            else:
                identity_rows.append(("object_preview", "(nonprintable)"))
        else:
            identity_rows.append(("object", "absent"))
        if tail.trailing_raw:
            identity_rows.append(("trailing_len", f"{len(tail.trailing_raw)} B"))
        sections.append(DisplaySection("Record Identity", rows=tuple(identity_rows)))
    return FormatResult(sections=tuple(sections))


SPEC = FamilySpec(STATIC_TYPE, "STATIC", parse_static, render_static)
