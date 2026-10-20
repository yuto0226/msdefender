"""Lossless CKOLDREC and CKSIMPLEREC wire models."""

from dataclasses import dataclass
from typing import Final

from ..core import DisplaySection, FamilySpec, FormatResult

CKOLDREC_TYPE: Final = 0x11
CKSIMPLEREC_TYPE: Final = 0x50
_BASE_SIZE: Final = 20
_PREVIEW_LIMIT: Final = 64


@dataclass(frozen=True, slots=True)
class CkOldPayload:
    first_word: int
    first_length: int
    first_crc32: int
    second_offset: int
    second_length: int
    second_crc32: int
    flags: int
    object_length: int | None
    object_data_raw: bytes | None
    object_wire_raw: bytes | None
    remaining_raw: bytes

    @property
    def ck_type(self) -> int:
        return (self.flags >> 26) & 0xF

    @property
    def callback_mode_index(self) -> int:
        return self.first_word & 0x3F


@dataclass(frozen=True, slots=True)
class CkSimplePayload:
    first_dword: int
    first16_crc32: int
    second_offset: int
    second_length: int
    second_crc32: int
    flags: int
    object_length: int | None
    object_data_raw: bytes | None
    object_wire_raw: bytes | None
    remaining_raw: bytes

    @property
    def ck_type(self) -> int:
        return (self.flags >> 26) & 0xF


def _u16(payload: bytes, offset: int) -> int:
    return int.from_bytes(payload[offset : offset + 2], "little")


def _u32(payload: bytes, offset: int) -> int:
    return int.from_bytes(payload[offset : offset + 4], "little")


def _parse_tail(
    payload: bytes, flags: int
) -> tuple[int | None, bytes | None, bytes | None, bytes]:
    """Project the conditional CK object while retaining every raw tail byte.

    ReceiveNewTemplate's 0x1006 descriptor only consumes an object when the
    preceding flags DWORD is negative. In that branch its wire prefix is a
    u16 byte length. The receiver does not require exact payload exhaustion.
    """
    tail = payload[_BASE_SIZE:]
    if flags & 0x80000000:
        if len(tail) < 2:
            raise ValueError("truncated CK conditional object")
        object_length = _u16(tail, 0)
        object_end = 2 + object_length
        if object_end > len(tail):
            raise ValueError("truncated CK conditional object")
        return object_length, tail[2:object_end], tail[:object_end], tail[object_end:]
    return None, None, None, tail


def parse_ckoldrec(payload: bytes) -> CkOldPayload:
    """Parse CKOLDREC's callback key/length fields and common tail."""
    if len(payload) < _BASE_SIZE:
        raise ValueError("truncated CKOLDREC header")
    flags = _u32(payload, 16)
    object_length, object_data_raw, object_wire_raw, remaining_raw = _parse_tail(
        payload, flags
    )
    return CkOldPayload(
        first_word=_u16(payload, 0),
        first_length=_u16(payload, 2),
        first_crc32=_u32(payload, 4),
        second_offset=_u16(payload, 8),
        second_length=_u16(payload, 10),
        second_crc32=_u32(payload, 12),
        flags=flags,
        object_length=object_length,
        object_data_raw=object_data_raw,
        object_wire_raw=object_wire_raw,
        remaining_raw=remaining_raw,
    )


def parse_cksimplerec(payload: bytes) -> CkSimplePayload:
    """Parse CKSIMPLEREC's prefix checks and second CRC descriptor."""
    if len(payload) < _BASE_SIZE:
        raise ValueError("truncated CKSIMPLEREC header")
    flags = _u32(payload, 16)
    object_length, object_data_raw, object_wire_raw, remaining_raw = _parse_tail(
        payload, flags
    )
    return CkSimplePayload(
        first_dword=_u32(payload, 0),
        first16_crc32=_u32(payload, 4),
        second_offset=_u16(payload, 8),
        second_length=_u16(payload, 10),
        second_crc32=_u32(payload, 12),
        flags=flags,
        object_length=object_length,
        object_data_raw=object_data_raw,
        object_wire_raw=object_wire_raw,
        remaining_raw=remaining_raw,
    )


def _preview(raw: bytes | None) -> str:
    if raw is None:
        return "absent"
    value = raw[:_PREVIEW_LIMIT].hex(" ") or "(empty)"
    if len(raw) > _PREVIEW_LIMIT:
        value += f" ... ({len(raw) - _PREVIEW_LIMIT} more)"
    return value


def _common_rows(
    *,
    second_offset: int,
    second_length: int,
    second_crc32: int,
    flags: int,
    ck_type: int,
    object_length: int | None,
    object_data_raw: bytes | None,
    object_wire_raw: bytes | None,
    remaining_raw: bytes,
) -> tuple[tuple[str, str], ...]:
    return (
        ("second_offset", str(second_offset)),
        ("second_length", str(second_length)),
        ("second_crc32", f"0x{second_crc32:08X}"),
        ("flags", f"0x{flags:08X}"),
        ("ck_type", str(ck_type)),
        (
            "object_length",
            "not projected" if object_length is None else str(object_length),
        ),
        ("object_data_preview", _preview(object_data_raw)),
        ("object_wire_preview", _preview(object_wire_raw)),
        (
            "remaining_length",
            str(len(remaining_raw)),
        ),
        ("remaining_preview", _preview(remaining_raw)),
    )


def render_ckoldrec(parsed: CkOldPayload) -> FormatResult:
    return FormatResult(
        sections=(
            DisplaySection(
                "CKOLDREC",
                rows=(
                    ("first_word", f"0x{parsed.first_word:04X}"),
                    ("callback_mode_index", str(parsed.callback_mode_index)),
                    ("first_length", str(parsed.first_length)),
                    ("first_crc32", f"0x{parsed.first_crc32:08X}"),
                    *_common_rows(
                        second_offset=parsed.second_offset,
                        second_length=parsed.second_length,
                        second_crc32=parsed.second_crc32,
                        flags=parsed.flags,
                        ck_type=parsed.ck_type,
                        object_length=parsed.object_length,
                        object_data_raw=parsed.object_data_raw,
                        object_wire_raw=parsed.object_wire_raw,
                        remaining_raw=parsed.remaining_raw,
                    ),
                ),
            ),
        )
    )


def render_cksimplerec(parsed: CkSimplePayload) -> FormatResult:
    return FormatResult(
        sections=(
            DisplaySection(
                "CKSIMPLEREC",
                rows=(
                    ("first_dword", f"0x{parsed.first_dword:08X}"),
                    ("first16_crc32", f"0x{parsed.first16_crc32:08X}"),
                    *_common_rows(
                        second_offset=parsed.second_offset,
                        second_length=parsed.second_length,
                        second_crc32=parsed.second_crc32,
                        flags=parsed.flags,
                        ck_type=parsed.ck_type,
                        object_length=parsed.object_length,
                        object_data_raw=parsed.object_data_raw,
                        object_wire_raw=parsed.object_wire_raw,
                        remaining_raw=parsed.remaining_raw,
                    ),
                ),
            ),
        )
    )


CK_SPECS = (
    FamilySpec(CKOLDREC_TYPE, "CKOLDREC", parse_ckoldrec, render_ckoldrec),
    FamilySpec(CKSIMPLEREC_TYPE, "CKSIMPLEREC", parse_cksimplerec, render_cksimplerec),
)
