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
    first_offset: int
    first_length: int
    first_crc32: int
    second_offset: int
    second_length: int
    second_crc32: int
    flags: int
    label: bytes | None
    extension: bytes | None
    trailing: bytes

    @property
    def ck_type(self) -> int:
        return (self.flags >> 26) & 0xF


@dataclass(frozen=True, slots=True)
class CkSimplePayload:
    first_dword: int
    first16_crc32: int
    second_offset: int
    second_length: int
    second_crc32: int
    flags: int
    label: bytes | None
    extension: bytes | None
    trailing: bytes

    @property
    def ck_type(self) -> int:
        return (self.flags >> 26) & 0xF


def _u16(payload: bytes, offset: int) -> int:
    return int.from_bytes(payload[offset : offset + 2], "little")


def _u32(payload: bytes, offset: int) -> int:
    return int.from_bytes(payload[offset : offset + 4], "little")


def _parse_tail(payload: bytes, flags: int) -> tuple[bytes | None, bytes | None, bytes]:
    cursor = _BASE_SIZE
    label = None
    extension = None

    if cursor < len(payload):
        label_length = payload[cursor]
        cursor += 1
        label_end = cursor + label_length
        if label_end > len(payload):
            raise ValueError("truncated CK label")
        label = payload[cursor:label_end]
        cursor = label_end
    elif flags & 0x80000000:
        raise ValueError("CK extension requires a label length byte")

    if flags & 0x80000000:
        if len(payload) - cursor < 2:
            raise ValueError("truncated CK extension length")
        extension_length = _u16(payload, cursor)
        cursor += 2
        extension_end = cursor + extension_length
        if extension_end > len(payload):
            raise ValueError("truncated CK extension")
        extension = payload[cursor:extension_end]
        cursor = extension_end

    return label, extension, payload[cursor:]


def parse_ckoldrec(payload: bytes) -> CkOldPayload:
    """Parse CKOLDREC's two offset/length/CRC descriptors and common tail."""
    if len(payload) < _BASE_SIZE:
        raise ValueError("truncated CKOLDREC header")
    flags = _u32(payload, 16)
    label, extension, trailing = _parse_tail(payload, flags)
    return CkOldPayload(
        first_offset=_u16(payload, 0),
        first_length=_u16(payload, 2),
        first_crc32=_u32(payload, 4),
        second_offset=_u16(payload, 8),
        second_length=_u16(payload, 10),
        second_crc32=_u32(payload, 12),
        flags=flags,
        label=label,
        extension=extension,
        trailing=trailing,
    )


def parse_cksimplerec(payload: bytes) -> CkSimplePayload:
    """Parse CKSIMPLEREC's prefix checks and second CRC descriptor."""
    if len(payload) < _BASE_SIZE:
        raise ValueError("truncated CKSIMPLEREC header")
    flags = _u32(payload, 16)
    label, extension, trailing = _parse_tail(payload, flags)
    return CkSimplePayload(
        first_dword=_u32(payload, 0),
        first16_crc32=_u32(payload, 4),
        second_offset=_u16(payload, 8),
        second_length=_u16(payload, 10),
        second_crc32=_u32(payload, 12),
        flags=flags,
        label=label,
        extension=extension,
        trailing=trailing,
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
    label: bytes | None,
    extension: bytes | None,
    trailing: bytes,
) -> tuple[tuple[str, str], ...]:
    return (
        ("second_offset", str(second_offset)),
        ("second_length", str(second_length)),
        ("second_crc32", f"0x{second_crc32:08X}"),
        ("flags", f"0x{flags:08X}"),
        ("ck_type", str(ck_type)),
        ("label_length", "absent" if label is None else str(len(label))),
        ("label_preview", _preview(label)),
        (
            "extension_length",
            "absent" if extension is None else str(len(extension)),
        ),
        ("extension_preview", _preview(extension)),
        ("trailing_length", str(len(trailing))),
        ("trailing_preview", _preview(trailing)),
    )


def render_ckoldrec(parsed: CkOldPayload) -> FormatResult:
    return FormatResult(
        sections=(
            DisplaySection(
                "CKOLDREC",
                rows=(
                    ("first_offset", str(parsed.first_offset)),
                    ("first_length", str(parsed.first_length)),
                    ("first_crc32", f"0x{parsed.first_crc32:08X}"),
                    *_common_rows(
                        second_offset=parsed.second_offset,
                        second_length=parsed.second_length,
                        second_crc32=parsed.second_crc32,
                        flags=parsed.flags,
                        ck_type=parsed.ck_type,
                        label=parsed.label,
                        extension=parsed.extension,
                        trailing=parsed.trailing,
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
                        label=parsed.label,
                        extension=parsed.extension,
                        trailing=parsed.trailing,
                    ),
                ),
            ),
        )
    )


CK_SPECS = (
    FamilySpec(CKOLDREC_TYPE, "CKOLDREC", parse_ckoldrec, render_ckoldrec),
    FamilySpec(CKSIMPLEREC_TYPE, "CKSIMPLEREC", parse_cksimplerec, render_cksimplerec),
)
