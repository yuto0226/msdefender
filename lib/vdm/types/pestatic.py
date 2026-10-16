"""Parser and concise renderer for PESTATIC (0x87) payloads."""

from dataclasses import dataclass
from typing import Final

from ..core import DisplaySection, FamilySpec, FormatResult
from ..recid import RecIdTail, parse_recid_tail

PESTATIC_TYPE: Final = 0x87
BASE_SIZE: Final = 16


@dataclass(frozen=True, slots=True)
class PeStaticPayload:
    raw: bytes
    crc_first_64: int
    crc_first_512: int
    content_crc: int
    content_size: int
    recid_tail: RecIdTail | None


def parse_pestatic(payload: bytes) -> PeStaticPayload:
    """Parse the fixed PESTATIC wire prefix and optional shared RecID tail."""
    if len(payload) < BASE_SIZE:
        raise ValueError(
            f"truncated PESTATIC header: need {BASE_SIZE} bytes, have {len(payload)}"
        )

    return PeStaticPayload(
        raw=payload,
        crc_first_64=int.from_bytes(payload[0:4], "little"),
        crc_first_512=int.from_bytes(payload[4:8], "little"),
        content_crc=int.from_bytes(payload[8:12], "little"),
        content_size=int.from_bytes(payload[12:16], "little"),
        recid_tail=parse_recid_tail(payload[BASE_SIZE:]),
    )


def _printable_object(data: bytes) -> str | None:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if text and all(char.isprintable() for char in text):
        return text
    return None


def render_pestatic(parsed: PeStaticPayload) -> FormatResult:
    sections = [
        DisplaySection(
            "PE Fingerprints",
            rows=(
                ("crc_first_64", f"0x{parsed.crc_first_64:08X}"),
                ("crc_first_512", f"0x{parsed.crc_first_512:08X}"),
                ("content_crc", f"0x{parsed.content_crc:08X}"),
                ("content_size", f"{parsed.content_size} B"),
            ),
        )
    ]

    if parsed.recid_tail is not None:
        tail = parsed.recid_tail
        identity_rows = [
            ("recid_tail_len", f"{len(tail.raw)} B"),
            ("object_length_limit", f"{tail.length_limit} B"),
            ("effective_object_len", f"{len(tail.object_raw)} B"),
        ]
        if tail.has_object:
            preview = _printable_object(tail.object_raw)
            identity_rows.append(
                ("object_preview", preview if preview is not None else "(nonprintable)")
            )
        else:
            identity_rows.append(("object", "absent"))
        if tail.trailing_raw:
            identity_rows.append(("trailing_len", f"{len(tail.trailing_raw)} B"))
        sections.append(DisplaySection("Record Identity", rows=tuple(identity_rows)))

    return FormatResult(sections=tuple(sections))


SPEC = FamilySpec(PESTATIC_TYPE, "PESTATIC", parse_pestatic, render_pestatic)
