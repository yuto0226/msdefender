"""Parser and concise renderer for KCRCE (0x80) payloads."""

from dataclasses import dataclass
from typing import Final

from ..core import DisplaySection, FamilySpec, FormatResult
from ..recid import RecIdTail, parse_recid_tail

KCRCE_TYPE: Final = 0x80
BASE_SIZE: Final = 16
UNRESOLVED_FLAGS_MASK: Final = 0x30000000
REQUIRE_FASTCRC_WHEN_PROVIDER_KEY_MISSING: Final = 0x40000000
SUPPRESS_WEAK_FASTCRC_FALLBACK: Final = 0x80000000


@dataclass(frozen=True, slots=True)
class KcrcePayload:
    raw: bytes
    fastcrc: int
    crc1: int
    crc2: int
    length_flags: int
    hash_length: int
    callback_relative_offset: int
    unresolved_flags: int
    require_fastcrc_when_provider_key_missing: bool
    suppress_weak_fastcrc_fallback: bool
    recid_tail: RecIdTail | None


def parse_kcrce(payload: bytes) -> KcrcePayload:
    """Parse the fixed KCRCE wire prefix and an optional shared RecID tail."""
    if len(payload) < BASE_SIZE:
        raise ValueError(
            f"truncated KCRCE header: need {BASE_SIZE} bytes, have {len(payload)}"
        )

    fastcrc = int.from_bytes(payload[0:4], "little")
    crc1 = int.from_bytes(payload[4:8], "little")
    crc2 = int.from_bytes(payload[8:12], "little")
    length_flags = int.from_bytes(payload[12:16], "little")
    return KcrcePayload(
        raw=payload,
        fastcrc=fastcrc,
        crc1=crc1,
        crc2=crc2,
        length_flags=length_flags,
        hash_length=length_flags & 0xFFFF,
        callback_relative_offset=(length_flags >> 16) & 0xFFF,
        unresolved_flags=length_flags & UNRESOLVED_FLAGS_MASK,
        require_fastcrc_when_provider_key_missing=bool(
            length_flags & REQUIRE_FASTCRC_WHEN_PROVIDER_KEY_MISSING
        ),
        suppress_weak_fastcrc_fallback=bool(
            length_flags & SUPPRESS_WEAK_FASTCRC_FALLBACK
        ),
        recid_tail=parse_recid_tail(payload[BASE_SIZE:]),
    )


def _printable_preview(data: bytes) -> str | None:
    try:
        preview = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return preview if preview and all(char.isprintable() for char in preview) else None


def _format_flags(parsed: KcrcePayload) -> str:
    states = []
    if parsed.require_fastcrc_when_provider_key_missing:
        states.append("require_fastcrc_when_provider_key_missing")
    if parsed.suppress_weak_fastcrc_fallback:
        states.append("suppress_weak_fastcrc_fallback")
    if parsed.unresolved_flags:
        states.append(f"unresolved=0x{parsed.unresolved_flags:08x}")
    if not states:
        return f"none (0x{parsed.length_flags:08x})"
    return f"{', '.join(states)} (0x{parsed.length_flags:08x})"


def render_kcrce(parsed: KcrcePayload) -> FormatResult:
    """Render confirmed matching inputs while keeping callback scope cautious."""
    sections = [
        DisplaySection(
            "Match Parameters",
            rows=(
                ("hash_length", f"{parsed.hash_length} B"),
                (
                    "callback_relative_offset",
                    f"{parsed.callback_relative_offset} B",
                ),
                ("flags", _format_flags(parsed)),
            ),
        ),
        DisplaySection(
            "CRC Fingerprints",
            rows=(
                ("fastcrc", f"0x{parsed.fastcrc:08x}"),
                ("crc1", f"0x{parsed.crc1:08x}"),
                ("crc2", f"0x{parsed.crc2:08x}"),
            ),
        ),
    ]

    if parsed.recid_tail is not None:
        tail = parsed.recid_tail
        alias_rows = [
            ("name_length_limit", f"{tail.length_limit} B"),
            ("effective_name_length", f"{len(tail.object_raw)} B"),
        ]
        if tail.has_object:
            preview = _printable_preview(tail.object_raw)
            if preview is not None:
                alias_rows.append(("name_preview", preview))
        alias_rows.extend(
            (
                ("attribute", str(tail.object_raw.startswith(b"!#")).lower()),
                ("trailing_length", f"{len(tail.trailing_raw)} B"),
            )
        )
        sections.append(DisplaySection("Threat Alias", rows=tuple(alias_rows)))

    return FormatResult(sections=tuple(sections))


SPEC = FamilySpec(KCRCE_TYPE, "KCRCE", parse_kcrce, render_kcrce)
