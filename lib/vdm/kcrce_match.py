"""Common-PE KCRCE CRC2 range/value projection for complete immutable bytes.

The scanner must actually select kcrc_callback and supply its normalized section
view. This does not infer a callback domain from a wire record or parse a PE image.
It models a fresh provider/cold window and successful absolute byte services,
including successful short/EOF reads. Negative HRESULTs, preexisting cache state,
OEP/VMM, fastcrc/crc1 arbitration, weak fallback and final verdict are outside it.
"""

import zlib
from dataclasses import dataclass
from typing import Literal

from .types.kcrce import KcrcePayload, parse_kcrce


def _u32(value: int, label: str) -> None:
    if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
        raise ValueError(f"{label} must be an unsigned 32-bit integer")


@dataclass(frozen=True, slots=True)
class KcrcePeSection:
    """Selected scanner table fields, not an inferred KCRCE wire domain.

    These correspond to pe+4048h/+4044h+40*index. No equivalence with an arbitrary
    unnormalized IMAGE_SECTION_HEADER is asserted by this constructor.
    """

    raw_offset: int
    raw_size: int

    def __post_init__(self) -> None:
        _u32(self.raw_offset, "section raw offset")
        _u32(self.raw_size, "section raw size")


@dataclass(frozen=True, slots=True)
class KcrcePeContext:
    """Explicit common-PE scanner view for a fresh provider/cold section window.

    source_bytes is the complete underlying immutable file. sections and index
    are the actual selected normalized scanner view, not a claim that a loader
    ran. len(sections) represents the WORD section count. Successful byte services
    return available bytes and allow EOF short reads; no negative HRESULT backend
    is synthesized. This context has no cache or general I/O policy API.
    """

    source_bytes: bytes
    sections: tuple[KcrcePeSection, ...]
    section_index: int

    def __post_init__(self) -> None:
        if not isinstance(self.source_bytes, bytes):
            raise TypeError("source_bytes must be complete immutable bytes")
        if not isinstance(self.sections, tuple) or any(
            not isinstance(section, KcrcePeSection) for section in self.sections
        ):
            raise TypeError("sections must be a tuple of KcrcePeSection")
        if len(self.sections) > 0xFFFF:
            raise ValueError("section count must fit the scanner WORD")
        _u32(self.section_index, "selected section index")


@dataclass(frozen=True, slots=True)
class KcrcePeRange:
    start: int
    length: int

    @property
    def end_exclusive(self) -> int:
        """HashOnFile advances a 64-bit cursor after the initial u32 sum."""
        return self.start + self.length


@dataclass(frozen=True, slots=True)
class KcrcePeCrc2Result:
    decoded_range: KcrcePeRange | None
    section_gate: Literal[
        "invalid_section_index", "raw_size_below_512", "window_short", "ready"
    ]
    section_window_bytes: int
    bytes_hashed: int
    range_complete: bool
    crc2: int
    record_local_crc2_match: bool


def _record(record: KcrcePayload) -> KcrcePayload:
    if not isinstance(record, KcrcePayload):
        raise TypeError("record must be a parsed KcrcePayload")
    # The original wire bytes, not replaceable parsed/display fields, are authority.
    return parse_kcrce(record.raw)


def decode_kcrce_pe_range(
    record: KcrcePayload, *, section: KcrcePeSection
) -> KcrcePeRange:
    """Decode this callback's arithmetic only; this does not pass its cold gate.

    The start addition wraps at 32 bits; the resulting start plus low16 length is
    not clamped to the section size. This formula is not universal to KCRCE.
    """
    parsed = _record(record)
    if not isinstance(section, KcrcePeSection):
        raise TypeError("section must be a KcrcePeSection")
    packed = parsed.length_flags & 0x0FFFFFFF
    return KcrcePeRange(
        (section.raw_offset + ((packed >> 16) & 0xFFF)) & 0xFFFFFFFF,
        packed & 0xFFFF,
    )


def evaluate_kcrce_pe_crc2(
    record: KcrcePayload, context: KcrcePeContext
) -> KcrcePeCrc2Result:
    """Project the common-PE fresh CRC2 value and its record-local equality.

    No AddData leaves reset CRC FFFFFFFF, which can match a record even when its
    section gate was skipped. Successful short reads hash available bytes; match
    and range_complete are separate. This is not the full candidate/Lookup policy.
    """
    parsed = _record(record)
    if not isinstance(context, KcrcePeContext):
        raise TypeError("context must be an explicit KcrcePeContext")
    selected_range = None
    window_bytes = 0
    data = b""
    complete = False
    if context.section_index >= len(context.sections):
        gate = "invalid_section_index"
    else:
        section = context.sections[context.section_index]
        selected_range = decode_kcrce_pe_range(parsed, section=section)
        if section.raw_size < 512:
            gate = "raw_size_below_512"
        else:
            window_bytes = len(
                context.source_bytes[
                    section.raw_offset : section.raw_offset
                    + min(section.raw_size, 1024)
                ]
            )
            if window_bytes < 512:
                gate = "window_short"
            else:
                gate = "ready"
                data = context.source_bytes[
                    selected_range.start : selected_range.end_exclusive
                ]
                complete = len(data) == selected_range.length
    actual = zlib.crc32(data) ^ 0xFFFFFFFF
    return KcrcePeCrc2Result(
        selected_range,
        gate,
        window_bytes,
        len(data),
        complete,
        actual,
        actual == parsed.crc2,
    )
