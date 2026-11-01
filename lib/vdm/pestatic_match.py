"""PESTATIC cold immutable-byte predicate and normalized section-caller decoder.

The context is a loaded pe_vars runtime view, not an on-disk PE parser. This
projects one explicitly selected file/mmap attempt; a single-record miss cannot
replay whole-store/PESTATICEX fallback. Negative I/O HRESULTs, unknown mappings,
warm caches and final scan policy are outside the successful byte-service model.
"""

import zlib
from dataclasses import dataclass
from typing import Literal

from .types.pestatic import PeStaticPayload, parse_pestatic

_U64 = (1 << 64) - 1


class UnsupportedPeStaticContext(ValueError):
    """The available runtime/source view cannot bind the modeled attempt."""


@dataclass(frozen=True, slots=True)
class PeStaticSectionContext:
    raw: bytes
    section_index: int
    header_adjustment_enabled: bool


@dataclass(frozen=True, slots=True)
class PeStaticSourceSelection:
    mapped_start: int
    file_offset: int
    adjustment: int
    header_adjustment_enabled_after: bool
    mmap_fallback_enabled: bool


@dataclass(frozen=True, slots=True)
class PeStaticStageResult:
    mode: int
    crc: int
    expected: int
    read_complete: bool
    error: bool
    matched: bool


@dataclass(frozen=True, slots=True)
class PeStaticMatch:
    selection: PeStaticSourceSelection
    source_kind: Literal["file", "mmap"]
    prefix_64: PeStaticStageResult
    prefix_512: PeStaticStageResult | None
    content: PeStaticStageResult | None
    record_local_fingerprint_candidate: bool
    all_stage_reads_complete: bool


def decode_pestatic_section(context: PeStaticSectionContext) -> PeStaticSourceSelection:
    """Decode original pestatic_match arithmetic from authoritative raw pe_vars.

    The original caller's section_index is uint16. Header-adjustment and final
    address arithmetic preserve the native uint32/uint64 wraps; table fields are
    not reinterpreted as standard IMAGE_SECTION_HEADER fields. This decoder does
    not infer that the selected section/namespace has been initialized.
    """
    if not isinstance(context, PeStaticSectionContext):
        raise TypeError("context must be PeStaticSectionContext")
    if not isinstance(context.raw, bytes):
        raise TypeError("context.raw must be immutable normalized pe_vars bytes")
    if (
        type(context.section_index) is not int
        or not 0 <= context.section_index <= 65535
    ):
        raise ValueError("section_index must be uint16")
    if type(context.header_adjustment_enabled) is not bool:
        raise TypeError("header_adjustment_enabled must be bool")

    def read(offset: int, size: int) -> int:
        if offset < 0 or offset + size > len(context.raw):
            raise UnsupportedPeStaticContext(
                "required normalized pe_vars field is absent"
            )
        return int.from_bytes(context.raw[offset : offset + size], "little")

    stride = 40 * context.section_index
    component = read(0x2150 + stride, 4)
    raw_offset = read(0x4048 + stride, 4)
    base = read(0x83798, 8)
    adjustment = 0
    enabled = context.header_adjustment_enabled
    count = read(0x83780, 4)
    width = 8 if read(0x2008, 2) == 0x20B else 4
    if count and enabled:
        bound = read(0x5F28, 8)
        if bound > base:
            candidate = read(24 * (count + 0x3F6), 8)
            if candidate > base:
                relative = candidate - base
                end = (relative + width) & _U64
                size_end = (read(0x214C + stride, 4) + component) & 0xFFFFFFFF
                if end > relative and component <= bound - base and size_end >= end:
                    adjustment = (relative + width - component) & _U64
                    enabled = False
    return PeStaticSourceSelection(
        (base + component + adjustment) & _U64,
        (raw_offset + adjustment) & _U64,
        adjustment,
        enabled,
        read(0x82B4D, 1) != 0,
    )


def _stage(
    source: bytes, start: int, size: int, expected: int, mode: int, kind: str
) -> PeStaticStageResult:
    if mode == 2 and size == 0:
        return PeStaticStageResult(
            2, 0xFFFFFFFF, expected, True, False, expected == 0xFFFFFFFF
        )
    available = 0 <= start <= len(source) and size <= len(source) - start
    if kind == "mmap" and not available:
        return PeStaticStageResult(
            mode,
            0xFFFFFFFF,
            expected,
            False,
            True,
            mode != 2 and expected == 0xFFFFFFFF,
        )
    data = source[start : start + size] if 0 <= start <= len(source) else b""
    running = zlib.crc32(data) ^ 0xFFFFFFFF
    if mode == 2:
        return PeStaticStageResult(
            mode,
            running,
            expected,
            available,
            not available,
            available and running == expected,
        )
    value = (
        running if available else (0 if mode == 0 and kind == "file" else 0xFFFFFFFF)
    )
    return PeStaticStageResult(
        mode, value, expected, available, not available, value == expected
    )


def evaluate_pestatic(
    record: PeStaticPayload,
    context: PeStaticSectionContext,
    source_bytes: bytes,
    *,
    source_kind: Literal["file", "mmap"],
    mapped_window_base: int | None = None,
) -> PeStaticMatch:
    """One cold stage attempt; prefix mismatch leaves later stages unexecuted.

    file bytes must be the complete current UFS object under successful ReadAt
    semantics (including short/EOF). mmap bytes must describe the entire explicit
    available address window: requests outside it return NULL. Merely having an
    arbitrary prefix of unknown memory is insufficient for this binding.
    Constructor seed is the original fresh consumed=0/running_crc=FFFFFFFF, not a
    caller-provided warm cache. Prefix64/512 are independent of content_size.
    A candidate may be true despite incomplete prefix reads, as native sentinel
    comparisons demonstrate. This is not a final lookup or detection verdict.
    """
    if not isinstance(record, PeStaticPayload):
        raise TypeError("record must be PeStaticPayload")
    if not isinstance(source_bytes, bytes):
        raise TypeError("source_bytes must be immutable complete source binding")
    if source_kind not in {"file", "mmap"}:
        raise UnsupportedPeStaticContext("an explicit file or mmap attempt is required")
    selection = decode_pestatic_section(context)
    if source_kind == "file":
        if selection.file_offset == _U64:
            raise UnsupportedPeStaticContext("UINT64_MAX selects mmap, not file")
        start = selection.file_offset
    else:
        if type(mapped_window_base) is not int or not 0 <= mapped_window_base <= _U64:
            raise UnsupportedPeStaticContext(
                "explicit uint64 mapped-window base required"
            )
        if len(source_bytes) > (1 << 64) - mapped_window_base:
            raise UnsupportedPeStaticContext("mapped window wraps the address space")
        start = selection.mapped_start - mapped_window_base
    parsed = parse_pestatic(record.raw)
    first = _stage(source_bytes, start, 64, parsed.crc_first_64, 0, source_kind)
    second = content = None
    if first.matched:
        second = _stage(source_bytes, start, 512, parsed.crc_first_512, 1, source_kind)
        if second.matched:
            content = _stage(
                source_bytes,
                start,
                parsed.content_size,
                parsed.content_crc,
                2,
                source_kind,
            )
    matched = content is not None and content.matched
    complete = (
        content is not None
        and first.read_complete
        and second is not None
        and second.read_complete
        and content.read_complete
    )
    return PeStaticMatch(
        selection, source_kind, first, second, content, matched, complete
    )
