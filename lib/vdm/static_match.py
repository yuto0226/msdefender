"""Record-local STATIC (0x67) matching model for complete in-memory sources.

This models the confirmed comparison stages, not engine I/O or a scan verdict.
``source_bytes`` is the complete underlying file, and ``provider_offset`` and
``provider_size`` select an absolute byte range within it. The offset-zero
first-page key requires the separate 4096-byte SCAN_REPLY buffer.
"""

from __future__ import annotations

import hashlib
import zlib
from dataclasses import dataclass
from typing import Literal

from .types.static import StaticHashMode, StaticPayload

MatchStatus = Literal["match", "no_match", "unknown"]
_PAGE_SIZE = 4096


@dataclass(frozen=True, slots=True)
class StaticMatchContext:
    source_bytes: bytes | None = None
    provider_offset: int | None = None
    provider_size: int | None = None
    scan_reply_first_page: bytes | None = None
    # Caller-supplied aggregate of the applicable engine CheckConfig calls.
    # True also covers a caller-confirmed case with no applicable CFG gate.
    configuration_gate: bool | None = None
    threat_exception_name: bool | None = None
    valid_signed: bool | None = None


@dataclass(frozen=True, slots=True)
class StaticStageResult:
    index: int
    name: str
    status: MatchStatus
    reason: str
    expected: int | bytes | None = None
    actual: int | bytes | None = None


@dataclass(frozen=True, slots=True)
class StaticMatchResult:
    record_local_match: MatchStatus
    reason: str
    stages: tuple[StaticStageResult, ...]
    final_verdict: Literal["unknown"] = "unknown"


def _crc_raw(data: bytes) -> int:
    # zlib uses the same reflected polynomial but applies a final XOR.
    return zlib.crc32(data) ^ 0xFFFFFFFF


def _stage(
    index: int,
    name: str,
    status: MatchStatus,
    reason: str,
    expected: int | bytes | None = None,
    actual: int | bytes | None = None,
) -> StaticStageResult:
    return StaticStageResult(index, name, status, reason, expected, actual)


def _selected_source(context: StaticMatchContext) -> bytes | None:
    source = context.source_bytes
    offset = context.provider_offset
    size = context.provider_size
    if (
        not isinstance(source, bytes)
        or not isinstance(offset, int)
        or isinstance(offset, bool)
        or not isinstance(size, int)
        or isinstance(size, bool)
        or offset < 0
        or size < 0
        or offset > len(source)
        or size > len(source) - offset
    ):
        return None
    return source[offset : offset + size]


def _size_gate(record: StaticPayload, context: StaticMatchContext) -> MatchStatus:
    size = context.provider_size
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        return "unknown"
    if size < record.file_size or (
        size != record.file_size and not record.allow_larger
    ):
        return "no_match"
    return "match"


def _first_page(
    record: StaticPayload, context: StaticMatchContext
) -> StaticStageResult:
    name = "first_page_crc_candidate_key"
    offset = context.provider_offset
    if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
        return _stage(0, name, "unknown", "provider_offset_unavailable")
    if offset == 0:
        page = context.scan_reply_first_page
        if not isinstance(page, bytes) or len(page) != _PAGE_SIZE:
            return _stage(0, name, "unknown", "scan_reply_first_page_required")
    else:
        selected = _selected_source(context)
        if selected is None:
            return _stage(0, name, "unknown", "selected_source_unavailable")
        page = selected[:_PAGE_SIZE].ljust(_PAGE_SIZE, b"\0")
    actual = _crc_raw(page)
    status: MatchStatus = "match" if actual == record.first_page_crc else "no_match"
    return _stage(
        0,
        name,
        status,
        "crc_equal" if status == "match" else "crc_mismatch",
        record.first_page_crc,
        actual,
    )


def _prefix(record: StaticPayload, context: StaticMatchContext) -> StaticStageResult:
    name = "prefix_crc"
    gate = _size_gate(record, context)
    if gate != "match":
        reason = "size_mismatch" if gate == "no_match" else "provider_size_unavailable"
        return _stage(1, name, gate, reason)
    selected = _selected_source(context)
    if selected is None:
        return _stage(1, name, "unknown", "selected_source_unavailable")
    actual = _crc_raw(selected[: min(record.file_size, 65536)])
    status: MatchStatus = "match" if actual == record.prefix_crc else "no_match"
    return _stage(
        1,
        name,
        status,
        "crc_equal" if status == "match" else "crc_mismatch",
        record.prefix_crc,
        actual,
    )


def _tail(record: StaticPayload, context: StaticMatchContext) -> StaticStageResult:
    name = "tail_page_crc"
    gate = _size_gate(record, context)
    if gate != "match":
        reason = "size_mismatch" if gate == "no_match" else "provider_size_unavailable"
        return _stage(2, name, gate, reason)
    selected = _selected_source(context)
    if selected is None:
        return _stage(2, name, "unknown", "selected_source_unavailable")
    count = min(record.file_size, _PAGE_SIZE)
    primary = _crc_raw(
        bytes(_PAGE_SIZE - count)
        + selected[record.file_size - count : record.file_size]
    )
    if primary == record.tail_page_crc:
        return _stage(
            2, name, "match", "record_tail_crc_equal", record.tail_page_crc, primary
        )
    if not record.allow_larger:
        return _stage(
            2,
            name,
            "no_match",
            "record_tail_crc_mismatch",
            record.tail_page_crc,
            primary,
        )
    if len(selected) < _PAGE_SIZE:
        return _stage(
            2,
            name,
            "unknown",
            "provider_tail_short_padding_unknown",
            record.tail_page_crc,
            primary,
        )
    alternative = _crc_raw(selected[-_PAGE_SIZE:])
    status: MatchStatus = "match" if alternative == record.tail_page_crc else "no_match"
    return _stage(
        2,
        name,
        status,
        "provider_tail_crc_equal" if status == "match" else "both_tail_crc_mismatch",
        record.tail_page_crc,
        alternative,
    )


def _digest(record: StaticPayload, data: bytes) -> bytes:
    mode = record.mode
    if mode is StaticHashMode.CRC_0:
        return _crc_raw(data).to_bytes(4, "little")
    algorithm = {
        StaticHashMode.MD5: "md5",
        StaticHashMode.SHA1: "sha1",
        StaticHashMode.SHA1_PREFIX4: "sha1",
        StaticHashMode.SHA256: "sha256",
    }[mode]
    digest = hashlib.new(algorithm, data).digest()
    return digest[:4] if mode is StaticHashMode.SHA1_PREFIX4 else digest


def _mode_hash(record: StaticPayload, context: StaticMatchContext) -> StaticStageResult:
    name = "mode_hash"
    if record.mode is None:
        return _stage(3, name, "no_match", "unsupported_mode_5_to_7")
    gate = _size_gate(record, context)
    if gate != "match":
        reason = "size_mismatch" if gate == "no_match" else "provider_size_unavailable"
        return _stage(3, name, gate, reason)
    if context.configuration_gate is False:
        return _stage(3, name, "no_match", "configuration_gate_failed")
    selected = _selected_source(context)
    if selected is None:
        return _stage(3, name, "unknown", "selected_source_unavailable")
    actual = _digest(record, selected[: record.file_size])
    if actual != record.hash_raw:
        return _stage(3, name, "no_match", "hash_mismatch", record.hash_raw, actual)
    if context.configuration_gate is not True:
        return _stage(
            3,
            name,
            "unknown",
            "configuration_gate_context_required",
            record.hash_raw,
            actual,
        )
    if context.provider_size == record.file_size:
        return _stage(
            3, name, "match", "hash_equal_exact_size", record.hash_raw, actual
        )
    if context.threat_exception_name is True or context.valid_signed is False:
        return _stage(
            3,
            name,
            "match",
            "hash_equal_long_target_gate_passed",
            record.hash_raw,
            actual,
        )
    if context.threat_exception_name is False and context.valid_signed is True:
        return _stage(
            3, name, "no_match", "long_target_gate_failed", record.hash_raw, actual
        )
    return _stage(
        3, name, "unknown", "long_target_gate_context_required", record.hash_raw, actual
    )


def evaluate_static(
    record: StaticPayload, context: StaticMatchContext
) -> StaticMatchResult:
    """Evaluate confirmed local stages; unknown never means a positive scan verdict.

    A known negative stage short-circuits later stages. Missing inputs or
    incomplete selected source bytes produce unknown, not a CRC/hash mismatch.
    """
    functions = (_first_page, _prefix, _tail, _mode_hash)
    names = ("first_page_crc_candidate_key", "prefix_crc", "tail_page_crc", "mode_hash")
    stages: list[StaticStageResult] = []
    if record.mode is None:
        stages.extend(
            _stage(index, name, "unknown", "not_evaluated_unsupported_mode")
            for index, name in enumerate(names[:3])
        )
        stages.append(_mode_hash(record, context))
        return StaticMatchResult("no_match", "unsupported_mode_5_to_7", tuple(stages))
    for index, function in enumerate(functions):
        stage = function(record, context)
        stages.append(stage)
        if stage.status == "no_match":
            stages.extend(
                _stage(later, names[later], "unknown", "not_evaluated_after_no_match")
                for later in range(index + 1, len(names))
            )
            return StaticMatchResult("no_match", stage.reason, tuple(stages))
    unknown = next((stage for stage in stages if stage.status == "unknown"), None)
    if unknown is not None:
        return StaticMatchResult("unknown", unknown.reason, tuple(stages))
    return StaticMatchResult("match", "all_record_local_stages_match", tuple(stages))
