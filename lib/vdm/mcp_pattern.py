"""Callback23 byte recipes and externally supplied compiled-vector outcomes.

No regex evaluator or JSON serializer is implemented. Runtime rows attest to
successful native compilation and actual vector order; wire order cannot supply it.
"""

from dataclasses import dataclass
from typing import Literal

BOOST_SYNTAX_FLAGS = 0x400000
BOOST_MATCH_FLAGS = 0x400


class UnsupportedMcpPattern(ValueError):
    """Requested counted storage is unavailable, not native regex rejection."""


def _count(value: int, maximum: int, label: str) -> None:
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError(f"{label} must be unsigned and at most {maximum}")


@dataclass(frozen=True, slots=True)
class McpPatternReceiverProjection:
    storage: bytes | None
    count: int

    def __post_init__(self) -> None:
        _count(self.count, 0xFFFFFFFF, "count")
        if self.storage is not None:
            if not isinstance(self.storage, bytes):
                raise TypeError("storage must be bytes or None")
            if len(self.storage) < self.count:
                raise UnsupportedMcpPattern("counted storage is unavailable")

    @property
    def counted_data(self) -> bytes | None:
        return None if self.storage is None else self.storage[: self.count]

    @property
    def physical_tail(self) -> bytes | None:
        return None if self.storage is None else self.storage[self.count :]

    @property
    def branch(self) -> Literal["null_noop", "invalid", "compile_candidate"]:
        if self.storage is None:
            return "null_noop"
        data = self.counted_data
        return "compile_candidate" if data and data[-1] == 0 else "invalid"

    @property
    def effective_pattern(self) -> bytes | None:
        data = self.counted_data
        return data[: data.index(0)] if self.branch == "compile_candidate" else None

    @property
    def after_terminator(self) -> bytes | None:
        data = self.counted_data
        return data[data.index(0) + 1 :] if self.branch == "compile_candidate" else None

    @property
    def known_return_u32(self) -> int | None:
        return {"null_noop": 0, "invalid": 32780, "compile_candidate": None}[
            self.branch
        ]

    @property
    def engine_compile_accepted(self) -> None:
        return None


def project_mcp_pattern_receiver(
    storage: bytes | None, count: int
) -> McpPatternReceiverProjection:
    return McpPatternReceiverProjection(storage, count)


@dataclass(frozen=True, slots=True)
class McpSubject:
    """Exact std::string byte range; NULs remain bytes, with no JSON conversion."""

    storage: bytes
    size: int

    def __post_init__(self) -> None:
        if not isinstance(self.storage, bytes):
            raise TypeError("storage must be bytes")
        _count(self.size, 0xFFFFFFFFFFFFFFFF, "size")
        if self.size > len(self.storage):
            raise UnsupportedMcpPattern("subject storage is unavailable")

    @property
    def data(self) -> bytes:
        return self.storage[: self.size]

    @property
    def physical_tail(self) -> bytes:
        return self.storage[self.size :]


@dataclass(frozen=True, slots=True)
class McpCompiledRuntimeRow:
    """Caller attests this row successfully compiled in the original runtime.

    record_id is runtime metadata, never a DWORD decoded from wire data.
    Opaque regex internals and padding@0x14 are deliberately not synthesized.
    """

    effective_pattern: bytes
    record_id: int
    compilation_succeeded: bool

    def __post_init__(self) -> None:
        if not isinstance(self.effective_pattern, bytes):
            raise TypeError("effective_pattern must be bytes")
        if b"\0" in self.effective_pattern:
            raise ValueError("effective CString pattern cannot contain NUL")
        _count(self.record_id, 0xFFFFFFFF, "record_id")
        if self.compilation_succeeded is not True:
            raise ValueError("runtime rows require explicit successful compilation")


@dataclass(frozen=True, slots=True)
class McpRuntimeVectorSnapshot:
    """Complete selected vector in externally attested actual runtime order."""

    rows: tuple[McpCompiledRuntimeRow, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.rows, tuple) or any(
            not isinstance(row, McpCompiledRuntimeRow) for row in self.rows
        ):
            raise TypeError("rows must be an immutable tuple of McpCompiledRuntimeRow")


@dataclass(frozen=True, slots=True)
class McpFirstMatchResult:
    matched: bool
    record_id: int
    row_index: int | None


def first_match_mcp_pattern(
    snapshot: McpRuntimeVectorSnapshot,
    subject: McpSubject,
    outcomes: tuple[bool, ...],
) -> McpFirstMatchResult:
    """Project first-match linkage using external per-row Search bool results.

    Outcomes must describe this exact subject and snapshot. No evaluation occurs;
    all outcomes are validated even if an early row matches. RecID0 still stops.
    """
    if not isinstance(snapshot, McpRuntimeVectorSnapshot):
        raise TypeError("snapshot must be McpRuntimeVectorSnapshot")
    if not isinstance(subject, McpSubject):
        raise TypeError("subject must be McpSubject")
    if not isinstance(outcomes, tuple) or any(type(v) is not bool for v in outcomes):
        raise TypeError("outcomes must be an immutable tuple of bool")
    if len(outcomes) != len(snapshot.rows):
        raise ValueError("outcomes must have one bool for every runtime row")
    for index, (row, matched) in enumerate(zip(snapshot.rows, outcomes, strict=True)):
        if matched:
            return McpFirstMatchResult(True, row.record_id, index)
    return McpFirstMatchResult(False, 0, None)
