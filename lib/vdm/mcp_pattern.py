"""Callback23 byte recipes and externally supplied compiled-vector outcomes.

Only two pinned effective patterns have a local Boolean evaluator. JSON
serialization remains external. Runtime rows attest to successful native
compilation and actual vector order; wire order cannot supply it.
"""

import hashlib
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


@dataclass(frozen=True, slots=True)
class McpActual2Profile:
    """Pins for the two compiled graphs and their reachable-handler closure."""

    engine_sha256: str
    closure_evidence_sha256: str
    compiled_snapshot_results_sha256: str
    syntax_flags: int
    match_flags: int

    def __post_init__(self) -> None:
        if any(
            type(value) is not str
            for value in (
                self.engine_sha256,
                self.closure_evidence_sha256,
                self.compiled_snapshot_results_sha256,
            )
        ):
            raise TypeError("profile hashes must be strings")
        if type(self.syntax_flags) is not int or type(self.match_flags) is not int:
            raise TypeError("profile flags must be integers")


MCP_ACTUAL2_PROFILE = McpActual2Profile(
    "928e171c60a44bb326776d2a356412ae98d78469bdf8c94ebfbfa09f8ec4b4b3",
    "6e3a743d0e5fda030401c49e4d00d7bf215a9ae7db3577e83dc8e6134639938f",
    "50d9975b553b5c9a11f24d39c915ee0cf4d751b3825a0934e5e6f47595247975",
    0x400000,
    0x400,
)
MCP_ACTUAL2_SCOPE = (
    "Only two exact effective patterns, case-sensitive Boolean existence on the same "
    "valid explicit byte span, conditional on original VM completing without "
    "resource/exception paths (including exceptions caught by Search). "
    "No offsets/captures, arbitrary regex, whole-file equivalence, JSON serializer, "
    "report, cleanup or final policy equivalence."
)
_ACTUAL2_PARTS = {
    "bcf0765b1f3e7c77efe791a0e87d6ee72aefeccd8e63908288b1e265b18954dd": (
        b"258909e0-d276-4c59-b89a-6a52f8605c4d",
        b"com/8e41bff5-6bdc-4805-b8e2-4858f0717177",
    ),
    "12ea10f2892611dc613b47242c5e02439fa09aa683d85a8122a0c94d20b9f26a": (
        b"29c69b61-3725-4b82-992f-ba13d0e3f048",
        b"com/9b715549-3478-4866-91eb-3763b669e77d",
    ),
}


def _actual2_parts(effective_pattern: bytes) -> tuple[bytes, bytes]:
    if not isinstance(effective_pattern, bytes):
        raise TypeError("effective_pattern must be bytes")
    parts = _ACTUAL2_PARTS.get(hashlib.sha256(effective_pattern).hexdigest())
    if (
        parts is None
        or effective_pattern != b"transport.*http.*" + parts[0] + b"." + parts[1]
    ):
        raise UnsupportedMcpPattern(
            "only two exact SHA-pinned actual effective patterns are locally supported; "
            "unsupported is not original engine rejection"
        )
    return parts


@dataclass(frozen=True, slots=True)
class McpActual2Pattern:
    effective_pattern: bytes
    profile: McpActual2Profile = MCP_ACTUAL2_PROFILE

    def __post_init__(self) -> None:
        _actual2_parts(self.effective_pattern)
        if (
            not isinstance(self.profile, McpActual2Profile)
            or self.profile != MCP_ACTUAL2_PROFILE
        ):
            raise UnsupportedMcpPattern("compiled graph profile pins do not match")

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.effective_pattern).hexdigest()


def compile_mcp_actual2_pattern(
    effective_pattern: bytes, *, profile: McpActual2Profile = MCP_ACTUAL2_PROFILE
) -> McpActual2Pattern:
    """Select an exact compiled-graph proof; does not compile arbitrary Boost syntax."""
    return McpActual2Pattern(effective_pattern, profile)


def search_mcp_actual2_pattern(pattern: McpActual2Pattern, subject: McpSubject) -> bool:
    """Existence only, with the conditional VM-completion scope in MCP_ACTUAL2_SCOPE.

    Earliest transport and then earliest http leave every later candidate available
    through the two unbounded gaps. A failed domain suffix advances to the next
    domain occurrence, including overlapping occurrences. NUL is an ordinary byte.
    """
    if not isinstance(pattern, McpActual2Pattern):
        raise TypeError("pattern must be McpActual2Pattern")
    if not isinstance(subject, McpSubject):
        raise TypeError("subject must be McpSubject")
    domain, tail = _actual2_parts(pattern.effective_pattern)
    data = subject.data
    transport = data.find(b"transport")
    if transport < 0:
        return False
    http = data.find(b"http", transport + len(b"transport"))
    if http < 0:
        return False
    position = data.find(domain, http + len(b"http"))
    while position >= 0:
        tail_start = position + len(domain) + 1
        if data.startswith(tail, tail_start):
            return True
        position = data.find(domain, position + 1)
    return False


def mcp_actual2_yara_rhs(pattern: McpActual2Pattern) -> str:
    """One hex string fragment, valid only when scanned on exactly subject.data."""
    if not isinstance(pattern, McpActual2Pattern):
        raise TypeError("pattern must be McpActual2Pattern")
    domain, tail = _actual2_parts(pattern.effective_pattern)
    literals = (b"transport", b"http", domain, tail)
    a, b, c, d = (value.hex(" ").upper() for value in literals)
    return "{ " + a + " [0-] " + b + " [0-] " + c + " ?? " + d + " }"
