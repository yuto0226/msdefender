"""Bounded callback12 value projections and wide full-match collection predicate.

Local syntax support is distinct from original-engine compile acceptance. This
module does not emulate allocation, callback completion, report policy or DNS
collection. Malformed UTF8 remains outside the local decoder's supported domain.
"""

from dataclasses import dataclass
from typing import Literal


class UnsupportedDnsCacheInfo(ValueError):
    """Unavailable readable storage or a locally unsupported encoding/syntax.

    This is not an original-engine rejection or native callback status.
    """


def decode_dns_cache_info_utf8(effective_utf8: bytes) -> tuple[int, ...]:
    """Decode a valid, NUL-free UTF8 pattern to exact UTF16 code units.

    Original CP65001/flags0 accepts some malformed inputs. Its 405-fixture
    replacement model is experimental and deliberately not used here.
    """
    if not isinstance(effective_utf8, bytes):
        raise TypeError("effective UTF8 pattern must be bytes")
    if b"\0" in effective_utf8:
        raise UnsupportedDnsCacheInfo("effective pattern must exclude its first NUL")
    try:
        wide = effective_utf8.decode("utf-8", errors="strict").encode("utf-16le")
    except UnicodeDecodeError as exc:
        raise UnsupportedDnsCacheInfo(
            "malformed UTF8 is unsupported locally, not rejected by the engine"
        ) from exc
    return tuple(
        int.from_bytes(wide[i : i + 2], "little") for i in range(0, len(wide), 2)
    )


def _pattern_parts(
    effective_utf8: bytes,
) -> tuple[tuple[int, ...], tuple[int, ...], Literal["none", "leading", "trailing"]]:
    units = decode_dns_cache_info_utf8(effective_utf8)
    wildcard: Literal["none", "leading", "trailing"] = "none"
    literal = units
    if units[:2] == (0x2E, 0x2A):
        wildcard, literal = "leading", units[2:]
    elif units[-2:] == (0x2E, 0x2A):
        wildcard, literal = "trailing", units[:-2]
    if any(unit in (*map(ord, ".^$*+?{}[]()|"), 0x5C) for unit in literal):
        raise UnsupportedDnsCacheInfo("supports literal and at most one edge .* only")
    return units, literal, wildcard


@dataclass(frozen=True, slots=True)
class DnsCacheInfoPattern:
    """Local scalar IR; successful native ingestion is a separate assertion.

    Valid UTF8 literals, including non-ASCII and supplementary scalars, retain
    their UTF16 units. Local support does not establish arbitrary Unicode
    literal acceptance, locale behavior or original constructor success.
    """

    effective_utf8: bytes
    utf16_units: tuple[int, ...]
    literal_units: tuple[int, ...]
    wildcard: Literal["none", "leading", "trailing"]

    def __post_init__(self) -> None:
        if type(self.utf16_units) is not tuple or type(self.literal_units) is not tuple:
            raise TypeError("pattern units must be immutable tuples")
        if any(type(unit) is not int for unit in self.utf16_units + self.literal_units):
            raise TypeError("UTF16 units must be integers")
        expected = _pattern_parts(self.effective_utf8)
        if (self.utf16_units, self.literal_units, self.wildcard) != expected:
            raise ValueError("pattern fields must agree with effective UTF8 syntax")

    @property
    def constructor_recipe(self) -> tuple[str, int, int]:
        """Original DLL RVA, wide CString syntax flags, match flags."""
        return "mpengine.dll+0x35D144", 0x400000, 0x400

    @property
    def engine_acceptance(self) -> None:
        """No per-object native compile assertion is synthesized by local parsing."""
        return None


def compile_dns_cache_info_pattern(effective_utf8: bytes) -> DnsCacheInfoPattern:
    """Compile empty/literal/single-edge-dotstar local syntax, without Python re."""
    return DnsCacheInfoPattern(effective_utf8, *_pattern_parts(effective_utf8))


@dataclass(frozen=True, slots=True)
class DnsCacheInfoSubject:
    """Readable UTF16LE CString storage supplied by an external source recipe.

    The first aligned NUL terminates selection. Bytes after it are preserved,
    including an odd trailing byte; lone surrogates are raw units, not errors.
    No NULL subject or missing terminator is inferred as an empty string.
    """

    raw_storage: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.raw_storage, bytes):
            raise TypeError("subject storage must be bytes")
        if self.terminator_offset is None:
            raise UnsupportedDnsCacheInfo("subject needs a readable aligned NUL WORD")

    @property
    def terminator_offset(self) -> int | None:
        return next(
            (
                i
                for i in range(0, len(self.raw_storage) - 1, 2)
                if self.raw_storage[i : i + 2] == b"\0\0"
            ),
            None,
        )

    @property
    def effective_units(self) -> tuple[int, ...]:
        end = self.terminator_offset
        assert end is not None
        return tuple(
            int.from_bytes(self.raw_storage[i : i + 2], "little")
            for i in range(0, end, 2)
        )

    @property
    def trailing_raw(self) -> bytes:
        end = self.terminator_offset
        assert end is not None
        return self.raw_storage[end + 2 :]


def fullmatch_dns_cache_info_pattern(
    pattern: DnsCacheInfoPattern, subject: DnsCacheInfoSubject
) -> bool:
    """Case-sensitive code-unit predicate over the explicitly selected CString.

    Dotstar covers non-NUL units; CString selection precedes this predicate.
    Single-unit exhaustive evidence is not an arbitrary-string native proof.
    """
    if not isinstance(pattern, DnsCacheInfoPattern) or not isinstance(
        subject, DnsCacheInfoSubject
    ):
        raise TypeError("expected typed pattern and explicit subject storage")
    units, literal = subject.effective_units, pattern.literal_units
    if len(units) < len(literal):
        return False
    if pattern.wildcard == "leading":
        return not literal or units[-len(literal) :] == literal
    if pattern.wildcard == "trailing":
        return units[: len(literal)] == literal
    return units == literal


@dataclass(frozen=True, slots=True)
class DnsCacheInfoCollectionSnapshot:
    """Externally resolved successful ingestion state, in runtime append order.

    Duplicates remain separate rows. No wire sorting, allocation, exception,
    compile-success or report-policy history is manufactured by this snapshot.
    """

    initialized: bool
    successfully_ingested_patterns: tuple[DnsCacheInfoPattern, ...]
    input_source: str

    def __post_init__(self) -> None:
        if type(self.initialized) is not bool:
            raise TypeError("initialized must be bool")
        if type(self.successfully_ingested_patterns) is not tuple or any(
            not isinstance(p, DnsCacheInfoPattern)
            for p in self.successfully_ingested_patterns
        ):
            raise TypeError("successful rows must be a tuple of supported patterns")
        if not self.initialized and self.successfully_ingested_patterns:
            raise ValueError("a NULL vector cannot contain ingested rows")
        if not isinstance(self.input_source, str) or not self.input_source.strip():
            raise ValueError("an external input/source context is required")


def should_collect_dns_info(
    snapshot: DnsCacheInfoCollectionSnapshot, subject: DnsCacheInfoSubject
) -> bool:
    """Collection selector only; report gates, DNS acquisition and verdict external.

    Static ShouldCollectDnsInfo has a NULL-vector false guard. The input API
    still requires a typed readable subject and makes no NULL-subject promise.
    """
    if not isinstance(snapshot, DnsCacheInfoCollectionSnapshot) or not isinstance(
        subject, DnsCacheInfoSubject
    ):
        raise TypeError("expected collection snapshot and explicit subject")
    return snapshot.initialized and any(
        fullmatch_dns_cache_info_pattern(pattern, subject)
        for pattern in snapshot.successfully_ingested_patterns
    )


@dataclass(frozen=True, slots=True)
class DnsCacheInfoReceiverProjection:
    """Receiver branch recipe, not an executed allocation/compile/append.

    ensure_vector precedes the non-NULL format gate. Invalid input preserves
    existing rows; projecting it does not clear or mutate a snapshot.
    """

    storage: bytes | None
    count: int
    branch: Literal["finalize", "invalid", "compile_candidate"]
    ensure_vector: bool
    known_return_u32: int | None
    counted_data: bytes | None
    effective_utf8: bytes | None
    after_pattern_terminator: bytes | None
    physical_tail: bytes | None


def project_dns_cache_info_receiver(
    storage: bytes | None, count: int
) -> DnsCacheInfoReceiverProjection:
    """Project NULL/0x800C gates separately from local pattern compilation.

    count is uint32; non-NULL input must expose count physical bytes. A valid
    gate does not assert callback completion or original compiler acceptance.
    RecID is intentionally absent: the original receiver does not read it.
    """
    if type(count) is not int or not 0 <= count <= 0xFFFFFFFF:
        raise ValueError("count must be uint32")
    if storage is not None and not isinstance(storage, bytes):
        raise TypeError("receiver storage must be bytes or None")
    if storage is None:
        return DnsCacheInfoReceiverProjection(
            None, count, "finalize", False, 0, None, None, None, None
        )
    if len(storage) < count:
        raise UnsupportedDnsCacheInfo("receiver gate requires unavailable bytes")
    data, tail = storage[:count], storage[count:]
    if not count or data[-1] != 0:
        return DnsCacheInfoReceiverProjection(
            storage, count, "invalid", True, 0x800C, data, None, None, tail
        )
    first = data.index(0)
    return DnsCacheInfoReceiverProjection(
        storage,
        count,
        "compile_candidate",
        True,
        None,
        data,
        data[:first],
        data[first + 1 :],
        tail,
    )
