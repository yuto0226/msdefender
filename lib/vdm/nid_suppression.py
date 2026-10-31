"""Reply-NULL/name-NULL NID64 lookup for explicit effective runtime snapshots.

This models raw statuses and the nid64search status==1 projection, not a whole
namespace/cache loader or general scan verdict. Names are raw C-string contents;
NULL and non-NULL empty differ. Recursion follows only reached candidates.
"""

import struct
import zlib
from collections.abc import Generator
from dataclasses import dataclass
from itertools import pairwise
from typing import Literal


class UnsupportedNidSuppression(ValueError):
    """The reached query is outside the snapshot view or has a recursive cycle."""


def _uint(value: int, bits: int, label: str) -> None:
    if type(value) is not int or not 0 <= value < 1 << bits:
        raise ValueError(f"{label} must be an unsigned {bits}-bit integer")


@dataclass(frozen=True, slots=True)
class Nid64RuntimeEntry:
    key: int
    selector: int
    runtime_name: bytes | None

    def __post_init__(self) -> None:
        _uint(self.key, 64, "NID64 key")
        _uint(self.selector, 8, "entry selector")
        if self.runtime_name is not None:
            if not isinstance(self.runtime_name, bytes):
                raise TypeError("runtime_name must be raw bytes or None")
            if b"\0" in self.runtime_name:
                raise ValueError("runtime_name must be NUL-free C-string content")


@dataclass(frozen=True, slots=True)
class Nid64LookupSnapshot:
    """Normalized effective rows with immutable names and consistent Bloom/index.

    Rows are flattened in normalized candidate order, sorted by unsigned key;
    equal-key order is retained. all means complete effective base/delta views.
    selector108 is an explicit filtered metadata view, never evidence that other
    selectors are absent. Queries outside that view raise Unsupported.
    """

    delta: tuple[Nid64RuntimeEntry, ...]
    base: tuple[Nid64RuntimeEntry, ...]
    metadata_view: Literal["all", "selector108"] = "all"

    def __post_init__(self) -> None:
        if self.metadata_view not in ("all", "selector108"):
            raise UnsupportedNidSuppression("unsupported NID64 metadata view")
        for rows in (self.delta, self.base):
            if not isinstance(rows, tuple) or any(
                not isinstance(row, Nid64RuntimeEntry) for row in rows
            ):
                raise TypeError("NID64 stores must be tuples of Nid64RuntimeEntry")
            if any(left.key > right.key for left, right in pairwise(rows)):
                raise ValueError(
                    "NID64 stores must retain normalized unsigned-key order"
                )
            if self.metadata_view == "selector108" and any(
                row.selector != 108 for row in rows
            ):
                raise ValueError("selector108 view contains a different selector")


@dataclass(frozen=True, slots=True)
class Nid64LookupResult:
    status: int
    runtime_name: bytes | None


def nid64_signature_sequence(key: int, selector: int) -> int:
    """Return entry GetSigSeq, not a general NID64 wire-key derivation."""
    _uint(key, 64, "NID64 key")
    _uint(selector, 8, "entry selector")
    return (zlib.crc32(struct.pack("<QB", key, selector)) ^ 0xFFFFFFFF) | 0x9CE00000000


def _candidates(
    snapshot: Nid64LookupSnapshot, selector: int, key: int
) -> Generator[tuple[int, int], Nid64LookupResult, Nid64LookupResult]:
    for rows in (snapshot.delta, snapshot.base):
        result = Nid64LookupResult(0, None)
        for row in rows:
            if row.key != key or row.selector != selector:
                continue
            name = row.runtime_name
            if name is not None and name.startswith(b"!#"):
                status = 1
            else:
                child = yield (108, nid64_signature_sequence(row.key, row.selector))
                status = 2 if child.status == 1 else 1
            result = Nid64LookupResult(status, name)
            if name is None and status == 1:
                return result
        if result.status:
            return result
    return Nid64LookupResult(0, None)


def lookup_nid64_name(
    snapshot: Nid64LookupSnapshot, selector: int, key: int
) -> Nid64LookupResult:
    """Evaluate original reply-NULL candidate policy with iterative lazy traversal.

    Query selector remains full u32. nid64search(name=NULL) accepts this result
    only when status==1. Reached cycles raise Unsupported; unreachable cycles do
    not invalidate a snapshot. No Python recursion or arbitrary depth truncation is
    used. The caller still asserts successful engine resource/initialization state.
    """
    if not isinstance(snapshot, Nid64LookupSnapshot):
        raise TypeError("an explicit Nid64LookupSnapshot is required")
    _uint(selector, 32, "query selector")
    _uint(key, 64, "NID64 query key")
    if snapshot.metadata_view == "selector108" and selector != 108:
        raise UnsupportedNidSuppression(
            "query is outside the selector108 metadata view"
        )
    state = (selector, key)
    active = {state}
    stack = [(state, _candidates(snapshot, *state))]
    memo: dict[tuple[int, int], Nid64LookupResult] = {}
    resumed = None
    while stack:
        current, iterator = stack[-1]
        try:
            child = next(iterator) if resumed is None else iterator.send(resumed)
            resumed = None
        except StopIteration as completed:
            result = completed.value
            memo[current] = result
            active.remove(current)
            stack.pop()
            if not stack:
                return result
            resumed = result
            continue
        if child in active:
            raise UnsupportedNidSuppression("reached recursive selector108 cycle")
        if child in memo:
            resumed = memo[child]
        else:
            active.add(child)
            stack.append((child, _candidates(snapshot, *child)))
    raise AssertionError("lookup traversal did not produce a result")
