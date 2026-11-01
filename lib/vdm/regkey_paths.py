"""REGKEY expansion comparison over invocation-bound resolver observations.

No resolver or offline patch service runs here. WCHAR buffers are physical
readable bytes, including any terminator/trailing bytes; missing reads remain
unknown. The final comparator uses code units, never host Unicode casefold.
"""

from dataclasses import dataclass, replace

from .regkey_offline import (
    RegKeyOfflinePatchResult,
    RegKeyOfflinePatchSnapshot,
    project_regkey_offline_patch,
)


class RegKeyPathSnapshotError(ValueError):
    """Malformed facts or observations bound to another invocation/input."""


def _uint(value: int, bits: int) -> None:
    if type(value) is not int or not 0 <= value < 1 << bits:
        raise RegKeyPathSnapshotError(f"expected uint{bits}")


def _bytes(value: bytes) -> None:
    if type(value) is not bytes:
        raise RegKeyPathSnapshotError("expected immutable bytes")


@dataclass(frozen=True, slots=True)
class RegKeyUncPrefixObservation:
    """Actual CRT comparison, bound to physical input and this invocation."""

    epoch: str
    input_utf16: bytes
    crt_profile_identity: bytes
    equal: bool

    def __post_init__(self) -> None:
        _epoch(self.epoch)
        _bytes(self.input_utf16)
        _bytes(self.crt_profile_identity)
        if type(self.equal) is not bool:
            raise RegKeyPathSnapshotError("UNC comparison must be bool")


@dataclass(frozen=True, slots=True)
class RegKeyPathValue:
    """Physical WCHAR bytes and optional actual CRT _wcsnicmp(...,8)==0.

    The CRT observation is needed only for a reached non-ASCII UNC-prefix
    comparison. None bytes means unreadable/unknown, not NULL or empty.
    """

    readable_utf16: bytes | None
    unc_prefix: RegKeyUncPrefixObservation | None = None

    def __post_init__(self) -> None:
        if self.readable_utf16 is not None:
            _bytes(self.readable_utf16)
        if (
            self.unc_prefix is not None
            and type(self.unc_prefix) is not RegKeyUncPrefixObservation
        ):
            raise RegKeyPathSnapshotError("wrong UNC observation type")


@dataclass(frozen=True, slots=True)
class RegKeyResolvedPathList:
    """One actual LUM_GetRealPathList output; None differs from empty tuple.

    epoch identifies this invocation, not an entire scan. input_utf16 binds the
    exact physical argument buffer. profile_identity is an opaque runtime
    identity, not a profile inferred from a path or the host environment.
    """

    epoch: str
    input_utf16: bytes
    profile_identity: bytes
    flags: int
    status: int | None
    paths: tuple[RegKeyPathValue, ...] | None

    def __post_init__(self) -> None:
        _epoch(self.epoch)
        _bytes(self.input_utf16)
        _bytes(self.profile_identity)
        _uint(self.flags, 32)
        if self.status is not None:
            _uint(self.status, 32)
        if self.paths is not None and (
            type(self.paths) is not tuple
            or any(type(p) is not RegKeyPathValue for p in self.paths)
        ):
            raise RegKeyPathSnapshotError("paths must be a tuple of PathValue or None")


def _epoch(value: str) -> None:
    if type(value) is not str or not value:
        raise RegKeyPathSnapshotError("nonempty invocation epoch required")


@dataclass(frozen=True, slots=True)
class RegKeyExpansionSnapshot:
    """Independent post-offline-patch and resolver facts for this invocation.

    The caller ignores patch status. postpatch is independently observed or
    computed from offline_patch inputs; known conflicts are rejected.
    expected_utf16 is NUL-free content; original_value_utf16/postpatch/resolved
    paths are physical bytes.
    """

    epoch: str
    payload_raw: bytes
    original_value_utf16: bytes
    expected_utf16: bytes
    postpatch: RegKeyPathValue | None
    profile_identity: bytes | None
    context_flags: int | None
    crt_profile_identity: bytes | None = None
    left: RegKeyResolvedPathList | None = None
    right: RegKeyResolvedPathList | None = None
    offline_patch: RegKeyOfflinePatchSnapshot | None = None

    def __post_init__(self) -> None:
        _epoch(self.epoch)
        for value in (self.payload_raw, self.original_value_utf16, self.expected_utf16):
            _bytes(value)
        if len(self.expected_utf16) % 2 or any(
            self.expected_utf16[i : i + 2] == b"\0\0"
            for i in range(0, len(self.expected_utf16), 2)
        ):
            raise RegKeyPathSnapshotError("expected must be NUL-free WCHAR content")
        if self.postpatch is not None and type(self.postpatch) is not RegKeyPathValue:
            raise RegKeyPathSnapshotError("postpatch must be PathValue or None")
        if self.profile_identity is not None:
            _bytes(self.profile_identity)
        if self.context_flags is not None:
            _uint(self.context_flags, 32)
        if self.crt_profile_identity is not None:
            _bytes(self.crt_profile_identity)
        for value in (self.left, self.right):
            if value is not None and type(value) is not RegKeyResolvedPathList:
                raise RegKeyPathSnapshotError("resolver facts have the wrong type")
        if (
            self.offline_patch is not None
            and type(self.offline_patch) is not RegKeyOfflinePatchSnapshot
        ):
            raise RegKeyPathSnapshotError("wrong offline patch snapshot type")


@dataclass(frozen=True, slots=True)
class RegKeyPathComparison:
    record_local_match: bool | None
    reason: str
    matched_pair: tuple[int, int] | None = None
    compared_pairs: tuple[tuple[int, int, bool | None], ...] = ()
    left_paths: tuple[RegKeyPathValue, ...] | None = None
    right_paths: tuple[RegKeyPathValue, ...] | None = None
    matched_left_friendly_utf16: bytes | None = None
    matched_right_friendly_utf16: bytes | None = None
    matched_comparison_utf16: bytes | None = None
    offline_patch: RegKeyOfflinePatchResult | None = None


def _unit(path: RegKeyPathValue, index: int) -> int | None:
    raw = path.readable_utf16
    offset = index * 2
    if raw is None or offset + 2 > len(raw):
        return None
    return int.from_bytes(raw[offset : offset + 2], "little")


def _friendly(path: RegKeyPathValue, snapshot: RegKeyExpansionSnapshot) -> int | None:
    # wcsncmp literal prefix first, with early mismatch/NUL termination.
    for i, expected in enumerate((92, 92, 63, 92)):
        actual = _unit(path, i)
        if actual is None:
            return None
        if actual != expected:
            return 0
    # _wcsnicmp eight WCHARs: ASCII subset, or actual CRT observation.
    observation = path.unc_prefix
    observed_equal = None
    if observation is not None:
        if (
            observation.epoch != snapshot.epoch
            or observation.input_utf16 != path.readable_utf16
            or snapshot.crt_profile_identity is None
            or observation.crt_profile_identity != snapshot.crt_profile_identity
        ):
            raise RegKeyPathSnapshotError("CRT UNC observation binding mismatch")
        observed_equal = observation.equal
    equal = True
    for i, expected in enumerate((92, 92, 63, 92, 85, 78, 67, 92)):
        actual = _unit(path, i)
        if actual is None or actual >= 128:
            equal = observed_equal
            break
        folded = actual - 32 if 97 <= actual <= 122 else actual
        if folded != expected:
            equal = False
            break
    if equal is None:
        return None
    if observed_equal is not None and observed_equal != equal:
        raise RegKeyPathSnapshotError("CRT UNC observation contradicts ASCII prefix")
    return 0 if equal else 4


def _fold(unit: int) -> int:
    if 97 <= unit <= 122:
        return unit - 32
    return 92 if unit == 47 else unit


def _pair(
    left: RegKeyPathValue, right: RegKeyPathValue, snapshot: RegKeyExpansionSnapshot
) -> bool | None:
    # GetFriendlyFileNameW executes for right before left in each pair.
    ro = _friendly(right, snapshot)
    if ro is None:
        return None
    lo = _friendly(left, snapshot)
    if lo is None:
        return None
    i = 0
    while True:
        r, l = _unit(right, ro + i), _unit(left, lo + i)
        if r is None or l is None:
            return None
        if _fold(r) != _fold(l):
            return False
        if r == 0:
            return True
        i += 1


def _matched_content(path: RegKeyPathValue, snapshot: RegKeyExpansionSnapshot) -> bytes:
    # Called only after equality reached both physical NUL terminators.
    start = _friendly(path, snapshot)
    assert start is not None
    units = []
    while (unit := _unit(path, start + len(units))) != 0:
        assert unit is not None
        units.append(unit)
    return b"".join(unit.to_bytes(2, "little") for unit in units)


def _project_regkey_expansion(
    payload_raw: bytes,
    original_value_utf16: bytes,
    expected_utf16: bytes,
    expand_left: bool,
    snapshot: RegKeyExpansionSnapshot | None,
) -> RegKeyPathComparison:
    """Compute only expand_path_cmp's result from concrete service outputs.

    Services execute left (if requested), then right, even for an empty left
    list. This is a result projection, not an executed service-call trace.
    Unknown earlier comparisons stop projection; later facts cannot establish
    reachability past an unknown call/read. A match skips all later pairs.
    """
    if type(expand_left) is not bool:
        raise RegKeyPathSnapshotError("expand_left must be bool")
    for value in (payload_raw, original_value_utf16, expected_utf16):
        _bytes(value)
    if snapshot is None:
        return RegKeyPathComparison(None, "expansion_snapshot_required")
    if type(snapshot) is not RegKeyExpansionSnapshot:
        raise RegKeyPathSnapshotError("wrong expansion snapshot type")
    if (
        snapshot.payload_raw != payload_raw
        or snapshot.original_value_utf16 != original_value_utf16
        or snapshot.expected_utf16 != expected_utf16
    ):
        raise RegKeyPathSnapshotError("expansion input binding mismatch")
    postpatch = snapshot.postpatch
    if postpatch is None or postpatch.readable_utf16 is None:
        return RegKeyPathComparison(None, "postpatch_value_unknown")
    if snapshot.profile_identity is None or snapshot.context_flags is None:
        return RegKeyPathComparison(None, "resolver_context_unknown")

    def service(
        observed: RegKeyResolvedPathList | None, input_bytes: bytes, side: str
    ) -> tuple[tuple[RegKeyPathValue, ...] | None, RegKeyPathComparison | None]:
        if observed is None:
            return None, RegKeyPathComparison(None, f"{side}_resolver_unknown")
        if (
            observed.epoch != snapshot.epoch
            or observed.input_utf16 != input_bytes
            or observed.profile_identity != snapshot.profile_identity
            or observed.flags != snapshot.context_flags | 0x10
        ):
            raise RegKeyPathSnapshotError(f"{side} resolver binding mismatch")
        if observed.status is None:
            return None, RegKeyPathComparison(None, f"{side}_resolver_status_unknown")
        if observed.status != 0:
            return None, RegKeyPathComparison(False, f"{side}_resolver_failed")
        return observed.paths, None

    if expand_left:
        left, stopped = service(snapshot.left, postpatch.readable_utf16, "left")
        if stopped is not None:
            return stopped
    else:
        left = (postpatch,)
    right, stopped = service(snapshot.right, expected_utf16 + b"\0\0", "right")
    if stopped is not None:
        return stopped
    # Successful output-list contents are only read after both status gates.
    if left == () or right == ():
        return RegKeyPathComparison(
            False, "empty_resolved_list", left_paths=left, right_paths=right
        )
    if left is None or right is None:
        return RegKeyPathComparison(
            None, "resolved_list_unknown", left_paths=left, right_paths=right
        )
    pairs = []
    for i, lp in enumerate(left):
        for j, rp in enumerate(right):
            equal = _pair(lp, rp, snapshot)
            pairs.append((i, j, equal))
            if equal is not False:
                lf = _matched_content(lp, snapshot) if equal else None
                rf = _matched_content(rp, snapshot) if equal else None
                folded = (
                    b"".join(
                        _fold(int.from_bytes(lf[k : k + 2], "little")).to_bytes(
                            2, "little"
                        )
                        for k in range(0, len(lf), 2)
                    )
                    if lf is not None
                    else None
                )
                return RegKeyPathComparison(
                    equal,
                    "resolved_path_equal" if equal else "path_read_or_crt_unknown",
                    (i, j) if equal else None,
                    tuple(pairs),
                    left,
                    right,
                    lf,
                    rf,
                    folded,
                )
    return RegKeyPathComparison(
        False,
        "resolved_paths_differ",
        compared_pairs=tuple(pairs),
        left_paths=left,
        right_paths=right,
    )


def project_regkey_expansion(
    payload_raw: bytes,
    original_value_utf16: bytes,
    expected_utf16: bytes,
    expand_left: bool,
    snapshot: RegKeyExpansionSnapshot | None,
) -> RegKeyPathComparison:
    """Compare actual paths after an observed or locally computed offline patch.

    Patch status never gates path comparison. Independent observed postpatch
    values can resolve an unknown producer; known computed/observed bytes must
    agree exactly. Patch and resolver facts identify the same invocation.
    """
    if type(expand_left) is not bool:
        raise RegKeyPathSnapshotError("expand_left must be bool")
    for value in (payload_raw, original_value_utf16, expected_utf16):
        _bytes(value)
    if snapshot is None:
        return _project_regkey_expansion(
            payload_raw, original_value_utf16, expected_utf16, expand_left, snapshot
        )
    if type(snapshot) is not RegKeyExpansionSnapshot:
        raise RegKeyPathSnapshotError("wrong expansion snapshot type")
    if (
        snapshot.payload_raw != payload_raw
        or snapshot.original_value_utf16 != original_value_utf16
        or snapshot.expected_utf16 != expected_utf16
    ):
        raise RegKeyPathSnapshotError("expansion input binding mismatch")
    facts = snapshot.offline_patch
    patch = None
    if facts is not None:
        if (
            facts.epoch != snapshot.epoch
            or facts.payload_raw != payload_raw
            or facts.original_value_utf16 != original_value_utf16
        ):
            raise RegKeyPathSnapshotError(
                "offline patch invocation/input binding mismatch"
            )
        patch = project_regkey_offline_patch(facts)
        if patch.postpatch_utf16 is not None:
            observed = snapshot.postpatch
            if (
                observed is not None
                and observed.readable_utf16 is not None
                and observed.readable_utf16 != patch.postpatch_utf16
            ):
                raise RegKeyPathSnapshotError(
                    "computed and observed postpatch bytes conflict"
                )
            snapshot = replace(
                snapshot,
                postpatch=RegKeyPathValue(
                    patch.postpatch_utf16,
                    None if observed is None else observed.unc_prefix,
                ),
            )
    result = _project_regkey_expansion(
        payload_raw, original_value_utf16, expected_utf16, expand_left, snapshot
    )
    return replace(result, offline_patch=patch)
