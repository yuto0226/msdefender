"""Physical-buffer model of REGKEY's offline patch wrapper and patcher.

CRT calls are explicit per-call observations, never Python Unicode transforms.
The physical memory window is relative to the offline object, not an A-Z map.
"""

from dataclasses import dataclass


class RegKeyOfflineSnapshotError(ValueError):
    """Malformed or conflicting invocation-bound offline patch observations."""


def _uint(value: int, bits: int) -> None:
    if type(value) is not int or not 0 <= value < 1 << bits:
        raise RegKeyOfflineSnapshotError(f"expected uint{bits}")


def _bytes(value: bytes) -> None:
    if type(value) is not bytes:
        raise RegKeyOfflineSnapshotError("immutable bytes required")


def _epoch(value: str) -> None:
    if type(value) is not str or not value:
        raise RegKeyOfflineSnapshotError("nonempty invocation epoch required")


@dataclass(frozen=True, slots=True)
class RegKeyOfflineByteWindow:
    """Readable bytes at [offline_base + start_offset, ...), possibly negative.

    No actual address arithmetic, allocation or host memory reads occur.
    A missing offset is unknown, never an implicit zero mapping.
    """

    start_offset: int
    data: bytes

    def __post_init__(self) -> None:
        if (
            type(self.start_offset) is not int
            or not -(1 << 63) <= self.start_offset < 1 << 63
        ):
            raise RegKeyOfflineSnapshotError("signed relative offset required")
        _bytes(self.data)

    def read(self, offset: int) -> int | None:
        index = offset - self.start_offset
        return self.data[index] if 0 <= index < len(self.data) else None


@dataclass(frozen=True, slots=True)
class RegKeyTowupperObservation:
    """Actual EAX after one reached engine CRT call; caller uses only AX.

    call_number is 1 (guard lookup) or 2 (write lookup), independently observed
    for the same preceding WCHAR. No stable CRT locale is inferred from epoch.
    """

    epoch: str
    crt_profile_identity: bytes
    previous_index: int
    call_number: int
    input_unit: int
    returned_eax: int | None

    def __post_init__(self) -> None:
        _epoch(self.epoch)
        _bytes(self.crt_profile_identity)
        _uint(self.previous_index, 32)
        _uint(self.input_unit, 16)
        if type(self.call_number) is not int or self.call_number not in (1, 2):
            raise RegKeyOfflineSnapshotError("call_number must be 1 or 2")
        if self.returned_eax is not None:
            _uint(self.returned_eax, 32)


@dataclass(frozen=True, slots=True)
class RegKeyOfflinePatchSnapshot:
    """Single invocation inputs for LUM_ResolveOfflineFile and its patcher.

    None means missing facts. original_value_utf16 contains physical readable
    bytes, not content padded/truncated by a registry declared size. path_present
    distinguishes an actual NULL argument from unknown readable bytes.
    offline_flags is the BYTE at offline+0x34. memory may also cover this byte;
    when it does, a contradictory separate flags observation is rejected.
    """

    epoch: str
    payload_raw: bytes
    original_value_utf16: bytes | None
    manager_present: bool | None
    offline_scan: bool | None
    context_present: bool | None
    offline_data_present: bool | None
    path_present: bool | None
    offline_flags: int | None
    memory: RegKeyOfflineByteWindow | None
    crt_profile_identity: bytes | None
    folds: tuple[RegKeyTowupperObservation, ...] | None

    def __post_init__(self) -> None:
        _epoch(self.epoch)
        _bytes(self.payload_raw)
        if self.original_value_utf16 is not None:
            _bytes(self.original_value_utf16)
        for value in (
            self.manager_present,
            self.offline_scan,
            self.context_present,
            self.offline_data_present,
            self.path_present,
        ):
            if value is not None and type(value) is not bool:
                raise RegKeyOfflineSnapshotError(
                    "pointer and scan gates must be bool or None"
                )
        if self.path_present is False and self.original_value_utf16 is not None:
            raise RegKeyOfflineSnapshotError(
                "NULL path cannot also have readable bytes"
            )
        if self.offline_flags is not None:
            _uint(self.offline_flags, 8)
        if self.memory is not None and type(self.memory) is not RegKeyOfflineByteWindow:
            raise RegKeyOfflineSnapshotError("wrong physical memory window type")
        if self.crt_profile_identity is not None:
            _bytes(self.crt_profile_identity)
        if self.folds is not None:
            if type(self.folds) is not tuple or any(
                type(f) is not RegKeyTowupperObservation for f in self.folds
            ):
                raise RegKeyOfflineSnapshotError(
                    "folds must be an immutable observation tuple"
                )
            keys = [(f.previous_index, f.call_number) for f in self.folds]
            if len(keys) != len(set(keys)):
                raise RegKeyOfflineSnapshotError("duplicate CRT call observations")


@dataclass(frozen=True, slots=True)
class RegKeyOfflinePatchResult:
    patch_status: int | None
    postpatch_utf16: bytes | None
    reason: str
    changed: bool | None
    written_index: int | None = None
    changed_position: int | None = None
    written_unit: int | None = None
    table_reads: tuple[tuple[int, int | None], ...] = ()
    fold_calls: tuple[RegKeyTowupperObservation, ...] = ()


def project_regkey_offline_patch(
    snapshot: RegKeyOfflinePatchSnapshot,
) -> RegKeyOfflinePatchResult:
    """Compute wrapper status and at most one physical WCHAR write.

    Source: CallistoPatchPathFromOffline 0x1804A1DD0 (226 bytes),
    LUM_ResolveOfflineFile 0x180221A20, CProfileMgr::ResolveOfflineFile 0x180D01240.
    Missing reached reads/status gates remain unknown. No services execute.
    """
    if type(snapshot) is not RegKeyOfflinePatchSnapshot:
        raise RegKeyOfflineSnapshotError("wrong offline patch snapshot type")
    s = snapshot
    raw = s.original_value_utf16
    reads = []
    calls = []

    def stopped(status: int | None, reason: str) -> RegKeyOfflinePatchResult:
        return RegKeyOfflinePatchResult(
            status,
            raw if status is not None else None,
            reason,
            False if status is not None else None,
            table_reads=tuple(reads),
            fold_calls=tuple(calls),
        )

    if s.manager_present is None:
        return stopped(None, "manager_presence_unknown")
    if not s.manager_present:
        return stopped(87, "manager_absent")
    if s.offline_scan is None:
        return stopped(None, "offline_scan_unknown")
    if not s.offline_scan:
        return stopped(0, "online_scan_no_patch")
    if s.context_present is None:
        return stopped(None, "context_presence_unknown")
    if not s.context_present:
        return stopped(87, "context_absent")
    # Patcher tests offline pointer before path pointer, before any reads.
    if s.offline_data_present is None:
        return stopped(None, "offline_data_presence_unknown")
    if not s.offline_data_present:
        return stopped(87, "offline_data_absent")
    if s.path_present is None:
        return stopped(None, "path_presence_unknown")
    if not s.path_present:
        return stopped(87, "path_null")
    flags = s.offline_flags
    physical_flags = None if s.memory is None else s.memory.read(0x34)
    if flags is not None and physical_flags is not None and flags != physical_flags:
        raise RegKeyOfflineSnapshotError("offline flags contradict physical +0x34 byte")
    if flags is None:
        flags = physical_flags
    if flags is None:
        return stopped(None, "offline_flags_unreadable")
    if flags & 1:
        return stopped(0, "offline_flag_skips_patch")

    def unit(index: int) -> int | None:
        offset = index * 2
        if raw is None or offset + 2 > len(raw):
            return None
        return int.from_bytes(raw[offset : offset + 2], "little")

    def fold(previous: int, number: int, value: int) -> int | None:
        observed = next(
            (
                f
                for f in s.folds or ()
                if f.previous_index == previous and f.call_number == number
            ),
            None,
        )
        if observed is None or s.crt_profile_identity is None:
            return None
        if (
            observed.epoch != s.epoch
            or observed.crt_profile_identity != s.crt_profile_identity
            or observed.input_unit != value
        ):
            raise RegKeyOfflineSnapshotError(
                "CRT observation invocation/input/profile mismatch"
            )
        calls.append(observed)
        return None if observed.returned_eax is None else observed.returned_eax & 0xFFFF

    def mapping(folded: int) -> int | None:
        offset = folded - 12
        value = (
            flags
            if offset == 0x34
            else None
            if s.memory is None
            else s.memory.read(offset)
        )
        reads.append((offset, value))
        return value

    index = 0
    while True:
        current = unit(index)
        if current is None:
            return stopped(None, "path_word_unreadable")
        if current == 0:
            return stopped(0, "terminator_no_write")
        if current == 58 and index != 0:
            following = unit((index + 1) & 0xFFFFFFFF)
            if following is None:
                return stopped(None, "colon_following_word_unreadable")
            if following in (92, 47):
                previous = (index - 1) & 0xFFFFFFFF
                value = unit(previous)
                assert value is not None  # prior scan already read this WCHAR
                first = fold(previous, 1, value)
                if first is None:
                    return stopped(None, "first_towupper_unknown")
                guard = mapping(first)
                if guard is None:
                    return stopped(None, "first_mapping_outside_readable_window")
                if guard != 0:
                    second = fold(previous, 2, value)
                    if second is None:
                        return stopped(None, "second_towupper_unknown")
                    replacement = mapping(second)
                    if replacement is None:
                        return stopped(None, "second_mapping_outside_readable_window")
                    assert raw is not None
                    offset = previous * 2
                    post = (
                        raw[:offset]
                        + replacement.to_bytes(2, "little")
                        + raw[offset + 2 :]
                    )
                    changed = replacement != value
                    return RegKeyOfflinePatchResult(
                        0,
                        post,
                        "wchar_written",
                        changed,
                        previous,
                        previous if changed else None,
                        replacement,
                        tuple(reads),
                        tuple(calls),
                    )
        index = (index + 1) & 0xFFFFFFFF
        if index == 0:
            return stopped(None, "uint32_scan_cycle")
