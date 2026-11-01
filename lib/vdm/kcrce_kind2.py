"""Source-only kind2 request recipes; no mapper, byte reads, CRC or verdict.

Snapshots describe one explicit epoch. None means unknown, integer zero means
NULL where applicable. Projected means the conditional recipe is available,
never that a service succeeded. Normal-subset arithmetic rejects u64 wrapping
and assertion domains; descriptor capacity multiplication explicitly wraps u32.
"""

from dataclasses import dataclass, fields, replace
from typing import Literal


class K2SnapshotError(ValueError):
    """Malformed, cross-epoch or outside-normal-subset supplied facts."""


class _Missing(Exception):
    pass


@dataclass(frozen=True, slots=True)
class K2Covering:
    epoch: str
    search_complete: bool | None
    base: int | None
    size: int | None
    index: int | None
    index_count: int | None
    excluded: bool | None


@dataclass(frozen=True, slots=True)
class K2Region:
    epoch: str
    page_start: int | None
    page_count: int | None
    kind: int | None
    covering: K2Covering | None


@dataclass(frozen=True, slots=True)
class K2Iterator:
    epoch: str
    initialized: bool | None
    init_result: bool | None
    ranges: tuple[K2Region, ...] | None
    next_index: int | None
    current_index: int | None
    cached_ptr: int | None
    cached_offset: int | None
    cached_length: int | None
    cached_flags: int | None
    locked: bool | None


@dataclass(frozen=True, slots=True)
class K2PeGates:
    epoch: str
    allowed_start: int | None
    allowed_end: int | None
    bypass: bool | None
    intervals: tuple[tuple[int, int], ...] | None
    special_start: int | None


@dataclass(frozen=True, slots=True)
class K2Snapshot:
    epoch: str
    callback_family: Literal["oepkcrc_callback"] | None
    kind: int | None
    mode: int
    mapper_profile: str
    page_size: int | None
    iterator: K2Iterator | None
    pe: K2PeGates | None
    mode2_ptr: int | None
    selected_length: int | None
    selected_base: int | None
    state_084: int | None


@dataclass(frozen=True, slots=True)
class K2Event:
    target: str
    value: int | str
    condition: str = "always"


@dataclass(frozen=True, slots=True)
class K2Request:
    route: Literal["lock", "copy"]
    start: int
    length: int
    flags: int
    logical_length: int


@dataclass(frozen=True, slots=True)
class K2Projection:
    status: Literal["projected", "unknown"]
    reason: str
    events: tuple[K2Event, ...] = ()
    selected_index: int | None = None
    next_index: int | None = None
    descriptor_base: int | None = None
    descriptor_capacity: int | None = None
    selected_base: int | None = None
    selected_length: int | None = None
    request: K2Request | None = None
    byte_pointer: int | None = None
    adddata_offset: int | None = None
    adddata_length: int | None = None
    adddata_condition: str | None = None
    mapping_outcome: Literal["unknown", "not_requested"] = "not_requested"


def _uint(value: int | None, width: int, name: str) -> None:
    if value is not None and (type(value) is not int or not 0 <= value < 1 << width):
        raise K2SnapshotError(f"{name} must be uint{width} or None")


def _validate(obj: object, epoch: str) -> None:
    if not isinstance(obj, (K2Snapshot, K2Iterator, K2Region, K2Covering, K2PeGates)):
        raise K2SnapshotError("invalid snapshot type")
    if type(obj.epoch) is not str or not obj.epoch or obj.epoch != epoch:
        raise K2SnapshotError("snapshot epoch mismatch or missing")
    bools = {
        "initialized",
        "init_result",
        "locked",
        "search_complete",
        "excluded",
        "bypass",
    }
    u32 = {
        "kind",
        "mode",
        "page_size",
        "page_count",
        "size",
        "cached_offset",
        "cached_length",
        "cached_flags",
        "index_count",
    }
    for field in fields(obj):
        name, value = field.name, getattr(obj, field.name)
        if name == "epoch" or value is None:
            continue
        if name in bools:
            if type(value) is not bool:
                raise K2SnapshotError(f"{name} must be bool or None")
        elif name in {"iterator", "pe", "covering"}:
            expected = {
                "iterator": K2Iterator,
                "pe": K2PeGates,
                "covering": K2Covering,
            }[name]
            if not isinstance(value, expected):
                raise K2SnapshotError(f"{name} has an invalid snapshot type")
            _validate(value, epoch)
        elif name == "ranges":
            if type(value) is not tuple:
                raise K2SnapshotError("ranges must be an immutable complete tuple")
            for region in value:
                if not isinstance(region, K2Region):
                    raise K2SnapshotError("invalid region")
                _validate(region, epoch)
        elif name == "intervals":
            if type(value) is not tuple:
                raise K2SnapshotError("intervals must be an immutable complete tuple")
            for interval in value:
                if type(interval) is not tuple or len(interval) != 2:
                    raise K2SnapshotError("interval must be (lo, hi)")
                for bound in interval:
                    _uint(bound, 64, "interval bound")
                    if bound is None:
                        raise K2SnapshotError("interval bounds cannot be unknown")
                if interval[0] >= interval[1]:
                    raise K2SnapshotError("malformed interval assertion domain")
        elif name == "callback_family":
            if value != "oepkcrc_callback":
                raise K2SnapshotError("invalid callback family")
        elif name == "mapper_profile":
            if type(value) is not str or not value:
                raise K2SnapshotError(
                    "mapper_profile must be a nonempty opaque identity"
                )
        else:
            _uint(value, 8 if name == "state_084" else 32 if name in u32 else 64, name)
    if isinstance(obj, K2Snapshot) and obj.mode not in (0, 1, 2):
        raise K2SnapshotError("mode must be 0, 1 or 2")
    if isinstance(obj, K2Snapshot) and not obj.mapper_profile:
        raise K2SnapshotError("mapper_profile missing")
    if isinstance(obj, K2Iterator) and obj.ranges is not None:
        for index in (obj.next_index, obj.current_index):
            if index is not None and index > len(obj.ranges):
                raise K2SnapshotError("iterator index beyond sentinel")


def _need(value, reason):
    if value is None:
        raise _Missing(reason)
    return value


def _sum64(a: int, b: int) -> int:
    if a + b >= 1 << 64:
        raise K2SnapshotError("u64 wrap outside normal subset")
    return a + b


def _descriptor(region: K2Region, page_size: int | None) -> tuple[int, int]:
    ps = _need(page_size, "page_size_unknown")
    if ps == 0 or ps & (ps - 1):
        raise K2SnapshotError("page_size must be a nonzero power of two")
    base = _need(region.page_start, "page_start_unknown") * ps
    if base >= 1 << 64:
        raise K2SnapshotError("descriptor base u64 wrap outside normal subset")
    return base, (_need(region.page_count, "page_count_unknown") * ps) & 0xFFFFFFFF


def _unlock(iterator: K2Iterator, events: list[K2Event]) -> None:
    if _need(iterator.locked, "lock_state_unknown"):
        events.extend(
            (K2Event("context.unlock", "vtable+0xb8"), K2Event("iterator+0x72", 0))
        )


def _accept(region: K2Region, base: int, capacity: int, pe: K2PeGates) -> bool:
    start = _need(pe.allowed_start, "image_interval_unknown")
    if base >= start and base < _need(pe.allowed_end, "image_interval_unknown"):
        return True
    if _need(pe.bypass, "pe_bypass_unknown"):
        return True
    covering = _need(region.covering, "covering_unknown")
    if not _need(covering.search_complete, "covering_search_unknown"):
        raise _Missing("covering_search_incomplete")
    if covering.base is not None:
        size = _need(covering.size, "covering_size_unknown")
        end = _sum64(covering.base, size)
        if covering.base <= base < end:
            index = _need(covering.index, "covering_index_unknown")
            count = _need(covering.index_count, "covering_index_count_unknown")
            if index == 0xFFFFFFFFFFFFFFFF or index >= count or index >= 0x400:
                raise K2SnapshotError("vdll index assertion domain")
            if _need(covering.excluded, "vdll_exclusion_unknown"):
                return False
    elif any(
        v is not None
        for v in (
            covering.size,
            covering.index,
            covering.index_count,
            covering.excluded,
        )
    ):
        raise K2SnapshotError("inconsistent absent covering entry")
    end = _sum64(base, capacity)
    for lo, hi in _need(pe.intervals, "overlap_intervals_unknown"):
        if base < end and lo < hi and lo < end and base < hi:
            if base < lo:
                if lo - base > capacity:
                    raise K2SnapshotError("overlap distance assertion domain")
                return True
            return hi < end
    return not (
        base == _need(pe.special_start, "special_start_unknown") and capacity == 0x1000
    )


def project_kcrce_kind2_mapping(
    requested: int, iterator: K2Iterator, page_size: int | None
) -> K2Projection:
    """Project mmap_crt_range(flags=1), including warm-before-cold order.

    This helper does not apply the callback's selected_length==0 rejection.
    current_index==len(ranges) explicitly means current=NULL.
    """
    _uint(requested, 32, "requested")
    _uint(page_size, 32, "page_size")
    if requested is None:
        raise K2SnapshotError("requested cannot be unknown")
    if not isinstance(iterator, K2Iterator):
        raise K2SnapshotError("expected K2Iterator")
    _validate(iterator, iterator.epoch)
    events: list[K2Event] = []
    try:
        ranges = _need(iterator.ranges, "ranges_unknown")
        index = _need(iterator.current_index, "current_unknown")
        if index == len(ranges):
            return K2Projection("projected", "current_null")
        known_miss = (
            iterator.cached_ptr == 0
            or iterator.cached_flags is not None
            and not iterator.cached_flags & 1
            or iterator.cached_offset is not None
            and iterator.cached_offset != 0
            or iterator.cached_length is not None
            and (iterator.cached_length == 0 or iterator.cached_length < requested)
        )
        offset = (
            1 if known_miss else _need(iterator.cached_offset, "cache_offset_unknown")
        )
        if offset == 0:
            length = _need(iterator.cached_length, "cache_length_unknown")
            if length > 0 and length >= requested:
                flags = _need(iterator.cached_flags, "cache_flags_unknown")
                if flags & 1:
                    ptr = _need(iterator.cached_ptr, "cache_pointer_unknown")
                    if ptr:
                        return K2Projection(
                            "projected", "iterator_cache_hit", byte_pointer=ptr
                        )
        _unlock(iterator, events)
        base, capacity = _descriptor(ranges[index], page_size)
        result = K2Projection(
            "projected",
            "cold_request",
            tuple(events),
            descriptor_base=base,
            descriptor_capacity=capacity,
        )
        if requested > capacity or requested == 0:
            return replace(
                result,
                reason="requested_exceeds_capacity"
                if requested > capacity
                else "requested_zero",
            )
        kind = _need(ranges[index].kind, "range_kind_unknown")
        if kind == 1:
            route, length, condition = "lock", requested, "mapping_success"
        else:
            ps = _need(page_size, "page_size_unknown")
            route, length, condition = (
                "copy",
                ((ps + requested - 1) & 0xFFFFFFFF) & (-ps & 0xFFFFFFFF),
                "allocation_and_copy_success",
            )
            if length == 0:
                raise K2SnapshotError("aligned copy length wrap outside normal subset")
        request = K2Request(route, base, length, 1, requested)
        if route == "lock":
            events.append(
                K2Event("iterator+0x72", "mapper_out_bool", "mapper_returned")
            )
        events.extend(
            (
                K2Event("iterator+0x64", 0, condition),
                K2Event("iterator+0x68", length, condition),
                K2Event("iterator+0x6c", 1, condition),
                K2Event("iterator+0x40", "service_pointer", condition),
            )
        )
        return replace(
            result,
            events=tuple(events),
            request=request,
            mapping_outcome="unknown",
            adddata_condition=condition,
        )
    except _Missing as exc:
        return K2Projection("unknown", str(exc), tuple(events))


def project_kcrce_kind2(packed: int, snapshot: K2Snapshot) -> K2Projection:
    """Project callback mode0/1/2 from explicit same-epoch snapshots only.

    ranges is the complete ordered enumeration (including skipped regions).
    An initialized iterator needs no init_result. For an uninitialized iterator,
    init_result=True and supplied ranges describe the explicit post-init view.
    All events are a recipe; conditional events do not assert service success.
    """
    _uint(packed, 32, "packed")
    if packed is None:
        raise K2SnapshotError("packed cannot be unknown")
    if not isinstance(snapshot, K2Snapshot):
        raise K2SnapshotError("expected K2Snapshot")
    _validate(snapshot, snapshot.epoch)
    events: list[K2Event] = []
    result = K2Projection("projected", "mode0_no_adddata")
    try:
        _need(snapshot.callback_family, "callback_family_unknown")
        if _need(snapshot.kind, "kind_unknown") != 2:
            raise K2SnapshotError("this projector requires kind2")
        events.extend((K2Event("userdata+0x85", 0), K2Event("pe+0x83fd0", 1)))
        if snapshot.mode == 0:
            return replace(result, events=tuple(events))
        if snapshot.mode == 2:
            selected_length = _need(snapshot.selected_length, "selected_length_unknown")
            result = replace(
                result,
                selected_length=selected_length,
                selected_base=snapshot.selected_base,
            )
            if selected_length == 0:
                events.append(K2Event("userdata+0x85", 1))
                return replace(
                    result, reason="selected_length_zero", events=tuple(events)
                )
            off, count = (packed >> 16) & 0xFFF, packed & 0xFFFF
            if off + count > selected_length:
                return replace(
                    result, reason="mode2_out_of_bounds", events=tuple(events)
                )
            ptr = _need(snapshot.mode2_ptr, "mode2_pointer_unknown")
            if ptr:
                _sum64(ptr, off)
                return replace(
                    result,
                    reason="callback_cache_hit",
                    events=tuple(events),
                    byte_pointer=ptr,
                    adddata_offset=off,
                    adddata_length=count,
                    adddata_condition="cached_pointer_available",
                )
            iterator = _need(snapshot.iterator, "iterator_unknown")
            mapped = project_kcrce_kind2_mapping(
                selected_length & 0xFFFFFFFF, iterator, snapshot.page_size
            )
            events.extend(mapped.events)
            if mapped.status == "unknown":
                return replace(
                    result, status="unknown", reason=mapped.reason, events=tuple(events)
                )
            if mapped.request is None and mapped.byte_pointer is None:
                events.extend(
                    (K2Event("userdata+0x98", 0), K2Event("userdata+0x85", 1))
                )
                return replace(
                    result,
                    reason=mapped.reason,
                    events=tuple(events),
                    descriptor_base=mapped.descriptor_base,
                    descriptor_capacity=mapped.descriptor_capacity,
                )
            condition = (
                "cached_pointer_available"
                if mapped.byte_pointer
                else mapped.adddata_condition
            )
            if mapped.byte_pointer is not None:
                _sum64(mapped.byte_pointer, off)
            events.append(
                K2Event(
                    "userdata+0x98",
                    mapped.byte_pointer or "service_pointer",
                    "always" if mapped.byte_pointer else condition,
                )
            )
            if mapped.request:
                events.extend(
                    (
                        K2Event("userdata+0x98", 0, "service_null"),
                        K2Event("userdata+0x85", 1, "service_null"),
                    )
                )
            return replace(
                result,
                reason=mapped.reason,
                events=tuple(events),
                request=mapped.request,
                byte_pointer=mapped.byte_pointer,
                descriptor_base=mapped.descriptor_base,
                descriptor_capacity=mapped.descriptor_capacity,
                adddata_offset=off,
                adddata_length=count,
                adddata_condition=condition,
                mapping_outcome=mapped.mapping_outcome,
            )
        events.extend(
            (
                K2Event("userdata+0x98", 0),
                K2Event("userdata+0xa0", 0),
                K2Event("userdata+0xa8", 0),
                K2Event("userdata+0x84", 0),
            )
        )
        iterator = _need(snapshot.iterator, "iterator_unknown")
        initialized = _need(iterator.initialized, "iterator_init_unknown")
        index = iterator.next_index
        while True:
            events.extend((K2Event("iterator+0x40", 0), K2Event("iterator+0x6c", 0)))
            if not initialized:
                if not _need(iterator.init_result, "init_result_unknown"):
                    return replace(
                        result,
                        reason="init_failed",
                        events=tuple(events),
                        next_index=index,
                    )
                initialized = True
                index = 0
            ranges = _need(iterator.ranges, "ranges_unknown")
            index = _need(index, "next_index_unknown")
            if index == len(ranges):
                events.append(K2Event("iterator+0x18", 0))
                _unlock(iterator, events)
                return replace(
                    result,
                    reason="iterator_exhausted",
                    events=tuple(events),
                    next_index=index,
                )
            region = ranges[index]
            events.extend(
                (
                    K2Event("iterator.cursor", index + 1),
                    K2Event("iterator+0x18", f"ranges[{index}]"),
                )
            )
            base, capacity = _descriptor(region, snapshot.page_size)
            _unlock(iterator, events)
            iterator = replace(iterator, locked=False)
            pe = _need(snapshot.pe, "pe_gates_unknown")
            selected = index
            index += 1
            if _accept(region, base, capacity, pe):
                break
        metadata_base, metadata_length = base, capacity
        if base == _need(pe.allowed_start, "image_start_unknown") and capacity > 0x1000:
            metadata_base, metadata_length = _sum64(base, 0x1000), capacity - 0x1000
        events.extend(
            (
                K2Event("userdata+0xa0", metadata_length),
                K2Event("userdata+0xa8", metadata_base),
            )
        )
        result = replace(
            result,
            selected_index=selected,
            next_index=index,
            descriptor_base=base,
            descriptor_capacity=capacity,
            selected_base=metadata_base,
            selected_length=metadata_length,
        )
        # Mode1 selection cleared ptr/flags; stale length cannot create a hit.
        if capacity < 0x100:
            return replace(
                result, reason="mode1_capacity_below_256", events=tuple(events)
            )
        iterator = replace(
            iterator, current_index=selected, cached_ptr=0, cached_flags=0
        )
        mapped = project_kcrce_kind2_mapping(0x100, iterator, snapshot.page_size)
        if mapped.status == "unknown":
            events.extend(mapped.events)
            return replace(
                result, status="unknown", reason=mapped.reason, events=tuple(events)
            )
        # Inline mode1 writes the same cache fields in a different order from
        # mmap_crt_range: length, pointer, flags, offset (F485..F493).
        events.extend(
            e
            for e in mapped.events
            if e.target
            not in {"iterator+0x64", "iterator+0x68", "iterator+0x6c", "iterator+0x40"}
        )
        events.extend(
            (
                K2Event(
                    "iterator+0x68", mapped.request.length, mapped.adddata_condition
                ),
                K2Event("iterator+0x40", "service_pointer", mapped.adddata_condition),
                K2Event("iterator+0x6c", 1, mapped.adddata_condition),
                K2Event("iterator+0x64", 0, mapped.adddata_condition),
            )
        )
        events.append(K2Event("userdata+0x84", 1, mapped.adddata_condition))
        return replace(
            result,
            reason="mode1_conditional_adddata",
            events=tuple(events),
            request=mapped.request,
            adddata_offset=0,
            adddata_length=0x100,
            adddata_condition=mapped.adddata_condition,
            mapping_outcome="unknown",
        )
    except _Missing as exc:
        return replace(result, status="unknown", reason=str(exc), events=tuple(events))
