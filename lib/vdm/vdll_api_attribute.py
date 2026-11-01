"""VDLL callback7 byte projection, explicit store outcomes and attribute maps.

Runtime module bindings, object storage and successful map insertion histories
are inputs. This module initializes no tables and owns no native pointers. Its
consumer projection describes a static pre-call handoff, not aggregation or a
scan verdict.
"""

from dataclasses import dataclass, field

from .vdll_api_membership import (
    UnsupportedVdllApi,
    VdllApiHost,
    VdllApiProjection,
    VdllOrdinal,
    parse_vdll_ordinal,
    project_vdll_api,
    vdll_api_bucket,
    vdll_api_crc,
)


class UnsupportedApiAttribute(ValueError):
    """Required readable bytes, runtime binding or store outcome is unknown."""


def _uint(value: int, bits: int, label: str) -> None:
    if type(value) is not int or not 0 <= value < 1 << bits:
        raise ValueError(f"{label} must be uint{bits}")


def _host(host: int) -> None:
    if type(host) is not int or not 0 <= host < 4:
        raise ValueError("host must be0..3")


def _name(name: bytes) -> None:
    if not isinstance(name, bytes):
        raise TypeError("attribute name must be bytes")
    if b"\0" in name:
        raise ValueError("attribute name must be CString content without NUL")


@dataclass(frozen=True, slots=True)
class ApiAttributeProjection:
    """Copied callback data; colon parsing does not imply module lookup success."""

    api: VdllApiProjection
    colon_offset: int | None
    attribute_name: bytes | None

    def __post_init__(self) -> None:
        if not isinstance(self.api, VdllApiProjection):
            raise TypeError("api must be VdllApiProjection")

    @property
    def name_crc(self) -> int | None:
        if self.api.route != "named" or self.colon_offset is None:
            return None
        return vdll_api_crc(self.api.selector[: self.colon_offset])

    @property
    def ordinal(self) -> VdllOrdinal | None:
        # The original callback never replaces ':' with NUL. Partial parsing
        # therefore receives the whole copied CString after '@'.
        if self.api.route != "ordinal" or self.colon_offset is None:
            return None
        return parse_vdll_ordinal(self.api.selector[1:])


def project_api_attribute(storage: bytes | None, count: int) -> ApiAttributeProjection:
    """Reuse counted first-'!' and copy128; find ':' in the copied CString.

    Copy HRESULT is retained in api, never promoted into a callback rejection.
    No trailing-NUL, Unicode, attribute-name or export-name grammar is added.
    """
    try:
        api = project_vdll_api(storage, count)
    except UnsupportedVdllApi as exc:
        raise UnsupportedApiAttribute(str(exc)) from exc
    colon = None if api.selector is None else api.selector.find(b":")
    if colon == -1:
        colon = None
    return ApiAttributeProjection(
        api, colon, None if colon is None else api.selector[colon + 1 :]
    )


@dataclass(frozen=True, slots=True)
class ApiAttributeStoredValue:
    """Value read from a confirmed non-NULL kstore pointer, excluding NUL.

    Bytes preserve a borrowed pointer's value, not its address or ownership.
    The caller must keep the associated object-store epoch valid when using
    this projection. No label or value here proves native pointer liveness.
    """

    name: bytes

    def __post_init__(self) -> None:
        _name(self.name)


@dataclass(frozen=True, slots=True)
class ApiAttributeStoreOutcome:
    """One actual ordered kstore call: valueNone means confirmed NULL."""

    host: int
    value: ApiAttributeStoredValue | None

    def __post_init__(self) -> None:
        _host(self.host)
        if self.value is not None and not isinstance(
            self.value, ApiAttributeStoredValue
        ):
            raise TypeError("store value must be typed or confirmed NULL")


@dataclass(frozen=True, slots=True)
class ApiAttributeStoreRequest:
    host: int
    name: bytes

    def __post_init__(self) -> None:
        _host(self.host)
        _name(self.name)

    @property
    def size(self) -> int:
        return len(self.name) + 1

    @property
    def flags(self) -> int:
        return 0

    @property
    def storage(self) -> bytes:
        return self.name + b"\0"


@dataclass(frozen=True, slots=True)
class ApiAttributeMapEntry:
    host: int
    api_va: int
    value: ApiAttributeStoredValue

    def __post_init__(self) -> None:
        _host(self.host)
        _uint(self.api_va, 64, "API VA")
        if not isinstance(self.value, ApiAttributeStoredValue):
            raise TypeError("entry value must be ApiAttributeStoredValue")

    @property
    def bucket(self) -> int:
        return vdll_api_bucket(self.api_va)


@dataclass(frozen=True, slots=True)
class ApiAttributeResolution:
    host: int
    resolved_va: int | None
    stored_va: int | None
    reason: str


@dataclass(frozen=True, slots=True)
class ApiAttributeCallbackProjection:
    """Store-stage results, conditional on intervening map calls returning.

    Candidates are not proof of map insertion. stop_hresult is only a known
    kstore-NULL termination; None does not claim native callback success or
    catch allocator exceptions. No rollback removes earlier candidates.
    """

    resolutions: tuple[ApiAttributeResolution, ...]
    store_requests: tuple[ApiAttributeStoreRequest, ...]
    candidates: tuple[ApiAttributeMapEntry, ...]
    stop_hresult: int | None


def resolve_api_attribute(
    projection: ApiAttributeProjection,
    hosts: tuple[VdllApiHost, ...],
    store_outcomes: tuple[ApiAttributeStoreOutcome, ...] = (),
) -> ApiAttributeCallbackProjection:
    """Resolve explicit hosts and consume outcomes in actual kstore call order.

    Module binding is consulted before the colon gate, as in the callback.
    Missing outcomes are unknown, distinct from an explicit NULL/0x8007 stop.
    Duplicate map keys still require kstore outcomes. This projects no map
    allocation or insertion success and performs no native object-store work.
    """
    if not isinstance(projection, ApiAttributeProjection):
        raise TypeError("projection must be ApiAttributeProjection")
    _uint(projection.api.count, 32, "count")
    if projection.api.storage is not None and not isinstance(
        projection.api.storage, bytes
    ):
        raise TypeError("callback storage must be bytes or None")
    if (
        not isinstance(hosts, tuple)
        or len(hosts) != 4
        or any(not isinstance(h, VdllApiHost) for h in hosts)
    ):
        raise TypeError("hosts requires four explicit VdllApiHost entries")
    if not isinstance(store_outcomes, tuple) or any(
        not isinstance(outcome, ApiAttributeStoreOutcome) for outcome in store_outcomes
    ):
        raise TypeError("store outcomes must be an immutable typed tuple")
    # Reparse original physical storage rather than trusting manually altered
    # derived fields. Do not call resolve_vdll_api: its named CRC span includes
    # the complete selector, whereas cb7 excludes ':' and the attribute tail.
    parsed = None
    resolutions = []
    requests = []
    candidates = []
    stop = None
    for i, host in enumerate(hosts):
        va = None
        stored = None
        reason = "host_disabled"
        if stop is not None:
            reason = "not_reached_after_store_failure"
        elif host.enabled:
            if parsed is None:
                parsed = project_api_attribute(
                    projection.api.storage, projection.api.count
                )
            api = parsed.api
            if api.skip_reason is not None:
                reason = api.skip_reason
            else:
                selection = host.selection
                if selection is None or selection.module_name != api.module_name:
                    raise UnsupportedApiAttribute(
                        f"host{i} lacks a binding for the copied module"
                    )
                if selection.index is None:
                    reason = "module_miss"
                elif parsed.colon_offset is None:
                    reason = "colon_missing"
                else:
                    if selection.exports is None:
                        raise UnsupportedApiAttribute(
                            f"host{i} selected module table is unknown"
                        )
                    va = (
                        selection.exports.lookup_ordinal(parsed.ordinal.value)
                        if api.route == "ordinal"
                        else selection.exports.lookup_name(parsed.name_crc)
                    )
                    reason = "export_miss"
                    if va:
                        stored = va & ~1 if i == 2 else va
                        request = ApiAttributeStoreRequest(i, parsed.attribute_name)
                        requests.append(request)
                        ordinal = len(requests) - 1
                        if ordinal >= len(store_outcomes):
                            raise UnsupportedApiAttribute(
                                f"host{i} kstore outcome is unknown"
                            )
                        outcome = store_outcomes[ordinal]
                        if outcome.host != i:
                            raise ValueError(
                                "kstore outcome host does not match call order"
                            )
                        if outcome.value is None:
                            stop = 0x8007
                            reason = "kstore_null"
                        else:
                            if outcome.value.name != request.name:
                                raise ValueError(
                                    "stored CString differs from kstore request"
                                )
                            candidates.append(
                                ApiAttributeMapEntry(i, stored, outcome.value)
                            )
                            reason = "insertion_candidate"
        resolutions.append(ApiAttributeResolution(i, va, stored, reason))
    if len(requests) != len(store_outcomes):
        raise ValueError("store outcomes include calls not reached by this projection")
    return ApiAttributeCallbackProjection(
        tuple(resolutions), tuple(requests), tuple(candidates), stop
    )


@dataclass(frozen=True, slots=True)
class ApiAttributeMapSnapshot:
    """Explicit successful insertion history in one caller-confirmed active epoch.

    Caller supplies completeness, ordering and borrowed-value lifetime context;
    this type cannot verify liveness or combine epochs. No default empty table
    is inferred from wire data or from callback insertion candidates. First
    wins within each host/full-u64 key; queries never clear host2's bit0.
    """

    ordered_insertions: tuple[ApiAttributeMapEntry, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.ordered_insertions, tuple) or any(
            not isinstance(entry, ApiAttributeMapEntry)
            for entry in self.ordered_insertions
        ):
            raise TypeError("ordered insertions must be an immutable typed tuple")

    def lookup(self, host: int, raw_api_va: int) -> ApiAttributeStoredValue | None:
        _host(host)
        _uint(raw_api_va, 64, "API VA")
        return next(
            (
                entry.value
                for entry in self.ordered_insertions
                if entry.host == host and entry.api_va == raw_api_va
            ),
            None,
        )


@dataclass(frozen=True, slots=True)
class AggregateApiAttributeRequest:
    """Static MpAggregateAttributeEx arguments, not a service result.

    The receiver is the caller's SCAN_REPLY pointer. EmptySha1 remains a
    symbolic source; no unverified twenty-byte value or IoC is invented.
    Return/out_recid values are unused by the original caller.
    """

    name: bytes
    sigseq: int = field(default=0, init=False)
    sha1_source: str = field(default="EmptySha1", init=False)
    recid: int = field(default=0xFFFFFFFF, init=False)
    unknown_a6: int = field(default=0, init=False)
    out_recid_initial: int = field(default=0, init=False)
    skip_recidtosx: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        _name(self.name)


@dataclass(frozen=True, slots=True)
class ApiAttributeConsumerProjection:
    aggregate_attribute: AggregateApiAttributeRequest | None
    counter_after: int | None
    reason: str


def project_api_attribute_consumer(
    snapshot: ApiAttributeMapSnapshot | None,
    host: int,
    post: bool,
    raw_api_va: int,
    counter_u32: int | None = None,
) -> ApiAttributeConsumerProjection:
    """Static pre-only exact-key request and ADD512, not whole pe_notify.

    Post needs no table, host, VA or counter state. Pre requires an explicit
    complete snapshot; a known miss needs no counter. A hit requires its input
    DWORD and adds with uint32 wrap, irrespective of the unused aggregate
    return. Omitted counters on misses remain None, never guessed zero.
    """
    if type(post) is not bool:
        raise TypeError("post must be an explicit bool")
    if counter_u32 is not None:
        _uint(counter_u32, 32, "counter")
    if post:
        return ApiAttributeConsumerProjection(None, counter_u32, "post_call")
    _host(host)
    _uint(raw_api_va, 64, "API VA")
    if not isinstance(snapshot, ApiAttributeMapSnapshot):
        raise UnsupportedApiAttribute("pre-call attribute map is unknown")
    value = snapshot.lookup(host, raw_api_va)
    if value is None:
        return ApiAttributeConsumerProjection(None, counter_u32, "map_miss")
    if counter_u32 is None:
        raise UnsupportedApiAttribute("attribute hit requires the input counter DWORD")
    return ApiAttributeConsumerProjection(
        AggregateApiAttributeRequest(value.name),
        (counter_u32 + 0x200) & 0xFFFFFFFF,
        "attribute_hit",
    )
