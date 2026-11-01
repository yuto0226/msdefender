"""VDLL callback4 runtime-name recipes and bounded consumer projections.

This does not turn wire suffixes into resolved names, publish native maps or
execute guest strings/registers, __siga_check or final trust/detection policy.
"""

import struct
from dataclasses import dataclass

from .vdll_api_membership import (
    UnsupportedVdllApi,
    VdllApiHost,
    parse_vdll_ordinal,
    project_vdll_api,
    resolve_vdll_api,
)


class UnsupportedFireEvent(ValueError):
    """Required resolved name, readable storage or parameter state is unknown."""


def _uint(value: int, bits: int, label: str) -> None:
    if type(value) is not int or not 0 <= value < 1 << bits:
        raise ValueError(f"{label} must be uint{bits}")


def _boolean(value: bool, label: str) -> None:
    if type(value) is not bool:
        raise TypeError(f"{label} must be bool")


def _byte(storage: bytes, offset: int) -> int:
    if not 0 <= offset < len(storage):
        raise UnsupportedFireEvent("recipe reads beyond supplied physical storage")
    return storage[offset]


def _cstring(storage: bytes, offset: int = 0) -> bytes:
    _byte(storage, offset)
    end = storage.find(b"\0", offset)
    if end < 0:
        raise UnsupportedFireEvent("required CString has no readable NUL")
    return storage[offset:end]


def fire_event_param_type(specifier: int, hex_modifier: bool) -> int:
    """Exact GetParamTypeFromSpecifier byte mapping, without printf grammar."""
    _uint(specifier, 8, "specifier")
    _boolean(hex_modifier, "hex_modifier")
    if specifier == ord("s"):
        return 1
    if specifier == ord("S"):
        return 2
    base = {ord("b"): 3, ord("w"): 4, ord("d"): 5, ord("q"): 6}.get(specifier)
    return 0 if base is None else base + 4 * hex_modifier


@dataclass(frozen=True, slots=True)
class FireEventData:
    event_id: int
    param1_index: int
    param1_type: int
    param2_index: int
    param2_type: int

    def __post_init__(self) -> None:
        _uint(self.event_id, 32, "event ID")
        for value in (
            self.param1_index,
            self.param1_type,
            self.param2_index,
            self.param2_type,
        ):
            _uint(value, 8, "parameter field")

    def pack(self) -> bytes:
        return struct.pack(
            "<IBBBB",
            self.event_id,
            self.param1_index,
            self.param1_type,
            self.param2_index,
            self.param2_type,
        )


@dataclass(frozen=True, slots=True)
class FireEventRecipe:
    """Local recipe parse, not proof of native registration/publication."""

    post: bool
    data: FireEventData | None
    skip_reason: str | None


def project_fire_event_recipe(storage: bytes) -> FireEventRecipe:
    """Parse an actual resolved runtime-name buffer, retaining native quirks.

    Later storage beyond its first NUL is not padding. An incomplete format
    can place a numeric CString there; missing required bytes are unsupported.
    No whitespace trimming, text decoding or automatic wire-name binding.
    """
    if not isinstance(storage, bytes):
        raise TypeError("runtime-name storage must be bytes")
    start = 1 if _byte(storage, 0) == ord("#") else 0
    post = _byte(storage, start) == ord("E")
    start += post
    name = _cstring(storage, start)
    event_id = parse_vdll_ordinal(name).value
    if not event_id:
        return FireEventRecipe(post, None, "event_id_zero")
    fields = [0, 0, 0, 0]
    comma = name.find(b",")
    if comma < 0:
        return FireEventRecipe(post, FireEventData(event_id, *fields), None)
    arg = start + comma + 1
    for parameter in range(2):
        if _byte(storage, arg) != ord("%"):
            return FireEventRecipe(post, None, "parameter_format_prefix")
        following = _byte(storage, arg + 1)
        if parameter == 1 and following == 0:
            return FireEventRecipe(post, None, "second_parameter_empty_specifier")
        hex_modifier = following == ord("x")
        spec_at = arg + (2 if hex_modifier else 1)
        specifier = _byte(storage, spec_at)
        index = parse_vdll_ordinal(_cstring(storage, spec_at + 1)).value
        fields[2 * parameter] = index & 255
        fields[2 * parameter + 1] = fire_event_param_type(specifier, hex_modifier)
        if parameter == 1:
            break
        # strchr begins at the first '%' and stops at that CString's first NUL.
        next_comma = _cstring(storage, arg).find(b",")
        if next_comma < 0:
            break
        arg += next_comma + 1
    return FireEventRecipe(post, FireEventData(event_id, *fields), None)


@dataclass(frozen=True, slots=True)
class ResolvedEventName:
    """Confirmed getter binding: storageNone is NULL, not unresolved state."""

    runtime_recid: int
    storage: bytes | None

    def __post_init__(self) -> None:
        _uint(self.runtime_recid, 32, "runtime RecID")
        if self.storage is not None and not isinstance(self.storage, bytes):
            raise TypeError("name storage must be bytes or confirmed NULL")


@dataclass(frozen=True, slots=True)
class FireEventResolution:
    host: int
    resolved_va: int | None
    stored_va: int | None
    recipe: FireEventRecipe | None
    reason: str


def resolve_fire_event(
    storage: bytes | None,
    count: int,
    runtime_recid: int,
    name: ResolvedEventName | None,
    hosts: tuple[VdllApiHost, ...],
) -> tuple[FireEventResolution, ...]:
    """Project callback's lazy stages over explicit successful runtime inputs.

    NULL data/all disabled hosts need no name. Getter NULL skips before input
    parsing; recipe bytes are read only after a nonzero resolved export. This
    supplies possible append values, not proof allocator/map insertion succeeded.
    """
    _uint(count, 32, "count")
    _uint(runtime_recid, 32, "runtime RecID")
    if storage is not None and not isinstance(storage, bytes):
        raise TypeError("callback storage must be bytes or None")
    if (
        not isinstance(hosts, tuple)
        or len(hosts) != 4
        or any(not isinstance(h, VdllApiHost) for h in hosts)
    ):
        raise TypeError("hosts requires four explicit VdllApiHost entries")

    def skipped(reason: str) -> tuple[FireEventResolution, ...]:
        return tuple(
            FireEventResolution(
                i, None, None, None, reason if h.enabled else "host_disabled"
            )
            for i, h in enumerate(hosts)
        )

    if storage is None:
        return skipped("null_input")
    if not any(h.enabled for h in hosts):
        return skipped("host_disabled")
    if not isinstance(name, ResolvedEventName) or name.runtime_recid != runtime_recid:
        raise UnsupportedFireEvent("missing resolved runtime-name binding")
    if name.storage is None:
        return skipped("runtime_name_null")
    try:
        api = resolve_vdll_api(project_vdll_api(storage, count), hosts)
    except UnsupportedVdllApi as exc:
        raise UnsupportedFireEvent(str(exc)) from exc
    recipe = None
    if any(result.stored_va is not None for result in api):
        recipe = project_fire_event_recipe(name.storage)
    return tuple(
        FireEventResolution(
            result.host,
            result.resolved_va,
            result.stored_va,
            recipe if result.stored_va is not None else None,
            recipe.skip_reason
            if result.stored_va is not None and recipe.skip_reason is not None
            else result.reason,
        )
        for result in api
    )


@dataclass(frozen=True, slots=True)
class FireEventMapEntry:
    host: int
    post: bool
    api_va: int
    data: FireEventData

    def __post_init__(self) -> None:
        if type(self.host) is not int or not 0 <= self.host < 4:
            raise ValueError("host must be0..3")
        _boolean(self.post, "post")
        _uint(self.api_va, 64, "API VA")
        if not isinstance(self.data, FireEventData):
            raise TypeError("data must be FireEventData")


@dataclass(frozen=True, slots=True)
class FireEventMapSnapshot:
    """Explicit successful insertion history for an identified active epoch.

    First wins within each phase/host/key. No default empty state, inferred wire
    order or automatic registration from a recipe/resolution is provided.
    """

    ordered_insertions: tuple[FireEventMapEntry, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.ordered_insertions, tuple) or any(
            not isinstance(e, FireEventMapEntry) for e in self.ordered_insertions
        ):
            raise TypeError("ordered_insertions must be an immutable entry tuple")

    def lookup(self, host: int, post: bool, raw_api_va: int) -> FireEventData | None:
        if type(host) is not int or not 0 <= host < 4:
            raise ValueError("host must be0..3")
        _boolean(post, "post")
        _uint(raw_api_va, 64, "API VA")
        return next(
            (
                e.data
                for e in self.ordered_insertions
                if e.host == host and e.post == post and e.api_va == raw_api_va
            ),
            None,
        )


@dataclass(frozen=True, slots=True)
class FireEventParamRequest:
    post: bool
    param_type: int
    index: int

    def __post_init__(self) -> None:
        _boolean(self.post, "post")
        _uint(self.param_type, 8, "parameter type")
        _uint(self.index, 8, "parameter index")


def fire_event_parameter_requests(
    data: FireEventData, post: bool
) -> tuple[FireEventParamRequest, ...]:
    if not isinstance(data, FireEventData):
        raise TypeError("data must be FireEventData")
    _boolean(post, "post")
    # Original caller tests param1_type twice, even if param2_type is zero.
    return (
        ()
        if data.param1_type == 0
        else (
            FireEventParamRequest(post, data.param1_type, data.param1_index),
            FireEventParamRequest(post, data.param2_type, data.param2_index),
        )
    )


@dataclass(frozen=True, slots=True)
class FireEventParamOutcome:
    """Confirmed GetParamData result; storageNone is failure, not unknown.

    Non-NULL storage represents ALtrue and must hold a nonempty CString within
    the260-byte output capacity. Physical bytes after its NUL are not selected.
    """

    storage: bytes | None

    def __post_init__(self) -> None:
        if self.storage is not None:
            if not isinstance(self.storage, bytes):
                raise TypeError("parameter output must be bytes or confirmed failure")
            content = _cstring(self.storage)
            if not content or len(content) >= 260:
                raise ValueError(
                    "successful parameter output must be nonempty and fit260bytes"
                )

    @property
    def cstring(self) -> bytes:
        return b"\0" if self.storage is None else _cstring(self.storage) + b"\0"


@dataclass(frozen=True, slots=True)
class FireEventAttribute:
    event_id_u16: int
    param1: bytes | None
    param2: bytes | None


def project_fire_event_attribute(
    data: FireEventData,
    post: bool,
    param1: FireEventParamOutcome | None = None,
    param2: FireEventParamOutcome | None = None,
) -> FireEventAttribute:
    """Consumer descriptor only; NULL pointers differ from non-NULL empty strings."""
    requests = fire_event_parameter_requests(data, post)
    if not requests:
        return FireEventAttribute(data.event_id & 0xFFFF, None, None)
    if not isinstance(param1, FireEventParamOutcome) or not isinstance(
        param2, FireEventParamOutcome
    ):
        raise UnsupportedFireEvent("both requested parameter outcomes must be known")
    return FireEventAttribute(data.event_id & 0xFFFF, param1.cstring, param2.cstring)


def project_fire_event_index0_parameter(
    post: bool, param_type: int, reg50_u32: int | None
) -> FireEventParamOutcome:
    """Original index0 numeric success profile, not an emulator/getter implementation."""
    _boolean(post, "post")
    _uint(param_type, 8, "parameter type")
    if not post:
        return FireEventParamOutcome(None)
    if reg50_u32 is None:
        raise UnsupportedFireEvent("post index0 reads reg50 before inspecting type")
    _uint(reg50_u32, 32, "reg50 value")
    if param_type in (1, 2):
        raise UnsupportedFireEvent(
            "guest string mapping is outside index0 numeric profile"
        )
    value = reg50_u32
    formats = {
        3: str(value & 255),
        4: str(value & 0xFFFF),
        5: str(value if value < 0x80000000 else value - (1 << 32)),
        6: str(value),
        7: f"0x{value & 255:02X}",
        8: f"0x{value & 0xFFFF:04X}",
        9: f"0x{value:08x}",
        10: f"0x{value:016x}",
    }
    return (
        FireEventParamOutcome(formats[param_type].encode("ascii") + b"\0")
        if param_type in formats
        else FireEventParamOutcome(None)
    )
