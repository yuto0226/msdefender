"""Callback3 parsing, explicitly selected VDLL exports and API membership.

The successful C-locale value projection does not load modules, initialize a
VDLL database, allocate native vectors or replay trust-switch/counter policy.
Module selections and active bucket state are resolved runtime inputs, never
inferred from signature order or OS exports.
"""

import zlib
from dataclasses import dataclass


class UnsupportedVdllApi(ValueError):
    """Required readable storage or selected runtime VDLL state is unknown."""


def _uint(value: int, bits: int, label: str) -> None:
    if type(value) is not int or not 0 <= value < 1 << bits:
        raise ValueError(f"{label} must be uint{bits}")


def _cstring_content(raw: bytes, label: str) -> None:
    if not isinstance(raw, bytes):
        raise TypeError(f"{label} must be bytes")
    if b"\0" in raw:
        raise ValueError(f"{label} must be CString content without NUL")


@dataclass(frozen=True, slots=True)
class VdllOrdinal:
    value: int
    hresult: int
    end_offset: int


def parse_vdll_ordinal(raw: bytes) -> VdllOrdinal:
    """Project StrToULongHelper<char>(raw,0) in the C-locale success domain.

    Accept C whitespace/sign/base0 and partial digits; overflow or no conversion
    leaves outDWORD zero with E_FAIL. The callback still looks up ordinal0.
    No Python int lexical rules, Unicode digits or full-consumption requirement.
    """
    _cstring_content(raw, "ordinal")
    pos = 0
    while pos < len(raw) and raw[pos] in b" \t\n\r\v\f":
        pos += 1
    negative = pos < len(raw) and raw[pos] == 45
    if pos < len(raw) and raw[pos] in b"+-":
        pos += 1
    base = 10
    if raw[pos : pos + 1] == b"0":
        base = 8
        if raw[pos + 1 : pos + 2] in (b"x", b"X"):
            base = 16
            pos += 2
    start = pos
    value = 0
    overflow = False
    while pos < len(raw):
        byte = raw[pos]
        digit = byte - 48 if 48 <= byte <= 57 else (byte | 32) - 87
        if not (48 <= byte <= 57 or 65 <= byte <= 90 or 97 <= byte <= 122):
            break
        if not 0 <= digit < base:
            break
        value = value * base + digit
        if value > 0xFFFFFFFF:
            overflow = True
            value &= 0xFFFFFFFF
        pos += 1
    if pos == start:
        return VdllOrdinal(0, 0x80004005, 0)
    if overflow:
        return VdllOrdinal(0, 0x80004005, pos)
    return VdllOrdinal((-value if negative else value) & 0xFFFFFFFF, 0, pos)


def vdll_api_crc(raw: bytes) -> int:
    """CRC_1 over an explicit byte span, without uppercase or final XOR.

    The callback selects effective name CString content excluding NUL first.
    This primitive also accepts binary spans, including NUL.
    """
    if not isinstance(raw, bytes):
        raise TypeError("CRC input must be bytes")
    return zlib.crc32(raw) ^ 0xFFFFFFFF


@dataclass(frozen=True, slots=True)
class VdllApiProjection:
    """Callback byte copies and selector, not completed runtime registration."""

    storage: bytes | None
    count: int
    delimiter_offset: int | None
    module_name: bytes | None
    selector: bytes | None
    selector_copy_hresult: int | None
    skip_reason: str | None

    @property
    def route(self) -> str | None:
        if self.selector is None:
            return None
        return "ordinal" if self.selector.startswith(b"@") else "named"

    @property
    def ordinal(self) -> VdllOrdinal | None:
        return (
            parse_vdll_ordinal(self.selector[1:]) if self.route == "ordinal" else None
        )

    @property
    def name_crc(self) -> int | None:
        return vdll_api_crc(self.selector) if self.route == "named" else None


def project_vdll_api(storage: bytes | None, count: int) -> VdllApiProjection:
    """Counted first '!' and ignored-HRESULT copy128, without a last-NUL gate."""
    _uint(count, 32, "count")
    if storage is not None and not isinstance(storage, bytes):
        raise TypeError("callback storage must be bytes or None")

    def skip(reason: str, delimiter: int | None = None) -> VdllApiProjection:
        return VdllApiProjection(storage, count, delimiter, None, None, None, reason)

    if storage is None:
        return skip("null_input")
    if count == 0:
        return skip("empty_count")
    delimiter = storage.find(b"!", 0, count)
    if delimiter < 0:
        if len(storage) < count:
            raise UnsupportedVdllApi("counted delimiter scan requires missing storage")
        return skip("delimiter_missing")
    if not 1 <= delimiter <= 127:
        return skip("module_offset_out_of_range", delimiter)
    remaining = count - delimiter - 1
    if not remaining:
        return skip("selector_bytes_absent", delimiter)
    status = 0
    if remaining > 0x7FFFFFFE:
        selector = b""
        status = 0x80070057
    else:
        copied = storage[delimiter + 1 : delimiter + 1 + min(remaining, 128)]
        nul = copied.find(b"\0")
        if nul >= 0:
            selector = copied[:nul]
        elif len(copied) == 128:
            selector = copied[:127]
            status = 0x8007007A
        elif len(copied) < remaining:
            raise UnsupportedVdllApi("selector copy requires missing storage")
        else:
            selector = copied
    return VdllApiProjection(
        storage,
        count,
        delimiter,
        storage[:delimiter].split(b"\0", 1)[0],
        selector,
        status,
        None,
    )


@dataclass(frozen=True, slots=True)
class VdllNamedExport:
    key: int
    relative_va: int

    def __post_init__(self) -> None:
        _uint(self.key, 32, "export key")
        if (
            type(self.relative_va) is not int
            or not -(1 << 31) <= self.relative_va < 1 << 31
        ):
            raise ValueError("relative_va must be int32")


@dataclass(frozen=True, slots=True)
class VdllExportTable:
    """Resolved fields: +0x08/+0x10 named rows, +0xE8 base, +0x100 salt,
    +0x20/+0x28 ordinal values and +0x108 ordinal base. No OS resolver.
    """

    named: tuple[VdllNamedExport, ...]
    base_va: int
    name_salt: int
    ordinal_base: int
    ordinals: tuple[int, ...]

    def __post_init__(self) -> None:
        _uint(self.base_va, 64, "base VA")
        _uint(self.name_salt, 32, "name salt")
        _uint(self.ordinal_base, 32, "ordinal base")
        if not isinstance(self.named, tuple) or any(
            not isinstance(row, VdllNamedExport) for row in self.named
        ):
            raise TypeError("named must be a tuple of VdllNamedExport")
        if any(a.key > b.key for a, b in zip(self.named, self.named[1:])):
            raise ValueError("named export keys must be unsigned nondecreasing")
        if not isinstance(self.ordinals, tuple):
            raise TypeError("ordinals must be a tuple")
        for va in self.ordinals:
            _uint(va, 64, "ordinal VA")

    def lookup_name(self, crc: int) -> int:
        _uint(crc, 32, "name CRC")
        key = crc ^ self.name_salt
        low, high = 0, len(self.named)
        while low < high:
            middle = (low + high) // 2
            if self.named[middle].key < key:
                low = middle + 1
            else:
                high = middle
        if low == len(self.named) or self.named[low].key != key:
            return 0
        return (self.base_va + self.named[low].relative_va) & 0xFFFFFFFFFFFFFFFF

    def lookup_ordinal(self, ordinal: int) -> int:
        _uint(ordinal, 32, "ordinal")
        index = ordinal - self.ordinal_base
        return self.ordinals[index] if 0 <= index < len(self.ordinals) else 0


@dataclass(frozen=True, slots=True)
class VdllModuleSelection:
    """Binding for the exact copied module request; indexNone is known miss.

    index0 is present. exportsNone with a present index means missing table
    context, distinct from a module miss. Raw module request is byte identity;
    this does not implement vdll_get_index_by_name's canonicalization.
    """

    module_name: bytes
    index: int | None
    exports: VdllExportTable | None

    def __post_init__(self) -> None:
        _cstring_content(self.module_name, "module name")
        if self.index is not None:
            _uint(self.index, 64, "module index")
            if self.index >= 1024:
                raise ValueError("present module index must fit its host's1024 slots")
        elif self.exports is not None:
            raise ValueError("a known module miss cannot contain exports")
        if self.exports is not None and not isinstance(self.exports, VdllExportTable):
            raise TypeError("exports must be VdllExportTable or None")


@dataclass(frozen=True, slots=True)
class VdllApiHost:
    enabled: bool
    selection: VdllModuleSelection | None

    def __post_init__(self) -> None:
        if type(self.enabled) is not bool:
            raise TypeError("enabled must be an explicit bool")
        if self.selection is not None and not isinstance(
            self.selection, VdllModuleSelection
        ):
            raise TypeError("selection must be VdllModuleSelection or None")


def vdll_api_bucket(va: int) -> int:
    _uint(va, 64, "API VA")
    mixed = ((va ^ (va >> 32)) * 0x9E3779B1) & 0xFFFFFFFF
    return (mixed ^ (mixed >> 16)) & 15


@dataclass(frozen=True, slots=True)
class VdllApiResolution:
    """Resolved/normalized append value, not proof a native append completed."""

    host: int
    resolved_va: int | None
    stored_va: int | None
    reason: str

    @property
    def bucket(self) -> int | None:
        return None if self.stored_va is None else vdll_api_bucket(self.stored_va)


def resolve_vdll_api(
    projection: VdllApiProjection, hosts: tuple[VdllApiHost, ...]
) -> tuple[VdllApiResolution, ...]:
    """Resolve four explicitly loaded host states; do not publish a global set.

    Copied input is reparsed from storage/count. Disabled hosts do not require
    a module selection. Present table lookup is original algorithm projection;
    actual module-name resolution, resources and active epoch are external.
    """
    if not isinstance(projection, VdllApiProjection):
        raise TypeError("projection must be VdllApiProjection")
    _uint(projection.count, 32, "count")
    if projection.storage is not None and not isinstance(projection.storage, bytes):
        raise TypeError("callback storage must be bytes or None")
    if (
        not isinstance(hosts, tuple)
        or len(hosts) != 4
        or any(not isinstance(host, VdllApiHost) for host in hosts)
    ):
        raise TypeError("hosts must contain exactly four VdllApiHost entries")
    if not any(host.enabled for host in hosts):
        return tuple(
            VdllApiResolution(i, None, None, "host_disabled") for i in range(4)
        )
    parsed = project_vdll_api(projection.storage, projection.count)
    result = []
    for i, host in enumerate(hosts):
        if not host.enabled:
            result.append(VdllApiResolution(i, None, None, "host_disabled"))
            continue
        if parsed.skip_reason is not None:
            result.append(VdllApiResolution(i, None, None, parsed.skip_reason))
            continue
        selection = host.selection
        if selection is None or selection.module_name != parsed.module_name:
            raise UnsupportedVdllApi(f"host{i} lacks a binding for the copied module")
        if selection.index is None:
            result.append(VdllApiResolution(i, None, None, "module_miss"))
            continue
        if selection.exports is None:
            raise UnsupportedVdllApi(f"host{i} selected module table is unknown")
        va = (
            selection.exports.lookup_ordinal(parsed.ordinal.value)
            if parsed.route == "ordinal"
            else selection.exports.lookup_name(parsed.name_crc)
        )
        stored = (va & ~1 if i == 2 else va) if va else None
        result.append(
            VdllApiResolution(i, va, stored, "export_miss" if not va else "resolved")
        )
    return tuple(result)


@dataclass(frozen=True, slots=True)
class VdllApiMembershipSnapshot:
    """Actual16bucket x4host vectors in a confirmed active runtime state.

    Rows may be unsorted/duplicated. No implicit empty epoch, wire insertion
    order, normalization or host2 query-bit clearing is supplied here.
    """

    buckets: tuple[tuple[tuple[int, ...], ...], ...]

    def __post_init__(self) -> None:
        if not isinstance(self.buckets, tuple) or len(self.buckets) != 16:
            raise TypeError("buckets must be a tuple of16 host-vector tuples")
        for bucket, hosts in enumerate(self.buckets):
            if not isinstance(hosts, tuple) or len(hosts) != 4:
                raise TypeError("each bucket requires four host vectors")
            for rows in hosts:
                if not isinstance(rows, tuple):
                    raise TypeError("host vectors must be immutable tuples")
                for va in rows:
                    if vdll_api_bucket(va) != bucket:
                        raise ValueError("stored API VA does not belong to its bucket")

    def contains(self, host: int, api_va: int) -> bool:
        if type(host) is not int or not 0 <= host < 4:
            raise ValueError("host must be0..3")
        return api_va in self.buckets[vdll_api_bucket(api_va)][host]
