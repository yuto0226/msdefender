"""Selector 98 import resolver for explicit, initialized runtime snapshots.

This covers the ASCII success profile of pe_parse_imports in mpengine 1.443.903.0.
Snapshots contain normalized NID4 store order and resolved runtime threat names;
they are not dictionaries of wire tails. Building the namespace/mini-threat store,
virtual host tables, PE traversal and OS load state is outside
this module. Snapshot construction is a caller precondition, never inferred from
an isolated VDM record. All names are C-string content without a terminating NUL.
"""

import struct
import zlib
from dataclasses import dataclass
from itertools import pairwise

from .nid_suppression import Nid64LookupSnapshot, lookup_nid64_name
from .snid_imphash import (
    ImportDescriptor,
    NamedImport,
    OrdinalImport,
    OrdinalResolution,
    imphash_token_stream,
)


def _uint(value: int, bits: int, label: str) -> None:
    if type(value) is not int or not 0 <= value < 1 << bits:
        raise ValueError(f"{label} must be an unsigned {bits}-bit integer")


def _ascii(raw: bytes, label: str) -> None:
    if not isinstance(raw, bytes):
        raise TypeError(f"{label} must be bytes")
    if b"\0" in raw or not raw.isascii():
        raise ValueError(f"{label} must be NUL-free ASCII C-string content")


def _raw_upper_crc(raw: bytes) -> int:
    return zlib.crc32(raw.upper()) ^ 0xFFFFFFFF


def virtual_dll_lookup_key(raw_name: bytes) -> int:
    """Return the virtual name-map key, including empty/all-trim name semantics.

    MSVCRT prefix canonicalization precedes Windows path stripping. Dot presence is
    recorded before trimming trailing spaces/dots. This is separate from the raw DLL
    CRC used on a virtual miss and the raw target CRC used after API-set mapping.
    """
    _ascii(raw_name, "virtual DLL name")
    if len(raw_name) > 259:
        raise ValueError("virtual DLL name exceeds the supported 259-byte bound")
    name = raw_name
    if name[:6].lower() == b"msvcrt":
        name = b"MSVCRT.DLL"
    if name[:20].upper() == b"C:\\WINDOWS\\SYSTEM32\\":
        name = name[20:]
    elif name[:11].upper() == b"C:\\WINDOWS\\":
        name = name[11:]
    had_dot = b"." in name
    name = name.rstrip(b" .")
    return _raw_upper_crc(name + (b"" if had_dot else b".DLL"))


@dataclass(frozen=True, slots=True)
class VirtualDllEntry:
    lookup_id: int
    stored_id: int

    def __post_init__(self) -> None:
        _uint(self.lookup_id, 32, "virtual lookup ID")
        _uint(self.stored_id, 32, "virtual stored ID")


@dataclass(frozen=True, slots=True)
class VirtualDllSnapshot:
    """One explicitly selected, initialized host's unique map and object IDs.

    Tuple position is the index; both index zero and stored ID zero are valid.
    The selected host's namespace and loaded object consistency are preconditions.
    """

    entries: tuple[VirtualDllEntry, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.entries, tuple) or any(
            not isinstance(entry, VirtualDllEntry) for entry in self.entries
        ):
            raise TypeError("virtual entries must be a tuple of VirtualDllEntry values")
        if len(self.entries) > 1024:
            raise ValueError("virtual snapshot exceeds the 1024-entry bound")
        if len({entry.lookup_id for entry in self.entries}) != len(self.entries):
            raise ValueError("virtual lookup IDs must be unique")

    def lookup(self, raw_name: bytes) -> VirtualDllEntry | None:
        key = virtual_dll_lookup_key(raw_name)
        return next((entry for entry in self.entries if entry.lookup_id == key), None)


@dataclass(frozen=True, slots=True)
class NidRuntimeEntry:
    """A normalized NID4 row whose threat namespace was already resolved.

    runtime_name=None represents a NULL pointer; b'' represents a non-NULL empty
    C string. They differ during duplicate-candidate arbitration. A missing wire
    tail alone does not establish either runtime name value.
    """

    key: int
    selector: int
    runtime_name: bytes | None

    def __post_init__(self) -> None:
        _uint(self.key, 32, "NID4 key")
        _uint(self.selector, 8, "entry selector")
        if self.runtime_name is not None:
            _ascii(self.runtime_name, "runtime threat name")


@dataclass(frozen=True, slots=True)
class NidLookupResult:
    status: int
    runtime_name: bytes | None


@dataclass(frozen=True, slots=True)
class NidLookupSnapshot:
    """Initialized reply-NULL NID4 stores for the selector97/99 caller profile.

    Rows are flattened in normalized chunk/candidate order, sorted by unsigned key;
    equal-key order is retained. Bloom/index consistency is a precondition. The
    suppression is an explicit effective NID64 runtime snapshot. Its recursive
    selector108 policy is evaluated only on reached non-attribute candidates;
    wire selector108 absence alone never establishes this runtime snapshot.
    """

    delta: tuple[NidRuntimeEntry, ...]
    base: tuple[NidRuntimeEntry, ...]
    suppression: Nid64LookupSnapshot

    def __post_init__(self) -> None:
        for rows in (self.delta, self.base):
            if not isinstance(rows, tuple) or any(
                not isinstance(row, NidRuntimeEntry) for row in rows
            ):
                raise TypeError("NID stores must be tuples of NidRuntimeEntry values")
            if any(left.key > right.key for left, right in pairwise(rows)):
                raise ValueError("NID stores must retain normalized unsigned-key order")
        if not isinstance(self.suppression, Nid64LookupSnapshot):
            raise TypeError("suppression must be an explicit Nid64LookupSnapshot")


def nid_signature_sequence(key: int, selector: int) -> int:
    """Return nid_entry_t::GetSigSeq; this is not the query-key derivation."""
    _uint(key, 32, "NID4 key")
    _uint(selector, 8, "entry selector")
    return (zlib.crc32(struct.pack("<IB", key, selector)) ^ 0xFFFFFFFF) | 0x55500000000


def lookup_nid_name(
    snapshot: NidLookupSnapshot, selector: int, key: int
) -> NidLookupResult:
    """Evaluate only the confirmed reply-NULL selector97/99 NID4 policy subset."""
    if not isinstance(snapshot, NidLookupSnapshot):
        raise TypeError("an explicit NidLookupSnapshot is required")
    if type(selector) is not int or selector not in (97, 99):
        raise ValueError("this resolver profile supports only selectors 97 and 99")
    _uint(key, 32, "NID4 query key")
    for rows in (snapshot.delta, snapshot.base):
        result = NidLookupResult(0, None)
        for row in rows:
            if row.key != key or row.selector != selector:
                continue
            name = row.runtime_name
            attribute = name is not None and name.startswith(b"!#")
            if attribute:
                status = 1
            else:
                suppressed = (
                    lookup_nid64_name(
                        snapshot.suppression, 108, nid_signature_sequence(key, selector)
                    ).status
                    == 1
                )
                status = 2 if suppressed else 1
            result = NidLookupResult(status, name)
            if name is None and status == 1:
                return result
        if result.status:
            return result
    return NidLookupResult(0, None)


def resolve_import_descriptor(
    raw_dll: bytes,
    raw_entries: tuple[bytes | int, ...],
    *,
    virtual_dlls: VirtualDllSnapshot,
    nid_snapshot: NidLookupSnapshot,
) -> ImportDescriptor:
    """Resolve effective mapped imports without manually supplying each ordinal.

    Both backends are explicit reusable runtime snapshots. This does not build them
    from wire tails or load a PE/VDM/OS module. Named imports preserve raw bytes;
    ordinal acceptance requires the native lookup status to equal exactly one.
    """
    ImportDescriptor(raw_dll, ())  # Existing effective-DLL ASCII/length contract.
    if not isinstance(raw_entries, tuple):
        raise TypeError("raw_entries must be a tuple of name bytes or ordinals")
    if not isinstance(virtual_dlls, VirtualDllSnapshot):
        raise TypeError("an explicit VirtualDllSnapshot is required")
    if not isinstance(nid_snapshot, NidLookupSnapshot):
        raise TypeError("an explicit NidLookupSnapshot is required")
    virtual = virtual_dlls.lookup(raw_dll)
    if virtual is not None:
        dll_id = virtual.stored_id
    else:
        dll_id = _raw_upper_crc(raw_dll)
        if raw_dll[:7].lower() == b"api-ms-":
            api = lookup_nid_name(nid_snapshot, 99, dll_id)
            if (
                api.status == 1
                and api.runtime_name is not None
                and api.runtime_name.startswith(b"#")
            ):
                target = api.runtime_name[1:]
                # Longer resolved targets are outside this verified bounded
                # success profile; do not emulate truncation or resource paths.
                if len(target) > 259:
                    raise ValueError(
                        "API-set target exceeds the supported 259-byte bound"
                    )
                virtual_dlls.lookup(target)
                # The original caller skips the stored-ID accessor on this branch.
                dll_id = _raw_upper_crc(target)
    entries = []
    for raw in raw_entries:
        if isinstance(raw, bytes):
            entries.append(NamedImport(raw))
            continue
        _uint(raw, 16, "import ordinal")
        result = lookup_nid_name(nid_snapshot, 97, dll_id ^ raw)
        if result.status != 1:
            resolution = OrdinalResolution("miss")
        elif not result.runtime_name:
            resolution = OrdinalResolution("matched_empty")
        else:
            resolution = OrdinalResolution("matched_name", result.runtime_name)
        entries.append(OrdinalImport(raw, resolution))
    descriptor = ImportDescriptor(raw_dll, tuple(entries))
    imphash_token_stream((descriptor,))  # Verify the existing destination bound.
    return descriptor
