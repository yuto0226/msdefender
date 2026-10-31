"""Selector 98 MD5 prefix for effective PE imports in an ASCII success profile.

Inputs are descriptors/thunks that have already passed engine traversal and
mapping. This does not parse PE files, resolve runtime virtual DLLs or perform
NID selector 97/99 lookups. Their per-ordinal results must be supplied explicitly.
The profile excludes non-ASCII/embedded-NUL names, mapping/resource failures,
malformed PE traversal, empty named imports and overflowing engine buffers.
"""

import hashlib
from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True, slots=True)
class OrdinalResolution:
    """Selector 97 result; matched names include the byte the engine discards.

    ``miss`` uses ordN. ``matched_empty`` means a matched RecID whose resolved name
    is NULL or empty, so the token is skipped. ``matched_name`` requires a nonempty
    raw name; its first byte is discarded unconditionally, including non-# bytes.
    The caller must account for virtual DLL IDs and selector 99 API-set remapping.
    """

    status: Literal["miss", "matched_empty", "matched_name"]
    raw_name: bytes = b""

    def __post_init__(self) -> None:
        if self.status not in ("miss", "matched_empty", "matched_name"):
            raise ValueError("invalid ordinal resolution status")
        if self.status == "matched_name":
            _ascii_name(self.raw_name, "mapped ordinal name")
        elif self.raw_name != b"":
            raise ValueError("only matched_name carries raw_name")


@dataclass(frozen=True, slots=True)
class NamedImport:
    raw_name: bytes

    def __post_init__(self) -> None:
        _ascii_name(self.raw_name, "named import", maximum=259)


@dataclass(frozen=True, slots=True)
class OrdinalImport:
    ordinal: int
    resolution: OrdinalResolution

    def __post_init__(self) -> None:
        if type(self.ordinal) is not int or not 0 <= self.ordinal <= 0xFFFF:
            raise ValueError("ordinal must be an unsigned 16-bit integer")
        if not isinstance(self.resolution, OrdinalResolution):
            raise TypeError("an explicit OrdinalResolution is required")


@dataclass(frozen=True, slots=True)
class ImportDescriptor:
    """One effective mapped descriptor, retaining raw DLL bytes and thunk order."""

    raw_dll: bytes
    entries: tuple[NamedImport | OrdinalImport, ...]

    def __post_init__(self) -> None:
        _ascii_name(self.raw_dll, "DLL name", maximum=259)
        if not isinstance(self.entries, tuple) or any(
            not isinstance(entry, (NamedImport, OrdinalImport))
            for entry in self.entries
        ):
            raise TypeError("entries must be a tuple of named or ordinal imports")


def _ascii_name(raw: bytes, label: str, *, maximum: int | None = None) -> None:
    if not isinstance(raw, bytes):
        raise TypeError(f"{label} must be bytes")
    if not raw or b"\0" in raw or not raw.isascii():
        raise ValueError(f"{label} must be nonempty NUL-free ASCII bytes")
    if maximum is not None and len(raw) > maximum:
        raise ValueError(f"{label} exceeds the supported {maximum}-byte bound")


def imphash_token_stream(imports: tuple[ImportDescriptor, ...]) -> bytes:
    """Build the exact token stream for the supported successful input subset.

    Order and duplicate descriptors/thunks are preserved. Mapped ordinal names have
    no separate 259-byte limit, but their post-discard name plus DLL prefix must fit
    the engine's 324-byte destination including its terminating NUL.
    """
    if not isinstance(imports, tuple) or any(
        not isinstance(descriptor, ImportDescriptor) for descriptor in imports
    ):
        raise TypeError("imports must be a tuple of effective ImportDescriptor values")
    tokens = []
    for descriptor in imports:
        dll = descriptor.raw_dll.lower()
        stem, dot, extension = dll.rpartition(b".")
        if dot and extension in (b"dll", b"sys", b"ocx"):
            dll = stem
        prefix = dll + b"."
        for entry in descriptor.entries:
            if isinstance(entry, NamedImport):
                name = entry.raw_name.lower()
            else:
                resolution = entry.resolution
                if resolution.status == "matched_empty":
                    continue
                name = (
                    b"ord%d" % entry.ordinal
                    if resolution.status == "miss"
                    else resolution.raw_name[1:].lower()
                )
            token = prefix + name
            if len(token) > 323:
                raise ValueError("import token exceeds the supported 323-byte bound")
            tokens.append(token)
    return b",".join(tokens)


def derive_imphash_digest(imports: tuple[ImportDescriptor, ...]) -> bytes:
    """Return the 16-byte MD5 prefix; this is not a file-content digest or verdict."""
    return hashlib.md5(imphash_token_stream(imports)).digest()


def assemble_snid98_key(digest: bytes, *, suffix_raw: bytes) -> bytes:
    """Combine digest and explicit context suffix without endian conversion.

    The reset slice sets suffix_raw to four zero bytes, but alias writers and outer
    scan gates are not closed. Callers must supply the suffix for their context.
    """
    if not isinstance(digest, bytes) or len(digest) != 16:
        raise ValueError("digest must contain exactly 16 bytes")
    if not isinstance(suffix_raw, bytes) or len(suffix_raw) != 4:
        raise ValueError("suffix_raw must contain exactly four bytes")
    return digest + suffix_raw
