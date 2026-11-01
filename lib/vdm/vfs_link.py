"""Callback6's counted-pair projection and CRC-keyed VFS redirect view.

This models successful immutable object storage, not its allocator, exceptions,
epoch/reset or full VFS normalization. Redirect order is supplied runtime order;
wire record order alone does not establish the active map's insertion history.
"""

from dataclasses import dataclass


class UnsupportedVfsLink(ValueError):
    """Required readable storage or resolved runtime state is unavailable."""


def _u32(value: int, name: str) -> None:
    if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
        raise ValueError(f"{name} must be a uint32")


def _wide_cstring(storage: bytes) -> bytes:
    if not isinstance(storage, bytes):
        raise TypeError("WCHAR storage must be bytes")
    for offset in range(0, len(storage) - 1, 2):
        if storage[offset : offset + 2] == b"\0\0":
            return storage[: offset + 2]
    raise UnsupportedVfsLink("WCHAR storage has no readable aligned NUL WORD")


def crc_upper_string_w(storage: bytes, seed: int = 0xFFFFFFFF) -> int:
    """Project CRCUpperStringW over a readable UTF16LE WCHAR CString.

    Only WORDs 0061..007A become 0041..005A. Other units, including lone
    surrogates and FFxx units, remain raw. Feed low byte then high byte, omit
    the NUL WORD, and return the running CRC without final XOR. Bytes after
    the first aligned NUL are not selected or validated as text.
    """
    _u32(seed, "seed")
    text = _wide_cstring(storage)
    crc = seed
    for offset in range(0, len(text) - 2, 2):
        unit = int.from_bytes(text[offset : offset + 2], "little")
        if 0x61 <= unit <= 0x7A:
            unit -= 0x20
        for byte in (unit & 255, unit >> 8):
            crc ^= byte
            for _ in range(8):
                crc = (crc >> 1) ^ (0xEDB88320 if crc & 1 else 0)
    return crc


def _signed_widen(raw: bytes) -> bytes:
    return (
        b"".join(
            (byte if byte < 0x80 else byte | 0xFF00).to_bytes(2, "little")
            for byte in raw
        )
        + b"\0\0"
    )


@dataclass(frozen=True, slots=True)
class VfsLinkProjection:
    """One callback's value projection, not a completed insertion or return code.

    Eligible pairs cause four identical storage/insertion attempts in native
    code. Object IDs, pointer identity and failure partial state are not replayed.
    CString fields include their terminator; delimiter_offset is counted bytes.
    """

    storage: bytes | None
    count: int
    delimiter_offset: int | None
    source_cstring: bytes | None
    target_cstring: bytes | None
    skip_reason: str | None

    @property
    def registration_eligible(self) -> bool:
        return self.skip_reason is None

    @property
    def source_key(self) -> int | None:
        return (
            None
            if self.source_cstring is None
            else crc_upper_string_w(self.source_cstring)
        )


def project_vfs_link(storage: bytes | None, count: int) -> VfsLinkProjection:
    """Project original counted first-'>' and two bounded byte-copy branches.

    No terminal input NUL is required. Missing physical bytes raise only when
    the original branch needs them; NULL input and count0 are ordinary skips.
    Embedded byte NUL ends each copy but not the earlier delimiter search.
    Signed-byte widening is neither UTF8 decoding nor path unescaping.
    """
    _u32(count, "count")
    if storage is not None and not isinstance(storage, bytes):
        raise TypeError("callback storage must be bytes or None")

    def skipped(reason: str, delimiter: int | None = None) -> VfsLinkProjection:
        return VfsLinkProjection(storage, count, delimiter, None, None, reason)

    if storage is None:
        return skipped("null_input")
    if count == 0:
        return skipped("empty_count")
    delimiter = storage.find(b">", 0, count)
    if delimiter < 0:
        if len(storage) < count:
            raise UnsupportedVfsLink("delimiter scan requires unavailable bytes")
        return skipped("delimiter_missing")
    if not 1 <= delimiter <= 259:
        return skipped("source_offset_out_of_range", delimiter)
    remaining = count - delimiter - 1
    if remaining == 0:
        return skipped("target_bytes_absent", delimiter)
    if remaining > 0x7FFFFFFE:
        return skipped("target_count_out_of_range", delimiter)
    start = delimiter + 1
    target = storage[start : start + min(remaining, 260)]
    nul = target.find(b"\0")
    if nul >= 0:
        target = target[:nul]
    elif len(target) == 260:
        return skipped("target_copy_exhausted", delimiter)
    elif len(target) < remaining:
        raise UnsupportedVfsLink("target copy requires unavailable bytes")
    source = storage[:delimiter].split(b"\0", 1)[0]
    return VfsLinkProjection(
        storage,
        count,
        delimiter,
        _signed_widen(source),
        _signed_widen(target),
        None,
    )


@dataclass(frozen=True, slots=True)
class VfsRedirectEntry:
    """A successful map insertion's key and immutable non-NULL target value.

    key is the actual DWORD, not an OS path identity. Distinct source strings
    with equal CRC use the same map entry. An empty target CString is valid.
    """

    key: int
    target_cstring: bytes

    def __post_init__(self) -> None:
        _u32(self.key, "redirect key")
        if _wide_cstring(self.target_cstring) != self.target_cstring:
            raise ValueError("target_cstring must end at its first aligned NUL")


@dataclass(frozen=True, slots=True)
class VfsRedirectSnapshot:
    """Explicit successful runtime insertion order, with native first-key wins.

    The caller must establish this order and the active epoch/initial state.
    This constructor does not interpret a signature stream, synthesize an
    engine initialization, or merge unknown preexisting redirects. Use an
    empty tuple only for a confirmed empty map. Storage is immutable and
    non-NULL; allocation failure and other map writers remain external.
    """

    ordered_insertions: tuple[VfsRedirectEntry, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.ordered_insertions, tuple) or any(
            not isinstance(entry, VfsRedirectEntry) for entry in self.ordered_insertions
        ):
            raise TypeError("ordered_insertions must be a tuple of VfsRedirectEntry")

    def lookup(self, requested_cstring: bytes) -> bytes | None:
        """Return the first matching key's target, or NULL represented by None.

        Input is the actual selected WCHAR CString. No slash, casefold beyond
        CRCUpperStringW, current-directory or other normalization is performed.
        Non-NULL empty target remains b'\\0\\0', distinct from a miss.
        """
        key = crc_upper_string_w(requested_cstring)
        return next(
            (
                entry.target_cstring
                for entry in self.ordered_insertions
                if entry.key == key
            ),
            None,
        )
