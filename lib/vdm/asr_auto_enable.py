"""Callback21 settings candidates and explicitly supplied map insertion order.

Local syntax support is not original UUID-parser acceptance, successful map
insertion, deferred load order or effective ASR policy. No engine state is owned.
"""

import re
from dataclasses import dataclass
from typing import Literal
from uuid import UUID


class UnsupportedAsrAutoEnable(ValueError):
    """Unavailable storage or locally unsupported syntax, not engine rejection."""


_ACTIONS = ((b"WARN_", 6), (b"AUDIT_", 2), (b"BLOCK_", 1))
_MODES = {
    b"M1:": (True, 0),
    b"M2:": (False, 0),
    b"M3:": (True, 0x100),
    b"M4:": (False, 0x180),
}
_UUID = re.compile(
    rb"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)


def _parts(data: bytes) -> tuple[bytes, bytes, UUID, bool, int, int]:
    if not isinstance(data, bytes):
        raise TypeError("effective UTF8 must be bytes")
    prefix, action = next(((p, a) for p, a in _ACTIONS if data.startswith(p)), (b"", 0))
    if not prefix:
        raise UnsupportedAsrAutoEnable("unrecognized case-sensitive action prefix")
    mode = data[len(prefix) : len(prefix) + 3]
    if mode not in _MODES:
        raise UnsupportedAsrAutoEnable("unrecognized case-sensitive mode")
    text = data[len(prefix) + 3 :]
    if not _UUID.fullmatch(text):
        raise UnsupportedAsrAutoEnable(
            "local UUID syntax requires exactly 36 ASCII hyphenated hex bytes; "
            "other forms or malformed UTF8 are unsupported, not engine rejection"
        )
    enabled, flags = _MODES[mode]
    return prefix, mode, UUID(text.decode("ascii")), enabled, action, flags


@dataclass(frozen=True, slots=True)
class AsrAutoEnableSettings:
    """Semantic fields in a 12-byte value; bytes1..3 are uninitialized padding.

    This value deliberately has no implicit byte serializer or effective-policy
    interpretation. The observed AutoEnableRule slice only reads action@4.
    """

    enabled: bool
    action: int
    flags: int

    def __post_init__(self) -> None:
        if type(self.enabled) is not bool:
            raise TypeError("enabled must be bool")
        if type(self.action) is not int or self.action not in (1, 2, 6):
            raise ValueError("action must be1,2,6")
        if (
            type(self.flags) is not int
            or (self.enabled, self.flags) not in _MODES.values()
        ):
            raise ValueError("enabled/flags must correspond to an observed M1..M4 mode")


@dataclass(frozen=True, slots=True)
class AsrAutoEnableCandidate:
    """Exact effective spelling plus derived GUID and settings, not a stored rule."""

    effective_utf8: bytes

    def __post_init__(self) -> None:
        _parts(self.effective_utf8)

    @property
    def prefix(self) -> bytes:
        return _parts(self.effective_utf8)[0]

    @property
    def mode(self) -> bytes:
        return _parts(self.effective_utf8)[1]

    @property
    def uuid(self) -> UUID:
        return _parts(self.effective_utf8)[2]

    @property
    def guid_bytes_le(self) -> bytes:
        return self.uuid.bytes_le

    @property
    def settings(self) -> AsrAutoEnableSettings:
        return AsrAutoEnableSettings(*_parts(self.effective_utf8)[3:])

    @property
    def constructor_recipe(self) -> tuple[str, str, str, str]:
        return (
            "mpengine.dll+0x5BC650",
            "mpengine.dll+0x668794; CP65001 flags0",
            "mpengine.dll+0x66BF24; UuidFromStringW",
            "mpengine.dll+0xAF1DE8; first-wins map emplace",
        )

    @property
    def engine_acceptance(self) -> None:
        return None


def compile_asr_auto_enable_candidate(effective_utf8: bytes) -> AsrAutoEnableCandidate:
    """Support exact action/mode plus hyphenated ASCII UUID, without broad UUID coercion."""
    return AsrAutoEnableCandidate(effective_utf8)


@dataclass(frozen=True, slots=True)
class AsrAutoEnableReceiverProjection:
    """Receiver bytes; all derived gates use authoritative storage and uint32 count."""

    storage: bytes | None
    count: int

    def __post_init__(self) -> None:
        if type(self.count) is not int or not 0 <= self.count <= 0xFFFFFFFF:
            raise ValueError("count must be uint32")
        if self.storage is not None:
            if not isinstance(self.storage, bytes):
                raise TypeError("storage must be bytes or None")
            if len(self.storage) < self.count:
                raise UnsupportedAsrAutoEnable("counted storage is unavailable")

    @property
    def counted_data(self) -> bytes | None:
        return None if self.storage is None else self.storage[: self.count]

    @property
    def physical_tail(self) -> bytes | None:
        return None if self.storage is None else self.storage[self.count :]

    @property
    def effective_utf8(self) -> bytes | None:
        data = self.counted_data
        if not data or data[-1] != 0:
            return None
        return data[: data.index(0)]

    @property
    def after_terminator(self) -> bytes | None:
        data = self.counted_data
        return None if self.effective_utf8 is None else data[data.index(0) + 1 :]

    @property
    def branch(
        self,
    ) -> Literal["null_noop", "invalid", "skip_prefix", "skip_mode", "uuid_candidate"]:
        if self.storage is None:
            return "null_noop"
        data = self.effective_utf8
        if data is None:
            return "invalid"
        prefix = next((p for p, _ in _ACTIONS if data.startswith(p)), None)
        if prefix is None:
            return "skip_prefix"
        if data[len(prefix) : len(prefix) + 3] not in _MODES:
            return "skip_mode"
        return "uuid_candidate"

    @property
    def known_return_u32(self) -> int | None:
        if self.branch == "invalid":
            return 0x800C
        return None if self.branch == "uuid_candidate" else 0


def project_asr_auto_enable_receiver(
    storage: bytes | None, count: int
) -> AsrAutoEnableReceiverProjection:
    return AsrAutoEnableReceiverProjection(storage, count)


@dataclass(frozen=True, slots=True)
class AsrAutoEnableCollectionSnapshot:
    """Explicit successful ingestion history in supplied runtime callback order.

    No sorting by wire offset/name/UUID is manufactured. Supplying a candidate
    here is the caller's assertion of successful native ingestion, not a result
    of local compilation. The first UUID occurrence supplies stored settings.
    The history must cover the complete selected map state, including earlier
    entries; omitting prior entries cannot establish a first-wins lookup.
    """

    initialized: bool
    successfully_ingested_candidates: tuple[AsrAutoEnableCandidate, ...]
    input_source: str

    def __post_init__(self) -> None:
        if type(self.initialized) is not bool:
            raise TypeError("initialized must be bool")
        if type(self.successfully_ingested_candidates) is not tuple or any(
            not isinstance(c, AsrAutoEnableCandidate)
            for c in self.successfully_ingested_candidates
        ):
            raise TypeError("successful candidates must be an immutable typed tuple")
        if not self.initialized and self.successfully_ingested_candidates:
            raise ValueError("an uninitialized map cannot contain successful rows")
        if not isinstance(self.input_source, str) or not self.input_source.strip():
            raise ValueError("runtime order provenance is required")


def lookup_asr_auto_enable_candidate(
    snapshot: AsrAutoEnableCollectionSnapshot, key: UUID
) -> AsrAutoEnableCandidate | None:
    """Read first supplied successful candidate by GUID; no effective-policy query."""
    if not isinstance(snapshot, AsrAutoEnableCollectionSnapshot) or not isinstance(
        key, UUID
    ):
        raise TypeError("expected an explicit collection snapshot and UUID")
    if not snapshot.initialized:
        raise UnsupportedAsrAutoEnable(
            "map state is uninitialized; lookup is unavailable"
        )
    return next(
        (c for c in snapshot.successfully_ingested_candidates if c.uuid == key), None
    )
