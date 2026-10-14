"""Shared parser for lossless, length-prefixed RecID tails."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class RecIdTail:
    """Lossless tail bytes and the engine's bounded object view."""

    raw: bytes
    length_limit: int
    object_raw: bytes
    trailing_raw: bytes
    has_object: bool


def parse_recid_tail(raw: bytes) -> RecIdTail | None:
    """Parse a RecID tail while preserving all bytes, including surplus."""
    if not raw:
        return None

    length_limit = raw[0]
    effective_length = min(length_limit, len(raw) - 1)
    object_raw = raw[1 : 1 + effective_length]
    trailing_raw = raw[1 + effective_length :]
    has_object = bool(object_raw) and object_raw[0] != 0
    return RecIdTail(
        raw=raw,
        length_limit=length_limit,
        object_raw=object_raw,
        trailing_raw=trailing_raw,
        has_object=has_object,
    )
