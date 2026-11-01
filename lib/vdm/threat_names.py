"""Raw CString names in an explicitly published direct-full namespace.

This is a conditional projection, not a namespace loader. The profile asserts
successful normal flags=1 copy, value-preserving storage, engine-published sorted
unique full rows, and no dependency redirects, mini/fast-path/alternate store,
shadowing or unresolved base/delta overrides. Sorting our index proves none of
those engine properties. Original THREAT_BEGIN raw bytes remain available.
"""

from dataclasses import dataclass, field
from typing import Final, Literal

from .types.threat import MAGIC_THREAT_IDS, ThreatBegin, parse_threat_begin

DIRECT_FULL_NAME_PROFILE: Final = (
    "mpengine-1.443.903.0.normal-copy.unique-sorted-direct-full.no-redirect.no-override"
)


class UnsupportedThreatNamespace(ValueError):
    """Missing, unproven or unsupported namespace state is never NULL."""


@dataclass(frozen=True, slots=True)
class DirectFullNameProfile:
    """Explicit effective publication and storage assertion for one epoch.

    Both loaded values are supported because this fixed profile excludes enabled
    dependency redirects. threats_loaded alone never establishes the profile.
    """

    kind: Literal[
        "mpengine-1.443.903.0.normal-copy.unique-sorted-direct-full.no-redirect.no-override"
    ]
    threats_loaded: bool
    epoch: str

    def __post_init__(self) -> None:
        if self.kind != DIRECT_FULL_NAME_PROFILE:
            raise UnsupportedThreatNamespace(
                "unsupported namespace publication profile"
            )
        if type(self.threats_loaded) is not bool:
            raise TypeError("threats_loaded must be explicitly true or false")
        if not isinstance(self.epoch, str) or not self.epoch:
            raise UnsupportedThreatNamespace("an explicit nonempty epoch is required")


@dataclass(frozen=True, slots=True)
class DirectFullNameSnapshot:
    """Immutable ID index from caller-selected effective raw THREAT_BEGIN rows."""

    threat_begins: tuple[ThreatBegin, ...]
    profile: DirectFullNameProfile
    _names: tuple[tuple[int, bytes | None], ...] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.profile, DirectFullNameProfile):
            raise TypeError("an explicit DirectFullNameProfile is required")
        if not isinstance(self.threat_begins, tuple) or any(
            not isinstance(begin, ThreatBegin) for begin in self.threat_begins
        ):
            raise TypeError("threat_begins must be a tuple of parsed raw THREAT_BEGINs")
        names = {}
        for supplied in self.threat_begins:
            if not isinstance(supplied.raw, bytes):
                raise TypeError("raw payload must be bytes")
            try:
                begin = parse_threat_begin(supplied.raw)
            except ValueError as exc:
                raise UnsupportedThreatNamespace(
                    "invalid raw THREAT_BEGIN context"
                ) from exc
            identifier = begin.threat_id
            if (
                identifier in MAGIC_THREAT_IDS
                or 0x7FFE0000 <= identifier <= 0x7FFE9FFF
                or 0x7FFF0000 <= identifier <= 0x7FFF9FFF
            ):
                raise UnsupportedThreatNamespace(
                    "special/magic namespace is unsupported"
                )
            if begin.dep_count:
                raise UnsupportedThreatNamespace("dependency namespace is unsupported")
            if identifier in names:
                raise UnsupportedThreatNamespace(
                    "duplicate ID has unresolved override order"
                )
            names[identifier] = (
                begin.name_raw.split(b"\0", 1)[0] if begin.name_len else None
            )
        object.__setattr__(self, "_names", tuple(sorted(names.items())))

    def runtime_name(self, caller_threat_id: int) -> bytes | None:
        """Return raw CString bytes or confirmed NULL, preserving high bits.

        No decode, marker skip, whitespace strip or ASCII restriction is applied.
        Missing association raises; zero counted span alone yields NULL, whereas
        a nonzero counted span beginning with NUL yields empty bytes.
        """
        if type(caller_threat_id) is not int or not 0 <= caller_threat_id <= 0xFFFFFFFF:
            raise ValueError("caller threat ID must be an unsigned 32-bit integer")
        for identifier, name in self._names:
            if identifier == caller_threat_id:
                return name
        raise UnsupportedThreatNamespace(
            "caller ID is absent from the selected namespace"
        )
