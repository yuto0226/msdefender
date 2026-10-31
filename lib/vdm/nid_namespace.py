"""Raw THREAT_BEGIN names for no-tail NID4 in a fixed direct-full profile.

This does not initialize a Defender namespace. The explicit profile asserts a
unique effective full namespace with no enabled redirects or mini/fast-path/
base-delta overrides, using the normal flags=1 raw-copy object-store path.
Unknown profiles and missing namespaces are errors, never synthesized NULL names.
"""

from dataclasses import dataclass, field
from typing import Final, Literal

from .snid_resolver import NidRuntimeEntry
from .types.nid import NID_TYPE, NidPayload
from .types.threat import MAGIC_THREAT_IDS, ThreatBegin, parse_threat_begin

DIRECT_FULL_NAME_PROFILE: Final = (
    "mpengine-1.443.903.0.normal-copy.unique-direct-full.no-redirect.no-override"
)


class UnsupportedNidNamespace(ValueError):
    """The requested association is outside the verified namespace profile."""


@dataclass(frozen=True, slots=True)
class NoTailNameProfile:
    """Explicit initialization assertion, not a claim that a loader ran.

    normal-copy means the verified normal object store's raw span plus extra NUL
    copy, without alternate-store or unmodeled preexisting interning-table state.
    The fixed kind also excludes enabled dependency redirects, mini/fast-path rows
    and base/delta overrides. threats_loaded alone does not establish this profile;
    both values are supported only because the fixed profile forbids redirects.
    """

    kind: Literal[
        "mpengine-1.443.903.0.normal-copy.unique-direct-full.no-redirect.no-override"
    ]
    threats_loaded: bool

    def __post_init__(self) -> None:
        if self.kind != DIRECT_FULL_NAME_PROFILE:
            raise UnsupportedNidNamespace(
                "unsupported namespace initialization profile"
            )
        if type(self.threats_loaded) is not bool:
            raise TypeError("threats_loaded must be explicitly true or false")


def _threat_id(value: int) -> None:
    if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
        raise ValueError("caller threat ID must be an unsigned 32-bit integer")


def _special(threat_id: int) -> bool:
    return (
        threat_id in MAGIC_THREAT_IDS
        or 0x7FFE0000 <= threat_id <= 0x7FFE9FFF
        or 0x7FFF0000 <= threat_id <= 0x7FFF9FFF
    )


@dataclass(frozen=True, slots=True)
class NoTailNameSnapshot:
    """Reusable raw wire contexts for the explicitly selected effective namespace.

    The original raw payloads are reparsed; display name, display_name_raw, marker
    skipping and lossy decoding are never used. Callers select one effective loading
    epoch, not an unqualified concatenation of base/delta databases. Duplicate IDs,
    dependencies and special/magic namespaces are rejected rather than guessed.
    """

    threat_begins: tuple[ThreatBegin, ...]
    profile: NoTailNameProfile
    _names: tuple[tuple[int, bytes | None], ...] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.profile, NoTailNameProfile):
            raise TypeError("an explicit NoTailNameProfile is required")
        if not isinstance(self.threat_begins, tuple) or any(
            not isinstance(begin, ThreatBegin) for begin in self.threat_begins
        ):
            raise TypeError("threat_begins must be a tuple of parsed raw THREAT_BEGINs")
        names = {}
        for supplied in self.threat_begins:
            try:
                begin = parse_threat_begin(supplied.raw)
            except ValueError as exc:
                raise UnsupportedNidNamespace(
                    "invalid raw THREAT_BEGIN context"
                ) from exc
            if _special(begin.threat_id):
                raise UnsupportedNidNamespace(
                    "special/magic namespace requires a loader profile"
                )
            if begin.dep_count:
                raise UnsupportedNidNamespace(
                    "dependency namespace is outside the direct profile"
                )
            if begin.threat_id in names:
                raise UnsupportedNidNamespace(
                    "duplicate threat ID has unresolved load/override order"
                )
            # Normal flags=1 copies all raw bytes and adds NUL. The C-string
            # accessor exposes bytes up to the first NUL; zero span has no object.
            names[begin.threat_id] = (
                begin.name_raw.split(b"\0", 1)[0] if begin.name_len else None
            )
        object.__setattr__(self, "_names", tuple(sorted(names.items())))

    def runtime_name(self, caller_threat_id: int) -> bytes | None:
        """Return proven raw bytes/NULL; an unresolved namespace raises instead.

        High-bit bytes and whitespace are preserved. The downstream ASCII resolver may
        reject such names; this accessor does not repair them using the display string.
        """
        _threat_id(caller_threat_id)
        for identifier, name in self._names:
            if identifier == caller_threat_id:
                return name
        raise UnsupportedNidNamespace(
            "caller threat ID is absent from the selected namespace"
        )


def no_tail_nid_runtime_entry(
    parsed_nid: NidPayload,
    *,
    caller_threat_id: int,
    namespace: NoTailNameSnapshot,
) -> NidRuntimeEntry:
    """Associate generic no-tail type55 name bytes without deriving its key.

    RecordPush copies metadata unchanged and stores the explicit caller threat ID;
    there is no selector-specific name branch. This does not assign an ordinal/API
    role to arbitrary selectors. Nonempty tails and other record families are outside
    the bridge; non-ASCII names are outside the existing NidRuntimeEntry profile.
    """
    if not isinstance(parsed_nid, NidPayload):
        raise TypeError("a parsed NidPayload is required")
    if parsed_nid.type_byte != NID_TYPE or len(parsed_nid.raw) != 5:
        raise UnsupportedNidNamespace(
            "bridge requires exactly five no-tail type55 bytes"
        )
    if not isinstance(namespace, NoTailNameSnapshot):
        raise TypeError("an explicit NoTailNameSnapshot is required")
    name = namespace.runtime_name(caller_threat_id)
    if name is not None and not name.isascii():
        raise UnsupportedNidNamespace(
            "raw runtime name is outside the ASCII NID resolver profile"
        )
    return NidRuntimeEntry(
        key=int.from_bytes(parsed_nid.raw[:4], "little"),
        selector=parsed_nid.raw[4],
        runtime_name=name,
    )
