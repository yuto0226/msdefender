"""Named NID4 raw-name projection in an explicit normal-copy mini profile.

This projects name values, not generated numeric mini IDs, signature counters or
report identities. It does not initialize an engine or resolve arbitrary loader
state. Unknown storage/namespace state is an error, never a synthesized NULL name.
"""

from dataclasses import dataclass
from typing import Final, Literal

from .nid_namespace import UnsupportedNidNamespace
from .snid_resolver import NidRuntimeEntry
from .threat_names import DirectFullNameSnapshot
from .types.nid import NID_TYPE, NidPayload

NAMED_MINI_NAME_PROFILE: Final = (
    "mpengine-1.443.903.0.normal-copy.consistent-mini.immutable-no-shadow"
)


@dataclass(frozen=True, slots=True)
class NamedTailNameProfile:
    """Assert successful, value-preserving normal flags=0 object storage.

    Each returned OID must denote exactly the requested bounded span, including
    its terminating NUL, with immutable bytes. Unverified dedup/interner state,
    case folding and collisions are excluded. InternalIdMap and mini rows must
    agree, retain flags=0x1F7 and their names, and have no full/fast-path shadow or
    counter collision. Consistent value-preserving cache reuse is allowed across
    parents. Allocation and namespace registration have succeeded. The explicit
    loaded state alone does not establish any of these assertions.
    """

    kind: Literal[
        "mpengine-1.443.903.0.normal-copy.consistent-mini.immutable-no-shadow"
    ]
    threats_loaded: bool

    def __post_init__(self) -> None:
        if self.kind != NAMED_MINI_NAME_PROFILE:
            raise UnsupportedNidNamespace("unsupported named mini namespace profile")
        if type(self.threats_loaded) is not bool:
            raise TypeError("threats_loaded must be explicitly true or false")


def named_tail_nid_runtime_entry(
    parsed_nid: NidPayload,
    *,
    caller_threat_id: int,
    caller_sig_id: int,
    profile: NamedTailNameProfile,
    parent_namespace: DirectFullNameSnapshot | None = None,
) -> NidRuntimeEntry:
    """Project a generic type55 nonempty tail into the existing ASCII row API.

    Raw payload bytes are authoritative; selector and key pass through unchanged.
    A nonzero label is bounded by its first NUL; later payload bytes never reach
    kpushobject. Unterminated names depend on external storage and are unsupported.
    A leading NUL instead retains the caller's parent namespace, requiring an
    explicit direct-full snapshot with the same loaded state. Its proven NULL and
    empty C-string values remain distinct. Special parents are valid for the named
    mini branch; no no-tail parent restrictions are imposed on that branch.
    """
    if not isinstance(parsed_nid, NidPayload):
        raise TypeError("a parsed NidPayload is required")
    if parsed_nid.type_byte != NID_TYPE or len(parsed_nid.raw) <= 5:
        raise UnsupportedNidNamespace("bridge requires a nonempty type55 tail")
    name = _named_tail_runtime_name(
        parsed_nid.raw[5:],
        caller_threat_id=caller_threat_id,
        caller_sig_id=caller_sig_id,
        profile=profile,
        parent_namespace=parent_namespace,
    )
    if name is not None and not name.isascii():
        raise UnsupportedNidNamespace(
            "raw runtime name is outside the ASCII NID resolver profile"
        )
    return NidRuntimeEntry(
        key=int.from_bytes(parsed_nid.raw[:4], "little"),
        selector=parsed_nid.raw[4],
        runtime_name=name,
    )


def _named_tail_runtime_name(
    tail: bytes,
    *,
    caller_threat_id: int,
    caller_sig_id: int,
    profile: NamedTailNameProfile,
    parent_namespace: DirectFullNameSnapshot | None,
) -> bytes | None:
    """Shared RecordPush/createrecidz flags0 name-value projection.

    Callers validate their family/header first. This preserves raw high-bit bytes;
    any narrower downstream row-name domain is checked by that row factory.
    """
    if type(caller_threat_id) is not int or not 0 <= caller_threat_id <= 0xFFFFFFFF:
        raise ValueError("caller threat ID must be an unsigned 32-bit integer")
    if type(caller_sig_id) is not int or not 0 <= caller_sig_id <= 0xFFFFF:
        raise UnsupportedNidNamespace("caller signature ID exceeds the 20-bit domain")
    if not isinstance(profile, NamedTailNameProfile):
        raise TypeError("an explicit NamedTailNameProfile is required")
    if parent_namespace is not None and not isinstance(
        parent_namespace, DirectFullNameSnapshot
    ):
        raise TypeError("parent_namespace must be a DirectFullNameSnapshot or None")

    if tail[0] == 0:
        if parent_namespace is None:
            raise UnsupportedNidNamespace("leading NUL requires a parent namespace")
        if parent_namespace.profile.threats_loaded != profile.threats_loaded:
            raise UnsupportedNidNamespace("parent and mini loaded states differ")
        name = parent_namespace.runtime_name(caller_threat_id)
    else:
        nul = tail.find(b"\0")
        if nul < 0:
            raise UnsupportedNidNamespace(
                "unterminated name depends on external object storage"
            )
        name = tail[:nul]
    return name
