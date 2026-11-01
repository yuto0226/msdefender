"""NID4 no-tail factory using the family-neutral direct-full namespace."""

from .snid_resolver import NidRuntimeEntry
from .threat_names import DirectFullNameSnapshot
from .types.nid import NID_TYPE, NidPayload


class UnsupportedNidNamespace(ValueError):
    """NID family ingress or row-name domain is unsupported."""


def no_tail_nid_runtime_entry(
    parsed_nid: NidPayload,
    *,
    caller_threat_id: int,
    namespace: DirectFullNameSnapshot,
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
    if not isinstance(namespace, DirectFullNameSnapshot):
        raise TypeError("an explicit DirectFullNameSnapshot is required")
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
