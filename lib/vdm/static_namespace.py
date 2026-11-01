"""No-tail STATIC caller-ID to raw namespace name projection."""

from .threat_names import DirectFullNameSnapshot
from .types.static import HEADER_SIZE, StaticPayload, parse_static


class UnsupportedStaticNameBridge(ValueError):
    """STATIC ingress or same-epoch association is outside the verified subset."""


def no_tail_static_name(
    parsed_static: StaticPayload,
    *,
    caller_threat_id: int,
    namespace: DirectFullNameSnapshot,
    epoch: str,
) -> bytes | None:
    """Project a complete mode0–4 no-tail record under explicit runtime facts.

    Raw payload bytes are authoritative over supplied derived fields. Nonempty
    tails require createrecidpc/threatidfromrecid and cannot use parent fallback.
    This supplies only the CString input; flags, config and provider stay external.
    """
    if not isinstance(parsed_static, StaticPayload):
        raise TypeError("a parsed StaticPayload is required")
    if not isinstance(parsed_static.raw, bytes):
        raise TypeError("raw payload must be bytes")
    try:
        actual = parse_static(parsed_static.raw)
    except ValueError as exc:
        raise UnsupportedStaticNameBridge("invalid raw STATIC payload") from exc
    if actual.mode is None or len(actual.raw) != HEADER_SIZE + len(actual.hash_raw):
        raise UnsupportedStaticNameBridge(
            "bridge requires complete mode0–4 without tail"
        )
    if not isinstance(namespace, DirectFullNameSnapshot):
        raise TypeError("an explicit DirectFullNameSnapshot is required")
    if not isinstance(epoch, str) or not epoch or namespace.profile.epoch != epoch:
        raise UnsupportedStaticNameBridge("STATIC and namespace epochs must agree")
    return namespace.runtime_name(caller_threat_id)
