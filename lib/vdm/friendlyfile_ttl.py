"""Source-only friendly TTL metadata and attribute/cache request projections.

No A0 digest/tail supplies these snapshots. No CRT parser, NID lookup, clock,
attribute setter or cache service is executed. Independent close-time snapshots
may describe a later epoch; caller results never become observed attributes.
"""

from dataclasses import dataclass
from typing import Literal


class FriendlyTtlSnapshotError(ValueError):
    """Invalid widths/types, mismatched provenance or unsupported API profile."""


class _Missing(Exception):
    pass


@dataclass(frozen=True, slots=True)
class SignatureTtlSnapshot:
    epoch: str
    signature_id: int | None
    nid150_result: int | None
    name_present: bool | None
    name_bytes: bytes | None
    parsed_u64: int | None
    crt_profile: Literal["mpengine.strtoull.base0"] | None
    locale_profile: str | None
    timestamp_value: int | None


@dataclass(frozen=True, slots=True)
class SignatureTtlResult:
    epoch: str
    signature_id: int | None
    status: Literal["projected", "unknown"]
    reason: str
    source: Literal["custom", "fallback_presence"] | None
    parsed_u64: int | None
    ttl_u64: int | None
    fallback_consulted: bool | None
    unit: None = None
    expiry: None = None


@dataclass(frozen=True, slots=True)
class FriendlyTtlCallerSnapshot:
    epoch: str
    signature_id: int | None
    caller_profile: (
        Literal[
            "IsSignedFile.friendly_attribute_path", "IsSignedFile.cached_fast_return"
        ]
        | None
    )
    helper: SignatureTtlSnapshot | None
    setter_result: bool | None


@dataclass(frozen=True, slots=True)
class FriendlyTtlAttributeRequest:
    epoch: str
    signature_id: int | None
    status: Literal["projected", "unknown"]
    reason: str
    helper: SignatureTtlResult | None
    requests_setter: bool | None
    requested_value_u64: int | None
    setter_succeeded: bool | None
    attribute_name: str = "MpMoacFriendlyAddTTL"
    attribute_value_after: None = None
    unit: None = None
    expiry: None = None


@dataclass(frozen=True, slots=True)
class FriendlyTtlCacheSnapshot:
    epoch: str
    signature_id: int | None
    cachemgr_profile: Literal["CacheMgr.MoacFriendlyAdd.V2"] | None
    ttl_attribute_present: bool | None
    ttl_attribute_value: int | None
    entry_write_reached: bool | None
    entry_ttl_before: int | None
    v2_filler_reached: bool | None


@dataclass(frozen=True, slots=True)
class FriendlyTtlCacheProjection:
    epoch: str
    signature_id: int | None
    status: Literal["projected", "unknown"]
    reason: str
    effective_attribute_ttl: int | None
    overwrites_entry: bool | None
    entry_ttl_u64: int | None
    event_ttl_u32: int | None
    event_code: int | None
    unit: None = None
    expiry: None = None
    cache_success: None = None
    final_allow_or_bypass: None = None


def _uint(value: int | None, bits: int, label: str) -> None:
    if value is not None and (type(value) is not int or not 0 <= value < (1 << bits)):
        raise FriendlyTtlSnapshotError(f"{label} must be uint{bits} or None")


def _boolean(value: bool | None, label: str) -> None:
    if value is not None and type(value) is not bool:
        raise FriendlyTtlSnapshotError(f"{label} must be bool or None")


def _epoch(value: str) -> None:
    if type(value) is not str or not value:
        raise FriendlyTtlSnapshotError("epoch must be a nonempty opaque string")


def _need(value, reason):
    if value is None:
        raise _Missing(reason)
    return value


def _helper_snapshot(snapshot: SignatureTtlSnapshot) -> None:
    if not isinstance(snapshot, SignatureTtlSnapshot):
        raise FriendlyTtlSnapshotError("expected SignatureTtlSnapshot")
    _epoch(snapshot.epoch)
    _uint(snapshot.signature_id, 64, "signature_id")
    _uint(snapshot.nid150_result, 32, "nid150_result")
    _uint(snapshot.parsed_u64, 64, "parsed_u64")
    _uint(snapshot.timestamp_value, 64, "timestamp_value")
    _boolean(snapshot.name_present, "name_present")
    if snapshot.name_bytes is not None and type(snapshot.name_bytes) is not bytes:
        raise FriendlyTtlSnapshotError("name_bytes must be immutable bytes or None")
    if snapshot.crt_profile not in (None, "mpengine.strtoull.base0"):
        raise FriendlyTtlSnapshotError("unsupported CRT parser provenance")
    if snapshot.locale_profile is not None and (
        type(snapshot.locale_profile) is not str or not snapshot.locale_profile
    ):
        raise FriendlyTtlSnapshotError("locale_profile must be nonempty or None")


def project_signature_custom_ttl(snapshot: SignatureTtlSnapshot) -> SignatureTtlResult:
    """Project GetSignatureCustomTTL from explicit original-CRT parsed output.

    parsed_u64 is asserted to be strtoull(name+1, NULL, 0) in the stated locale
    and same signature/epoch. This function does not parse or validate the text.
    Missing required facts never select fallback; invalid known custom facts do.
    """
    _helper_snapshot(snapshot)
    consulted = None
    parsed = None
    try:
        _need(snapshot.signature_id, "signature_identity_unknown")
        if _need(snapshot.nid150_result, "nid150_result_unknown") == 1 and _need(
            snapshot.name_present, "name_presence_unknown"
        ):
            name = _need(snapshot.name_bytes, "name_bytes_unknown")
            if name.startswith(b"#"):
                _need(snapshot.crt_profile, "crt_profile_unknown")
                _need(snapshot.locale_profile, "locale_profile_unknown")
                parsed = _need(snapshot.parsed_u64, "parsed_u64_unknown")
                if 0 < parsed < 0xFFFFFFFFFFFFFFFF:
                    return SignatureTtlResult(
                        snapshot.epoch,
                        snapshot.signature_id,
                        "projected",
                        "custom_value",
                        "custom",
                        parsed,
                        (parsed * 60) & 0xFFFFFFFFFFFFFFFF,
                        False,
                    )
        consulted = True
        timestamp = _need(snapshot.timestamp_value, "timestamp_value_unknown")
        return SignatureTtlResult(
            snapshot.epoch,
            snapshot.signature_id,
            "projected",
            "fallback_presence",
            "fallback_presence",
            parsed,
            1440 if timestamp else 0,
            True,
        )
    except _Missing as exc:
        return SignatureTtlResult(
            snapshot.epoch,
            snapshot.signature_id,
            "unknown",
            str(exc),
            None,
            parsed,
            None,
            consulted,
        )


def project_friendly_ttl_attribute(
    snapshot: FriendlyTtlCallerSnapshot,
) -> FriendlyTtlAttributeRequest:
    """Project only the observed IsSignedFile TTL callsite, never its gate.

    friendly_attribute_path explicitly asserts that the shared attribute block
    was reached (after the preceding FriendlyAdd request); a digest candidate
    does not establish it. Setter success is independent and never read as a
    close-time attribute observation, even when explicitly supplied as true.
    """
    if not isinstance(snapshot, FriendlyTtlCallerSnapshot):
        raise FriendlyTtlSnapshotError("expected FriendlyTtlCallerSnapshot")
    _epoch(snapshot.epoch)
    _uint(snapshot.signature_id, 64, "signature_id")
    _boolean(snapshot.setter_result, "setter_result")
    if snapshot.helper is not None:
        _helper_snapshot(snapshot.helper)
        if snapshot.helper.epoch != snapshot.epoch:
            raise FriendlyTtlSnapshotError("helper/caller epoch mismatch")
        if snapshot.helper.signature_id != snapshot.signature_id:
            raise FriendlyTtlSnapshotError("helper/caller signature identity mismatch")
    if snapshot.caller_profile not in (
        None,
        "IsSignedFile.friendly_attribute_path",
        "IsSignedFile.cached_fast_return",
    ):
        raise FriendlyTtlSnapshotError("unsupported caller profile")
    status, reason, helper, request, value, setter = (
        "projected",
        "cached_fast_return",
        None,
        False,
        None,
        None,
    )
    try:
        profile = _need(snapshot.caller_profile, "caller_profile_unknown")
        if profile != "IsSignedFile.cached_fast_return":
            _need(snapshot.signature_id, "signature_identity_unknown")
            helper = project_signature_custom_ttl(
                _need(snapshot.helper, "helper_snapshot_unknown")
            )
            if helper.status == "unknown":
                status, reason, request = "unknown", helper.reason, None
            elif helper.ttl_u64:
                reason, request, value, setter = (
                    "ttl_setter_requested",
                    True,
                    helper.ttl_u64,
                    snapshot.setter_result,
                )
            else:
                reason = "ttl_zero_no_setter"
    except _Missing as exc:
        status, reason, request = "unknown", str(exc), None
    return FriendlyTtlAttributeRequest(
        snapshot.epoch,
        snapshot.signature_id,
        status,
        reason,
        helper,
        request,
        value,
        setter,
    )


def project_friendly_ttl_cache(
    snapshot: FriendlyTtlCacheSnapshot,
) -> FriendlyTtlCacheProjection:
    """Project explicit close-time attribute and pre-custom-write entry facts.

    entry_ttl_before is the local MOAC entry field immediately before the
    nonzero custom override; it is not a persistent cache lookup result. No
    constructor default is assumed. This stage accepts no caller result, so a
    later epoch must be supplied independently rather than silently bridged.
    entry_write_reached and v2_filler_reached are explicit observed reachability
    facts covering the relevant outer gates/services; they are not inferred.
    """
    if not isinstance(snapshot, FriendlyTtlCacheSnapshot):
        raise FriendlyTtlSnapshotError("expected FriendlyTtlCacheSnapshot")
    _epoch(snapshot.epoch)
    for name in ("signature_id", "ttl_attribute_value", "entry_ttl_before"):
        _uint(getattr(snapshot, name), 64, name)
    for name in ("ttl_attribute_present", "entry_write_reached", "v2_filler_reached"):
        _boolean(getattr(snapshot, name), name)
    if snapshot.cachemgr_profile not in (None, "CacheMgr.MoacFriendlyAdd.V2"):
        raise FriendlyTtlSnapshotError("unsupported cache profile")
    if snapshot.entry_write_reached is False and snapshot.v2_filler_reached is True:
        raise FriendlyTtlSnapshotError(
            "V2 filler cannot precede this entry write route"
        )
    effective = overwrites = entry = event = code = None
    status, reason = "projected", "entry_write_not_reached"
    try:
        if _need(snapshot.entry_write_reached, "entry_reachability_unknown"):
            _need(snapshot.cachemgr_profile, "cachemgr_profile_unknown")
            _need(snapshot.signature_id, "signature_identity_unknown")
            present = _need(
                snapshot.ttl_attribute_present, "attribute_presence_unknown"
            )
            effective = (
                _need(snapshot.ttl_attribute_value, "attribute_value_unknown")
                if present
                else 0
            )
            overwrites = effective != 0
            entry = (
                effective
                if overwrites
                else _need(snapshot.entry_ttl_before, "entry_ttl_before_unknown")
            )
            reason = "entry_value_projected"
            if _need(snapshot.v2_filler_reached, "v2_reachability_unknown"):
                if snapshot.signature_id == 0:
                    raise FriendlyTtlSnapshotError(
                        "V2 filler zero identity assertion domain"
                    )
                event, code, reason = entry & 0xFFFFFFFF, 55, "v2_event_value_projected"
    except _Missing as exc:
        status, reason = "unknown", str(exc)
    return FriendlyTtlCacheProjection(
        snapshot.epoch,
        snapshot.signature_id,
        status,
        reason,
        effective,
        overwrites,
        entry,
        event,
        code,
    )
