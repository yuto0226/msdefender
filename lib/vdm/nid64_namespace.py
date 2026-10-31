"""NID64 wire-to-name factories within explicit, verified loading profiles.

These project raw names, not generated RecID/mini IDs or arbitrary cache/namespace
state. The empty108 factory returns a filtered metadata view, never an assertion
that every other selector is absent or that the current engine was initialized.
"""

from dataclasses import dataclass
from typing import Final, Literal

from .nid_named_namespace import NamedTailNameProfile, _named_tail_runtime_name
from .nid_namespace import NoTailNameSnapshot, UnsupportedNidNamespace
from .nid_suppression import (
    Nid64LookupSnapshot,
    Nid64RuntimeEntry,
    UnsupportedNidSuppression,
)
from .types.nid import NID64_TYPE, NidPayload

WIRE_ONLY_EMPTY108_PROFILE: Final = "mpengine-1.443.903.0.complete-base-wire-ce.empty-effective-delta.no-cache-overlay-or-other-producers"


@dataclass(frozen=True, slots=True)
class WireOnlyEmpty108Profile:
    """Explicit assertion that the supplied base CE projection is complete.

    The selected effective loading epoch contains no cache restore, overlays,
    runtime registrations or other producers beyond these wire CE records, and
    its effective delta is empty. No default profile is inferred from a corpus.
    """

    kind: Literal[
        "mpengine-1.443.903.0.complete-base-wire-ce.empty-effective-delta.no-cache-overlay-or-other-producers"
    ]

    def __post_init__(self) -> None:
        if self.kind != WIRE_ONLY_EMPTY108_PROFILE:
            raise UnsupportedNidSuppression("unsupported wire-only loading profile")


def _ce_raw(parsed_nid: NidPayload) -> bytes:
    if not isinstance(parsed_nid, NidPayload):
        raise TypeError("a parsed NidPayload is required")
    if parsed_nid.type_byte != NID64_TYPE or len(parsed_nid.raw) < 9:
        raise UnsupportedNidNamespace("bridge requires raw typeCE framing")
    return parsed_nid.raw


def no_tail_nid64_runtime_entry(
    parsed_nid: NidPayload,
    *,
    caller_threat_id: int,
    namespace: NoTailNameSnapshot,
) -> Nid64RuntimeEntry:
    """Associate exact9 generic CE with raw parent bytes/NULL, preserving high bits.

    No-tail receiver stores caller sig directly; this name-value output does not
    contain that sig and does not impose createrecid's named-tail 20-bit bound.
    """
    raw = _ce_raw(parsed_nid)
    if len(raw) != 9:
        raise UnsupportedNidNamespace("bridge requires exactly nine no-tail CE bytes")
    if not isinstance(namespace, NoTailNameSnapshot):
        raise TypeError("an explicit NoTailNameSnapshot is required")
    return Nid64RuntimeEntry(
        int.from_bytes(raw[:8], "little"),
        raw[8],
        namespace.runtime_name(caller_threat_id),
    )


def named_tail_nid64_runtime_entry(
    parsed_nid: NidPayload,
    *,
    caller_threat_id: int,
    caller_sig_id: int,
    profile: NamedTailNameProfile,
    parent_namespace: NoTailNameSnapshot | None = None,
) -> Nid64RuntimeEntry:
    """Associate generic CE via the verified flags0 mini name-value projection.

    The original createrecidz chain has the same bounded span/first-NUL parent
    fallback as NID4. High-bit bytes stay raw; generated IDs are not reconstructed.
    """
    raw = _ce_raw(parsed_nid)
    if len(raw) == 9:
        raise UnsupportedNidNamespace("bridge requires a nonempty CE tail")
    name = _named_tail_runtime_name(
        raw[9:],
        caller_threat_id=caller_threat_id,
        caller_sig_id=caller_sig_id,
        profile=profile,
        parent_namespace=parent_namespace,
    )
    return Nid64RuntimeEntry(int.from_bytes(raw[:8], "little"), raw[8], name)


def empty108_snapshot_from_wire(
    base_records: tuple[NidPayload, ...],
    delta_records: tuple[NidPayload, ...],
    *,
    profile: WireOnlyEmpty108Profile,
) -> Nid64LookupSnapshot:
    """Validate a complete caller-selected wire projection with no CE108 records.

    The returned view supports only selector108 queries. Nonempty effective delta
    or any CE108 record is unsupported: those require real runtime-name snapshots.
    Other CE selectors are checked as wire input then explicitly outside this view.
    Completeness and absence of other producers are explicit profile assertions;
    an isolated VDM record or a corpus count cannot prove them.
    """
    if not isinstance(profile, WireOnlyEmpty108Profile):
        raise TypeError("an explicit WireOnlyEmpty108Profile is required")
    if not isinstance(base_records, tuple) or not isinstance(delta_records, tuple):
        raise TypeError("wire projections must be explicit tuples of CE records")
    for parsed_nid in base_records + delta_records:
        try:
            raw = _ce_raw(parsed_nid)
        except UnsupportedNidNamespace as exc:
            raise UnsupportedNidSuppression(
                "wire projection requires valid CE framing only"
            ) from exc
        if raw[8] == 108:
            raise UnsupportedNidSuppression("wire CE108 needs a runtime-name snapshot")
    if delta_records:
        raise UnsupportedNidSuppression(
            "wire-only empty108 profile requires empty delta"
        )
    return Nid64LookupSnapshot((), (), metadata_view="selector108")
