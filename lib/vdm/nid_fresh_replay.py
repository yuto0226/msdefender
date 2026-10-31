"""Fresh NID4-only generation and ordered row-name projection from wire events.

This is not a full VDM/cache/engine loader. A fixed explicit profile asserts fresh
map/counters, successful normal immutable storage and no other generation producer
or namespace shadow. The name/chunk result is a projection after successful mini
namespace publication and NID PostProcess/RecID range publication. Merely setting
threats_loaded does not establish either success. Physical OIDs/outer RecIDs and raw post-sort sig/tie order are
not reproduced. Unsupported input returns no snapshot; it does not imply that an
original failed engine epoch was rolled back or can safely be continued.
"""

from dataclasses import dataclass
from typing import Final, Literal

from .nid_named_namespace import (
    NAMED_MINI_NAME_PROFILE,
    NamedTailNameProfile,
    named_tail_nid_runtime_entry,
)
from .nid_namespace import (
    NoTailNameSnapshot,
    UnsupportedNidNamespace,
    no_tail_nid_runtime_entry,
)
from .snid_resolver import NidRuntimeEntry
from .types.nid import NID_TYPE, NidPayload
from .types.threat import MAGIC_THREAT_IDS, parse_threat_begin

FRESH_NID4_REPLAY_PROFILE: Final = (
    "mpengine-1.443.903.0.fresh-nid4-only.normal-store.successful-consistent-no-shadow"
)
_CHUNK_ROWS: Final = 0x1000000


class UnsupportedNid4Replay(ValueError):
    """The events or loading state are outside the fresh successful profile."""


def _u32(value: int, label: str) -> None:
    if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
        raise ValueError(f"{label} must be an unsigned 32-bit integer")


@dataclass(frozen=True, slots=True)
class Nid4FreshReplayProfile:
    """Explicit fresh epoch, not the effect of Receivers_New_Init alone.

    InternalIdMap starts empty, AS/AV counters at 0x10000000/0x90000000. No other
    createrecid/Generate/map mutation or mid-epoch reset is allowed. All relevant
    generation events must be supplied in original arrival order, including every
    NID4 selector. Arbitrarily filtering NID4 from a full VDM load does not prove
    that other families performed no generation. Existing mini/full shadows and
    unknown cache/alternate-store/override history are excluded.

    table-present requires a well-formed complete normal intern table, immutable
    OIDs/bytes and successful insertion/rehash, with no eviction or table mutation.
    Harmless allocations can shift numeric OIDs, but must preserve this equality.
    table-absent means normal flags0 always copies to a fresh immutable identity.
    Both modes assert successful object/mini/outer allocation and registration,
    successful threat_info_end mini/full namespace publication, and successful
    NID PostProcess/RecID range publication. The fixed namespace profile has zero
    dependencies, no latent work, and successfully preloaded builtin entries;
    full/mini IDs and immutable names are consistent and unshadowed. This pure
    projection does not invoke the original publisher, allocator or OS. Its
    threats_loaded input describes parent-name resolution during arrival, not
    a substitute for the publication success asserted by this profile.
    """

    kind: Literal[
        "mpengine-1.443.903.0.fresh-nid4-only.normal-store.successful-consistent-no-shadow"
    ]
    interning: Literal["table-present", "table-absent"]
    threats_loaded: bool

    def __post_init__(self) -> None:
        if self.kind != FRESH_NID4_REPLAY_PROFILE:
            raise UnsupportedNid4Replay("unsupported fresh generation profile")
        if self.interning not in ("table-present", "table-absent"):
            raise UnsupportedNid4Replay("normal intern-table mode must be explicit")
        if type(self.threats_loaded) is not bool:
            raise TypeError("threats_loaded must be explicitly true or false")


@dataclass(frozen=True, slots=True)
class Nid4WireEvent:
    """One original type55 RecordPush input, not a supplied generated identity."""

    record: NidPayload
    caller_threat_id: int
    caller_sig_id: int

    def __post_init__(self) -> None:
        if not isinstance(self.record, NidPayload):
            raise TypeError("record must be a parsed NidPayload")
        if self.record.type_byte != NID_TYPE or len(self.record.raw) < 5:
            raise UnsupportedNid4Replay("fresh replay accepts type55 wire events only")
        _u32(self.caller_threat_id, "caller threat ID")
        _u32(self.caller_sig_id, "caller signature ID")


@dataclass(frozen=True, slots=True)
class Nid4StoredRow:
    """Arrival-order stored fields, before native raw PostProcess tie reordering."""

    entry: NidRuntimeEntry
    stored_threat_id: int
    entry_sig_id: int


@dataclass(frozen=True, slots=True)
class Nid4FreshReplayResult:
    stored_rows: tuple[Nid4StoredRow, ...]
    chunks: tuple[tuple[NidRuntimeEntry, ...], ...]
    next_as_threat_id: int
    next_av_threat_id: int


def _generated_id_allowed(identifier: int, *, av: bool, protected: set[int]) -> None:
    if identifier > 0xFFFFFFFF or (not av and identifier >= 0x80000000):
        raise UnsupportedNid4Replay("generated threat counter would cross its domain")
    if (
        identifier in protected
        or identifier in MAGIC_THREAT_IDS
        or 0x7FFE0000 <= identifier <= 0x7FFE9FFF
        or 0x7FFF0000 <= identifier <= 0x7FFF9FFF
    ):
        raise UnsupportedNid4Replay(
            "generated threat ID collides with a namespace/sentinel"
        )


def replay_fresh_nid4(
    events: tuple[Nid4WireEvent, ...],
    *,
    profile: Nid4FreshReplayProfile,
    namespace: NoTailNameSnapshot | None = None,
) -> Nid4FreshReplayResult:
    """Derive stored IDs/sig fields and normalized name/status chunks.

    Caller IDs/sigs remain original receiver inputs; there is no OID, initial
    counter or map input. Bounded raw spans supply the normal interning equivalence
    only within the explicit profile. First-NUL/no-tail parent names use the raw
    direct-full snapshot, preserving NULL versus empty and never display strings.

    Arrival chunks are cut at the receiver's 2**24 boundary before each chunk is
    sorted by key, selector and descending stored ID. Equivalent triples have the
    same immutable resolved name, so this value projection is independent of raw
    sig/padding tie permutations. No raw stable-sort or physical RecID claim is made.
    Callers explicitly place result.chunks into base/delta with a suppression view.
    """
    if not isinstance(profile, Nid4FreshReplayProfile):
        raise TypeError("an explicit Nid4FreshReplayProfile is required")
    if not isinstance(events, tuple) or any(
        not isinstance(event, Nid4WireEvent) for event in events
    ):
        raise TypeError("events must be an ordered tuple of Nid4WireEvent")
    if namespace is not None:
        if not isinstance(namespace, NoTailNameSnapshot):
            raise TypeError("namespace must be a NoTailNameSnapshot or None")
        if namespace.profile.threats_loaded != profile.threats_loaded:
            raise UnsupportedNid4Replay("namespace and replay loaded states differ")

    protected = {event.caller_threat_id for event in events}
    if namespace is not None:
        protected.update(
            parse_threat_begin(begin.raw).threat_id for begin in namespace.threat_begins
        )
    named_profile = NamedTailNameProfile(
        NAMED_MINI_NAME_PROFILE, profile.threats_loaded
    )
    as_counter, av_counter = 0x10000000, 0x90000000
    identities: dict[bytes, tuple[int, int]] = {}
    names_by_id: dict[int, bytes | None] = {}
    rows: list[Nid4StoredRow] = []
    for event in events:
        raw = event.record.raw
        tail = raw[5:]
        try:
            if not tail:
                if namespace is None:
                    raise UnsupportedNid4Replay(
                        "no-tail event requires a parent namespace"
                    )
                entry = no_tail_nid_runtime_entry(
                    event.record,
                    caller_threat_id=event.caller_threat_id,
                    namespace=namespace,
                )
            else:
                entry = named_tail_nid_runtime_entry(
                    event.record,
                    caller_threat_id=event.caller_threat_id,
                    caller_sig_id=event.caller_sig_id,
                    profile=named_profile,
                    parent_namespace=namespace,
                )
        except UnsupportedNidNamespace as exc:
            raise UnsupportedNid4Replay(str(exc)) from exc

        stored_id, sig_id = event.caller_threat_id, event.caller_sig_id
        if tail and tail[0] != 0:
            # The name factory already requires a bounded NUL and ASCII content.
            span = tail[: tail.index(0) + 1]
            interned = profile.interning == "table-present" and len(span) <= 4096
            existing = identities.get(span) if interned else None
            if existing is not None:
                stored_id, previous_sig = existing
                sig_id = previous_sig + 1
                if sig_id > 0xFFFFF:
                    raise UnsupportedNid4Replay(
                        "generated signature counter exceeds 20 bits"
                    )
            else:
                av = event.caller_threat_id >= 0x80000000
                stored_id = av_counter if av else as_counter
                _generated_id_allowed(stored_id, av=av, protected=protected)
                if av:
                    av_counter += 1
                else:
                    as_counter += 1
                sig_id = 0
            if interned:
                identities[span] = (stored_id, sig_id)
        if stored_id in names_by_id and names_by_id[stored_id] != entry.runtime_name:
            raise UnsupportedNid4Replay("stored ID has inconsistent runtime names")
        names_by_id[stored_id] = entry.runtime_name
        rows.append(Nid4StoredRow(entry, stored_id, sig_id))

    chunks = tuple(
        tuple(
            row.entry
            for row in sorted(
                rows[start : start + _CHUNK_ROWS],
                key=lambda row: (
                    row.entry.key,
                    row.entry.selector,
                    -row.stored_threat_id,
                ),
            )
        )
        for start in range(0, len(rows), _CHUNK_ROWS)
    )
    return Nid4FreshReplayResult(tuple(rows), chunks, as_counter, av_counter)
