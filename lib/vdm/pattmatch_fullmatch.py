"""Pure Q full-match/cohort projection under an immutable loaded-index profile.

Provider calls, bsearch, sorting and report policy do not execute. Each external
callback observation belongs to the fixed libmatch_callback normal-return
profile. Index order and the valid bsearch anchor are explicit premises; no
stable ordering of equal comparator rows is inferred. Candidate buffers are
per-call facts and are never copied from the prematch producer implicitly.
"""

from dataclasses import dataclass, field
from typing import Literal

from .types.pattmatch import PattMatchPayload, parse_pattmatch


class PattFullMatchSnapshotError(ValueError):
    """Malformed facts or facts outside the named immutable normal profile."""


def _uint(value: int, bits: int) -> None:
    if type(value) is not int or not 0 <= value < 1 << bits:
        raise PattFullMatchSnapshotError(f"uint{bits} required")


def _identity(value: bytes) -> None:
    if type(value) is not bytes or not value:
        raise PattFullMatchSnapshotError("nonempty immutable identity required")


@dataclass(frozen=True, slots=True)
class PattQBinding:
    invocation_id: str
    epoch: str
    index_identity: bytes

    def __post_init__(self) -> None:
        if any(type(v) is not str or not v for v in (self.invocation_id, self.epoch)):
            raise PattFullMatchSnapshotError("explicit invocation and epoch required")
        _identity(self.index_identity)


@dataclass(frozen=True, slots=True)
class PattQEntry:
    """Normal loaded wire fields and a separately supplied physical code window.

    Metadata, code pointer/content and expected CRC remain immutable across the
    callback in this profile. Physical bytes start at code_base, including the
    key. Missing bytes are unknown. Extra bytes can describe known readable
    memory following the stored record; they are never fabricated from padding.
    Reached bytes within the stored record must agree with the original wire.
    """

    binding: PattQBinding
    entry_identity: bytes
    raw_payload: bytes
    physical_code: bytes | None
    parsed: PattMatchPayload = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if type(self.binding) is not PattQBinding:
            raise PattFullMatchSnapshotError("entry binding required")
        _identity(self.entry_identity)
        if type(self.raw_payload) is not bytes:
            raise PattFullMatchSnapshotError("immutable raw payload required")
        if self.physical_code is not None and type(self.physical_code) is not bytes:
            raise PattFullMatchSnapshotError("immutable physical code required")
        try:
            parsed = parse_pattmatch(self.raw_payload)
        except ValueError as exc:
            raise PattFullMatchSnapshotError(str(exc)) from exc
        object.__setattr__(self, "parsed", parsed)


@dataclass(frozen=True, slots=True)
class PattQCallback:
    """Actual normally returned fixed-wrapper observation for one entry attempt.

    Non-NULL implies returned_size=requested_size in the installed wrapper;
    a supplied contradictory size is an error. An omitted size is projected
    from that invariant, not from a provider execution. NULL skips the body,
    retaining any actual provider-written size without using it as a gate.
    """

    binding: PattQBinding
    entry_identity: bytes
    attempt_ordinal: int
    requested_size: int
    provider_nonnull: bool | None
    observed_returned_size: int | None
    physical_bytes: bytes | None

    def __post_init__(self) -> None:
        if type(self.binding) is not PattQBinding:
            raise PattFullMatchSnapshotError("callback binding required")
        _identity(self.entry_identity)
        _uint(self.attempt_ordinal, 32)
        _uint(self.requested_size, 32)
        if (
            self.provider_nonnull is not None
            and type(self.provider_nonnull) is not bool
        ):
            raise PattFullMatchSnapshotError("provider result must be bool or unknown")
        if self.observed_returned_size is not None:
            _uint(self.observed_returned_size, 32)
        if self.physical_bytes is not None and type(self.physical_bytes) is not bytes:
            raise PattFullMatchSnapshotError("immutable candidate bytes required")


@dataclass(frozen=True, slots=True)
class PattQRequest:
    binding: PattQBinding
    entry_identity: bytes
    attempt_ordinal: int
    requested_size: int


@dataclass(frozen=True, slots=True)
class PattQRead:
    domain: Literal["code", "candidate"]
    offset: int
    size: int


@dataclass(frozen=True, slots=True)
class PattQSegment:
    """A complete-length CRC request; absent data/state_after means unreadable."""

    candidate_offset: int
    length: int
    state_before: int
    data: bytes | None
    state_after: int | None


@dataclass(frozen=True, slots=True)
class PattQEntryResult:
    outcome: Literal["matched", "missed", "unknown"]
    reason: str
    request: PattQRequest
    effective_returned_size: int | None
    raw_crc_state: int | None
    crc_equal: bool | None
    code_cursor: int
    nibble_phase: int
    candidate_offset: int
    last_length: int | None
    logical_zero_reads: tuple[int, ...]
    segments: tuple[PattQSegment, ...]
    pending_read: PattQRead | None


def _crc0_update(state: int, data: bytes) -> int:
    # CRC_0's reflected raw accumulator; no final XOR and no seed conversion.
    for value in data:
        state ^= value
        for _ in range(8):
            state = (state >> 1) ^ (0xEDB88320 if state & 1 else 0)
    return state


class _MissingRead(Exception):
    def __init__(self, read: PattQRead) -> None:
        self.read = read


def evaluate_pattmatch_q_entry(
    entry: PattQEntry,
    callback: PattQCallback | None,
    *,
    attempt_ordinal: int = 0,
) -> PattQEntryResult:
    """Apply the source-ordered Q body without invoking external services.

    The source probes the raw sentinel before candidate bounds or the codec's
    logical-size test. Logical exhaustion returns zero nibbles without reads;
    a missing reached physical byte is unknown. Positive segments are read and
    CRC'd in full before the requested-size end check, with no clipping/padding.
    """
    if type(entry) is not PattQEntry:
        raise PattFullMatchSnapshotError("Q entry required")
    if callback is not None and type(callback) is not PattQCallback:
        raise PattFullMatchSnapshotError("Q callback observation required")
    _uint(attempt_ordinal, 32)
    size = entry.parsed.requested_callback_size
    request = PattQRequest(entry.binding, entry.entry_identity, attempt_ordinal, size)
    cursor = 8
    phase = 0
    candidate_offset = 0
    state: int | None = None
    returned: int | None = None
    last_length: int | None = None
    logical_zeros: list[int] = []
    segments: list[PattQSegment] = []

    def result(
        outcome: Literal["matched", "missed", "unknown"],
        reason: str,
        equal: bool | None = None,
        pending: PattQRead | None = None,
    ) -> PattQEntryResult:
        return PattQEntryResult(
            outcome,
            reason,
            request,
            returned,
            state,
            equal,
            cursor,
            phase,
            candidate_offset,
            last_length,
            tuple(logical_zeros),
            tuple(segments),
            pending,
        )

    if callback is None:
        return result("unknown", "callback_observation_missing")
    if (
        callback.binding != entry.binding
        or callback.entry_identity != entry.entry_identity
        or callback.attempt_ordinal != attempt_ordinal
        or callback.requested_size != size
    ):
        raise PattFullMatchSnapshotError("reached callback binding mismatch")
    if callback.provider_nonnull is None:
        return result("unknown", "callback_pointer_unknown")
    if not callback.provider_nonnull:
        returned = callback.observed_returned_size
        return result("missed", "callback_returned_null")
    if (
        callback.observed_returned_size is not None
        and callback.observed_returned_size != size
    ):
        raise PattFullMatchSnapshotError(
            "non-NULL fixed-wrapper size must equal request"
        )
    returned = size
    state = 0xFFFFFFFF
    wire_code = entry.parsed.opcode_key + entry.parsed.nibble_stream_raw

    def read_code(offset: int) -> int:
        if entry.physical_code is None or offset >= len(entry.physical_code):
            raise _MissingRead(PattQRead("code", offset, 1))
        value = entry.physical_code[offset]
        if offset < len(wire_code) and value != wire_code[offset]:
            raise PattFullMatchSnapshotError("reached loaded code disagrees with wire")
        return value

    def get_nibble() -> int:
        nonlocal cursor, phase
        if cursor >= size:
            logical_zeros.append(cursor)
            return 0
        value = read_code(cursor)
        nibble = (value >> 4) & 15 if phase else value & 15
        if phase:
            cursor += 1
            phase = 0
        else:
            phase = 1
        return nibble

    try:
        while True:
            if read_code(cursor) == 0x90 and read_code(cursor + 1) == 0:
                reason = "raw_90_00_sentinel"
                break
            if candidate_offset >= returned:
                reason = "candidate_offset_at_returned_size"
                break
            # decodelen itself returns before calling get_nibble at entry end.
            if cursor >= size:
                last_length = 0
                reason = "length_zero_at_logical_code_end"
                break
            logical_before = len(logical_zeros)
            opcode = get_nibble()
            if opcode <= 7:
                length = opcode
            elif opcode <= 11:
                length = 16 * (opcode & 3) + get_nibble()
            elif opcode <= 13:
                high = get_nibble()
                length = 256 * (opcode & 1) + 16 * high + get_nibble()
            else:
                length = 0
            last_length = length
            if length == 0:
                reason = (
                    "length_zero_at_logical_code_end"
                    if len(logical_zeros) > logical_before
                    else "decoded_length_zero"
                )
                break
            data = callback.physical_bytes
            if data is None or candidate_offset + length > len(data):
                segments.append(
                    PattQSegment(candidate_offset, length, state, None, None)
                )
                raise _MissingRead(PattQRead("candidate", candidate_offset, length))
            chunk = data[candidate_offset : candidate_offset + length]
            after = _crc0_update(state, chunk)
            segments.append(PattQSegment(candidate_offset, length, state, chunk, after))
            state = after
            candidate_offset = (candidate_offset + length) & 0xFFFFFFFF
            if candidate_offset >= size:
                reason = "segment_end_at_requested_size"
                break
            candidate_offset = (candidate_offset + 4) & 0xFFFFFFFF
    except _MissingRead as exc:
        return result("unknown", "reached_physical_bytes_unavailable", pending=exc.read)
    equal = state == entry.parsed.expected_crc
    return result("matched" if equal else "missed", reason, equal)


@dataclass(frozen=True, slots=True)
class PattQIndex:
    """Complete actual ordered Q index and a valid externally observed anchor.

    Normal readable key snapshots, immutable loaded entries and actual engine
    sorting are premises. This validates identities/bindings and key contiguity,
    not the full comparator or qsort stability. No index is sorted here.
    """

    binding: PattQBinding
    entries: tuple[PattQEntry, ...]
    anchor_index: int

    def __post_init__(self) -> None:
        if type(self.binding) is not PattQBinding:
            raise PattFullMatchSnapshotError("index binding required")
        if (
            type(self.entries) is not tuple
            or not self.entries
            or any(type(entry) is not PattQEntry for entry in self.entries)
        ):
            raise PattFullMatchSnapshotError(
                "complete nonempty immutable index required"
            )
        _uint(len(self.entries), 32)
        _uint(self.anchor_index, 32)
        if self.anchor_index >= len(self.entries):
            raise PattFullMatchSnapshotError("anchor outside actual index")
        identities: set[bytes] = set()
        closed_keys: set[bytes] = set()
        previous: bytes | None = None
        for entry in self.entries:
            if entry.binding != self.binding or entry.entry_identity in identities:
                raise PattFullMatchSnapshotError(
                    "index binding or unique identity violated"
                )
            identities.add(entry.entry_identity)
            key = entry.parsed.opcode_key
            if key != previous:
                if key in closed_keys:
                    raise PattFullMatchSnapshotError(
                        "same-key index rows are not contiguous"
                    )
                if previous is not None:
                    closed_keys.add(previous)
            previous = key


@dataclass(frozen=True, slots=True)
class PattQCohortResult:
    outcome: Literal["selected", "no_match", "unknown"]
    reason: str
    anchor_index: int
    run_start_index: int
    selected_index: int | None
    selected_entry_identity: bytes | None
    attempted_indices: tuple[int, ...]
    attempt_count: int
    entry_results: tuple[PattQEntryResult, ...]


def select_pattmatch_q_cohort(
    index: PattQIndex, callbacks: tuple[PattQCallback, ...]
) -> PattQCohortResult:
    """Backwalk the supplied key run and return its first definite CRC success.

    A prior unknown prevents selecting a later row. Callback facts are consumed
    in actual attempt order, not array-slot order. Later unused facts need no
    semantic binding. No search hit, stable tie order or final verdict is added.
    """
    if type(index) is not PattQIndex:
        raise PattFullMatchSnapshotError("actual Q index required")
    if type(callbacks) is not tuple or any(
        type(c) is not PattQCallback for c in callbacks
    ):
        raise PattFullMatchSnapshotError(
            "ordered immutable callback observations required"
        )

    def same_key(left: PattQEntry, right: PattQEntry) -> bool:
        # The index profile supplies normal readable key snapshots. Any known
        # physical prefix must agree when this comparator is actually reached.
        for entry in (left, right):
            physical = entry.physical_code
            if (
                physical is not None
                and physical[:8] != entry.parsed.opcode_key[: len(physical[:8])]
            ):
                raise PattFullMatchSnapshotError(
                    "reached physical index key conflicts with snapshot"
                )
        return left.parsed.opcode_key == right.parsed.opcode_key

    start = index.anchor_index
    while start and same_key(index.entries[start], index.entries[start - 1]):
        start -= 1
    attempts: list[int] = []
    results: list[PattQEntryResult] = []

    def result(
        outcome: Literal["selected", "no_match", "unknown"],
        reason: str,
        selected: int | None = None,
    ) -> PattQCohortResult:
        return PattQCohortResult(
            outcome,
            reason,
            index.anchor_index,
            start,
            selected,
            None if selected is None else index.entries[selected].entry_identity,
            tuple(attempts),
            len(attempts),
            tuple(results),
        )

    current = start
    while True:
        ordinal = len(attempts)
        attempts.append(current)
        callback = callbacks[ordinal] if ordinal < len(callbacks) else None
        evaluated = evaluate_pattmatch_q_entry(
            index.entries[current], callback, attempt_ordinal=ordinal
        )
        results.append(evaluated)
        if evaluated.outcome == "unknown":
            return result("unknown", "earlier_entry_outcome_unknown")
        if evaluated.outcome == "matched":
            return result("selected", "first_crc_success_in_actual_order", current)
        following = current + 1
        if following >= len(index.entries):
            return result("no_match", "actual_index_ended")
        if not same_key(index.entries[current], index.entries[following]):
            return result("no_match", "same_key_run_ended")
        current = following
