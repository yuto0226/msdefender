"""Conditional OEP callback requests; no mapper, byte source or scan verdict."""

from dataclasses import dataclass
from typing import Literal

from .types.kcrce import KcrcePayload, parse_kcrce


def _uint(value: int, bits: int, label: str) -> None:
    if type(value) is not int or not 0 <= value < (1 << bits):
        raise ValueError(f"{label} must be an unsigned {bits}-bit integer")


@dataclass(frozen=True, slots=True)
class KcrceOepContext:
    """Externally supplied callback identity and opaque same-epoch mapper profile.

    candidate is the caller's mapping coordinate, never an inferred disk OEP.
    Neither the epoch nor mapper_profile asserts a successful mapping snapshot.
    None explicitly represents missing callback identity/kind/candidate.
    """

    callback_family: Literal["oepkcrc_callback"] | None
    kind: int | None
    candidate: int | None
    callback_mode: int
    epoch: str
    mapper_profile: str

    def __post_init__(self) -> None:
        if self.callback_family not in (None, "oepkcrc_callback"):
            raise ValueError("callback_family must be oepkcrc_callback or None")
        if self.kind is not None:
            _uint(self.kind, 32, "kind")
        if self.candidate is not None:
            _uint(self.candidate, 64, "candidate")
        _uint(self.callback_mode, 32, "callback_mode")
        if self.callback_mode not in (0, 1, 2):
            raise ValueError("callback_mode must be 0, 1 or 2")
        for label in ("epoch", "mapper_profile"):
            value = getattr(self, label)
            if type(value) is not str or not value:
                raise ValueError(f"{label} must be a nonempty opaque string")


@dataclass(frozen=True, slots=True)
class KcrceOepRequest:
    context: KcrceOepContext
    packed_low28: int
    status: Literal["projected", "unknown", "unsupported"]
    reason: str | None
    direction: Literal["backward", "forward"] | None
    start: int | None
    length: int | None
    requests_mapping: bool | None
    skipped_adddata_reason: str | None
    map_flags: int | None
    # These describe execution branches, not side effects of this projector.
    callback_entry_writes: tuple[tuple[str, int], ...]
    mapping_null_writes: tuple[tuple[str, int], ...]
    mapping_success_adddata_length: int | None
    mapping_outcome: Literal["unknown", "not_requested"]


def project_kcrce_oep_request(
    record: KcrcePayload, context: KcrceOepContext
) -> KcrceOepRequest:
    """Project the saved kind0/1 source recipe with exact u64 ADD/SUB.

    Requesting a map says nothing about mapped bytes or AddData execution. Zero
    count and wrapping requests still reach the mapper in the analyzed branches.
    """
    if not isinstance(record, KcrcePayload):
        raise TypeError("record must be a parsed KcrcePayload")
    if not isinstance(record.raw, bytes):
        raise TypeError("record.raw must be immutable bytes")
    if not isinstance(context, KcrceOepContext):
        raise TypeError("context must be a KcrceOepContext")
    packed = parse_kcrce(record.raw).length_flags & 0x0FFFFFFF
    status = "projected"
    reason = None
    direction = None
    start = length = None
    requests = None
    skipped = None
    flags = None
    entry = null = ()
    success_length = None
    outcome = "unknown"
    if context.callback_family is None:
        status, reason = "unknown", "callback_family_unknown"
    elif context.kind is None:
        status, reason = "unknown", "kind_unknown"
    elif context.kind not in (0, 1):
        status, reason = "unsupported", "kind_not_supported"
    else:
        entry = (("userdata+0x85", 0), ("pe+0x83fd0", 1))
        direction = "backward" if context.kind == 0 else "forward"
        if context.callback_mode == 0:
            skipped = "mode0_no_adddata"
        elif context.kind == 0 and context.callback_mode == 2 and packed >> 16:
            skipped = "kind0_nonzero_offset"
        else:
            length = 0x100 if context.callback_mode == 1 else packed & 0xFFFF
            requests = True
            flags = 0x40000000
            null = (("userdata+0x85", 1),)
            success_length = length
            if context.candidate is None:
                status, reason = "unknown", "candidate_unknown"
            elif context.kind == 0:
                start = (context.candidate - length) & 0xFFFFFFFFFFFFFFFF
            else:
                offset = 0 if context.callback_mode == 1 else packed >> 16
                start = (context.candidate + offset) & 0xFFFFFFFFFFFFFFFF
        if skipped is not None:
            requests, outcome = False, "not_requested"
    return KcrceOepRequest(
        context,
        packed,
        status,
        reason,
        direction,
        start,
        length,
        requests,
        skipped,
        flags,
        entry,
        null,
        success_length,
        outcome,
    )


@dataclass(frozen=True, slots=True)
class KcrceOepFreshCrc2:
    """Fresh-reset local stage2 projection, never a Lookup or final result."""

    status: Literal["projected", "unknown", "unsupported"]
    crc2: int | None
    record_local_crc2_match: bool | None
    reason: str


def project_kcrce_oep_fresh_crc2(
    record: KcrcePayload, context: KcrceOepContext
) -> KcrceOepFreshCrc2:
    """Assume a fresh get_crc2 Reset and project only proven no-AddData.

    The callback is void: get_crc2 caches the reset value and marks ready even
    when mode2 skips AddData. Unknown map outcome cannot establish this case.
    """
    request = project_kcrce_oep_request(record, context)
    if context.callback_mode != 2:
        raise ValueError("fresh CRC2 projection requires callback_mode 2")
    if request.status == "unsupported":
        return KcrceOepFreshCrc2("unsupported", None, None, request.reason)
    if request.requests_mapping is False:
        parsed = parse_kcrce(record.raw)
        return KcrceOepFreshCrc2(
            "projected",
            0xFFFFFFFF,
            parsed.crc2 == 0xFFFFFFFF,
            "fresh_reset_no_adddata; local_stage2_only",
        )
    return KcrceOepFreshCrc2(
        "unknown", None, None, request.reason or "mapping_outcome_unknown"
    )
