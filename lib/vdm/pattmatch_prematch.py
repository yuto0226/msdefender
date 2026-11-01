"""Pure Q prematch raw-key assembly from external decoder observations.

No provider or decoder executes here. A normal-return dgetlen_x86 observation
is an external premise, not evidence that its internal physical reads succeeded.
The known byte window starts at the provider's returned pointer; its length is
neither the callback's nominal returned size nor a required 32-byte allocation.
"""

from dataclasses import dataclass
from typing import Final, Literal

PREMATCH_PROFILE: Final = "pattmatch_q_get_prematch_18022DB40"
DECODER_PROFILE: Final = "dgetlen_x86_18025120C_normal_return"


class PattPrematchSnapshotError(ValueError):
    """Malformed facts or facts inconsistent with the named source profile."""


def _uint(value: int, bits: int) -> None:
    if type(value) is not int or not 0 <= value < 1 << bits:
        raise PattPrematchSnapshotError(f"uint{bits} required")


def _optional_uint(value: int | None, bits: int) -> None:
    if value is not None:
        _uint(value, bits)


@dataclass(frozen=True, slots=True)
class PattPrematchBinding:
    """Exact invocation and known physical-image binding, not engine identity.

    physical_bytes is a known immutable contiguous window from offset zero.
    None means no physical bytes were supplied; no tail is padded or inferred.
    An observation binds this same window without claiming it covers all reads
    performed internally by the external original decoder.
    """

    invocation_id: str
    epoch: str
    candidate_identity: bytes
    physical_bytes: bytes | None

    def __post_init__(self) -> None:
        if any(type(v) is not str or not v for v in (self.invocation_id, self.epoch)):
            raise PattPrematchSnapshotError("nonempty invocation and epoch required")
        if type(self.candidate_identity) is not bytes or not self.candidate_identity:
            raise PattPrematchSnapshotError("immutable candidate identity required")
        if self.physical_bytes is not None and type(self.physical_bytes) is not bytes:
            raise PattPrematchSnapshotError("immutable physical bytes required")


@dataclass(frozen=True, slots=True)
class PattDecodeObservation:
    """Actual normal-return EAX observation for one original decoder call.

    The raw uint32 EAX is interpreted as signed int32 by get_prematch. Unknown
    observations have result_bits=None. There is no decoder-success boolean.
    """

    binding: PattPrematchBinding
    ordinal: int
    input_offset: int
    declared_size: int
    mode_flags: int
    result_bits: int | None
    profile: str = DECODER_PROFILE

    def __post_init__(self) -> None:
        if type(self.binding) is not PattPrematchBinding:
            raise PattPrematchSnapshotError("decoder binding required")
        for value in (
            self.ordinal,
            self.input_offset,
            self.declared_size,
            self.mode_flags,
        ):
            _uint(value, 32)
        _optional_uint(self.result_bits, 32)
        if type(self.profile) is not str or self.profile != DECODER_PROFILE:
            raise PattPrematchSnapshotError("unsupported decoder observation profile")


@dataclass(frozen=True, slots=True)
class PattPrematchSnapshot:
    """Normal-pointer Q caller facts, separate from record or sorted-index data.

    provider_out_size is the actual out-size value *after* the provider returns,
    including any provider write. None is unknown, not an implicit no-write/zero.
    The wrapper overwrites it with 256 only on non-NULL provider return.
    NULL-result projection needs no mode value; this does not erase the source's
    earlier context read or claim to be a full wrapper read trace.
    """

    binding: PattPrematchBinding
    provider_nonnull: bool | None
    context_mode_bits: int | None
    provider_out_size: int | None
    decoder_observations: tuple[PattDecodeObservation, ...]
    profile: str = PREMATCH_PROFILE

    def __post_init__(self) -> None:
        if type(self.binding) is not PattPrematchBinding:
            raise PattPrematchSnapshotError("prematch binding required")
        if (
            self.provider_nonnull is not None
            and type(self.provider_nonnull) is not bool
        ):
            raise PattPrematchSnapshotError("provider result must be bool or unknown")
        _optional_uint(self.context_mode_bits, 32)
        _optional_uint(self.provider_out_size, 32)
        if type(self.decoder_observations) is not tuple or any(
            type(step) is not PattDecodeObservation
            for step in self.decoder_observations
        ):
            raise PattPrematchSnapshotError(
                "ordered immutable decoder observations required"
            )
        if type(self.profile) is not str or self.profile != PREMATCH_PROFILE:
            raise PattPrematchSnapshotError(
                "only the named Q prematch profile is supported"
            )


@dataclass(frozen=True, slots=True)
class PattDecodeRequest:
    ordinal: int
    input_offset: int
    declared_size: int
    mode_flags: int | None
    known_input_prefix: bytes


@dataclass(frozen=True, slots=True)
class PattPrematchResult:
    """Projection only; key_ready permits search, never asserts a search hit.

    key_prefix includes the byte written before a failed or unknown decoder
    call. Requests are reached/conditional source requests, not executed calls.
    The full key exists only after all eight positive decoder results.
    """

    outcome: Literal["key_ready", "prematch_failed", "unknown"]
    reason: str
    key: bytes | None
    key_prefix: bytes
    instruction_offsets: tuple[int, ...]
    positive_lengths: tuple[int, ...]
    decoder_requests: tuple[PattDecodeRequest, ...]
    failed_decode_result: int | None
    callback_returned_size: int | None
    decoder_mode: int | None


def project_pattmatch_q_prematch(snapshot: PattPrematchSnapshot) -> PattPrematchResult:
    """Assemble raw instruction-first-byte key using source-ordered lazy facts.

    Missing facts produce unknown with the proven prefix. Reached contradictory
    input/epoch/ordinal/mode/size bindings raise PattPrematchSnapshotError; they
    are not prematch misses. Later unused observations are not consumed.
    """
    if type(snapshot) is not PattPrematchSnapshot:
        raise PattPrematchSnapshotError("prematch snapshot required")
    binding = snapshot.binding
    mode = (
        None
        if snapshot.context_mode_bits is None
        else (snapshot.context_mode_bits & 1) + 1
    )
    prefix = bytearray()
    offsets: list[int] = []
    lengths: list[int] = []
    requests: list[PattDecodeRequest] = []
    returned_size = None

    def result(
        outcome: Literal["key_ready", "prematch_failed", "unknown"],
        reason: str,
        failed: int | None = None,
    ) -> PattPrematchResult:
        return PattPrematchResult(
            outcome,
            reason,
            bytes(prefix) if outcome == "key_ready" else None,
            bytes(prefix),
            tuple(offsets),
            tuple(lengths),
            tuple(requests),
            failed,
            returned_size,
            mode,
        )

    if snapshot.provider_nonnull is None:
        return result("unknown", "provider_result_unknown")
    if not snapshot.provider_nonnull:
        returned_size = snapshot.provider_out_size
        return result("prematch_failed", "provider_returned_null")
    returned_size = 256
    offset = 0
    for ordinal in range(8):
        if binding.physical_bytes is None or offset >= len(binding.physical_bytes):
            return result("unknown", "reached_raw_key_byte_unavailable")
        # The source writes this byte before attempting dgetlen_x86.
        prefix.append(binding.physical_bytes[offset])
        offsets.append(offset)
        requests.append(
            PattDecodeRequest(
                ordinal,
                offset,
                32,
                mode,
                binding.physical_bytes[offset : offset + 32],
            )
        )
        if mode is None:
            return result("unknown", "context_mode_bits_unknown")
        if ordinal >= len(snapshot.decoder_observations):
            return result("unknown", "decoder_observation_missing")
        observation = snapshot.decoder_observations[ordinal]
        if (
            observation.binding != binding
            or observation.ordinal != ordinal
            or observation.input_offset != offset
            or observation.declared_size != 32
            or observation.mode_flags != mode
        ):
            raise PattPrematchSnapshotError(
                "reached decoder observation binding mismatch"
            )
        bits = observation.result_bits
        if bits is None:
            return result("unknown", "decoder_result_unknown")
        value = bits if bits < 0x80000000 else bits - 0x100000000
        if value <= 0:
            return result("prematch_failed", "decoder_returned_nonpositive", value)
        if value > 32:
            raise PattPrematchSnapshotError(
                "positive result exceeds original wrapper cap"
            )
        lengths.append(value)
        offset += value
    return result("key_ready", "eight_positive_original_decoder_observations")
