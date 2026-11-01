"""Conditional PE validator requests from explicit worker-entry facts.

No matcher, PE/VMM page classifier, memory reader or final verdict is implemented.
The runtime worker flags and matched span are supplied, not inferred from bytes.
"""

from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from .core import JSONArray, JSONObject

if TYPE_CHECKING:
    from .types.hstr import HstrPayload

VALIDATOR = 0x1800E94C0
CODE_PAGE_HELPER = 0x1804C1F40
GATE_MASK = 0x5C


def _uint(value: int | None, bits: int, name: str) -> None:
    if value is not None and (type(value) is not int or not 0 <= value < 1 << bits):
        raise ValueError(f"{name} must be an unsigned {bits}-bit integer or None")


def _label(value: str | None, name: str, *, allow_none: bool = False) -> None:
    if value is None and allow_none:
        return
    if type(value) is not str or not value:
        raise ValueError(f"{name} must be a nonempty string")


@dataclass(frozen=True, slots=True)
class HstrCodePageObservation:
    """A separately resolved helper result bound to one PE/address/epoch."""

    pe_identity: str
    address: int
    epoch: str
    value: bool

    def __post_init__(self) -> None:
        _uint(self.address, 64, "observation address")
        if self.address is None or type(self.value) is not bool:
            raise ValueError("observation requires a concrete address and bool value")
        _label(self.pe_identity, "observation PE identity")
        _label(self.epoch, "observation epoch")


@dataclass(frozen=True, slots=True, kw_only=True)
class HstrCodePageContext:
    """Explicit scan_vbuff worker invocation; None denotes unavailable facts.

    base is scan_vbuff's fourth argument, separate from its host buffer pointer.
    match_offset/span are actual worker match facts, never raw pattern lengths.
    validator_function is the actual validator vtable entry, not a record field.
    """

    epoch: str
    caller_profile: str | None = None
    family_index: int | None = None
    matcher_succeeded: bool | None = None
    validator_present: bool | None = None
    matched_span_length: int | None = None
    validator_function: int | None = None
    worker_flags: int | None = None
    pe_identity: str | None = None
    base: int | None = None
    match_offset: int | None = None
    helper_observation: HstrCodePageObservation | None = None

    def __post_init__(self) -> None:
        _label(self.epoch, "epoch")
        _label(self.caller_profile, "caller_profile", allow_none=True)
        _label(self.pe_identity, "pe_identity", allow_none=True)
        for name in ("matcher_succeeded", "validator_present"):
            value = getattr(self, name)
            if value is not None and type(value) is not bool:
                raise ValueError(f"{name} must be bool or None")
        for name in (
            "matched_span_length",
            "validator_function",
            "base",
            "match_offset",
        ):
            _uint(getattr(self, name), 64, name)
        _uint(self.family_index, 8, "family_index")
        _uint(self.worker_flags, 32, "worker_flags")
        if self.helper_observation is not None and not isinstance(
            self.helper_observation, HstrCodePageObservation
        ):
            raise TypeError(
                "helper_observation must be HstrCodePageObservation or None"
            )


@dataclass(frozen=True, slots=True)
class HstrCodePageRequest:
    status: Literal["projected", "unknown", "unsupported"]
    reason: str
    wire_flags: int
    worker_flags: int | None
    calls_helper: bool | None
    address: int | None
    enters_location_management: bool | None


def project_hstr_code_page_request(
    record: "HstrPayload", subsignature_index: int, context: HstrCodePageContext
) -> HstrCodePageRequest:
    """Project one validator layer, preserving lazy gates and u64 ADD wrapping."""
    from .types.hstr import HstrPayload, parse_hstr

    if not isinstance(record, HstrPayload) or not isinstance(record.raw, bytes):
        raise TypeError("record must be HstrPayload with immutable raw bytes")
    if not isinstance(context, HstrCodePageContext):
        raise TypeError("context must be HstrCodePageContext")
    parsed = parse_hstr(record.raw, type_byte=record.type_byte)
    if type(subsignature_index) is not int or not 0 <= subsignature_index < len(
        parsed.subsignatures
    ):
        raise ValueError("subsignature_index is outside the parsed record")
    flags = parsed.subsignatures[subsignature_index].flags
    wire_flags = 0 if flags is None else flags.value

    def result(status, reason, calls=None, address=None, enters=None):
        return HstrCodePageRequest(
            status, reason, wire_flags, context.worker_flags, calls, address, enters
        )

    if parsed.receiver_ignored:
        return result("unsupported", "receiver_ignored")
    if parsed.type_byte not in (0x78, 0x85):
        return result("unsupported", "record_outside_code_page_recipe")
    if context.caller_profile is None or context.family_index is None:
        return result("unknown", "caller_profile_unknown")
    if context.caller_profile != "scan_vbuff" or context.family_index != 0:
        return result("unsupported", "caller_profile_not_covered")
    if context.matcher_succeeded is False:
        return result("projected", "matcher_has_no_candidate", False, enters=False)
    if context.matcher_succeeded is None:
        return result("unknown", "matcher_outcome_unknown")
    if context.worker_flags is None:
        return result("unknown", "worker_flags_unknown")
    if not context.worker_flags & 0x40:
        return result("unsupported", "actual_worker_flags_outside_code_page_domain")
    if context.validator_present is False:
        return result("projected", "validator_null", False, enters=False)
    if context.validator_present is None:
        return result("unknown", "validator_presence_unknown")
    if context.matched_span_length == 0:
        return result("projected", "matched_span_zero", False, enters=False)
    if context.matched_span_length is None:
        return result("unknown", "matched_span_unknown")
    if context.validator_function is None:
        return result("unknown", "validator_identity_unknown")
    if context.validator_function != VALIDATOR:
        return result("unsupported", "validator_identity_not_covered")
    # Actual runtime flags are authoritative for this validator invocation.
    # Wire flags remain provenance, not an equality invariant of the engine.
    if context.worker_flags & GATE_MASK != 0x40:
        return result("projected", "mixed_validator_mask_rejected", False, enters=False)
    if context.base is None or context.match_offset is None:
        return result("unknown", "helper_coordinates_unknown", True)
    address = (context.base + context.match_offset) & 0xFFFFFFFFFFFFFFFF
    observation = context.helper_observation
    if observation is None:
        return result("unknown", "helper_outcome_unknown", True, address)
    if (
        not context.pe_identity
        or observation.pe_identity != context.pe_identity
        or observation.epoch != context.epoch
        or observation.address != address
    ):
        return result("unknown", "helper_observation_not_bound", True, address)
    return result(
        "projected", "resolved_same_epoch_helper", True, address, observation.value
    )


def build_hstr_code_page_recipe(wire_flags: int) -> JSONObject:
    """A source recipe requiring an explicit actual worker invocation."""
    _uint(wire_flags, 32, "wire_flags")
    if wire_flags is None or wire_flags & ~0x03FF or not wire_flags & 0x40:
        raise ValueError(
            "wire_flags must describe a receiver-accepted code-page record"
        )
    return JSONObject(
        (
            ("representation", "hstr.code_page_validator_recipe.v1"),
            ("evidence_tier", "engine_static"),
            ("callable", "lib.vdm.hstr_code_page.project_hstr_code_page_request"),
            ("context_type", "lib.vdm.hstr_code_page.HstrCodePageContext"),
            ("observation_type", "lib.vdm.hstr_code_page.HstrCodePageObservation"),
            ("wire_flags", wire_flags),
            (
                "runtime_flags_source",
                "explicit actual worker flags; not inferred from matcher bytes",
            ),
            (
                "caller_profile",
                "explicit scan_vbuff@0x1801A2DFC, family_index=0; never inferred from record flags",
            ),
            ("validator", VALIDATOR),
            ("helper", CODE_PAGE_HELPER),
            (
                "validator_gate",
                "(worker_flags low byte & 0x5c) == 0x40; other bits including 0x20/0x80 do not affect this validator branch",
            ),
            (
                "address",
                "u64(scan_vbuff_arg4_base + worker_match_offset); offset0 and wrap allowed; not a host pointer or inferred file offset",
            ),
            (
                "lazy_gates",
                JSONArray(
                    (
                        "actual matcher candidate",
                        "validator nonnull",
                        "actual matched span nonzero",
                        "actual PE validator identity",
                        "exact low-byte validator mask",
                    )
                ),
            ),
            (
                "helper_outcome",
                "unknown unless separately resolved for same PE identity, address and epoch; unknown is not false",
            ),
            ("true_disposition", "enters_location_candidate_management"),
            ("false_disposition", "this_subsignature_match_not_inserted"),
            (
                "unknown_boundary",
                "matcher semantics, helper VMM classifier, score/location dedup, report and final verdict are not implemented; old status/issues stay unchanged",
            ),
        )
    )
