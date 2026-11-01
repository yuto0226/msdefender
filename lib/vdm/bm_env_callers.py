"""Two named BM tokenized caller recipes with invocation/phase-bound facts.

Outputs are requests and partial field-write plans. No IEnvMatch, allocation,
general detection or reference side effects execute; complete frames are never
rebuilt from constructor holes or from a prior candidate's unknown ref writes.
"""

from dataclasses import dataclass, replace
from typing import Final

from .bm_env_map import (
    BMEnvLookupResult,
    BMEnvLookupSnapshot,
    BMEnvSnapshotError,
    query_bm_env_maps,
)

SECOND_PROFILE: Final = "tokenized_path_second_180063268"
BOTH_PROFILE: Final = "tokenized_path_both_1802EFA80"
TEST_FOR_DETECTION: Final = 0x1802BB9A4


def _uint(value: int, bits: int) -> None:
    if type(value) is not int or not 0 <= value < 1 << bits:
        raise BMEnvSnapshotError(f"uint{bits} required")


def _optional_uint(value: int | None, bits: int) -> None:
    if value is not None:
        _uint(value, bits)


def _text(value: str) -> None:
    if type(value) is not str or not value:
        raise BMEnvSnapshotError("nonempty identity required")


@dataclass(frozen=True, slots=True)
class BMEnvCallerBinding:
    invocation_id: str
    profile: str
    phase: str
    epoch: str
    source_identity: bytes

    def __post_init__(self) -> None:
        _text(self.invocation_id)
        _text(self.epoch)
        if type(self.source_identity) is not bytes:
            raise BMEnvSnapshotError("immutable source identity required")
        phases = {
            SECOND_PROFILE: ("second_query",),
            BOTH_PROFILE: ("both_entry", "both_post_initial"),
        }
        if (
            type(self.profile) is not str
            or type(self.phase) is not str
            or self.profile not in phases
            or self.phase not in phases[self.profile]
        ):
            raise BMEnvSnapshotError("invalid named caller phase/profile")


def _same_invocation(entry: BMEnvCallerBinding, later: BMEnvCallerBinding) -> None:
    if (
        entry.invocation_id != later.invocation_id
        or entry.profile != later.profile
        or entry.source_identity != later.source_identity
    ):
        raise BMEnvSnapshotError("caller invocation/profile/source binding mismatch")


@dataclass(frozen=True, slots=True)
class BMEnvReturnedLookup:
    """Actual normally returned lookup observation for this exact query phase."""

    binding: BMEnvCallerBinding
    key: int | None
    hresult_bits: int | None
    output_a: int | None
    output_b: int | None

    def __post_init__(self) -> None:
        if (
            type(self.binding) is not BMEnvCallerBinding
            or self.binding.phase == "both_entry"
        ):
            raise BMEnvSnapshotError("returned lookup requires a query phase")
        _optional_uint(self.key, 16)
        _optional_uint(self.hresult_bits, 32)
        _optional_uint(self.output_a, 64)
        _optional_uint(self.output_b, 64)


@dataclass(frozen=True, slots=True)
class BMEnvQueryPhase:
    binding: BMEnvCallerBinding
    feature_byte: int | None
    env_match_hresult: int | None
    key: int | None
    returned: BMEnvReturnedLookup | None = None
    map_query: BMEnvLookupSnapshot | None = None

    def __post_init__(self) -> None:
        if (
            type(self.binding) is not BMEnvCallerBinding
            or self.binding.phase == "both_entry"
        ):
            raise BMEnvSnapshotError(
                "query requires second_query or both_post_initial phase"
            )
        _optional_uint(self.feature_byte, 8)
        _optional_uint(self.env_match_hresult, 32)
        _optional_uint(self.key, 16)
        if self.returned is not None and type(self.returned) is not BMEnvReturnedLookup:
            raise BMEnvSnapshotError("wrong returned lookup type")
        if (
            self.map_query is not None
            and type(self.map_query) is not BMEnvLookupSnapshot
        ):
            raise BMEnvSnapshotError("wrong map query snapshot type")


@dataclass(frozen=True, slots=True)
class BMEnvVirtualRequest:
    ordinal: int
    virtual_slot: int
    input_role: str
    input_pointer: int | None
    mask_role: str | None
    mask_value: int | None
    requires_prior_virtual_normal_return: bool = False

    def __post_init__(self) -> None:
        if type(self.ordinal) is not int or self.ordinal not in (0, 1):
            raise BMEnvSnapshotError("virtual request ordinal must be 0 or 1")
        if type(self.virtual_slot) is not int or self.virtual_slot not in (0x18, 0x20):
            raise BMEnvSnapshotError("invalid virtual slot")
        if self.input_role not in ("input", "input_a", "input_b"):
            raise BMEnvSnapshotError("invalid virtual input role")
        _optional_uint(self.input_pointer, 64)
        _optional_uint(self.mask_value, 64)
        if self.virtual_slot == 0x20:
            if self.mask_role is not None or self.mask_value is not None:
                raise BMEnvSnapshotError("fallback request has no mask argument")
        elif (
            self.mask_role
            != {"input": "b", "input_a": "a", "input_b": "b"}[self.input_role]
        ):
            raise BMEnvSnapshotError("masked request role mismatch")
        if type(self.requires_prior_virtual_normal_return) is not bool:
            raise BMEnvSnapshotError("prior normal-return condition must be bool")


@dataclass(frozen=True, slots=True)
class BMEnvVariantRoute:
    profile: str
    reason: str
    requests: tuple[BMEnvVirtualRequest, ...] = ()
    query_key: int | None = None
    conditional_on_lookup_normal_return: bool = False
    lookup_projection: BMEnvLookupResult | None = None
    lookup_origin: str = "explicit_returned_values"


def route_bm_env_second_lookup(
    hresult_bits: int | None, output_b: int | None, *, input_pointer: int | None = None
) -> BMEnvVariantRoute:
    """Second caller uses B only; negative HRESULT does not read either mask."""
    _optional_uint(hresult_bits, 32)
    _optional_uint(input_pointer, 64)
    if hresult_bits is None:
        return BMEnvVariantRoute(SECOND_PROFILE, "lookup_hresult_unknown")
    if hresult_bits & 0x80000000:
        return BMEnvVariantRoute(
            SECOND_PROFILE,
            "fallback_request",
            (BMEnvVirtualRequest(0, 0x20, "input", input_pointer, None, None),),
        )
    _optional_uint(output_b, 64)
    if output_b is None:
        return BMEnvVariantRoute(SECOND_PROFILE, "mask_b_unknown")
    if output_b == 0:
        return BMEnvVariantRoute(SECOND_PROFILE, "zero_mask_b_skip")
    return BMEnvVariantRoute(
        SECOND_PROFILE,
        "masked_b_request",
        (BMEnvVirtualRequest(0, 0x18, "input", input_pointer, "b", output_b),),
    )


def route_bm_env_both_lookup(
    hresult_bits: int | None,
    output_a: int | None,
    output_b: int | None,
    *,
    input_a: int | None = None,
    input_b: int | None = None,
) -> BMEnvVariantRoute:
    """Both caller plans A then B; nonnegative status never zero-gates masks.

    Request B is conditional on normal return/transfer/tidy of virtual A, not
    on its vector being nonempty or a fictitious virtual HRESULT/Boolean.
    """
    _optional_uint(hresult_bits, 32)
    _optional_uint(input_a, 64)
    _optional_uint(input_b, 64)
    if hresult_bits is None:
        return BMEnvVariantRoute(BOTH_PROFILE, "lookup_hresult_unknown")
    negative = bool(hresult_bits & 0x80000000)
    if not negative:
        _optional_uint(output_a, 64)
        _optional_uint(output_b, 64)
    return BMEnvVariantRoute(
        BOTH_PROFILE,
        "fallback_pair_requests" if negative else "masked_pair_requests",
        (
            BMEnvVirtualRequest(
                0,
                0x20 if negative else 0x18,
                "input_a",
                input_a,
                None if negative else "a",
                None if negative else output_a,
            ),
            BMEnvVirtualRequest(
                1,
                0x20 if negative else 0x18,
                "input_b",
                input_b,
                None if negative else "b",
                None if negative else output_b,
                True,
            ),
        ),
    )


def _query(
    phase: BMEnvQueryPhase,
) -> tuple[
    str | None,
    int | None,
    int | None,
    int | None,
    int | None,
    bool,
    BMEnvLookupResult | None,
]:
    if phase.feature_byte is None:
        return "feature_byte_unknown", None, None, None, None, False, None
    if phase.feature_byte == 0:
        return "feature_disabled", None, None, None, None, False, None
    if phase.env_match_hresult is None:
        return "env_match_hresult_unknown", None, None, None, None, False, None
    if phase.env_match_hresult & 0x80000000:
        return "env_match_failed", None, None, None, None, False, None
    observed = phase.returned
    key = phase.key
    if observed is not None:
        if observed.binding != phase.binding:
            raise BMEnvSnapshotError("returned lookup phase binding mismatch")
        if key is not None and observed.key is not None and key != observed.key:
            raise BMEnvSnapshotError("returned lookup key binding mismatch")
        if key is None:
            key = observed.key
    projection = None
    if phase.map_query is not None and key is not None:
        if phase.map_query.epoch != phase.binding.epoch:
            raise BMEnvSnapshotError("map query must use this query phase epoch")
        projection = query_bm_env_maps(key, phase.map_query, prior_a=0, prior_b=0)
    if observed is not None:
        if projection is not None:
            for actual, projected in (
                (observed.hresult_bits, projection.hresult_bits),
                (observed.output_a, projection.output_a),
                (observed.output_b, projection.output_b),
            ):
                if actual is not None and projected is not None and actual != projected:
                    raise BMEnvSnapshotError(
                        "returned and composed lookup facts conflict"
                    )
        return (
            None,
            observed.hresult_bits,
            observed.output_a,
            observed.output_b,
            key,
            False,
            projection,
        )
    if key is None:
        return "actual_source_key_unknown", None, None, None, None, False, None
    if projection is None:
        return "lookup_facts_unknown", None, None, None, key, False, None
    return (
        None,
        projection.hresult_bits,
        projection.output_a,
        projection.output_b,
        key,
        True,
        projection,
    )


@dataclass(frozen=True, slots=True)
class BMEnvCandidate:
    """Actual c_str pointer observation; content need not be read by a plan."""

    c_str_pointer: int | None
    physical_utf16: bytes | None = None

    def __post_init__(self) -> None:
        _optional_uint(self.c_str_pointer, 64)
        if self.physical_utf16 is not None and type(self.physical_utf16) is not bytes:
            raise BMEnvSnapshotError("immutable physical candidate bytes required")


@dataclass(frozen=True, slots=True)
class BMEnvVectorObservation:
    query_binding: BMEnvCallerBinding
    request: BMEnvVirtualRequest
    normal_return_and_transfer_completed: bool | None
    candidates: tuple[BMEnvCandidate | None, ...] | None

    def __post_init__(self) -> None:
        if (
            type(self.query_binding) is not BMEnvCallerBinding
            or self.query_binding.phase == "both_entry"
        ):
            raise BMEnvSnapshotError(
                "vector observation requires its query phase binding"
            )
        if type(self.request) is not BMEnvVirtualRequest:
            raise BMEnvSnapshotError("wrong vector request binding type")
        if (
            self.normal_return_and_transfer_completed is not None
            and type(self.normal_return_and_transfer_completed) is not bool
        ):
            raise BMEnvSnapshotError(
                "normal return/transfer completion must be bool or None"
            )
        if self.candidates is not None and (
            type(self.candidates) is not tuple
            or any(
                c is not None and type(c) is not BMEnvCandidate for c in self.candidates
            )
        ):
            raise BMEnvSnapshotError("immutable actual candidate tuple required")


@dataclass(frozen=True, slots=True)
class BMEnvSourceCopyObservation:
    """Actual source bytes at Second's post-virtual pre-loop copy point."""

    query_binding: BMEnvCallerBinding
    raw48: bytes | None

    def __post_init__(self) -> None:
        if (
            type(self.query_binding) is not BMEnvCallerBinding
            or self.query_binding.phase != "second_query"
        ):
            raise BMEnvSnapshotError("copy observation requires second query binding")
        if self.raw48 is not None and (
            type(self.raw48) is not bytes or len(self.raw48) != 48
        ):
            raise BMEnvSnapshotError(
                "source copy must be exactly48 physical bytes or unknown"
            )


@dataclass(frozen=True, slots=True)
class BMEnvFieldWrite:
    offset: int
    width: int
    value: int | None
    value_source: str


@dataclass(frozen=True, slots=True)
class BMEnvDetectionStep:
    candidate_a_index: int | None
    candidate_b_index: int | None
    writes: tuple[BMEnvFieldWrite, ...]
    requires_previous_detection_normal_return: bool
    detection_va: int = TEST_FOR_DETECTION
    extra_forwarded: bool = True
    last_argument: bool = False


@dataclass(frozen=True, slots=True)
class BMEnvCopyPlan:
    raw48: bytes | None
    length: int = 48
    count: int = 1
    after_virtual_normal_return_and_transfer: bool = True
    before_vector_empty_check: bool = True


@dataclass(frozen=True, slots=True)
class BMEnvCandidatePlan:
    reason: str
    copy_once: BMEnvCopyPlan | None = None
    steps: tuple[BMEnvDetectionStep, ...] = ()
    complete_frames_materialized: bool = False


@dataclass(frozen=True, slots=True)
class BMEnvSecondSnapshot:
    phase: BMEnvQueryPhase
    input_pointer: int | None
    vector: BMEnvVectorObservation | None = None
    source_copy: BMEnvSourceCopyObservation | None = None

    def __post_init__(self) -> None:
        if (
            type(self.phase) is not BMEnvQueryPhase
            or self.phase.binding.profile != SECOND_PROFILE
        ):
            raise BMEnvSnapshotError("Second snapshot needs its named query profile")
        _optional_uint(self.input_pointer, 64)
        if self.vector is not None and type(self.vector) is not BMEnvVectorObservation:
            raise BMEnvSnapshotError("wrong Second vector observation")
        if (
            self.source_copy is not None
            and type(self.source_copy) is not BMEnvSourceCopyObservation
        ):
            raise BMEnvSnapshotError("wrong source copy observation")


@dataclass(frozen=True, slots=True)
class BMEnvBothSnapshot:
    entry_binding: BMEnvCallerBinding
    input_a_pointer: int | None
    input_b_pointer: int | None
    initial_detection_normal_return: bool | None
    post_initial: BMEnvQueryPhase | None
    vector_a: BMEnvVectorObservation | None = None
    vector_b: BMEnvVectorObservation | None = None

    def __post_init__(self) -> None:
        if (
            type(self.entry_binding) is not BMEnvCallerBinding
            or self.entry_binding.phase != "both_entry"
        ):
            raise BMEnvSnapshotError("Both snapshot requires its entry phase")
        _optional_uint(self.input_a_pointer, 64)
        _optional_uint(self.input_b_pointer, 64)
        if (
            self.initial_detection_normal_return is not None
            and type(self.initial_detection_normal_return) is not bool
        ):
            raise BMEnvSnapshotError(
                "initial detection completion must be bool or None"
            )
        if self.post_initial is not None and (
            type(self.post_initial) is not BMEnvQueryPhase
            or self.post_initial.binding.phase != "both_post_initial"
        ):
            raise BMEnvSnapshotError("wrong post-initial phase")
        for value in (self.vector_a, self.vector_b):
            if value is not None and type(value) is not BMEnvVectorObservation:
                raise BMEnvSnapshotError("wrong Both vector observation")


@dataclass(frozen=True, slots=True)
class BMEnvCallerPlan:
    route: BMEnvVariantRoute
    candidates: BMEnvCandidatePlan
    constructor_writes: tuple[BMEnvFieldWrite, ...] = ()
    initial_detection_requested: bool = False
    initial_detection_normal_return: bool | None = None
    vector_completions: tuple[bool | None, ...] = ()
    services_executed: bool = False


def _bound_vector(
    binding: BMEnvCallerBinding,
    request: BMEnvVirtualRequest,
    observation: BMEnvVectorObservation | None,
) -> tuple[bool | None, tuple[BMEnvCandidate | None, ...] | None]:
    if observation is None:
        return None, None
    if observation.query_binding != binding or observation.request != request:
        raise BMEnvSnapshotError(
            "vector invocation/phase/exact request binding mismatch"
        )
    return observation.normal_return_and_transfer_completed, observation.candidates


def project_bm_env_second_call(snapshot: BMEnvSecondSnapshot) -> BMEnvCallerPlan:
    if type(snapshot) is not BMEnvSecondSnapshot:
        raise BMEnvSnapshotError("wrong Second caller snapshot")
    s = snapshot
    reason, hr, _, mask_b, key, conditional, lookup = _query(s.phase)
    route = (
        BMEnvVariantRoute(SECOND_PROFILE, reason)
        if reason
        else route_bm_env_second_lookup(hr, mask_b, input_pointer=s.input_pointer)
    )
    route = replace(
        route,
        query_key=key,
        conditional_on_lookup_normal_return=conditional,
        lookup_projection=lookup,
        lookup_origin="phase_gates"
        if reason
        else "map_projection"
        if conditional
        else "returned_observation"
        if s.phase.returned is not None
        else "phase_gates",
    )
    if not route.requests:
        return BMEnvCallerPlan(route, BMEnvCandidatePlan("no_selected_virtual_request"))
    completed, values = _bound_vector(s.phase.binding, route.requests[0], s.vector)
    copy_plan = BMEnvCopyPlan(None)
    if completed is not True:
        return BMEnvCallerPlan(
            route,
            BMEnvCandidatePlan("virtual_return_transfer_not_established", copy_plan),
            vector_completions=(completed,),
        )
    copy_raw = None
    if s.source_copy is not None:
        if s.source_copy.query_binding != s.phase.binding:
            raise BMEnvSnapshotError("source copy invocation/phase binding mismatch")
        copy_raw = s.source_copy.raw48
    copy_plan = BMEnvCopyPlan(copy_raw)
    if values is None:
        return BMEnvCallerPlan(
            route,
            BMEnvCandidatePlan("candidate_count_unknown", copy_plan),
            vector_completions=(completed,),
        )
    steps = tuple(
        BMEnvDetectionStep(
            None,
            i,
            (
                BMEnvFieldWrite(
                    0x10,
                    8,
                    None if value is None else value.c_str_pointer,
                    f"candidate[{i}].c_str",
                ),
                BMEnvFieldWrite(0x18, 2, 0, "constant_zero_WORD"),
            ),
            i != 0,
        )
        for i, value in enumerate(values)
    )
    return BMEnvCallerPlan(
        route,
        BMEnvCandidatePlan("ordered_second_candidates", copy_plan, steps),
        vector_completions=(completed,),
    )


def project_bm_env_both_call(snapshot: BMEnvBothSnapshot) -> BMEnvCallerPlan:
    if type(snapshot) is not BMEnvBothSnapshot:
        raise BMEnvSnapshotError("wrong Both caller snapshot")
    s = snapshot
    constructor = (
        BMEnvFieldWrite(0, 8, s.input_a_pointer, "preserved_input_a"),
        BMEnvFieldWrite(8, 4, 0x00400000, "constant_DWORD"),
        BMEnvFieldWrite(0x10, 8, s.input_b_pointer, "preserved_input_b"),
        BMEnvFieldWrite(0x18, 4, 0x00400000, "constant_DWORD"),
        BMEnvFieldWrite(0x20, 1, 0, "constant_BYTE"),
        BMEnvFieldWrite(0x22, 2, 0x4049, "constructor_only_not_post_call_key"),
        BMEnvFieldWrite(0x28, 8, 0, "constant_QWORD"),
    )

    def result(
        route: BMEnvVariantRoute,
        candidates: BMEnvCandidatePlan,
        completions: tuple[bool | None, ...] = (),
    ) -> BMEnvCallerPlan:
        return BMEnvCallerPlan(
            route,
            candidates,
            constructor,
            True,
            s.initial_detection_normal_return,
            completions,
        )

    if s.initial_detection_normal_return is not True:
        return result(
            BMEnvVariantRoute(
                BOTH_PROFILE,
                "initial_detection_normal_return_not_established",
                lookup_origin="entry_phase",
            ),
            BMEnvCandidatePlan("initial_call_precedes_all_tokenization"),
        )
    if s.post_initial is None:
        return result(
            BMEnvVariantRoute(
                BOTH_PROFILE, "post_initial_phase_unknown", lookup_origin="entry_phase"
            ),
            BMEnvCandidatePlan("no_post_initial_facts"),
        )
    phase = s.post_initial
    _same_invocation(s.entry_binding, phase.binding)
    reason, hr, mask_a, mask_b, key, conditional, lookup = _query(phase)
    route = (
        BMEnvVariantRoute(BOTH_PROFILE, reason)
        if reason
        else route_bm_env_both_lookup(
            hr, mask_a, mask_b, input_a=s.input_a_pointer, input_b=s.input_b_pointer
        )
    )
    route = replace(
        route,
        query_key=key,
        conditional_on_lookup_normal_return=conditional,
        lookup_projection=lookup,
        lookup_origin="phase_gates"
        if reason
        else "map_projection"
        if conditional
        else "returned_observation"
        if phase.returned is not None
        else "phase_gates",
    )
    if not route.requests:
        return result(route, BMEnvCandidatePlan("no_selected_virtual_requests"))
    done_a, values_a = _bound_vector(phase.binding, route.requests[0], s.vector_a)
    if done_a is not True:
        return result(
            route,
            BMEnvCandidatePlan("virtual_a_transfer_not_established"),
            (done_a, None),
        )
    done_b, values_b = _bound_vector(phase.binding, route.requests[1], s.vector_b)
    completions = (done_a, done_b)
    if done_a is not True or done_b is not True:
        return result(
            route,
            BMEnvCandidatePlan("both_virtual_transfers_not_established"),
            completions,
        )
    if values_a == () or values_b == ():
        return result(
            route, BMEnvCandidatePlan("empty_cartesian_no_candidate_reads"), completions
        )
    if values_a is None or values_b is None:
        return result(
            route, BMEnvCandidatePlan("candidate_counts_unknown"), completions
        )
    steps = []
    for i, a in enumerate(values_a):
        for j, b in enumerate(values_b):
            steps.append(
                BMEnvDetectionStep(
                    i,
                    j,
                    (
                        BMEnvFieldWrite(
                            0,
                            8,
                            None if a is None else a.c_str_pointer,
                            f"candidate_a[{i}].c_str",
                        ),
                        BMEnvFieldWrite(
                            0x10,
                            8,
                            None if b is None else b.c_str_pointer,
                            f"candidate_b[{j}].c_str",
                        ),
                    ),
                    bool(steps),
                )
            )
    return result(
        route,
        BMEnvCandidatePlan("a_outer_b_inner_partial_writes", steps=tuple(steps)),
        completions,
    )
