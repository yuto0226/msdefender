"""BM environment alias, shared-map values and one tokenized caller route.

The ASCII CRT profile is explicit. Maps are complete immutable snapshots;
normal successful insertion is a separate conditional execution premise.
No environment expansion, allocation, registry or IEnvMatch service runs.
"""

from dataclasses import dataclass, replace
from typing import Final

BM_ENV_ASCII_CRT_PROFILE: Final = "mpengine-1.443.903.0.bm-env.stable-ascii-c-locale.v1"
# Source order within each signed-second-byte dispatch branch matters.
BM_ENV_ALIAS_BRANCHES: Final = (
    (97, ((b"%appdata%", 0x100),)),
    (
        99,
        (
            (b"%commonfiles%", 0x2000),
            (b"%common_startmenu%", 0x1000),
            (b"%common_programs%", 0x4000),
            (b"%common_startup%", 0x8000),
            (b"%common_desktop%", 0x10000),
            (b"%common_appdata%", 0x20000),
        ),
    ),
    (100, ((b"%desktopdirectory%", 0x80),)),
    (102, ((b"%favorites%", 0x40),)),
    (105, ((b"%internet_cache%", 0x400),)),
    (108, ((b"%localappdata%", 0x200),)),
    (112, ((b"%programs%", 0x10), (b"%program_files%", 4))),
    (115, ((b"%system%", 2), (b"%startmenu%", 8), (b"%startup%", 0x20))),
    (116, ((b"%temp%", 0x800), (b"%testpath%", 0x80000))),
    (117, ((b"%userprofile%", 0x40000),)),
    (119, ((b"%windir%", 1), (b"%windows%", 1))),
)
BM_ENV_MAIN_TOKENIZED_CALLER: Final = 0x1802C1B10


class BMEnvSnapshotError(ValueError):
    """Malformed or conflicting explicit BM environment model inputs."""


def _uint(value: int, bits: int) -> None:
    if type(value) is not int or not 0 <= value < 1 << bits:
        raise BMEnvSnapshotError(f"uint{bits} required")


def _bytes(value: bytes) -> None:
    if type(value) is not bytes:
        raise BMEnvSnapshotError("immutable bytes required")


def _epoch(value: str) -> None:
    if type(value) is not str or not value:
        raise BMEnvSnapshotError("nonempty epoch required")


def _crt_profile(value: str | None) -> None:
    if value is not None and (
        type(value) is not str or value != BM_ENV_ASCII_CRT_PROFILE
    ):
        raise BMEnvSnapshotError("unsupported CRT profile")


@dataclass(frozen=True, slots=True)
class BMEnvNameResult:
    environment_id: int | None
    reason: str
    second_byte: int | None = None
    compared_aliases: tuple[bytes, ...] = ()


def resolve_bm_env_name(
    name_raw: bytes, *, crt_profile: str | None, physical_tail: bytes | None = None
) -> BMEnvNameResult:
    """Resolve a normally constructed receiver string, never host environment.

    The constructed buffer guarantees name_raw plus its terminator only.
    physical_tail supplies actual bytes following that terminator; it is needed
    for the unconditional name[1] read of an empty name. No zero padding occurs.
    The profile explicitly assumes stable ASCII C-locale _stricmp for this call.
    """
    _bytes(name_raw)
    _crt_profile(crt_profile)
    if physical_tail is not None:
        _bytes(physical_tail)
    physical = name_raw + b"\0" + (physical_tail or b"")
    if len(physical) < 2:
        return BMEnvNameResult(None, "second_name_byte_unreadable")
    second = physical[1]
    branch = second + 32 if 65 <= second <= 90 else second
    aliases = next(
        (rows for selector, rows in BM_ENV_ALIAS_BRANCHES if selector == branch), ()
    )
    if not aliases:
        return BMEnvNameResult(0, "no_second_byte_branch", second)
    if crt_profile is None:
        return BMEnvNameResult(None, "ascii_crt_profile_required", second)
    visited = []
    for literal, environment_id in aliases:
        visited.append(literal)
        expected = literal + b"\0"
        cursor = 0
        while True:
            if cursor >= len(physical):
                return BMEnvNameResult(
                    None, "cstring_byte_unreadable", second, tuple(visited)
                )
            left = physical[cursor]
            right = expected[cursor] if cursor < len(expected) else 0
            if left >= 128:
                return BMEnvNameResult(
                    None, "non_ascii_crt_comparison_required", second, tuple(visited)
                )
            folded = left + 32 if 65 <= left <= 90 else left
            if folded != right:
                break
            if left == 0:
                return BMEnvNameResult(
                    environment_id, "alias_equal", second, tuple(visited)
                )
            cursor += 1
    return BMEnvNameResult(0, "alias_miss", second, tuple(visited))


def decode_bm_env_mask(
    value: int,
) -> tuple[tuple[tuple[int, tuple[bytes, ...]], ...], int]:
    """Describe known alias bits while preserving arbitrary unknown QWORD bits."""
    _uint(value, 64)
    ids = sorted(
        {
            environment_id
            for _, rows in BM_ENV_ALIAS_BRANCHES
            for _, environment_id in rows
        }
    )
    rows = tuple(
        (
            environment_id,
            tuple(
                name
                for _, aliases in BM_ENV_ALIAS_BRANCHES
                for name, bit in aliases
                if bit == environment_id
            ),
        )
        for environment_id in ids
        if value & environment_id
    )
    known_mask = 0
    for environment_id in ids:
        known_mask |= environment_id
    return rows, value & ~known_mask


@dataclass(frozen=True, slots=True)
class BMEnvMapEntry:
    key: int
    value: int

    def __post_init__(self) -> None:
        _uint(self.key, 16)
        _uint(self.value, 64)


@dataclass(frozen=True, slots=True)
class BMEnvMapSnapshot:
    """Complete actual entries of one global map at this explicit epoch."""

    epoch: str
    entries: tuple[BMEnvMapEntry, ...]

    def __post_init__(self) -> None:
        _epoch(self.epoch)
        if type(self.entries) is not tuple or any(
            type(e) is not BMEnvMapEntry for e in self.entries
        ):
            raise BMEnvSnapshotError("complete immutable map entry tuple required")
        if len({e.key for e in self.entries}) != len(self.entries):
            raise BMEnvSnapshotError("duplicate map keys")


@dataclass(frozen=True, slots=True)
class BMEnvMutationSnapshot:
    epoch: str
    payload_raw: bytes
    map_a: BMEnvMapSnapshot | None
    map_b: BMEnvMapSnapshot | None
    crt_profile: str | None
    normal_insertions: bool | None
    physical_name_tail: bytes | None = None

    def __post_init__(self) -> None:
        _epoch(self.epoch)
        _bytes(self.payload_raw)
        _crt_profile(self.crt_profile)
        if (
            self.normal_insertions is not None
            and type(self.normal_insertions) is not bool
        ):
            raise BMEnvSnapshotError("normal_insertions must be bool or None")
        if self.physical_name_tail is not None:
            _bytes(self.physical_name_tail)
        for value in (self.map_a, self.map_b):
            if value is not None and type(value) is not BMEnvMapSnapshot:
                raise BMEnvSnapshotError("wrong map snapshot type")


@dataclass(frozen=True, slots=True)
class BMEnvMapWrite:
    map_name: str
    key: int
    before: int | None
    after: int
    operation: str


@dataclass(frozen=True, slots=True)
class BMEnvMutationResult:
    complete: bool
    reason: str
    environment_id: int | None
    map_a_after: tuple[BMEnvMapEntry, ...] | None
    map_b_after: tuple[BMEnvMapEntry, ...] | None
    writes: tuple[BMEnvMapWrite, ...] = ()


def project_bm_env_receiver(
    payload_raw: bytes, snapshot: BMEnvMutationSnapshot
) -> BMEnvMutationResult:
    """Reparse one record and compute conditional normal shared-map mutations.

    No per-record/per-threat reset exists. Insertion needs explicit successful
    normal insertion premise; existing-key OR does not require allocation.
    Failed/throwing insertion or allocator partial state is outside this model.
    Source calls AddVar/name lookup for each WORD. Reusing the computed name ID
    coalesces pure calculations only under the explicitly selected stable CRT
    and normally constructed immutable name-buffer profile, not engine calls.
    """
    from .types.bm_env_var_map import parse_bm_env_var_map

    _bytes(payload_raw)
    if (
        type(snapshot) is not BMEnvMutationSnapshot
        or snapshot.payload_raw != payload_raw
    ):
        raise BMEnvSnapshotError("receiver payload binding mismatch")
    row = parse_bm_env_var_map(payload_raw)
    s = snapshot

    def unused_prior(
        mapping: BMEnvMapSnapshot | None,
    ) -> tuple[BMEnvMapEntry, ...] | None:
        # No-write does not establish the current contents of a stale snapshot.
        # This check never rejects or semantically consumes an unused map.
        return (
            mapping.entries
            if mapping is not None and mapping.epoch == s.epoch
            else None
        )

    prior_a = unused_prior(s.map_a)
    prior_b = unused_prior(s.map_b)
    if not row.vector_a and not row.vector_b:
        return BMEnvMutationResult(
            True, "no_words_no_alias_call", None, prior_a, prior_b
        )
    name = resolve_bm_env_name(
        row.name_raw, crt_profile=s.crt_profile, physical_tail=s.physical_name_tail
    )
    if name.environment_id is None:
        return BMEnvMutationResult(False, name.reason, None, None, None)
    environment_id = name.environment_id
    if environment_id == 0:
        return BMEnvMutationResult(True, "zero_id_no_map_write", 0, prior_a, prior_b)
    writes = []
    outputs = []
    for label, words, mapping in (
        ("a", row.vector_a, s.map_a),
        ("b", row.vector_b, s.map_b),
    ):
        if not words:
            outputs.append(unused_prior(mapping))
            continue
        if mapping is None:
            return BMEnvMutationResult(
                False,
                f"map_{label}_unknown",
                environment_id,
                outputs[0] if outputs else None,
                None,
                tuple(writes),
            )
        if mapping.epoch != s.epoch:
            raise BMEnvSnapshotError(f"mutation map {label} epoch mismatch")
        assert mapping is not None
        values = {e.key: e.value for e in mapping.entries}
        for key in words:
            before = values.get(key)
            if before is None and s.normal_insertions is not True:
                if s.normal_insertions is False:
                    raise BMEnvSnapshotError(
                        "failed insertion outside normal-success profile"
                    )
                return BMEnvMutationResult(
                    False,
                    "normal_insertion_premise_required",
                    environment_id,
                    outputs[0] if outputs else None,
                    None,
                    tuple(writes),
                )
            after = environment_id if before is None else before | environment_id
            writes.append(
                BMEnvMapWrite(
                    label, key, before, after, "insert" if before is None else "or"
                )
            )
            values[key] = after
        outputs.append(
            tuple(BMEnvMapEntry(key, value) for key, value in sorted(values.items()))
        )
    return BMEnvMutationResult(
        True,
        "normal_map_updates",
        environment_id,
        outputs[0],
        outputs[1],
        tuple(writes),
    )


@dataclass(frozen=True, slots=True)
class BMEnvLookupSnapshot:
    epoch: str
    disable_byte: int | None
    map_a: BMEnvMapSnapshot | None
    map_b: BMEnvMapSnapshot | None
    controller_hresult: int | None = None
    controller_present: bool | None = None

    def __post_init__(self) -> None:
        _epoch(self.epoch)
        if self.disable_byte is not None:
            _uint(self.disable_byte, 8)
        if self.controller_hresult is not None:
            _uint(self.controller_hresult, 32)
        if (
            self.controller_present is not None
            and type(self.controller_present) is not bool
        ):
            raise BMEnvSnapshotError("controller_present must be bool or None")
        for value in (self.map_a, self.map_b):
            if value is not None and type(value) is not BMEnvMapSnapshot:
                raise BMEnvSnapshotError("wrong lookup map snapshot type")


@dataclass(frozen=True, slots=True)
class BMEnvLookupResult:
    hresult_bits: int | None
    output_a: int | None
    output_b: int | None
    reason: str
    hit_a: bool | None = None
    hit_b: bool | None = None
    controller_requested: bool = False
    controller_flag_write: bool | None = False
    controller_release: bool | None = False
    controller_xchg_requested: bool | None = False
    return_projection: str = "conditional_on_normal_return"


def query_bm_env_maps(
    key: int, snapshot: BMEnvLookupSnapshot, *, prior_a: int | None, prior_b: int | None
) -> BMEnvLookupResult:
    """Compute GetVarListFromSigs outputs; HRESULT is not a detection Boolean."""
    _uint(key, 16)
    for value in (prior_a, prior_b):
        if value is not None:
            _uint(value, 64)
    if type(snapshot) is not BMEnvLookupSnapshot:
        raise BMEnvSnapshotError("wrong lookup snapshot type")
    s = snapshot
    if s.disable_byte is None:
        return BMEnvLookupResult(None, None, None, "disable_byte_unknown")
    if s.disable_byte != 0:
        return BMEnvLookupResult(0x80004004, prior_a, prior_b, "consumer_disabled")
    if s.map_a is None:
        return BMEnvLookupResult(None, None, None, "map_a_size_unknown")
    if s.map_a.epoch != s.epoch:
        raise BMEnvSnapshotError("lookup map A epoch mismatch")
    if not s.map_a.entries:
        requested = (
            None if s.controller_hresult is None else s.controller_hresult < 0x80000000
        )
        if requested is True and s.controller_present is False:
            raise BMEnvSnapshotError(
                "successful controller result with NULL dereference"
            )
        write = (
            False
            if requested is False
            else True
            if requested and s.controller_present
            else None
        )
        return BMEnvLookupResult(
            0x80004004,
            prior_a,
            prior_b,
            "map_a_empty",
            controller_requested=True,
            controller_flag_write=write,
            controller_release=s.controller_present,
            controller_xchg_requested=requested,
        )
    values_a = {e.key: e.value for e in s.map_a.entries}
    hit_a = key in values_a
    out_a = values_a[key] if hit_a else prior_a
    if s.map_b is None:
        return BMEnvLookupResult(0, out_a, None, "map_b_entries_unknown", hit_a=hit_a)
    if s.map_b.epoch != s.epoch:
        raise BMEnvSnapshotError("lookup map B epoch mismatch")
    values_b = {e.key: e.value for e in s.map_b.entries}
    hit_b = key in values_b
    return BMEnvLookupResult(
        0, out_a, values_b[key] if hit_b else prior_b, "maps_queried", hit_a, hit_b
    )


@dataclass(frozen=True, slots=True)
class BMEnvCallerSnapshot:
    epoch: str
    feature_byte: int | None
    env_match_hresult: int | None
    lookup: BMEnvLookupSnapshot | None

    def __post_init__(self) -> None:
        _epoch(self.epoch)
        if self.feature_byte is not None:
            _uint(self.feature_byte, 8)
        if self.env_match_hresult is not None:
            _uint(self.env_match_hresult, 32)
        if self.lookup is not None and type(self.lookup) is not BMEnvLookupSnapshot:
            raise BMEnvSnapshotError("wrong caller lookup snapshot")


@dataclass(frozen=True, slots=True)
class BMEnvCallerRoute:
    route: str
    virtual_slot: int | None = None
    mask_a: int | None = None
    lookup: BMEnvLookupResult | None = None
    caller_va: int = BM_ENV_MAIN_TOKENIZED_CALLER
    conditional_on_normal_return: bool = False


def route_bm_env_lookup(
    hresult_bits: int | None, output_a: int | None
) -> BMEnvCallerRoute:
    """Pure branch predicate for an explicit returned HRESULT/outA observation.

    This does not prove the invocation returned, execute a service, or project
    the other tokenized-path callers. A negative HRESULT never reads outA.
    """
    if hresult_bits is not None:
        _uint(hresult_bits, 32)
    if hresult_bits is None:
        return BMEnvCallerRoute("lookup_status_unknown")
    if hresult_bits & 0x80000000:
        return BMEnvCallerRoute("fallback_request", 0x20)
    if output_a is not None:
        _uint(output_a, 64)
    if output_a is None:
        return BMEnvCallerRoute("mask_a_unknown")
    if output_a == 0:
        return BMEnvCallerRoute("zero_mask_skip")
    return BMEnvCallerRoute("masked_request", 0x18, output_a)


def project_bm_env_tokenized_call(
    key: int, snapshot: BMEnvCallerSnapshot
) -> BMEnvCallerRoute:
    """Only caller 0x1802C1B10: negative lookup HRESULT falls back to slot+0x20.

    Caller initializes both priors to zero. Success with outA==0 skips the
    virtual call; nonzero outA requests slot+0x18 with r9=&outA. outB is unused.
    No candidate paths or IEnvMatch result is inferred. Other variants excluded.
    """
    _uint(key, 16)
    if type(snapshot) is not BMEnvCallerSnapshot:
        raise BMEnvSnapshotError("wrong tokenized caller snapshot")
    s = snapshot
    if s.feature_byte is None:
        return BMEnvCallerRoute("feature_gate_unknown")
    if s.feature_byte == 0:
        return BMEnvCallerRoute("feature_disabled")
    if s.env_match_hresult is None:
        return BMEnvCallerRoute("env_match_hresult_unknown")
    if s.env_match_hresult & 0x80000000:
        return BMEnvCallerRoute("env_match_failed")
    if s.lookup is None:
        return BMEnvCallerRoute("lookup_facts_unknown")
    if s.lookup.epoch != s.epoch:
        raise BMEnvSnapshotError("caller lookup epoch mismatch")
    result = query_bm_env_maps(key, s.lookup, prior_a=0, prior_b=0)
    route = route_bm_env_lookup(result.hresult_bits, result.output_a)
    return replace(route, lookup=result, conditional_on_normal_return=True)
