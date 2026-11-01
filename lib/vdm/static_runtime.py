"""Explicit STATIC runtime recipes; no host configuration or wire inference."""

from dataclasses import dataclass
from enum import Enum
from typing import Literal

from .core import JSONArray, JSONObject, SemanticJSONValue


class StaticUnknown(Enum):
    UNKNOWN = "unknown"


UNKNOWN = StaticUnknown.UNKNOWN
type RuntimeBool = bool | StaticUnknown
type RuntimeU32 = int | None | StaticUnknown
type RuntimeU64 = int | StaticUnknown
UINT64_MAX = (1 << 64) - 1
EXCEPTION_NAME_DISABLE_MASK = 1 << 34


@dataclass(frozen=True, slots=True)
class StaticConfigSnapshot:
    """Confirmed non-NULL config; its DWORD may still be unresolved."""

    flags: int | StaticUnknown = UNKNOWN

    def __post_init__(self) -> None:
        if self.flags is not UNKNOWN and (
            type(self.flags) is not int or not 0 <= self.flags <= 0xFFFFFFFF
        ):
            raise ValueError("config flags must be u32 or UNKNOWN")


@dataclass(frozen=True, slots=True)
class StaticRuntimeSnapshot:
    """Caller attests every supplied value belongs to this immutable epoch.

    None denotes a confirmed NULL pointer, UNKNOWN an unresolved value. Name is
    narrow pointer storage, never decoded text. Prefix comparison reads bytes[1:5]
    independently of byte0; scanner starts at byte5 and stops at NUL/colon.
    Exactly one virtual NUL follows supplied storage; no bytes beyond it are
    inferred. Empty storage has a virtual first-byte NUL and is non-exception.
    epoch must be explicitly supplied. resolved_cmdline_flags_u64 is the already
    resolved GetCmdlineFlags result; its writers/TLS/epoch are external inputs.
    config is the resolved effective pointer *(reply+0xB8), after CheckConfig's
    fixed passed_config=NULL fallback; config=None means that resolved pointer
    is confirmed NULL, not merely that the fixed argument is NULL.
    """

    epoch: str
    name: bytes | None | StaticUnknown = UNKNOWN
    resolved_cmdline_flags_u64: RuntimeU64 = UNKNOWN
    config: StaticConfigSnapshot | None | StaticUnknown = UNKNOWN
    scan_state_kind: RuntimeU32 = UNKNOWN
    force_scan_archives: RuntimeBool = UNKNOWN
    force_scan_mail: RuntimeBool = UNKNOWN
    force_scan_packed: RuntimeBool = UNKNOWN

    def __post_init__(self) -> None:
        if not isinstance(self.epoch, str) or not self.epoch:
            raise ValueError("explicit same-epoch snapshot identifier required")
        if (
            self.name is not None
            and self.name is not UNKNOWN
            and not isinstance(self.name, bytes)
        ):
            raise TypeError("name must be narrow CString bytes, NULL, or UNKNOWN")
        for value in (
            self.force_scan_archives,
            self.force_scan_mail,
            self.force_scan_packed,
        ):
            if type(value) is not bool and value is not UNKNOWN:
                raise TypeError("boolean snapshot values must be bool or UNKNOWN")
        if (
            self.config is not None
            and self.config is not UNKNOWN
            and not isinstance(self.config, StaticConfigSnapshot)
        ):
            raise TypeError("config must be StaticConfigSnapshot, NULL, or UNKNOWN")
        for value in (self.scan_state_kind,):
            if (
                value is not None
                and value is not UNKNOWN
                and (type(value) is not int or not 0 <= value <= 0xFFFFFFFF)
            ):
                raise ValueError("snapshot DWORD must be u32, NULL, or UNKNOWN")
        if self.resolved_cmdline_flags_u64 is not UNKNOWN and (
            type(self.resolved_cmdline_flags_u64) is not int
            or not 0 <= self.resolved_cmdline_flags_u64 <= UINT64_MAX
        ):
            raise ValueError("resolved cmdline flags must be u64 or UNKNOWN")

    @property
    def exception_name(self) -> RuntimeBool:
        """One derived helper result shared by CFG and long-target consumers."""
        return project_static_exception_name(self).value


@dataclass(frozen=True, slots=True)
class StaticExceptionProjection:
    status: Literal["true", "false", "unknown", "no_match"]
    reason: str
    queried_fields: tuple[str, ...] = ()

    @property
    def value(self) -> RuntimeBool:
        return {"true": True, "false": False}.get(self.status, UNKNOWN)


def project_static_exception_name(
    snapshot: StaticRuntimeSnapshot,
) -> StaticExceptionProjection:
    """Project IsExceptionName from narrow storage and resolved flags, not text.

    NULL belongs to the caller's rejection path and never invokes the helper.
    Empty storage supplies the contract's one virtual NUL as its first byte.
    """
    name = snapshot.name
    if name is None:
        return StaticExceptionProjection("no_match", "null_name_no_match")
    if name is UNKNOWN:
        return StaticExceptionProjection("unknown", "name_unresolved")
    if not name or name[0] not in (0x23, 0x7E):
        return StaticExceptionProjection("false", "non_exception_prefix", ("name[0]",))
    flags = snapshot.resolved_cmdline_flags_u64
    queries = ("name[0]", "resolved_cmdline_flags_u64")
    if flags is UNKNOWN:
        return StaticExceptionProjection("unknown", "cmdline_flags_unresolved", queries)
    disabled = bool(flags & EXCEPTION_NAME_DISABLE_MASK)
    return StaticExceptionProjection(
        "false" if disabled else "true",
        "cmdline_bit34_set" if disabled else "cmdline_bit34_clear",
        queries,
    )


@dataclass(frozen=True, slots=True)
class StaticCfgQuery:
    field: str
    value: RuntimeBool | RuntimeU32
    execution: Literal["required", "conditional"] = "required"


@dataclass(frozen=True, slots=True)
class StaticCfgCall:
    name_byte_offset: int
    flag: int
    value: RuntimeBool
    queries: tuple[StaticCfgQuery, ...]


@dataclass(frozen=True, slots=True)
class StaticCfgProjection:
    status: Literal["true", "false", "unknown", "invalid_state"]
    reason: str
    calls: tuple[StaticCfgCall, ...] = ()

    @property
    def value(self) -> bool | None:
        return {"true": True, "false": False}.get(self.status)


def _check_config(
    snapshot: StaticRuntimeSnapshot, flag: int, offset: int
) -> StaticCfgCall:
    queries: list[StaticCfgQuery] = []
    flags = snapshot.config.flags
    queries.append(StaticCfgQuery("config_flags", flags))

    # NULL is rejected separately by the projector, before any normal predicate.
    def bit(index: int) -> RuntimeBool:
        return UNKNOWN if flags is UNKNOWN else bool(flags & (1 << index))

    def attr(field: str, conditional: bool = False) -> RuntimeBool:
        value = getattr(snapshot, field)
        queries.append(
            StaticCfgQuery(field, value, "conditional" if conditional else "required")
        )
        return value

    def either(left: RuntimeBool, field: str) -> RuntimeBool:
        if left is True:
            return True
        right = attr(field, left is UNKNOWN)
        if right is True:
            return True
        return right if left is False else UNKNOWN

    if flag in (1, 3):
        kind = snapshot.scan_state_kind
        queries.append(StaticCfgQuery("scan_state_kind", kind))
        special = UNKNOWN if kind is UNKNOWN else kind in (0x19, 0x1A)
        if special is True:
            value = False
        else:
            enabled = bit(1 if flag == 1 else 4)
            field = "force_scan_archives" if flag == 1 else "force_scan_mail"
            if enabled is True:
                value = True if special is False else UNKNOWN
            else:
                forced = attr(field, special is UNKNOWN or enabled is UNKNOWN)
                enabled = (
                    True
                    if forced is True
                    else False
                    if forced is False and enabled is False
                    else UNKNOWN
                )
                value = enabled if special is False or enabled is False else UNKNOWN
    else:
        first = bit(0)
        if first is True:
            value = True
        elif flags is UNKNOWN:
            value = either(UNKNOWN, "force_scan_packed")
        else:
            enabled = bit(1) and (not bit(16) or bit(15))
            value = either(enabled, "force_scan_packed")
    return StaticCfgCall(offset, flag, value, tuple(queries))


def project_static_cfg_gate(snapshot: StaticRuntimeSnapshot) -> StaticCfgProjection:
    """Project ordered CheckConfig calls with a failure latch and query trace."""
    name = snapshot.name
    if name is None:
        return StaticCfgProjection("false", "null_name_no_match")
    if name is UNKNOWN:
        return StaticCfgProjection("unknown", "name_unresolved")
    if snapshot.exception_name is False:
        return StaticCfgProjection("true", "cfg_not_applicable")
    # Input is narrow pointer storage, not a decoded CString starting at byte0.
    # strncmp is called at name+1; only the later scanner starts at name+5.
    for offset, expected in enumerate(b"CFG:", 1):
        byte = name[offset] if offset < len(name) else 0  # one virtual NUL
        if byte != expected:
            return StaticCfgProjection("true", "cfg_not_applicable")
    if snapshot.exception_name is UNKNOWN:
        return StaticCfgProjection("unknown", "exception_name_unresolved")
    calls = []
    for offset in range(5, len(name)):
        byte = name[offset]
        if byte in (0, ord(":")):
            break
        flag = {ord("A"): 1, ord("M"): 3, ord("P"): 2}.get(byte)
        if flag is None:
            continue
        if snapshot.config is None:
            return StaticCfgProjection(
                "invalid_state", "null_config_unsupported", tuple(calls)
            )
        if snapshot.config is UNKNOWN:
            calls.append(
                StaticCfgCall(
                    offset, flag, UNKNOWN, (StaticCfgQuery("config", UNKNOWN),)
                )
            )
        else:
            calls.append(_check_config(snapshot, flag, offset))
    status = (
        "false"
        if any(c.value is False for c in calls)
        else "unknown"
        if any(c.value is UNKNOWN for c in calls)
        else "true"
    )
    return StaticCfgProjection(status, "ordered_calls_with_failure_latch", tuple(calls))


class StaticCallerProfile(Enum):
    TROJ_SCAN_ENTRY = "troj_scan_entry"
    RPF_CHECK_STATIC = "rpf_check_static"


@dataclass(frozen=True, slots=True)
class StaticProviderProjection:
    status: Literal["provider", "skip", "unknown"]
    offset: int | None = None
    size: int | None = None
    reason: str = "runtime_inputs_required"


def project_static_provider(
    profile: StaticCallerProfile,
    *,
    reply_size: int | None = None,
    slot_offset: int | None = None,
    slot_size: int | None = None,
) -> StaticProviderProjection:
    """Resolve worker range only; does not validate UFS identity or source bytes."""
    if not isinstance(profile, StaticCallerProfile):
        raise TypeError("explicit StaticCallerProfile required")

    def u64(value: object) -> bool:
        return type(value) is int and 0 <= value <= UINT64_MAX

    if profile is StaticCallerProfile.TROJ_SCAN_ENTRY:
        if slot_offset is not None or slot_size is not None:
            raise ValueError("troj_scan_entry has constant offset and size arguments")
        offset, size = 0, UINT64_MAX
    else:
        if not u64(slot_offset) or not u64(slot_size):
            return StaticProviderProjection("unknown")
        offset, size = slot_offset, slot_size
    if size != UINT64_MAX:
        return StaticProviderProjection(
            "provider", offset, size, "explicit_size_unchanged"
        )
    if not u64(reply_size):
        return StaticProviderProjection("unknown")
    if offset >= reply_size:
        return StaticProviderProjection(
            "skip", reason="sentinel_offset_not_below_reply_size"
        )
    return StaticProviderProjection(
        "provider", offset, reply_size - offset, "sentinel_reply_size_minus_offset"
    )


def static_runtime_recipes() -> JSONObject:
    """Symbolic metadata shared by inventory and semantic exports."""

    def obj(**values: SemanticJSONValue) -> JSONObject:
        return JSONObject(tuple(values.items()))

    def expr(operation: str, *operands: SemanticJSONValue) -> JSONObject:
        return obj(operation=operation, operands=JSONArray(operands))

    special = expr("state_kind_in", "SCAN_REPLY+0x20C8 -> +0x518", 0x19, 0x1A)

    def bit(index: int) -> JSONObject:
        return expr("bit_u32", "SCAN_REPLY+0xB8 -> +0", index)

    def attribute(name: str) -> JSONObject:
        return expr("attribute_present", "MpGetAttribute", name)

    return obj(
        format="static.runtime_recipes.v1",
        evidence_tier="engine_static",
        selected_caller_profile=None,
        record_local_match=None,
        final_verdict=None,
        caller_selection="external_only; never inferred from record",
        exception_name_recipe=obj(
            helper="IsExceptionName@0x180185370",
            flags_helper="GetCmdlineFlags@0x180185894",
            provenance="derived only from explicit same-epoch narrow name storage and resolved_cmdline_flags_u64; no snapshot boolean override",
            predicate=expr(
                "and",
                expr("first_byte_in", "name", 0x23, 0x7E),
                expr("equal", expr("bit_u64", "resolved_cmdline_flags_u64", 34), 0),
            ),
            evaluation="non #/~ first byte returns false without querying flags; #/~ with unresolved flags remains unknown; empty storage supplies one virtual NUL; NULL is caller no_match before helper",
            flags_source="qword_18128A488 NULL returns 0; otherwise GetOpt@0x1800B8090 non-NULL reads selected+0x18 QWORD, fallback reads global+0x08 QWORD",
            unresolved="name provenance outside the explicitly selected direct-full bridge/profile remains external; caller ID, effective namespace and epoch are required; global and selected/default flags writers, GetOpt TLS selection and same-epoch provenance remain external; no command-line text parsing",
            consumers=JSONArray(
                ("CFG applicability", "long-target exception-or-signature gate")
            ),
            external_observation="StaticMatchContext without runtime_snapshot may accept an externally observed helper boolean; that observation is not a derived recipe result",
        ),
        caller_profiles=obj(
            troj_scan_entry=obj(
                callsite="0x180B027CB",
                pool="SCAN_REPLY+0x20D8",
                pool_capacity_minimum=0x937D0,
                initialize="0x1802D88A4; pool+0=reply; fresh specified fields only",
                worker_offset=0,
                worker_size=UINT64_MAX,
                provider_size=expr("subtract", "SCAN_REPLY+0x50", 0),
                skip_when=expr("equal", "SCAN_REPLY+0x50", 0),
            ),
            rpf_check_static=obj(
                callsite="0x1802D87EF",
                reply="slot0",
                offset="slot1",
                size="slot2",
                pool="new 0x937D0-byte pool; initialize(pool,slot0)",
                explicit_size="unchanged, including zero; no wrapper clamp",
                sentinel=UINT64_MAX,
                sentinel_size=expr("subtract", "reply+0x50", "slot1"),
                sentinel_requires=expr("less_than", "slot1", "reply+0x50"),
            ),
        ),
        cfg_recipe=obj(
            name="resolved narrow pointer storage; helper first byte must be #/~ before raw bytes[1:5] CFG prefix; empty storage is non-exception; exactly one virtual NUL after supplied bytes; NULL=no_match",
            applicability=expr(
                "and", "exception_name", expr("bytes_equal", "name[1:5]", "4346473a")
            ),
            scan=expr(
                "ordered_calls_with_failure_latch",
                "byte5 until colon or NUL",
                obj(A=1, M=3, P=2),
            ),
            byte_contract="case-sensitive raw bytes[1:5] prefix; scan only from byte5 until NUL/colon or supplied storage end (one virtual NUL); preserve order, offsets and duplicates; ignore other bytes; continue after false",
            snapshot="explicit immutable same-epoch name storage, resolved_cmdline_flags_u64:u64, config flags:u32, state NULL/kind:u32, three ForceScan attribute booleans; exception_name is derived; unknown distinct from false",
            config_source="CheckConfig passed_config=NULL; effective_config=*(SCAN_REPLY+0xB8); flags=*(u32*)(effective_config+0)",
            null_config="resolved fallback effective_config is NULL: invalid_state unsupported when CheckConfig is called",
            C1=expr(
                "and",
                expr("not", special),
                expr("or", bit(1), attribute("MpForceScanArchives")),
            ),
            C3=expr(
                "and",
                expr("not", special),
                expr("or", bit(4), attribute("MpForceScanMail")),
            ),
            C2=expr(
                "or",
                bit(0),
                expr("and", bit(1), expr("or", expr("not", bit(16)), bit(15))),
                attribute("MpForceScanPacked"),
            ),
            evaluation="short circuit within each call; conditional queries distinguished for unknown paths",
        ),
        valid_signed=obj(
            helper="IsValidSigned@0x18058EA18",
            call="IsSignedFile(reply,false,&local_id,&local_sha1,true,false,true,true)",
            meaning="policy-helper result including cache, friendly and trust paths; no provider offset/size; not hash-slice Authenticode validity",
        ),
        remaining_unknown="caller identity, reply_size writer, UFS identity, first-page producer, config/state/attribute producers and epoch/trust remain external",
    )
