"""Parser and renderer for VERSIONCHECK (0x7A) payloads."""

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final, Literal

from ..core import DisplaySection, FamilySpec, FormatResult

VERSIONCHECK_TYPE: Final = 0x7A
BASE_SIZE: Final = 8
PredicateStatus = Literal["known", "partial", "unknown"]


@dataclass(frozen=True, slots=True)
class VersionCheckPredicate:
    status: PredicateStatus
    expression: str | None = None
    field_04_domain: str | None = None
    effect: str | None = None


VERSIONCHECK_PREDICATES: Final[Mapping[int, VersionCheckPredicate]] = MappingProxyType(
    {
        0x00: VersionCheckPredicate(
            "known", "always true; field_04 unused", "not read"
        ),
        0x02: VersionCheckPredicate(
            "known",
            "dword(dword_1810766B0) <= field_04",
            "full uint32_t unsigned comparison",
        ),
        0x31: VersionCheckPredicate(
            "known",
            "bool(gktab+0xB43) == bool(field_04)",
            "uint32_t truthiness; zero vs nonzero",
        ),
        0x34: VersionCheckPredicate(
            "known",
            "bool(gktab+0xB47) == bool(field_04)",
            "uint32_t truthiness; zero vs nonzero",
        ),
        0x3C: VersionCheckPredicate(
            "known", "dword(gktab+0x15868) == field_04", "full uint32_t equality"
        ),
        0x3D: VersionCheckPredicate(
            "known", "dword(gktab+0x1586C) == field_04", "full uint32_t equality"
        ),
        0x3E: VersionCheckPredicate(
            "known", "dword(gktab+0x15870) == field_04", "full uint32_t equality"
        ),
        0x3F: VersionCheckPredicate(
            "known", "dword(gktab+0x15874) == field_04", "full uint32_t equality"
        ),
        0x40: VersionCheckPredicate(
            "known",
            "byte(gktab+0xB4E) == bool(field_04)",
            "uint32_t truthiness compared with raw uint8_t state",
        ),
        0x43: VersionCheckPredicate(
            "known",
            "byte(gktab+0xB4F) == bool(field_04)",
            "uint32_t truthiness compared with raw uint8_t state",
        ),
        0x58: VersionCheckPredicate(
            "known", "dword(gktab+0xB9C) > field_04", "unsigned uint32_t comparison"
        ),
        0x63: VersionCheckPredicate(
            "known",
            "qword(gktab+0xBE0) > field_04",
            "zero-extended uint32_t vs unsigned uint64_t",
        ),
        0x64: VersionCheckPredicate(
            "known",
            "qword(gktab+0xBE0) < field_04",
            "zero-extended uint32_t vs unsigned uint64_t",
        ),
        0x65: VersionCheckPredicate(
            "known",
            "bool(gktab+0xB48) == bool(field_04)",
            "uint32_t truthiness; zero vs nonzero",
        ),
        0x66: VersionCheckPredicate(
            "known", "dword(gktab+0x15884) == field_04", "full uint32_t equality"
        ),
        0x6A: VersionCheckPredicate(
            "known",
            "high_dword(qword(gktab+0x15968)) < field_04",
            "unsigned uint32_t comparison",
        ),
        0x6B: VersionCheckPredicate(
            "known",
            "high_dword(qword(gktab+0x15968)) < field_04",
            "full uint32_t unsigned comparison",
        ),
        0x14: VersionCheckPredicate(
            "known", "dword(gktab+0xB64) == field_04", "full uint32_t equality"
        ),
        0x15: VersionCheckPredicate(
            "known",
            "dword(gktab+0xB68) < field_04",
            "full uint32_t unsigned comparison",
        ),
        0x27: VersionCheckPredicate(
            "known", "dword(gktab+0xB90) > field_04", "unsigned uint32_t comparison"
        ),
        0x6F: VersionCheckPredicate(
            "known",
            "qword(gktab+0x15968) > field_04",
            "zero-extended uint32_t vs unsigned uint64_t",
        ),
        0x0E: VersionCheckPredicate(
            "known", "dword(gktab+0xB28) == field_04", "full uint32_t equality"
        ),
        0x0F: VersionCheckPredicate(
            "known",
            "dword(gktab+0xB2C) <= field_04",
            "full uint32_t unsigned comparison",
        ),
        0x0D: VersionCheckPredicate(
            "known",
            "dword(gktab+0xB28) <= field_04",
            "full uint32_t unsigned comparison",
        ),
        0x16: VersionCheckPredicate(
            "known",
            "dword(gktab+0xB68) <= field_04",
            "full uint32_t unsigned comparison",
        ),
        0x8A: VersionCheckPredicate(
            "known",
            "byte(gktab+0xB44) == bool(field_04)",
            "uint32_t truthiness compared with raw uint8_t state",
        ),
        0x91: VersionCheckPredicate(
            "known",
            "always true",
            "full uint32_t value",
            "set staging_uuid_a[0:4] = field_04 and zero staging_uuid_a[4:16]",
        ),
        0x92: VersionCheckPredicate(
            "known",
            "always true",
            "full uint32_t value",
            "set staging_uuid_a[4:8] = field_04",
        ),
        0x93: VersionCheckPredicate(
            "known",
            "always true",
            "full uint32_t value",
            "set staging_uuid_a[8:12] = field_04",
        ),
        0x94: VersionCheckPredicate(
            "known",
            "qword(gktab+0x15868) != qword(staging_uuid_a[0:8]) or qword(gktab+0x15870) != qword(staging_uuid_a[8:16]) or qword(gktab+0x158A8) == 0",
            "full uint32_t value",
            "set staging_uuid_a[12:16] = field_04; format staged UUID only on false result",
        ),
        0x95: VersionCheckPredicate(
            "known",
            "always true",
            "full uint32_t value",
            "set staging_uuid_b[0:4] = field_04 and zero staging_uuid_b[4:16]",
        ),
        0x96: VersionCheckPredicate(
            "known",
            "always true",
            "full uint32_t value",
            "set staging_uuid_b[4:8] = field_04",
        ),
        0x97: VersionCheckPredicate(
            "known",
            "always true",
            "full uint32_t value",
            "set staging_uuid_b[8:12] = field_04",
        ),
        0x98: VersionCheckPredicate(
            "known",
            "qword(gktab+0x15878) != qword(staging_uuid_b[0:8]) or qword(gktab+0x15880) != qword(staging_uuid_b[8:16]) or qword(gktab+0x15900) == 0",
            "full uint32_t value",
            "set staging_uuid_b[12:16] = field_04; format staged UUID only on false result",
        ),
        0xB3: VersionCheckPredicate(
            "known", "dword(gktab+0x15888) == field_04", "full uint32_t equality"
        ),
        0xB4: VersionCheckPredicate(
            "known", "dword(gktab+0x1588C) == field_04", "full uint32_t equality"
        ),
        0xB5: VersionCheckPredicate(
            "known", "dword(gktab+0x15890) == field_04", "full uint32_t equality"
        ),
        0xB6: VersionCheckPredicate(
            "known", "dword(gktab+0x15894) == field_04", "full uint32_t equality"
        ),
        0x13: VersionCheckPredicate(
            "known",
            "dword(gktab+0xB64) <= field_04",
            "full uint32_t unsigned comparison",
        ),
        0x29: VersionCheckPredicate(
            "known", "g_CustomSetId == field_04", "full uint32_t equality"
        ),
        0x2E: VersionCheckPredicate(
            "known",
            "byte(gktab+0xB3E) == bool(field_04)",
            "uint32_t truthiness compared with raw uint8_t state",
        ),
        0x2F: VersionCheckPredicate(
            "known",
            "byte(gktab+0xB41) == bool(field_04)",
            "uint32_t truthiness compared with raw uint8_t state",
        ),
        0x3B: VersionCheckPredicate(
            "known", "dword(gktab+0xB74) != field_04", "full uint32_t inequality"
        ),
        0x83: VersionCheckPredicate(
            "known",
            "version_state(gktab) != field_04",
            (
                "full uint32_t inequality; state is gktab+0xBBC if nonzero, "
                "else +0xBA8 if nonzero, else 5 (0 if gktab is null)"
            ),
        ),
        0x22: VersionCheckPredicate(
            "partial",
            "shared CRC/lower-string path; complete state gates and comparison predicate unresolved",
            "field_04 high byte seeds CRCLowerStringW; low 24 bits feed a floating-point comparison; accepted domain unresolved",
        ),
        0x39: VersionCheckPredicate(
            "partial",
            "shared CRC/lower-string path; complete state gates and comparison predicate unresolved",
            "field_04 high byte seeds CRCLowerStringW; low 24 bits feed a floating-point comparison; accepted domain unresolved",
        ),
        0x84: VersionCheckPredicate(
            "known",
            "always false; unsupported selector path",
            "field_04 is not read by the selector path",
        ),
        0x77: VersionCheckPredicate("partial"),
        0x78: VersionCheckPredicate(
            "known",
            "(gktab == nullptr ? 0 : (dword(gktab+0x15964) & 1)) == bool(field_04)",
            "low bit of uint32_t state (or zero when gktab is null) compared with uint32_t truthiness",
        ),
        0x38: VersionCheckPredicate("partial"),
        0x2C: VersionCheckPredicate("partial"),
        0x05: VersionCheckPredicate("partial"),
        0x06: VersionCheckPredicate(
            "known",
            "dword(gktab+0xB20) < field_04",
            "full uint32_t unsigned comparison",
        ),
        0x08: VersionCheckPredicate(
            "known", "dword(gktab+0xB20) != field_04", "full uint32_t inequality"
        ),
        0x0C: VersionCheckPredicate(
            "known",
            "dword(gktab+0xB28) < field_04",
            "full uint32_t unsigned comparison",
        ),
        0x10: VersionCheckPredicate(
            "known",
            "dword(gktab+0xB2C) >= field_04",
            "full uint32_t unsigned comparison",
        ),
        0x12: VersionCheckPredicate(
            "known", "dword(gktab+0xB64) != field_04", "full uint32_t inequality"
        ),
        0x26: VersionCheckPredicate(
            "known", "dword(gktab+0xB8C) != field_04", "full uint32_t inequality"
        ),
        0x30: VersionCheckPredicate(
            "known",
            "dword(gktab+0xB80) >= field_04 and byte(gktab+0xB40) != bool(field_04) and byte(gktab+0xB51) != bool(field_04)",
            "full uint32_t unsigned comparison plus two raw uint8_t comparisons against operand truthiness",
        ),
        0x4D: VersionCheckPredicate(
            "known",
            "byte(gktab+0xB40) != bool(field_04) and byte(gktab+0xB51) != bool(field_04)",
            "two raw uint8_t comparisons against uint32_t truthiness",
        ),
        0x6E: VersionCheckPredicate(
            "known",
            "dword(gktab+0x15968) >= field_04",
            "full uint32_t unsigned comparison",
        ),
        0x72: VersionCheckPredicate(
            "known", "dword(gktab+0xB74) == field_04", "full uint32_t equality"
        ),
        0x76: VersionCheckPredicate("partial"),
        0x85: VersionCheckPredicate(
            "known",
            "version_state(gktab) != field_04",
            "full uint32_t inequality; state is gktab+0xBBC if nonzero, else +0xBA8 if nonzero, else 5 (0 if gktab is null)",
        ),
        0x01: VersionCheckPredicate(
            "known",
            "dword(dword_1810766B0) >= field_04",
            "full uint32_t unsigned comparison",
        ),
        0x04: VersionCheckPredicate(
            "known",
            "byte(gktab+0xB38) == bool(field_04)",
            "uint32_t truthiness compared with raw uint8_t state",
        ),
        0x17: VersionCheckPredicate(
            "known", "dword(gktab+0xB68) != field_04", "full uint32_t inequality"
        ),
        0x1A: VersionCheckPredicate(
            "known", "dword(gktab+0xB60) != field_04", "full uint32_t inequality"
        ),
        0x1D: VersionCheckPredicate(
            "known",
            "byte(gktab+0xB3B) == bool(field_04)",
            "raw uint8_t state compared with uint32_t truthiness (0 or 1)",
        ),
        0x36: VersionCheckPredicate("partial"),
        0x4C: VersionCheckPredicate(
            "known", "dword(gktab+0xB80) != field_04", "full uint32_t inequality"
        ),
        0x57: VersionCheckPredicate(
            "known",
            "dword(gktab+0xB9C) >= field_04",
            "full uint32_t unsigned comparison",
        ),
        0x6D: VersionCheckPredicate(
            "known",
            "low_dword(qword(gktab+0x15968)) != field_04",
            "low uint32_t equality test",
        ),
        0x80: VersionCheckPredicate(
            "known",
            "version_state(gktab) != field_04 and (field_04 != 1 or gktab+0xB20 not in {7, 10})",
            "full uint32_t comparison with gated fallback state at +0xBB8/+0xBA4",
        ),
        0x82: VersionCheckPredicate(
            "known",
            "version_state(gktab) <= field_04",
            "full uint32_t unsigned comparison; state is +0xBB8 if nonzero, else +0xBA4 if nonzero, else 5 (0 if gktab is null)",
        ),
        0x28: VersionCheckPredicate(
            "known", "dword(gktab+0xB90) == field_04", "full uint32_t equality"
        ),
        0x2D: VersionCheckPredicate(
            "known",
            "byte(gktab+0xB43) == bool(field_04)",
            "raw uint8_t state compared with uint32_t truthiness (0 or 1)",
        ),
        0x81: VersionCheckPredicate(
            "known",
            "(field_04 == 2 and dword(gktab+0xB20) in {7, 10}) or version_state(gktab) < field_04",
            "unsigned uint32_t comparison; version_state is +0xBB8 if nonzero, else +0xBA4 if nonzero, else 5 (0 if gktab is null); field_04 == 2 reads +0xB20 before the null check",
        ),
    }
)


@dataclass(frozen=True, slots=True)
class VersionCheckPayload:
    raw: bytes
    field_00: int
    field_04: int
    trailing_raw: bytes


def parse_versioncheck(payload: bytes) -> VersionCheckPayload:
    """Parse the observed two-DWORD prefix and preserve any trailing bytes."""
    if len(payload) < BASE_SIZE:
        raise ValueError(
            f"truncated VERSIONCHECK header: need {BASE_SIZE} bytes, "
            f"have {len(payload)}"
        )

    return VersionCheckPayload(
        raw=payload,
        field_00=int.from_bytes(payload[0:4], "little"),
        field_04=int.from_bytes(payload[4:8], "little"),
        trailing_raw=payload[BASE_SIZE:],
    )


def render_versioncheck(parsed: VersionCheckPayload) -> FormatResult:
    """Render raw DWORDs with only engine-confirmed predicate details."""
    predicate = VERSIONCHECK_PREDICATES.get(
        parsed.field_00, VersionCheckPredicate("unknown")
    )
    condition = (
        predicate.expression
        if predicate.status == "known"
        else (
            "partial: see EvaluateVersioningOperator analysis"
            if predicate.status == "partial"
            else "unknown"
        )
    )
    rows = [
        ("field_00", f"0x{parsed.field_00:08x}"),
        ("field_04", f"0x{parsed.field_04:08x}"),
        ("condition", condition),
    ]
    if predicate.field_04_domain is not None:
        rows.append(("field_04_domain", predicate.field_04_domain))
    if predicate.effect is not None:
        rows.append(("effect", predicate.effect))
    sections = [
        DisplaySection(
            "Version Check",
            rows=tuple(rows),
        )
    ]
    if parsed.trailing_raw:
        sections.append(
            DisplaySection(
                "Trailing Data",
                rows=(("trailing_len", f"{len(parsed.trailing_raw)} B"),),
            )
        )
    return FormatResult(sections=tuple(sections))


SPEC = FamilySpec(
    VERSIONCHECK_TYPE,
    "VERSIONCHECK",
    parse_versioncheck,
    render_versioncheck,
)
