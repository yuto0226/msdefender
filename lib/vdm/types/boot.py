"""Typed, lossless parser for BOOT (0x44) payloads."""

from dataclasses import dataclass
from typing import Final, Literal

from ..core import DisplaySection, FamilySpec, FormatResult

BOOT_TYPE: Final = 0x44
_FIELD_SIZE: Final = 32
_PREVIEW_SIZE: Final = 32


@dataclass(frozen=True, slots=True)
class BootPayload:
    """A current 32-byte template descriptor or preserved legacy bytes."""

    raw: bytes
    variant: Literal["current", "legacy_opaque"]
    receiver_acceptance: Literal[
        "accepted_by_current_template", "unaccepted_by_current_template"
    ]
    identity_raw: bytes | None
    identity: str | None
    field_raw: bytes | None
    selector: int | None
    selector_kind: str | None
    compare_length: int | None
    pattern_raw: bytes | None
    wildcard_count: int | None
    special_prefix: bytes | None
    special_check_length: int | None
    special_crc32: int | None
    trailing_raw: bytes


def parse_boot(payload: bytes) -> BootPayload:
    """Parse a bounded identity + fixed descriptor, retaining all raw bytes.

    Payloads without a complete descriptor are preserved as legacy opaque data;
    observed legacy corpus variants are not rejected by this parser.
    """
    identity_end = payload.find(b"\0")
    if identity_end < 0 or len(payload) < identity_end + 1 + _FIELD_SIZE:
        return BootPayload(
            raw=payload,
            variant="legacy_opaque",
            receiver_acceptance="unaccepted_by_current_template",
            identity_raw=None,
            identity=None,
            field_raw=None,
            selector=None,
            selector_kind=None,
            compare_length=None,
            pattern_raw=None,
            wildcard_count=None,
            special_prefix=None,
            special_check_length=None,
            special_crc32=None,
            trailing_raw=b"",
        )

    field_start = identity_end + 1
    field_end = field_start + _FIELD_SIZE
    identity_raw = payload[:identity_end]
    field = payload[field_start:field_end]
    selector = field[0]
    if selector == 0x20:
        selector_kind = "value32"
        compare_length = None
        pattern_raw = None
        wildcard_count = None
        special_prefix = field[2:10]
        special_check_length = int.from_bytes(field[10:12], "little")
        special_crc32 = int.from_bytes(field[12:16], "little")
    else:
        selector_kind = "compare_length"
        compare_length = selector
        pattern_raw = field[1 : 1 + min(compare_length, _FIELD_SIZE - 1)]
        wildcard_count = pattern_raw.count(b"\x90")
        special_prefix = None
        special_check_length = None
        special_crc32 = None

    return BootPayload(
        raw=payload,
        variant="current",
        receiver_acceptance="accepted_by_current_template",
        identity_raw=identity_raw,
        identity=identity_raw.decode("utf-8", errors="replace"),
        field_raw=field,
        selector=selector,
        selector_kind=selector_kind,
        compare_length=compare_length,
        pattern_raw=pattern_raw,
        wildcard_count=wildcard_count,
        special_prefix=special_prefix,
        special_check_length=special_check_length,
        special_crc32=special_crc32,
        trailing_raw=payload[field_end:],
    )


def _preview(raw: bytes) -> str:
    preview = raw[:_PREVIEW_SIZE].hex(" ")
    return preview + (" ..." if len(raw) > _PREVIEW_SIZE else "")


def render_boot(parsed: BootPayload) -> FormatResult:
    """Render bounded metadata and previews without inferring engine acceptance."""
    rows: list[tuple[str, str]] = [
        ("variant", parsed.variant),
        ("receiver_acceptance", parsed.receiver_acceptance),
        ("payload_length", f"{len(parsed.raw)} B"),
    ]
    if parsed.variant == "legacy_opaque":
        rows.extend(
            (
                ("raw_preview", _preview(parsed.raw)),
                ("interpretation", "unaccepted by current template; preserved opaque"),
            )
        )
        return FormatResult(sections=(DisplaySection("BOOT", rows=tuple(rows)),))

    assert parsed.identity_raw is not None and parsed.field_raw is not None
    rows.extend(
        (
            ("identity_length", f"{len(parsed.identity_raw)} B"),
            (
                "identity",
                repr(parsed.identity[:256] if parsed.identity is not None else ""),
            ),
            ("field_length", f"{len(parsed.field_raw)} B"),
            ("selector", f"0x{parsed.selector:02X}"),
            ("selector_kind", parsed.selector_kind or "unknown"),
            ("trailing_length", f"{len(parsed.trailing_raw)} B"),
            ("trailing_preview", _preview(parsed.trailing_raw) or "(empty)"),
            (
                "receiver_note",
                "descriptor shape recognized by the current engine template",
            ),
        )
    )
    if parsed.selector_kind == "value32":
        assert parsed.special_prefix is not None
        rows.extend(
            (
                ("special_prefix", _preview(parsed.special_prefix)),
                ("special_check_length", str(parsed.special_check_length)),
                (
                    "special_crc32",
                    f"0x{parsed.special_crc32:08X}"
                    if parsed.special_crc32 is not None
                    else "unknown",
                ),
            )
        )
    else:
        rows.extend(
            (
                ("compare_length", str(parsed.compare_length)),
                ("pattern_length", str(len(parsed.pattern_raw or b""))),
                ("pattern_preview", _preview(parsed.pattern_raw or b"")),
                ("0x90_wildcard_count", str(parsed.wildcard_count)),
            )
        )
    return FormatResult(sections=(DisplaySection("BOOT", rows=tuple(rows)),))


BOOT_SPEC = FamilySpec(BOOT_TYPE, "BOOT", parse_boot, render_boot)
