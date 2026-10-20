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
    descriptor_raw: bytes | None
    selector_raw: int | None
    selector_domain: Literal["ordinary", "special_32", "wrapped_unknown"] | None
    runtime_compare_span: tuple[int, int] | None
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
            descriptor_raw=None,
            selector_raw=None,
            selector_domain=None,
            runtime_compare_span=None,
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
        selector_domain = "special_32"
        runtime_compare_span = None
        pattern_raw = None
        wildcard_count = None
        special_prefix = field[2:10]
        special_check_length = int.from_bytes(field[10:12], "little")
        special_crc32 = int.from_bytes(field[12:16], "little")
    elif 4 <= selector <= 31:
        selector_domain = "ordinary"
        runtime_compare_span = (0, selector)
        pattern_raw = field[1 : 1 + selector]
        wildcard_count = pattern_raw[4:].count(b"\x90")
        special_prefix = None
        special_check_length = None
        special_crc32 = None
    else:
        # Outside 4..32, the matcher wraps (selector - 4) with & 0x1F after
        # a fixed dword compare. Preserve values without assigning a span.
        selector_domain = "wrapped_unknown"
        runtime_compare_span = None
        pattern_raw = None
        wildcard_count = None
        special_prefix = None
        special_check_length = None
        special_crc32 = None

    return BootPayload(
        raw=payload,
        variant="current",
        receiver_acceptance="accepted_by_current_template",
        identity_raw=identity_raw,
        identity=identity_raw.decode("utf-8", errors="replace"),
        descriptor_raw=field,
        selector_raw=selector,
        selector_domain=selector_domain,
        runtime_compare_span=runtime_compare_span,
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

    assert parsed.identity_raw is not None and parsed.descriptor_raw is not None
    rows.extend(
        (
            ("identity_length", f"{len(parsed.identity_raw)} B"),
            (
                "identity",
                repr(parsed.identity[:256] if parsed.identity is not None else ""),
            ),
            ("descriptor_length", f"{len(parsed.descriptor_raw)} B"),
            (
                "selector_raw",
                f"0x{parsed.selector_raw:02X}"
                if parsed.selector_raw is not None
                else "unknown",
            ),
            ("selector_domain", parsed.selector_domain or "unknown"),
            (
                "runtime_compare_span",
                f"candidate+{parsed.runtime_compare_span[0]}, "
                f"{parsed.runtime_compare_span[1]} B"
                if parsed.runtime_compare_span is not None
                else "unknown",
            ),
            ("trailing_length", f"{len(parsed.trailing_raw)} B"),
            ("trailing_preview", _preview(parsed.trailing_raw) or "(empty)"),
            (
                "receiver_note",
                "descriptor shape recognized by the current engine template",
            ),
        )
    )
    if parsed.selector_domain == "special_32":
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
    elif parsed.selector_domain == "ordinary":
        rows.extend(
            (
                (
                    "pattern_length",
                    str(len(parsed.pattern_raw))
                    if parsed.pattern_raw is not None
                    else "unknown",
                ),
                ("pattern_preview", _preview(parsed.pattern_raw or b"")),
                (
                    "0x90_wildcard_count",
                    str(parsed.wildcard_count)
                    if parsed.wildcard_count is not None
                    else "unknown",
                ),
            )
        )
    else:
        rows.extend(
            (
                (
                    "runtime_note",
                    "wrapped selector; runtime compare span unknown",
                ),
                ("descriptor_preview", _preview(parsed.descriptor_raw)),
            )
        )
    return FormatResult(sections=(DisplaySection("BOOT", rows=tuple(rows)),))


BOOT_SPEC = FamilySpec(BOOT_TYPE, "BOOT", parse_boot, render_boot)
