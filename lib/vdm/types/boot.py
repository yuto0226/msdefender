"""Typed, lossless parser for BOOT (0x44) payloads."""

from dataclasses import dataclass
from typing import Final, Literal

from ..core import (
    DisplaySection,
    FamilySpec,
    FormatResult,
    JSONArray,
    JSONObject,
    RuleSemantics,
    SemanticIssue,
)

BOOT_TYPE: Final = 0x44
_FIELD_SIZE: Final = 32
_PREVIEW_SIZE: Final = 32


@dataclass(frozen=True, slots=True)
class BootPayload:
    """A current 32-byte template descriptor or preserved legacy bytes."""

    raw: bytes
    variant: Literal["current", "legacy_opaque"]
    receiver_acceptance: Literal[
        "accepted_by_current_template", "rejected_by_current_template"
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
            receiver_acceptance="rejected_by_current_template",
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
        # The matcher compares a fixed dword plus a wrapped secondary span.
        # The descriptor only supplies 31 bytes after selector; do not invent
        # the bytes the runtime may read beyond that stored body.
        selector_domain = "wrapped_unknown"
        runtime_compare_span = (0, 4 + ((selector - 4) & 0x1F))
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
                (
                    "interpretation",
                    "current template rejects with 0xA004; preserved opaque",
                ),
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
        assert parsed.descriptor_raw is not None
        available_body_length = len(parsed.descriptor_raw) - 1
        compare_length = (
            parsed.runtime_compare_span[1]
            if parsed.runtime_compare_span is not None
            else 0
        )
        rows.extend(
            (
                (
                    "runtime_note",
                    "wrapped selector; span is binary-derived, selector meaning unknown",
                ),
                ("available_descriptor_body", f"{available_body_length} B"),
                (
                    "unavailable_compare_bytes",
                    f"{max(0, compare_length - available_body_length)} B",
                ),
                ("descriptor_preview", _preview(parsed.descriptor_raw)),
            )
        )
    return FormatResult(sections=(DisplaySection("BOOT", rows=tuple(rows)),))


def _wire_span(name: str, raw: bytes, offset: int) -> JSONObject:
    return JSONObject(
        (
            ("name", name),
            ("raw_span", JSONObject((("offset", offset), ("length", len(raw))))),
            ("raw_hex", raw.hex()),
        )
    )


def _ordinary_pattern_atoms(pattern: bytes) -> JSONArray:
    return JSONArray(
        tuple(
            JSONObject(
                (
                    ("offset", offset),
                    (
                        "kind",
                        "wildcard" if offset >= 4 and value == 0x90 else "exact",
                    ),
                    ("value", None if offset >= 4 and value == 0x90 else value),
                )
            )
            for offset, value in enumerate(pattern)
        )
    )


def export_boot_semantics(parsed: BootPayload) -> RuleSemantics:
    """Export receiver-confirmed BOOT probe details without a verdict."""
    issues = [
        SemanticIssue(
            "outer_verdict_unknown",
            "A BOOT probe result does not establish a final detection verdict.",
        ),
    ]
    identity_end = parsed.raw.find(b"\0")
    framing: list[JSONObject] = []
    unsupported = parsed.variant != "current"
    if parsed.variant == "current":
        assert identity_end >= 0 and parsed.descriptor_raw is not None
        field_offset = identity_end + 1
        field = parsed.descriptor_raw
        framing.extend(
            (
                _wire_span("identity", parsed.identity_raw or b"", 0),
                _wire_span("identity_terminator", b"\0", identity_end),
                _wire_span("descriptor", field, field_offset),
                _wire_span("trailing", parsed.trailing_raw, field_offset + len(field)),
            )
        )
        if parsed.selector_domain == "ordinary":
            assert parsed.pattern_raw is not None and parsed.selector_raw is not None
            selector_raw = field[:1]
            pattern_offset = field_offset + 1
            rule = JSONObject(
                (
                    ("kind", "candidate_byte_probe"),
                    ("selector_raw", parsed.selector_raw),
                    ("selector", _wire_span("selector", selector_raw, field_offset)),
                    (
                        "runtime_compare_span",
                        JSONObject((("offset", 0), ("length", parsed.selector_raw))),
                    ),
                    (
                        "pattern",
                        _wire_span("pattern", parsed.pattern_raw, pattern_offset),
                    ),
                    ("comparison", _ordinary_pattern_atoms(parsed.pattern_raw)),
                    ("candidate_end_bound", "offset + length < buffer_length"),
                )
            )
        elif parsed.selector_domain == "special_32":
            assert parsed.selector_raw is not None
            rule = JSONObject(
                (
                    ("kind", "special_crc_probe"),
                    ("selector_raw", parsed.selector_raw),
                    ("flags_raw", field[1]),
                    (
                        "special_header",
                        _wire_span("special_header", field[:2], field_offset),
                    ),
                    (
                        "prefix",
                        _wire_span(
                            "prefix", parsed.special_prefix or b"", field_offset + 2
                        ),
                    ),
                    (
                        "check_length_raw",
                        _wire_span("check_length", field[10:12], field_offset + 10),
                    ),
                    ("check_length", parsed.special_check_length),
                    (
                        "crc32_raw",
                        _wire_span("crc32", field[12:16], field_offset + 12),
                    ),
                    ("crc32", parsed.special_crc32),
                    ("crc_algorithm", "mpengine.CRC_1"),
                    ("candidate_end_bound", "offset + check_length < buffer_length"),
                )
            )
        else:
            unsupported = True
            issues.append(
                SemanticIssue(
                    "wrapped_selector_semantics_unknown",
                    "The selector span wraps, but its predicate semantics are unknown.",
                    (("selector_raw", parsed.selector_raw),),
                )
            )
            rule = JSONObject(
                (
                    ("kind", "opaque_wrapped_probe"),
                    ("selector_raw", parsed.selector_raw),
                    (
                        "runtime_compare_span",
                        JSONArray(parsed.runtime_compare_span or ()),
                    ),
                    ("descriptor_raw_hex", field.hex()),
                )
            )
        if parsed.trailing_raw:
            issues.append(
                SemanticIssue(
                    "receiver_ignored_trailing",
                    "The current template receiver ignores bytes after the fixed descriptor.",
                    (("length", len(parsed.trailing_raw)),),
                )
            )
    else:
        rule = JSONObject((("kind", "opaque_legacy"),))
        framing.append(_wire_span("payload", parsed.raw, 0))
        issues.append(
            SemanticIssue(
                "legacy_shape_unrecognized",
                "The observed legacy shape is opaque; do not infer legacy fields.",
            )
        )
        issues.append(
            SemanticIssue(
                "current_template_rejects_shape",
                "mpengine 1.443.903.0 ReceiveNewTemplate returns 0xA004 for this "
                "missing-NUL or short-descriptor shape; DispatchRecords propagates "
                "the error and DispatchRecord has no receiver fallback.",
                (
                    ("current_template_error_code", 40964),
                    ("current_template_error_hex", "0xA004"),
                    ("dispatch_fallback", False),
                ),
            )
        )

    return RuleSemantics(
        status="unsupported" if unsupported else "confirmed_subset",
        representation="boot.candidate_probe.ir.v1",
        data=JSONObject(
            (
                ("raw_hex", parsed.raw.hex()),
                ("framing", JSONArray(tuple(framing))),
                (
                    "identity_raw_hex",
                    parsed.identity_raw.hex()
                    if parsed.identity_raw is not None
                    else None,
                ),
                (
                    "current_template_shape_disposition",
                    "rejected_with_0xA004"
                    if parsed.variant == "legacy_opaque"
                    else "matches_current_template_shape",
                ),
                (
                    "current_template_error_code",
                    40964 if parsed.variant == "legacy_opaque" else None,
                ),
                ("selector_domain", parsed.selector_domain),
                ("rule", rule),
                ("trailing_raw_hex", parsed.trailing_raw.hex()),
            )
        ),
        evidence=(
            "BOOT receiver selector span, modulo-wrap, and special CRC path",
            "BOOT identity and cure caller path",
        ),
        profile="mpengine-1.443.903.0",
        issues=tuple(issues),
    )


BOOT_SPEC = FamilySpec(
    BOOT_TYPE,
    "BOOT",
    parse_boot,
    render_boot,
    semantic_exporter=export_boot_semantics,
)
