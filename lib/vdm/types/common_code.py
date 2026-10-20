"""Lossless parser and renderer for COMMON_CODE (0xAF) payloads."""

from dataclasses import dataclass
from typing import Final

from ..core import (
    DisplaySection,
    FamilySpec,
    FormatResult,
    JSONObject,
    RuleSemantics,
    SemanticIssue,
)

COMMON_CODE_TYPE: Final = 0xAF
HEADER_SIZE: Final = 4
MIN_CODE_SIZE: Final = 1
MAX_CODE_SIZE: Final = 0x100
FLAGS_LOOKUP_MASK: Final = 0x0003


@dataclass(frozen=True, slots=True)
class CommonCodePayload:
    """A validated COMMON_CODE header and opaque body, preserving raw bytes."""

    raw: bytes
    header_raw: bytes
    flags: int
    code_size: int
    body_raw: bytes

    @property
    def lookup_mode(self) -> int | None:
        """Return the loader's selected lookup mode for recognized low bits."""
        value = self.flags & FLAGS_LOOKUP_MASK
        if value == 0:
            return 1
        if value == 1:
            return 2
        return None


def parse_common_code(payload: bytes) -> CommonCodePayload:
    """Parse the receiver-validated 4-byte header and exact-length code body."""
    if len(payload) < HEADER_SIZE:
        raise ValueError(
            f"truncated COMMON_CODE header: need {HEADER_SIZE} bytes, "
            f"have {len(payload)}"
        )

    flags = int.from_bytes(payload[0:2], "little")
    code_size = int.from_bytes(payload[2:4], "little")
    if code_size < MIN_CODE_SIZE:
        raise ValueError("COMMON_CODE code_size must be at least 1 byte")
    if code_size > MAX_CODE_SIZE:
        raise ValueError(
            f"COMMON_CODE code_size exceeds {MAX_CODE_SIZE} bytes: {code_size}"
        )

    body_end = HEADER_SIZE + code_size
    if len(payload) < body_end:
        raise ValueError(
            f"truncated COMMON_CODE body: need {code_size} bytes, "
            f"have {len(payload) - HEADER_SIZE}"
        )
    if len(payload) > body_end:
        raise ValueError(
            f"COMMON_CODE has {len(payload) - body_end} trailing bytes; "
            "receiver requires an exact payload size"
        )

    return CommonCodePayload(
        raw=payload,
        header_raw=payload[:HEADER_SIZE],
        flags=flags,
        code_size=code_size,
        body_raw=payload[HEADER_SIZE:body_end],
    )


def render_common_code(parsed: CommonCodePayload) -> FormatResult:
    """Render confirmed header metadata without interpreting code bytes."""
    lookup_mode = (
        str(parsed.lookup_mode)
        if parsed.lookup_mode is not None
        else "skipped by loader (low flag bits 2 or 3)"
    )
    sections = (
        DisplaySection(
            "COMMON_CODE Header",
            rows=(
                ("flags", f"0x{parsed.flags:04x}"),
                ("code_size", f"{parsed.code_size} B"),
                ("loader_lookup_mode", lookup_mode),
            ),
        ),
        DisplaySection(
            "Opaque Code Bytes",
            rows=(
                ("body_length", f"{len(parsed.body_raw)} B"),
                ("body_raw", parsed.body_raw.hex(" ")),
            ),
        ),
    )
    return FormatResult(sections=sections)


def export_common_code_semantics(parsed: CommonCodePayload) -> RuleSemantics:
    """Export receiver framing and lookup routing while keeping code opaque."""
    mode = parsed.lookup_mode
    unresolved_bits = parsed.flags & ~FLAGS_LOOKUP_MASK
    issues = [
        SemanticIssue(
            "common_code_body_format_unknown",
            "The code body is passed to GlobalBlocksInfo as bytes, but its "
            "internal format and execution semantics are not confirmed.",
        )
    ]
    if unresolved_bits:
        issues.append(
            SemanticIssue(
                "common_code_other_flags_unknown",
                "Flag bits outside the low two bits have no confirmed meaning.",
                (("unresolved_bits", unresolved_bits),),
            )
        )
    return RuleSemantics(
        status="observed_only" if mode is not None else "ignored",
        representation="common_code.receiver-observation.ir.v1",
        data=JSONObject(
            (
                ("type", "COMMON_CODE"),
                ("raw_hex", parsed.raw.hex()),
                ("receiver_framing", "u16le flags, u16le code_size, code bytes"),
                ("payload_length", HEADER_SIZE + parsed.code_size),
                ("flags", parsed.flags),
                ("lookup_flag_bits", parsed.flags & FLAGS_LOOKUP_MASK),
                (
                    "global_blocks_lookup",
                    JSONObject(
                        (
                            ("disposition", "lookup" if mode is not None else "skip"),
                            ("mode", mode),
                        )
                    ),
                ),
                ("code_size", parsed.code_size),
                ("code_body_raw_hex", parsed.body_raw.hex()),
                ("code_body_semantics", "opaque; internal format unconfirmed"),
            )
        ),
        evidence=(
            "ccode_receiver requires payload length == 4 + code_size",
            "ccode_receiver accepts code_size from 1 through 256 bytes",
            "GBB_load_ccode maps low flag bits 0/1 to lookup mode 1/2",
            "GBB_load_ccode skips lookup when low flag bits are 2 or 3",
            "GBB_load_ccode passes the body as a byte span to GlobalBlocksInfo",
        ),
        profile="mpengine-1.443.903.0",
        issues=tuple(issues),
    )


SPEC = FamilySpec(
    COMMON_CODE_TYPE,
    "COMMON_CODE",
    parse_common_code,
    render_common_code,
    semantic_exporter=export_common_code_semantics,
)
