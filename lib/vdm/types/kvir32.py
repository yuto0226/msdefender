"""Typed model for observed KVIR32 records (type 0x20)."""

from dataclasses import dataclass
from typing import Final

from ..core import DisplaySection, FamilySpec, FormatResult

KVIR32_TYPE: Final = 0x20
_PREFIX_SIZE: Final = 16
_EXTENSION_MARKER: Final = 0x21
_DATA_PREVIEW_SIZE: Final = 64


@dataclass(frozen=True, slots=True)
class Kvir32Payload:
    raw: bytes
    opaque_prefix: bytes
    extension_marker: int | None
    extension_data: bytes | None


def parse_kvir32(payload: bytes) -> Kvir32Payload:
    """Parse the fixed opaque prefix and the observed optional extension."""
    if len(payload) < _PREFIX_SIZE:
        raise ValueError(
            f"truncated KVIR32 prefix: need {_PREFIX_SIZE} bytes, have {len(payload)}"
        )

    opaque_prefix = payload[:_PREFIX_SIZE]
    remainder = payload[_PREFIX_SIZE:]
    if not remainder:
        return Kvir32Payload(payload, opaque_prefix, None, None)

    if len(remainder) < 2:
        raise ValueError("truncated KVIR32 extension header")

    declared_size = remainder[0]
    marker = remainder[1]
    if marker != _EXTENSION_MARKER:
        raise ValueError(f"unexpected KVIR32 extension marker 0x{marker:02X}")
    if declared_size == 0:
        raise ValueError("invalid KVIR32 extension size 0")

    expected_size = declared_size + 1
    if len(remainder) != expected_size:
        raise ValueError(
            "KVIR32 extension size mismatch: "
            f"declared {declared_size}, expected {expected_size} bytes, "
            f"have {len(remainder)}"
        )

    return Kvir32Payload(
        raw=payload,
        opaque_prefix=opaque_prefix,
        extension_marker=marker,
        extension_data=remainder[2:],
    )


def _hex_preview(data: bytes) -> str:
    preview = data[:_DATA_PREVIEW_SIZE].hex(" ")
    if len(data) > _DATA_PREVIEW_SIZE:
        preview += " ..."
    return preview or "(empty)"


def render_kvir32(parsed: Kvir32Payload) -> FormatResult:
    rows = [("opaque_prefix", parsed.opaque_prefix.hex(" "))]
    if parsed.extension_marker is not None:
        assert parsed.extension_data is not None
        rows.extend(
            (
                ("extension_marker", f"0x{parsed.extension_marker:02X}"),
                ("extension_data_length", str(len(parsed.extension_data))),
                ("extension_data", _hex_preview(parsed.extension_data)),
            )
        )
    return FormatResult(sections=(DisplaySection("KVIR32", rows=tuple(rows)),))


SPEC: Final = FamilySpec(KVIR32_TYPE, "KVIR32", parse_kvir32, render_kvir32)
