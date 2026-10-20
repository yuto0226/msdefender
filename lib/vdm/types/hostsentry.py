"""Lossless parser and bounded renderer for HOSTSENTRY (0x64) payloads."""

import json
from dataclasses import dataclass
from typing import Final

from ..core import DisplaySection, FamilySpec, FormatResult

HOSTSENTRY_TYPE: Final = 0x64
ADDRESS_NULL_SENTINEL: Final = b"NULL"
PREVIEW_LIMIT: Final = 64


@dataclass(frozen=True, slots=True)
class HostsentryPayload:
    """Parsed HOSTSENTRY strings with their complete declared spans retained."""

    raw: bytes
    address_raw: bytes
    hostname_raw: bytes
    trailing_raw: bytes

    @property
    def address_c_string(self) -> bytes:
        """Return the address bytes before its first NUL, if present."""
        return self.address_raw.split(b"\0", 1)[0]

    @property
    def hostname_c_string(self) -> bytes:
        """Return the hostname bytes before its first NUL, if present."""
        return self.hostname_raw.split(b"\0", 1)[0]

    @property
    def address_null_sentinel(self) -> bool:
        """Match the handler's case-insensitive C-string ``NULL`` sentinel."""
        return self.address_c_string.lower() == ADDRESS_NULL_SENTINEL.lower()

    @property
    def wildcard_hostname(self) -> bool:
        """Whether the hostname C-string starts with the observed ``*.`` prefix."""
        return self.hostname_c_string.startswith(b"*.")


def _read_string_span(payload: bytes, cursor: int, label: str) -> tuple[bytes, int]:
    if cursor >= len(payload):
        raise ValueError(f"truncated HOSTSENTRY {label} length")
    length = payload[cursor]
    cursor += 1
    if length < 2:
        raise ValueError(f"HOSTSENTRY {label} length must be at least 2")
    end = cursor + length
    if end > len(payload):
        raise ValueError(f"truncated HOSTSENTRY {label}: need {length} bytes")
    span = payload[cursor:end]
    if span[-1] != 0:
        raise ValueError(f"HOSTSENTRY {label} span must end with NUL")
    return span, end


def parse_hostsentry(payload: bytes) -> HostsentryPayload:
    """Parse two length-prefixed, NUL-terminated strings and retain any tail."""
    address_raw, cursor = _read_string_span(payload, 0, "address")
    hostname_raw, cursor = _read_string_span(payload, cursor, "hostname")
    return HostsentryPayload(
        raw=payload,
        address_raw=address_raw,
        hostname_raw=hostname_raw,
        trailing_raw=payload[cursor:],
    )


def _bounded_hex(data: bytes) -> str:
    shown = data[:PREVIEW_LIMIT].hex(" ").upper()
    if len(data) > PREVIEW_LIMIT:
        return f"{shown} … ({len(data) - PREVIEW_LIMIT} B omitted)"
    return shown or "(empty)"


def _byte_preview(data: bytes) -> str:
    return json.dumps(data.decode("latin-1"), ensure_ascii=True)


def render_hostsentry(parsed: HostsentryPayload) -> FormatResult:
    """Render semantic flags and bounded byte previews without decoding assumptions."""
    return FormatResult(
        sections=(
            DisplaySection(
                "HOSTS Entry",
                rows=(
                    ("address_length", f"{len(parsed.address_raw)} B"),
                    (
                        "address_preview",
                        _byte_preview(parsed.address_c_string[:PREVIEW_LIMIT]),
                    ),
                    ("address_raw", _bounded_hex(parsed.address_raw)),
                    (
                        "address_null_sentinel",
                        str(parsed.address_null_sentinel).lower(),
                    ),
                    ("hostname_length", f"{len(parsed.hostname_raw)} B"),
                    (
                        "hostname_preview",
                        _byte_preview(parsed.hostname_c_string[:PREVIEW_LIMIT]),
                    ),
                    ("hostname_raw", _bounded_hex(parsed.hostname_raw)),
                    ("wildcard_hostname", str(parsed.wildcard_hostname).lower()),
                    ("trailing_length", f"{len(parsed.trailing_raw)} B"),
                    ("trailing_raw", _bounded_hex(parsed.trailing_raw)),
                ),
            ),
        )
    )


SPEC = FamilySpec(HOSTSENTRY_TYPE, "HOSTSENTRY", parse_hostsentry, render_hostsentry)
