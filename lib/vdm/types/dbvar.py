"""Parser and bounded renderer for DBVAR (0x5B) payloads."""

from dataclasses import dataclass
from typing import Final

from ..core import DisplaySection, FamilySpec, FormatResult

DBVAR_TYPE: Final = 0x5B
_VALUE_PREVIEW_SIZE: Final = 32


@dataclass(frozen=True, slots=True)
class DbVarPayload:
    """Lossless DBVAR fields; names remain raw bytes for exact round trips."""

    raw: bytes
    name_len: int
    name_raw: bytes
    value_len: int
    value_raw: bytes
    trailing: bytes

    @property
    def name(self) -> str:
        """Decode a display-friendly name while preserving ``name_raw``."""
        return self.name_raw.decode("utf-8", errors="replace")


def parse_dbvar(payload: bytes) -> DbVarPayload:
    """Parse the canonical name/value envelope and preserve trailing bytes.

    The offline parser validates both declared byte ranges regardless of
    registry state. Bytes after the declared value are retained verbatim.
    """
    if len(payload) < 1:
        raise ValueError("truncated DBVAR header: need 1-byte name length")

    name_len = payload[0]
    name_end = 1 + name_len
    value_length_end = name_end + 4
    if len(payload) < value_length_end:
        raise ValueError(
            f"truncated DBVAR name/value-length header: need {value_length_end} "
            f"bytes, have {len(payload)}"
        )

    value_len = int.from_bytes(payload[name_end:value_length_end], "little")
    value_end = value_length_end + value_len
    if len(payload) < value_end:
        raise ValueError(
            f"truncated DBVAR value: need {value_len} bytes, "
            f"have {len(payload) - value_length_end}"
        )

    return DbVarPayload(
        raw=payload,
        name_len=name_len,
        name_raw=payload[1:name_end],
        value_len=value_len,
        value_raw=payload[value_length_end:value_end],
        trailing=payload[value_end:],
    )


def render_dbvar(parsed: DbVarPayload) -> FormatResult:
    """Render metadata and a fixed-size hex preview of the potentially large value."""
    preview = parsed.value_raw[:_VALUE_PREVIEW_SIZE].hex(" ")
    if parsed.value_len > _VALUE_PREVIEW_SIZE:
        preview += f" … ({parsed.value_len - _VALUE_PREVIEW_SIZE} more bytes)"
    name_display = ascii(parsed.name)
    sections = (
        DisplaySection(
            "Database Variable",
            rows=(
                ("name_len", str(parsed.name_len)),
                ("name_raw", parsed.name_raw.hex(" ")),
                ("name", name_display),
                ("value_len", str(parsed.value_len)),
                ("value_preview", preview),
                ("trailing_len", str(len(parsed.trailing))),
            ),
        ),
    )
    return FormatResult(sections=sections)


SPEC = FamilySpec(DBVAR_TYPE, "DBVAR", parse_dbvar, render_dbvar)
