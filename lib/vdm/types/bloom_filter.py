"""Parser and bounded renderer for BLOOM_FILTER (0xDB) payloads."""

from dataclasses import dataclass
from typing import Final

from ..core import DisplaySection, FamilySpec, FormatResult

BLOOM_FILTER_TYPE: Final = 0xDB
_FILTER_PREVIEW_BYTES: Final = 16
_KEYS_TEXT_PREVIEW_CHARS: Final = 64
_KEYS_RAW_PREVIEW_BYTES: Final = 24
_TRAILING_PREVIEW_BYTES: Final = 16


@dataclass(frozen=True, slots=True)
class BloomFilterPayload:
    """Parsed Bloom filter fields with all source bytes retained losslessly."""

    raw: bytes
    filter_len: int
    filter_data: bytes
    keys_len: int
    keys_data: bytes
    version: int
    version_raw: bytes
    trailing_raw: bytes

    @property
    def keys_text(self) -> str:
        """Decode the bounded key/setting field for display, retaining raw bytes."""
        return self.keys_data.decode("utf-8", errors="replace")


def _need(payload: bytes, cursor: int, size: int, label: str) -> int:
    end = cursor + size
    if end > len(payload):
        raise ValueError(
            f"truncated BLOOM_FILTER {label}: need {size} bytes, "
            f"have {len(payload) - cursor}"
        )
    return end


def parse_bloom_filter(payload: bytes) -> BloomFilterPayload:
    """Parse the observed 0xDB layout, retaining optional and trailing bytes.

    The version WORD exists only when at least two bytes remain after the keys
    field. A single remaining byte is retained as trailing data and produces
    the default version value 0.
    """
    header_end = _need(payload, 0, 4, "header")
    filter_len = int.from_bytes(payload[:header_end], "little")
    filter_end = _need(payload, header_end, filter_len, "filter_data")
    filter_data = payload[header_end:filter_end]

    keys_len_end = _need(payload, filter_end, 1, "keys_len")
    keys_len = payload[filter_end]
    keys_end = _need(payload, keys_len_end, keys_len, "keys_data")
    keys_data = payload[keys_len_end:keys_end]

    remaining = len(payload) - keys_end
    if remaining >= 2:
        version_end = keys_end + 2
        version_raw = payload[keys_end:version_end]
        version = int.from_bytes(version_raw, "little")
        trailing_raw = payload[version_end:]
    else:
        version = 0
        version_raw = b""
        trailing_raw = payload[keys_end:]

    return BloomFilterPayload(
        raw=payload,
        filter_len=filter_len,
        filter_data=filter_data,
        keys_len=keys_len,
        keys_data=keys_data,
        version=version,
        version_raw=version_raw,
        trailing_raw=trailing_raw,
    )


def _hex_preview(data: bytes, limit: int) -> str:
    preview = data[:limit].hex(" ").upper()
    if len(data) > limit:
        preview += f" … ({len(data) - limit} more bytes)"
    return preview or "(empty)"


def render_bloom_filter(parsed: BloomFilterPayload) -> FormatResult:
    """Render metadata and bounded previews without dumping the filter blob."""
    keys_text = ascii(parsed.keys_text[:_KEYS_TEXT_PREVIEW_CHARS])
    if len(parsed.keys_text) > _KEYS_TEXT_PREVIEW_CHARS:
        keys_text += (
            f" … ({len(parsed.keys_text) - _KEYS_TEXT_PREVIEW_CHARS} more chars)"
        )

    return FormatResult(
        fields=(
            ("filter_len", f"{parsed.filter_len} B"),
            ("keys_len", str(parsed.keys_len)),
            ("version", f"0x{parsed.version:04X}"),
            ("version_present", "yes" if parsed.version_raw else "no"),
            ("trailing_len", f"{len(parsed.trailing_raw)} B"),
            ("raw_len", f"{len(parsed.raw)} B"),
        ),
        sections=(
            DisplaySection(
                "Bloom Filter",
                rows=(
                    (
                        "filter_preview",
                        _hex_preview(parsed.filter_data, _FILTER_PREVIEW_BYTES),
                    ),
                    ("keys_text", keys_text),
                    (
                        "keys_raw_preview",
                        _hex_preview(parsed.keys_data, _KEYS_RAW_PREVIEW_BYTES),
                    ),
                    (
                        "trailing_preview",
                        _hex_preview(parsed.trailing_raw, _TRAILING_PREVIEW_BYTES),
                    ),
                ),
            ),
        ),
    )


SPEC = FamilySpec(
    BLOOM_FILTER_TYPE,
    "BLOOM_FILTER",
    parse_bloom_filter,
    render_bloom_filter,
)
BLOOM_FILTER_SPEC = SPEC


__all__ = [
    "BLOOM_FILTER_SPEC",
    "BLOOM_FILTER_TYPE",
    "SPEC",
    "BloomFilterPayload",
    "parse_bloom_filter",
    "render_bloom_filter",
]
