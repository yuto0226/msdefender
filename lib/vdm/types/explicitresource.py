"""Lossless parser and bounded renderer for EXPLICITRESOURCE (0xD6)."""

from dataclasses import dataclass
from typing import Final

from ..core import DisplaySection, FamilySpec, FormatResult

EXPLICITRESOURCE_TYPE: Final = 0xD6
_PATH_PREVIEW_CHARS: Final = 64
_TAIL_PREVIEW_BYTES: Final = 16


@dataclass(frozen=True, slots=True)
class ExplicitResourcePayload:
    """Parsed path and opaque optional tail, retaining the complete payload."""

    raw: bytes
    path_len: int
    path_raw: bytes
    tail_raw: bytes

    @property
    def path(self) -> str:
        """Decode the UTF-16LE path without losing isolated surrogate code units."""
        return self.path_raw.decode("utf-16le", errors="surrogatepass")


def parse_explicitresource(payload: bytes) -> ExplicitResourcePayload:
    """Parse the length-prefixed UTF-16LE path and preserve an optional tail."""
    if len(payload) < 2:
        raise ValueError(
            f"truncated EXPLICITRESOURCE path_len: need 2 bytes, have {len(payload)}"
        )

    path_len = int.from_bytes(payload[:2], "little")
    if path_len < 2:
        raise ValueError(
            f"invalid EXPLICITRESOURCE path_len: need at least 2 bytes, have {path_len}"
        )
    if path_len & 1:
        raise ValueError(
            f"invalid EXPLICITRESOURCE path_len: must be even, have {path_len}"
        )

    path_end = 2 + path_len
    if path_end > len(payload):
        raise ValueError(
            "truncated EXPLICITRESOURCE path: "
            f"need {path_len} bytes, have {len(payload) - 2}"
        )

    return ExplicitResourcePayload(
        raw=payload,
        path_len=path_len,
        path_raw=payload[2:path_end],
        tail_raw=payload[path_end:],
    )


def _hex_preview(data: bytes, limit: int) -> str:
    preview = data[:limit].hex(" ").upper()
    if len(data) > limit:
        preview += f" … ({len(data) - limit} more bytes)"
    return preview or "(empty)"


def render_explicitresource(parsed: ExplicitResourcePayload) -> FormatResult:
    """Render path and tail metadata with fixed-size previews."""
    path = parsed.path
    path_preview = ascii(path[:_PATH_PREVIEW_CHARS])
    if len(path) > _PATH_PREVIEW_CHARS:
        path_preview += f" … ({len(path) - _PATH_PREVIEW_CHARS} more chars)"

    return FormatResult(
        fields=(
            ("path_len", f"{parsed.path_len} B"),
            ("path_chars", str(len(path))),
            ("tail_len", f"{len(parsed.tail_raw)} B"),
            ("payload_len", f"{len(parsed.raw)} B"),
        ),
        sections=(
            DisplaySection(
                "Explicit Resource",
                rows=(
                    ("path", path_preview),
                    ("path_raw_preview", _hex_preview(parsed.path_raw, 24)),
                    (
                        "tail_raw_preview",
                        _hex_preview(parsed.tail_raw, _TAIL_PREVIEW_BYTES),
                    ),
                ),
            ),
        ),
    )


SPEC = FamilySpec(
    EXPLICITRESOURCE_TYPE,
    "EXPLICITRESOURCE",
    parse_explicitresource,
    render_explicitresource,
)

__all__ = [
    "EXPLICITRESOURCE_TYPE",
    "SPEC",
    "ExplicitResourcePayload",
    "parse_explicitresource",
    "render_explicitresource",
]
