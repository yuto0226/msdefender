"""Lossless corpus-profile parser for VFILE (0x83) and VFILEEX (0xB2)."""

from dataclasses import dataclass
from typing import Final

from ..core import DisplaySection, FamilySpec, FormatResult

VFILE_TYPE: Final = 0x83
VFILEEX_TYPE: Final = 0xB2
_INNER_HEADER_WORD: Final = 0x20
_REPEATED_REGION_SIZE: Final = 24
_VFILE_PATH_OFFSET: Final = 0x2C
_VFILEEX_PATH_OFFSET: Final = 0x30
_PATH_PREVIEW_CHARS: Final = 80
_RAW_PREVIEW_BYTES: Final = 24
_TAIL_PREVIEW_BYTES: Final = 16


@dataclass(frozen=True, slots=True)
class VFilePayload:
    """Corpus-observed shared field view; no inner blob semantics are inferred."""

    raw: bytes
    signature_type: int
    outer_prefix: int | None
    inner_header_word: int
    repeated_raw: bytes
    repeated_words: tuple[int, int, int]
    header_words: tuple[int, int, int, int]
    path_offset: int
    path_raw: bytes
    path_terminator: bytes
    tail_raw: bytes
    corpus_profile: str

    @property
    def path(self) -> str:
        """Decode UTF-16LE while retaining unpaired surrogate code units."""
        return self.path_raw.decode("utf-16le", errors="surrogatepass")


def _parse(payload: bytes, signature_type: int) -> VFilePayload:
    if signature_type == VFILE_TYPE:
        outer_prefix = None
        inner_offset = 0
        path_offset = _VFILE_PATH_OFFSET
    elif signature_type == VFILEEX_TYPE:
        if len(payload) < 4:
            raise ValueError(
                "VFILE corpus profile: truncated VFILEEX outer prefix; need 4 bytes"
            )
        outer_prefix = int.from_bytes(payload[:4], "little")
        inner_offset = 4
        path_offset = _VFILEEX_PATH_OFFSET
    else:
        raise ValueError(f"unsupported VFILE signature type: {signature_type:#x}")

    if len(payload) < path_offset + 2:
        raise ValueError(
            "VFILE corpus profile: truncated header/path start; "
            f"need at least {path_offset + 2} bytes, have {len(payload)}"
        )

    inner_header_word = int.from_bytes(
        payload[inner_offset : inner_offset + 4], "little"
    )
    repeated_start = inner_offset + 4
    repeated_end = repeated_start + _REPEATED_REGION_SIZE
    repeated_raw = payload[repeated_start:repeated_end]
    header_start = inner_offset + 28
    header_words = tuple(
        int.from_bytes(payload[offset : offset + 4], "little")
        for offset in range(header_start, header_start + 16, 4)
    )

    terminator_at = next(
        (
            offset
            for offset in range(path_offset, len(payload) - 1, 2)
            if payload[offset : offset + 2] == b"\0\0"
        ),
        None,
    )
    if terminator_at is None:
        raise ValueError(
            "VFILE corpus profile: UTF-16LE path has no aligned NUL terminator"
        )
    path_raw = payload[path_offset:terminator_at]
    terminator_end = terminator_at + 2
    tail_raw = payload[terminator_end:]
    repeated_words = tuple(
        int.from_bytes(repeated_raw[offset : offset + 8], "little")
        for offset in (0, 8, 16)
    )

    return VFilePayload(
        raw=payload,
        signature_type=signature_type,
        outer_prefix=outer_prefix,
        inner_header_word=inner_header_word,
        repeated_raw=repeated_raw,
        repeated_words=repeated_words,
        header_words=header_words,
        path_offset=path_offset,
        path_raw=path_raw,
        path_terminator=payload[terminator_at:terminator_end],
        tail_raw=tail_raw,
        corpus_profile="observed VFILE/VFILEEX shared layout",
    )


def parse_vfile(payload: bytes) -> VFilePayload:
    """Parse the observed 0x83 corpus profile, without validating engine schema."""
    return _parse(payload, VFILE_TYPE)


def parse_vfileex(payload: bytes) -> VFilePayload:
    """Parse the observed 0xB2 corpus profile with its variable u32 prefix."""
    return _parse(payload, VFILEEX_TYPE)


def _hex_preview(data: bytes, limit: int) -> str:
    preview = data[:limit].hex(" ").upper() or "(empty)"
    if len(data) > limit:
        preview += f" … (+{len(data) - limit} B)"
    return preview


def render_vfile(parsed: VFilePayload) -> FormatResult:
    """Render corpus observations with fixed bounds for every raw/string preview."""
    path = parsed.path
    path_preview = ascii(path[:_PATH_PREVIEW_CHARS])
    if len(path) > _PATH_PREVIEW_CHARS:
        path_preview += f" … (+{len(path) - _PATH_PREVIEW_CHARS} more chars)"

    fields = [
        ("profile", parsed.corpus_profile),
        ("signature_type", f"0x{parsed.signature_type:02X}"),
        ("payload_size", f"{len(parsed.raw)} B"),
        ("inner_header_word", f"0x{parsed.inner_header_word:08X}"),
        ("path_offset", f"0x{parsed.path_offset:X}"),
        ("path_chars", str(len(path))),
        ("path_raw_size", f"{len(parsed.path_raw)} B"),
        ("tail_size", f"{len(parsed.tail_raw)} B"),
    ]
    if parsed.outer_prefix is not None:
        fields.insert(2, ("outer_prefix", f"0x{parsed.outer_prefix:08X}"))

    section_rows = [
        ("path", path_preview),
        ("path_raw_preview", _hex_preview(parsed.path_raw, _RAW_PREVIEW_BYTES)),
        ("path_terminator", parsed.path_terminator.hex(" ").upper()),
        (
            "repeated_24b_preview",
            _hex_preview(parsed.repeated_raw, _RAW_PREVIEW_BYTES),
        ),
        (
            "header_words_u32le",
            ", ".join(f"0x{word:08X}" for word in parsed.header_words),
        ),
        ("tail_raw_preview", _hex_preview(parsed.tail_raw, _TAIL_PREVIEW_BYTES)),
    ]
    return FormatResult(
        fields=tuple(fields),
        sections=(
            DisplaySection("VFILE-like payload (corpus profile)", tuple(section_rows)),
        ),
    )


VFILE_SPEC = FamilySpec(VFILE_TYPE, "VFILE", parse_vfile, render_vfile)
VFILEEX_SPEC = FamilySpec(VFILEEX_TYPE, "VFILEEX", parse_vfileex, render_vfile)

__all__ = [
    "VFILEEX_SPEC",
    "VFILEEX_TYPE",
    "VFILE_SPEC",
    "VFILE_TYPE",
    "VFilePayload",
    "parse_vfile",
    "parse_vfileex",
    "render_vfile",
]
