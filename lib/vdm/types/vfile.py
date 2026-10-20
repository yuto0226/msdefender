"""Lossless receiver-framing view for VFILE (0x83) and VFILEEX (0xB2)."""

from dataclasses import dataclass
from typing import Final

from ..core import DisplaySection, FamilySpec, FormatResult

VFILE_TYPE: Final = 0x83
VFILEEX_TYPE: Final = 0xB2
_ENTRY_STRIDE: Final = 592
_ENTRY_PREFIX_SIZE: Final = 44
_ENTRY_PATH_FIELD_SIZE: Final = 0x208
_MAX_ENTRY_COUNT: Final = 0x6EB3E4
_PATH_PREVIEW_CHARS: Final = 80
_RAW_PREVIEW_BYTES: Final = 24
_TAIL_PREVIEW_BYTES: Final = 16


@dataclass(frozen=True, slots=True)
class VFilePayload:
    """Receiver-bounded field view; unconfirmed fields remain raw observations."""

    raw: bytes
    signature_type: int
    entry_count: int
    entries_raw: bytes
    entry_prefix_raw: bytes | None
    path_offset: int | None
    path_raw: bytes | None
    path_terminator: bytes | None
    path_terminated: bool | None
    tail_raw: bytes

    @property
    def path(self) -> str | None:
        """Decode the first entry's bounded UTF-16LE NUL-terminated candidate."""
        if not self.path_terminated or self.path_raw is None:
            return None
        return self.path_raw.decode("utf-16le", errors="surrogatepass")


def _parse(payload: bytes, signature_type: int) -> VFilePayload:
    if signature_type == VFILE_TYPE:
        prefix_size = 0
        entry_count = 1
    elif signature_type == VFILEEX_TYPE:
        if len(payload) < 4:
            raise ValueError(
                "VFILE receiver framing: truncated VFILEEX entry-count prefix; "
                "need 4 bytes"
            )
        prefix_size = 4
        entry_count = int.from_bytes(payload[:4], "little")
    else:
        raise ValueError(f"unsupported VFILE signature type: {signature_type:#x}")

    if entry_count > _MAX_ENTRY_COUNT:
        raise ValueError(
            "VFILE receiver framing: entry count exceeds receiver limit "
            f"({_MAX_ENTRY_COUNT:#x})"
        )

    entries_size = _ENTRY_STRIDE * entry_count
    tail_offset = prefix_size + entries_size
    if len(payload) <= tail_offset:
        raise ValueError(
            "VFILE receiver framing: receiver requires bytes beyond the entry "
            f"region ending at {tail_offset}; have {len(payload)}"
        )

    entries_raw = payload[prefix_size:tail_offset]
    first_entry = entries_raw[:_ENTRY_STRIDE] if entry_count else None
    if first_entry is None:
        entry_prefix_raw = None
        path_offset = None
        path_raw = None
        path_terminator = None
        path_terminated = None
    else:
        entry_prefix_raw = first_entry[:_ENTRY_PREFIX_SIZE]
        path_offset = prefix_size + _ENTRY_PREFIX_SIZE
        terminator_at = next(
            (
                offset
                for offset in range(0, _ENTRY_PATH_FIELD_SIZE, 2)
                if first_entry[
                    _ENTRY_PREFIX_SIZE + offset : _ENTRY_PREFIX_SIZE + offset + 2
                ]
                == b"\0\0"
            ),
            None,
        )
        path_terminated = terminator_at is not None
        path_raw = (
            first_entry[_ENTRY_PREFIX_SIZE : _ENTRY_PREFIX_SIZE + terminator_at]
            if path_terminated
            else first_entry[
                _ENTRY_PREFIX_SIZE : _ENTRY_PREFIX_SIZE + _ENTRY_PATH_FIELD_SIZE
            ]
        )
        path_terminator = b"\0\0" if path_terminated else b""
    tail_raw = payload[tail_offset:]

    return VFilePayload(
        raw=payload,
        signature_type=signature_type,
        entry_count=entry_count,
        entries_raw=entries_raw,
        entry_prefix_raw=entry_prefix_raw,
        path_offset=path_offset,
        path_raw=path_raw,
        path_terminator=path_terminator,
        path_terminated=path_terminated,
        tail_raw=tail_raw,
    )


def parse_vfile(payload: bytes) -> VFilePayload:
    """Parse the observed 0x83 receiver framing, not a complete engine schema."""
    return _parse(payload, VFILE_TYPE)


def parse_vfileex(payload: bytes) -> VFilePayload:
    """Parse the observed 0xB2 receiver framing with a u32 entry-count prefix."""
    return _parse(payload, VFILEEX_TYPE)


def _hex_preview(data: bytes, limit: int) -> str:
    preview = data[:limit].hex(" ").upper() or "(empty)"
    if len(data) > limit:
        preview += f" … (+{len(data) - limit} B)"
    return preview


def render_vfile(parsed: VFilePayload) -> FormatResult:
    """Render receiver-framing observations with bounded raw/string previews."""
    path = parsed.path
    path_preview = (
        "(no entries)"
        if parsed.entry_count == 0
        else "(no aligned NUL within bounded 520-byte field)"
        if path is None
        else ascii(path[:_PATH_PREVIEW_CHARS])
    )
    if path is not None and len(path) > _PATH_PREVIEW_CHARS:
        path_preview += f" … (+{len(path) - _PATH_PREVIEW_CHARS} more chars)"

    fields = [
        ("profile", "engine-confirmed VFILE/VFILEEX receiver framing"),
        ("signature_type", f"0x{parsed.signature_type:02X}"),
        ("payload_size", f"{len(parsed.raw)} B"),
        ("entry_count", str(parsed.entry_count)),
        ("entry_region_size", f"{len(parsed.entries_raw)} B"),
        ("tail_size", f"{len(parsed.tail_raw)} B"),
    ]
    section_rows = []
    if parsed.entry_count:
        fields.extend(
            (
                ("path_candidate_offset", f"0x{parsed.path_offset:X}"),
                ("path_chars", str(len(path)) if path is not None else "unknown"),
                ("path_raw_size", f"{len(parsed.path_raw)} B"),
                (
                    "path_terminated_within_520B",
                    str(parsed.path_terminated),
                ),
            )
        )
        section_rows.extend(
            (
                ("path_candidate", path_preview),
                ("path_raw_preview", _hex_preview(parsed.path_raw, _RAW_PREVIEW_BYTES)),
                (
                    "path_terminator_candidate",
                    parsed.path_terminator.hex(" ").upper()
                    if parsed.path_terminator is not None
                    else "",
                ),
                (
                    "entry_prefix_preview",
                    _hex_preview(parsed.entry_prefix_raw, _RAW_PREVIEW_BYTES),
                ),
            )
        )

    section_rows.append(
        ("tail_raw_preview", _hex_preview(parsed.tail_raw, _TAIL_PREVIEW_BYTES))
    )
    return FormatResult(
        fields=tuple(fields),
        sections=(
            DisplaySection("VFILE receiver-framed payload", tuple(section_rows)),
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
