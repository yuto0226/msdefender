"""Lossless parser for Defender's shared file path signature family."""

import json
from collections.abc import Callable
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final, Literal

from ..core import DisplaySection, FamilySpec, FormatResult

FPATH_TYPES: Final = MappingProxyType(
    {
        0x5F: "FILEPATH",
        0x60: "FOLDERNAME",
        0x71: "ASEP_FILEPATH",
        0x75: "ASEP_FOLDERNAME",
    }
)
FILEPATH_TYPES: Final = frozenset({0x5F, 0x71})
FOLDERNAME_TYPES: Final = frozenset({0x60, 0x75})
HEADER_SIZE: Final = 2


@dataclass(frozen=True, slots=True)
class FpathPayload:
    """Parsed fields for a FILEPATH family payload, retaining every byte."""

    raw: bytes
    type_byte: int
    csidl_value: int
    path_kind: Literal["filepath", "foldername"]
    path_region_raw: bytes
    path_bytes: bytes
    runtime_path_bytes: bytes
    nul_terminated: bool
    nul_offset: int | None
    pipe_offset: int | None
    tail_raw: bytes

    @property
    def path_text(self) -> str:
        """Return a reversible single-byte view without assuming UTF-16LE."""
        return self.path_bytes.decode("latin-1")


def parse_fpath(payload: bytes, *, type_byte: int) -> FpathPayload:
    """Parse the type-specific path or folder record envelope losslessly."""
    try:
        FPATH_TYPES[type_byte]
    except KeyError as exc:
        raise ValueError(f"unsupported FPATH family type 0x{type_byte:02X}") from exc

    if len(payload) <= HEADER_SIZE:
        raise ValueError(
            "truncated FPATH path data: need at least 1 byte after the "
            f"{HEADER_SIZE}-byte header, have {len(payload) - HEADER_SIZE}"
        )

    csidl_value = int.from_bytes(payload[:HEADER_SIZE], "little")
    path_kind = "filepath" if type_byte in FILEPATH_TYPES else "foldername"
    path_and_tail = payload[HEADER_SIZE:]
    nul_offset = path_and_tail.find(b"\0")
    nul_terminated = nul_offset >= 0

    if nul_terminated:
        path_region_raw = path_and_tail[:nul_offset]
        tail_raw = path_and_tail[nul_offset + 1 :]
    else:
        path_region_raw = path_and_tail
        tail_raw = b""

    pipe_offset = path_region_raw.find(b"|") if path_kind == "filepath" else -1
    path_bytes = path_region_raw if pipe_offset < 0 else path_region_raw[:pipe_offset]
    runtime_path_bytes = path_bytes
    if (
        path_kind == "foldername"
        and runtime_path_bytes
        and not runtime_path_bytes.endswith(b"\\")
    ):
        runtime_path_bytes += b"\\"

    return FpathPayload(
        raw=payload,
        type_byte=type_byte,
        csidl_value=csidl_value,
        path_kind=path_kind,
        path_region_raw=path_region_raw,
        path_bytes=path_bytes,
        runtime_path_bytes=runtime_path_bytes,
        nul_terminated=nul_terminated,
        nul_offset=None if not nul_terminated else nul_offset,
        pipe_offset=None if pipe_offset < 0 else pipe_offset,
        tail_raw=tail_raw,
    )


def render_fpath(parsed: FpathPayload) -> FormatResult:
    """Render known path fields and opaque tail lengths as logger sections."""
    name = FPATH_TYPES[parsed.type_byte]
    path_rows = (
        ("csidl_value", f"0x{parsed.csidl_value:04X}"),
        ("path_len", f"{len(parsed.path_bytes)} B"),
        (
            "path",
            json.dumps(parsed.path_text, ensure_ascii=True)
            if parsed.path_bytes
            else "(empty)",
        ),
        (
            "path_terminator",
            "NUL" if parsed.nul_terminated else "absent (payload boundary)",
        ),
    )

    if parsed.path_kind == "foldername":
        path_rows += (
            (
                "runtime_path",
                json.dumps(
                    parsed.runtime_path_bytes.decode("latin-1"),
                    ensure_ascii=True,
                ),
            ),
            ("normalization", "append '\\' when absent"),
        )

    if parsed.pipe_offset is not None:
        path_rows += (
            ("pipe_offset", str(parsed.pipe_offset)),
            (
                "pipe_suffix_len",
                f"{len(parsed.path_region_raw) - parsed.pipe_offset - 1} B",
            ),
        )

    sections = [
        DisplaySection("Path", rows=path_rows),
        DisplaySection(
            "Opaque Tail",
            rows=(("tail_len", f"{len(parsed.tail_raw)} B"),),
        ),
        DisplaySection(
            "Record Type",
            rows=(("type", f"{name} (0x{parsed.type_byte:02X})"),),
        ),
    ]
    return FormatResult(sections=tuple(sections))


def _parser_for(type_byte: int) -> Callable[[bytes], FpathPayload]:
    def parser(payload: bytes) -> FpathPayload:
        return parse_fpath(payload, type_byte=type_byte)

    return parser


FPATH_SPECS = tuple(
    FamilySpec(type_byte, name, _parser_for(type_byte), render_fpath)
    for type_byte, name in FPATH_TYPES.items()
)
