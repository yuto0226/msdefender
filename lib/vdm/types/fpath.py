"""Lossless parser for Defender's shared file path signature family."""

import json
from collections.abc import Callable
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final, Literal

from ..core import (
    DisplaySection,
    FamilySpec,
    FormatResult,
    JSONObject,
    RuleSemantics,
    SemanticIssue,
)

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


def _wire_field(kind: str, raw: bytes, offset: int) -> JSONObject:
    return JSONObject(
        (
            ("kind", kind),
            ("raw_span", JSONObject((("offset", offset), ("length", len(raw))))),
            ("raw_hex", raw.hex()),
        )
    )


def export_fpath_semantics(parsed: FpathPayload) -> RuleSemantics:
    """Export the receiver-confirmed path storage subset, preserving opaque bytes."""
    type_name = FPATH_TYPES[parsed.type_byte]
    is_asep = parsed.type_byte in {0x71, 0x75}
    path_offset = HEADER_SIZE
    path_end = path_offset + len(parsed.path_region_raw)
    pipe_suffix = (
        b""
        if parsed.pipe_offset is None
        else parsed.path_region_raw[parsed.pipe_offset :]
    )
    issues = [
        SemanticIssue(
            "path_match_and_verdict_unknown",
            "This receiver analysis does not establish path matching or final verdict semantics.",
        ),
        SemanticIssue(
            "csidl_mapping_result_unknown",
            "The CSIDL value is passed to CSIDL_2_ix; the resulting runtime index is not encoded here.",
        ),
    ]
    if parsed.pipe_offset is not None:
        issues.append(
            SemanticIssue(
                "pcode_boundary_payload_not_exported",
                "FILEPATH uses the first pipe as the stored-path boundary; the "
                "following PCode/RecID input is preserved but not interpreted.",
                (
                    ("offset", path_offset + parsed.pipe_offset),
                    ("length", len(pipe_suffix)),
                ),
            )
        )
    if parsed.tail_raw:
        issues.append(
            SemanticIssue(
                "pcode_tail_not_exported",
                "Bytes after NUL are sent to createrecidp; their program and "
                "record-identity semantics are not exported.",
                (("length", len(parsed.tail_raw)),),
            )
        )
    evidence = (
        f"mpengine 1.443.903.0 {type_name} receiver registration and storage wrapper",
        "mpengine 1.443.903.0 shared FILEPATH/FOLDERNAME receiver path handling",
        "mpengine 1.443.903.0 CSIDL_2_ix mapping call",
    )
    return RuleSemantics(
        status="unsupported" if parsed.tail_raw or pipe_suffix else "confirmed_subset",
        representation="fpath.receiver-storage.ir.v1",
        data=JSONObject(
            (
                ("type", type_name),
                ("raw_hex", parsed.raw.hex()),
                ("storage_family", "asep" if is_asep else "standard"),
                (
                    "csidl",
                    JSONObject(
                        (
                            ("value", parsed.csidl_value),
                            ("wire", _wire_field("csidl_value", parsed.raw[:2], 0)),
                            ("consumer", "CSIDL_2_ix"),
                        )
                    ),
                ),
                (
                    "path",
                    JSONObject(
                        (
                            ("kind", parsed.path_kind),
                            (
                                "wire",
                                _wire_field(
                                    "path_region", parsed.path_region_raw, path_offset
                                ),
                            ),
                            ("bytes_hex", parsed.path_bytes.hex()),
                            ("nul_terminated", parsed.nul_terminated),
                            (
                                "terminator",
                                None
                                if not parsed.nul_terminated
                                else _wire_field(
                                    "nul_terminator",
                                    parsed.raw[
                                        parsed.nul_offset
                                        + path_offset : parsed.nul_offset
                                        + path_offset
                                        + 1
                                    ],
                                    parsed.nul_offset + path_offset,
                                ),
                            ),
                            (
                                "runtime_bytes_hex",
                                parsed.runtime_path_bytes.hex(),
                            ),
                            (
                                "normalization",
                                "append_backslash_if_nonempty_and_missing"
                                if parsed.path_kind == "foldername"
                                else "none_confirmed",
                            ),
                            (
                                "wildcard_detection",
                                JSONObject(
                                    (
                                        ("consumer", "ResutilsStrHasWildcards"),
                                        ("input", "runtime_bytes"),
                                        (
                                            "stored_effect",
                                            "set_bit_31_of_csidl_index",
                                        ),
                                    )
                                ),
                            ),
                            (
                                "pcode_boundary_payload",
                                None
                                if parsed.pipe_offset is None
                                else _wire_field(
                                    "pcode_boundary_payload",
                                    pipe_suffix,
                                    path_offset + parsed.pipe_offset,
                                ),
                            ),
                        )
                    ),
                ),
                (
                    "pcode_tail",
                    JSONObject(
                        (
                            (
                                "wire",
                                _wire_field(
                                    "pcode_tail",
                                    parsed.tail_raw,
                                    path_end + 1 if parsed.nul_terminated else path_end,
                                ),
                            ),
                            (
                                "receiver_path",
                                "createrecidp" if parsed.tail_raw else "createrecid",
                            ),
                            ("meaning", None),
                        )
                    ),
                ),
            )
        ),
        evidence=evidence,
        profile="mpengine-1.443.903.0",
        issues=tuple(issues),
    )


def _parser_for(type_byte: int) -> Callable[[bytes], FpathPayload]:
    def parser(payload: bytes) -> FpathPayload:
        return parse_fpath(payload, type_byte=type_byte)

    return parser


FPATH_SPECS = tuple(
    FamilySpec(
        type_byte,
        name,
        _parser_for(type_byte),
        render_fpath,
        semantic_exporter=export_fpath_semantics,
    )
    for type_byte, name in FPATH_TYPES.items()
)
