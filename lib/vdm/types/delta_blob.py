"""Parser for the observed DELTA_BLOB (0x73) patch stream."""

from __future__ import annotations

import zlib
from dataclasses import dataclass
from typing import BinaryIO, Final

from ..core import (
    DisplaySection,
    FamilySpec,
    FormatResult,
    JSONArray,
    JSONObject,
    RuleSemantics,
    SemanticIssue,
)
from ._semantic_claims import scoped_claim

DELTA_BLOB_TYPE: Final = 0x73
HEADER_SIZE: Final = 8
LITERAL_PREVIEW_LIMIT: Final = 16


@dataclass(frozen=True, slots=True)
class DeltaBlobCommand:
    """One literal or source-copy operation in a DELTA_BLOB stream."""

    kind: str
    command_offset: int
    output_length: int
    data_offset: int | None = None
    source_offset: int | None = None


@dataclass(frozen=True, slots=True)
class DeltaBlob:
    """Observed output header and parsed patch commands."""

    raw: bytes
    expected_output_size: int
    expected_output_crc32: int
    source_size: int | None
    source_offset_width: int
    commands: tuple[DeltaBlobCommand, ...]
    literal_bytes: int
    copied_bytes: int

    @property
    def output_size(self) -> int:
        return self.literal_bytes + self.copied_bytes


def parse_delta_blob(
    payload: bytes,
    *,
    source_size: int | None = None,
    source_offset_width: int | None = None,
    input_size: int | None = None,
) -> DeltaBlob:
    """Parse the observed size/CRC header and literal/copy command stream.

    Engine evidence shows that it selects three-byte offsets iff both its
    expected output size and external input-length argument are below 16 MiB.
    The declared output size alone selects four-byte offsets at or above that
    threshold. Below it, ``input_size`` selects the engine width when supplied;
    otherwise both grammars are tried and the unique parse reaching EOF with
    the declared output size is used. ``source_size`` separately enables
    copy-range checks.
    Literal bytes stay represented by offsets into ``raw``; this parser does
    not reconstruct or allocate the output stream.
    """
    if len(payload) < HEADER_SIZE:
        raise ValueError("truncated DELTA_BLOB header")
    if source_size is not None and source_size < 0:
        raise ValueError("source_size must be nonnegative")
    if source_offset_width is not None and source_offset_width not in (3, 4):
        raise ValueError("source_offset_width must be 3 or 4")
    if input_size is not None and input_size < 0:
        raise ValueError("input_size must be nonnegative")

    expected_output_size = int.from_bytes(payload[:4], "little")
    engine_width: int | None = None
    if expected_output_size >= 0x1000000:
        engine_width = 4
    elif input_size is not None:
        engine_width = 3 if max(expected_output_size, input_size) < 0x1000000 else 4
    selected_width = (
        source_offset_width if source_offset_width is not None else engine_width
    )
    widths = (selected_width,) if selected_width is not None else (3, 4)
    valid_widths: list[int] = []
    errors: list[ValueError] = []
    for width in widths:
        try:
            _parse_with_width(payload, source_size, width, materialize_commands=False)
            valid_widths.append(width)
        except ValueError as error:
            errors.append(error)
    if len(valid_widths) == 1:
        return _parse_with_width(payload, source_size, valid_widths[0])
    if len(valid_widths) > 1:
        raise ValueError("ambiguous DELTA_BLOB source offset width")
    raise errors[0]


def _parse_with_width(
    payload: bytes,
    source_size: int | None,
    offset_width: int,
    *,
    materialize_commands: bool = True,
) -> DeltaBlob:
    expected_output_size = int.from_bytes(payload[0:4], "little")
    expected_output_crc32 = int.from_bytes(payload[4:8], "little")
    pos = HEADER_SIZE
    literal_bytes = 0
    copied_bytes = 0
    commands: list[DeltaBlobCommand] = []
    command_count = 0
    max_command_count = (len(payload) - HEADER_SIZE) // 2

    while pos < len(payload):
        command_start = pos
        if command_count >= max_command_count:
            raise ValueError("DELTA_BLOB command count exceeds stream bounds")
        command_offset = pos
        if len(payload) - pos < 2:
            raise ValueError("truncated DELTA_BLOB command")
        control = int.from_bytes(payload[pos : pos + 2], "little")
        pos += 2

        if control & 0x8000:
            length = (control & 0x7FFF) + 6
            if len(payload) - pos < offset_width:
                raise ValueError("truncated DELTA_BLOB copy offset")
            source_offset = int.from_bytes(payload[pos : pos + offset_width], "little")
            pos += offset_width
            if source_size is not None and (
                source_offset > source_size or length > source_size - source_offset
            ):
                raise ValueError("DELTA_BLOB copy exceeds source bounds")
            copied_bytes += length
            if materialize_commands:
                commands.append(
                    DeltaBlobCommand(
                        kind="copy",
                        command_offset=command_offset,
                        output_length=length,
                        source_offset=source_offset,
                    )
                )
        else:
            length = control
            if length > len(payload) - pos:
                raise ValueError("truncated DELTA_BLOB literal")
            literal_bytes += length
            if materialize_commands:
                commands.append(
                    DeltaBlobCommand(
                        kind="literal",
                        command_offset=command_offset,
                        output_length=length,
                        data_offset=pos,
                    )
                )
            pos += length

        if pos <= command_start:
            raise ValueError("DELTA_BLOB command parser made no progress")
        command_count += 1

        if literal_bytes + copied_bytes > expected_output_size:
            raise ValueError("DELTA_BLOB commands exceed expected output size")

    if literal_bytes + copied_bytes != expected_output_size:
        raise ValueError("DELTA_BLOB output size does not match header")

    return DeltaBlob(
        raw=payload,
        expected_output_size=expected_output_size,
        expected_output_crc32=expected_output_crc32,
        source_size=source_size,
        source_offset_width=offset_width,
        commands=tuple(commands),
        literal_bytes=literal_bytes,
        copied_bytes=copied_bytes,
    )


def compute_delta_blob_output_crc32(
    parsed: DeltaBlob, source: BinaryIO, *, chunk_size: int = 1 << 20
) -> int:
    """Compute the engine's raw CRC32 over reconstructed bytes, without output.

    ``source`` must be seekable and contain the referenced copy-source bytes.
    The engine's CRC routine starts from ``0xFFFFFFFF`` and returns the raw
    accumulator, which is the bitwise complement of ``zlib.crc32(..., 0)``.
    """
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")

    crc = 0
    for command in parsed.commands:
        if command.kind == "literal":
            assert command.data_offset is not None
            data = parsed.raw[
                command.data_offset : command.data_offset + command.output_length
            ]
            crc = zlib.crc32(data, crc)
            continue

        assert command.source_offset is not None
        source.seek(command.source_offset)
        remaining = command.output_length
        while remaining:
            data = source.read(min(remaining, chunk_size))
            if not data:
                raise ValueError("truncated DELTA_BLOB source data")
            crc = zlib.crc32(data, crc)
            remaining -= len(data)

    return (~crc) & 0xFFFFFFFF


def render_delta_blob(parsed: DeltaBlob) -> FormatResult:
    """Render a bounded command summary and preview."""
    rows = [
        ("output_size", str(parsed.expected_output_size)),
        ("output_crc32", f"0x{parsed.expected_output_crc32:08X}"),
        (
            "source_size",
            "unspecified" if parsed.source_size is None else str(parsed.source_size),
        ),
        ("source_offset_width", str(parsed.source_offset_width)),
        ("commands", str(len(parsed.commands))),
        ("literal_bytes", str(parsed.literal_bytes)),
        ("copied_bytes", str(parsed.copied_bytes)),
    ]
    for index, command in enumerate(parsed.commands[:LITERAL_PREVIEW_LIMIT]):
        detail = (
            f"data_offset=0x{command.data_offset:X}"
            if command.kind == "literal"
            else f"source_offset=0x{command.source_offset:X}"
        )
        rows.append(
            (
                f"command[{index}]",
                f"{command.kind} len={command.output_length} {detail}",
            )
        )
    if len(parsed.commands) > LITERAL_PREVIEW_LIMIT:
        rows.append(
            ("commands_omitted", str(len(parsed.commands) - LITERAL_PREVIEW_LIMIT))
        )
    return FormatResult(sections=(DisplaySection("DELTA_BLOB", rows=tuple(rows)),))


def export_delta_blob_semantics(parsed: DeltaBlob) -> RuleSemantics:
    """Export the complete observed patch program without calling it a rule."""
    claim, claim_evidence = scoped_claim(
        "delta_blob",
        "patch_artifact",
        "runtime_consumer",
        "The consumer interprets framed commands as a compressed input patch artifact and exposes expected output size and CRC metadata.",
        "This does not establish detection semantics, codec semantics beyond observed framing, or a final verdict.",
        "consumer",
        "DispatchRecords @ 0x1800F99A8; ConsumeInputCompressed @ 0x1800D9ED0",
    )
    commands = JSONArray(
        tuple(
            JSONObject(
                (
                    ("index", index),
                    ("command_offset", command.command_offset),
                    ("operation", command.kind),
                    ("output_length", command.output_length),
                    ("literal_data_offset", command.data_offset),
                    ("source_offset", command.source_offset),
                )
            )
            for index, command in enumerate(parsed.commands)
        )
    )
    return RuleSemantics(
        status="confirmed_subset",
        representation="delta_blob.patch_artifact.v1",
        data=JSONObject(
            (
                ("record_type", "DELTA_BLOB"),
                ("role", "compressed_input_patch_artifact"),
                (
                    "wire",
                    JSONObject(
                        (
                            ("raw_hex", parsed.raw.hex()),
                            ("header_size", HEADER_SIZE),
                            ("expected_output_size", parsed.expected_output_size),
                            ("expected_output_crc32_raw", parsed.expected_output_crc32),
                            ("source_offset_width", parsed.source_offset_width),
                            ("command_stream_consumed_to_eof", True),
                        )
                    ),
                ),
                (
                    "application",
                    JSONObject(
                        (
                            ("operation", "copy_from_source_or_inline_literal"),
                            ("source_size", parsed.source_size),
                            ("reconstruction_performed", False),
                            ("commands", commands),
                        )
                    ),
                ),
                (
                    "integrity",
                    JSONObject(
                        (
                            ("declared_output_size_matches_command_total", True),
                            ("copy_ranges_checked", parsed.source_size is not None),
                            ("crc32_status", "not_verified_without_source"),
                            (
                                "crc32_algorithm",
                                "raw CRC32; initial 0xFFFFFFFF; no final XOR",
                            ),
                        )
                    ),
                ),
                (
                    "detection_relevance",
                    "patch artifact; not a detection predicate or rule",
                ),
                (
                    "command_totals",
                    JSONObject(
                        (
                            ("count", len(parsed.commands)),
                            ("literal_bytes", parsed.literal_bytes),
                            ("copied_bytes", parsed.copied_bytes),
                        )
                    ),
                ),
            )
        ),
        evidence=(
            (
                "mpengine 1.443.903.0 DispatchRecords @ 0x1800F99A8 stores the "
                "0x73 payload as the compressed input block"
            ),
            (
                "mpengine 1.443.903.0 DispatchProxy::ConsumeInputCompressed "
                "@ 0x1800D9ED0 consumes the block using the exported literal/copy "
                "grammar, output-size checks, and CRC update"
            ),
        ),
        profile="mpengine-1.443.903.0",
        issues=(
            SemanticIssue(
                "source_required_for_crc_verification",
                (
                    "The expected CRC covers reconstructed bytes; no source bytes "
                    "were supplied to this semantic exporter."
                ),
                (("expected_crc32_raw", parsed.expected_output_crc32),),
            ),
        ),
        claims=(claim,),
        claim_evidence=(claim_evidence,),
    )


SPEC = FamilySpec(
    DELTA_BLOB_TYPE,
    "DELTA_BLOB",
    parse_delta_blob,
    render_delta_blob,
    semantic_exporter=export_delta_blob_semantics,
)
