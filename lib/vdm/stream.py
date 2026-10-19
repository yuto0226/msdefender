"""Streaming readers and threat grouping for VDM signature streams."""

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Literal

from .types.threat import (
    THREAT_BEGIN_TYPE,
    THREAT_END_TYPE,
    ThreatBegin,
    ThreatEnd,
    parse_threat_begin,
    parse_threat_end,
)


@dataclass(frozen=True, slots=True)
class WireRecord:
    offset: int
    type_byte: int
    payload: bytes
    raw: bytes

    @property
    def header_size(self) -> int:
        return len(self.raw) - len(self.payload)

    @property
    def size(self) -> int:
        return len(self.payload)


@dataclass(frozen=True, slots=True)
class ThreatBlock:
    begin: ThreatBegin
    begin_record: WireRecord
    records: tuple[WireRecord, ...]
    end: ThreatEnd | None = None
    end_record: WireRecord | None = None

    @property
    def id_matches(self) -> bool | None:
        if self.end is None:
            return None
        return self.begin.threat_id == self.end.threat_id

    def to_bytes(self) -> bytes:
        records = (self.begin_record, *self.records)
        if self.end_record is not None:
            records += (self.end_record,)
        return b"".join(record.raw for record in records)


BlockReason = Literal["nested_begin", "unterminated", "id_mismatch"]


@dataclass(frozen=True, slots=True)
class ThreatBlockEvent:
    block: ThreatBlock
    reason: BlockReason | None = None


@dataclass(frozen=True, slots=True)
class OrphanRecordEvent:
    record: WireRecord


@dataclass(frozen=True, slots=True)
class UnmatchedEndEvent:
    record: WireRecord


type StreamEvent = ThreatBlockEvent | OrphanRecordEvent | UnmatchedEndEvent


def _read_exact(stream: BinaryIO, size: int) -> bytes:
    """Accumulate short reads until size bytes arrive or the stream reaches EOF."""
    chunks = bytearray()
    while len(chunks) < size:
        chunk = stream.read(size - len(chunks))
        if not chunk:
            break
        chunks.extend(chunk)
    return bytes(chunks)


def iter_wire_records(source: Path | BinaryIO) -> Iterator[WireRecord]:
    """Read records incrementally from a path or binary file-like object."""
    owns_stream = isinstance(source, Path)
    stream = source.open("rb") if owns_stream else source
    offset = 0
    try:
        while header := _read_exact(stream, 4):
            if len(header) != 4:
                raise ValueError(f"truncated record header at offset 0x{offset:X}")
            type_byte = header[0]
            size = int.from_bytes(header[1:4], "little")
            raw_header = header
            if size == 0xFFFFFF:
                extended = _read_exact(stream, 4)
                if len(extended) != 4:
                    raise ValueError(
                        f"truncated extended record header at offset 0x{offset:X}"
                    )
                raw_header += extended
                size = int.from_bytes(extended, "little")
            payload = _read_exact(stream, size)
            if len(payload) != size:
                raise ValueError(
                    f"truncated record payload at offset 0x{offset:X}: "
                    f"expected {size} bytes, got {len(payload)}"
                )
            raw = raw_header + payload
            yield WireRecord(offset, type_byte, payload, raw)
            offset += len(raw)
    finally:
        if owns_stream:
            stream.close()


def iter_threat_events(source: Path | BinaryIO) -> Iterator[StreamEvent]:
    """Group records while yielding out-of-block records in original order."""
    begin_record: WireRecord | None = None
    begin: ThreatBegin | None = None
    interior: list[WireRecord] = []

    def make_block(end: ThreatEnd | None = None, end_record: WireRecord | None = None):
        assert begin_record is not None and begin is not None
        return ThreatBlock(begin, begin_record, tuple(interior), end, end_record)

    for record in iter_wire_records(source):
        if record.type_byte == THREAT_BEGIN_TYPE:
            if begin_record is not None:
                yield ThreatBlockEvent(make_block(), reason="nested_begin")
            begin = parse_threat_begin(record.payload)
            begin_record = record
            interior = []
        elif record.type_byte == THREAT_END_TYPE:
            end = parse_threat_end(record.payload)
            if begin_record is None:
                yield UnmatchedEndEvent(record)
            else:
                yield ThreatBlockEvent(
                    make_block(end, record),
                    reason="id_mismatch" if begin.threat_id != end.threat_id else None,
                )
                begin_record = None
                begin = None
                interior = []
        elif begin_record is None:
            yield OrphanRecordEvent(record)
        else:
            interior.append(record)

    if begin_record is not None:
        yield ThreatBlockEvent(make_block(), reason="unterminated")
