"""Shared record-parsing utilities for Microsoft Defender .sig tools."""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Iterator

from lib.debug import warn


# ── Wire-format record iterator (in-memory) ──────────────────────────────── #

def iter_records(stream: bytes) -> Iterator[tuple[int, bytes]]:
    """Yield (type_byte, payload_bytes) for every record in a byte buffer.

    Record wire format:
        [type: 1B] [size: 3B LE] [payload: size B]

    Extended size (size == 0xFFFFFF):
        [type: 1B] [0xFF 0xFF 0xFF] [real_size: 4B LE] [payload: real_size B]
    """
    pos = 0
    end = len(stream)

    while pos + 4 <= end:
        type_byte = stream[pos]
        size = stream[pos+1] | (stream[pos+2] << 8) | (stream[pos+3] << 16)

        if size == 0xFFFFFF:
            if pos + 8 > end:
                break
            size = struct.unpack_from("<I", stream, pos + 4)[0]
            data_off = pos + 8
        else:
            data_off = pos + 4

        yield type_byte, stream[data_off : data_off + size]
        pos = data_off + size


# ── Wire-format record iterator (streaming, memory-efficient) ─────────────── #

def iter_records_from_file(path: Path) -> Iterator[tuple[int, bytes]]:
    """Yield (type_byte, payload_bytes) by streaming a .sig file.

    Does not load the entire file into memory — suitable for mpas.sig (271 MB).
    """
    with path.open("rb") as f:
        while True:
            hdr = f.read(4)
            if not hdr:
                break
            if len(hdr) < 4:
                warn("truncated record header at EOF")
                break

            type_byte = hdr[0]
            size = hdr[1] | (hdr[2] << 8) | (hdr[3] << 16)

            if size == 0xFFFFFF:
                ext = f.read(4)
                if len(ext) < 4:
                    warn("truncated extended-size header at EOF")
                    break
                size = struct.unpack("<I", ext)[0]

            payload = f.read(size)
            if len(payload) < size:
                warn("truncated payload at EOF (expected %d, got %d)", size, len(payload))
                break

            yield type_byte, payload


# ── Contextual iterator: tracks current threat ───────────────────────────── #
SIG_THREAT_BEGIN = 0x5C
SIG_THREAT_END   = 0x5D


def iter_records_with_context(
    path: Path,
) -> Iterator[tuple[int, bytes, str, int]]:
    """Yield (type_byte, payload, threat_name, sig_index) for every record.

    threat_name  — name of the enclosing THREAT_BEGIN block, or "" for orphans
    sig_index    — 0-based index of the record within its threat block
                   (THREAT_BEGIN itself is index 0)
    """
    from lib.threat import parse_threat_name   # local import to avoid circularity

    current_name = ""
    sig_idx = 0

    for type_byte, payload in iter_records_from_file(path):
        if type_byte == SIG_THREAT_BEGIN:
            current_name = parse_threat_name(payload)
            sig_idx = 0
            yield type_byte, payload, current_name, sig_idx
        elif type_byte == SIG_THREAT_END:
            yield type_byte, payload, current_name, sig_idx
            current_name = ""
            sig_idx = 0
        else:
            sig_idx += 1
            yield type_byte, payload, current_name, sig_idx
