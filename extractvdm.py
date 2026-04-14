#!/usr/bin/env python3
"""
extractsig.py - Extract and merge signatures from VDM files.

Reads one or more .vdm files, extracts the decompressed signature record
stream from each, and concatenates them into a single .sig file.

Usage:
    python extractsig.py <file.vdm> [file.vdm ...] [-o output.sig]

Examples:
    python extractsig.py mpavbase.vdm mpavdlta.vdm
    python extractsig.py mpavbase.vdm
    python extractsig.py mpavdlta.vdm -o delta_only.sig
"""

from __future__ import annotations

import argparse
import struct
import zlib
from pathlib import Path

from lib.debug import error, debug, info, ok, warn

# RMDX header constants
RMDX_MAGIC = 0x58444D52  # b'RMDX' little-endian
RMDX_FLAG_COMPRESSED = 0x02  # bit1: zlib compressed
RMDX_FLAG_VERIFIED = 0x200000  # bit21: must be set

_RMDX_HEADER_FIELDS = (
    (0x00, "magic"),
    (0x04, "version"),
    (0x0C, "flags"),
    (0x18, "data_rel_off"),
    (0x1C, "uncomp_size"),
)

# Suffixes to strip when deriving output name
_VDM_SUFFIXES = ("base", "dlta")


def _find_rmdx_offset(data: bytes) -> int:
    """Locate the RMDX header by scanning for its magic bytes."""
    idx = data.find(b"RMDX")
    if idx == -1:
        raise ValueError("RMDX magic not found")
    return idx


def _parse_rmdx_header(data: bytes, rmdx_off: int) -> dict:
    """Unpack the 64-byte RMDX header starting at rmdx_off."""
    if rmdx_off + 0x40 > len(data):
        raise ValueError(f"File too short for RMDX header at 0x{rmdx_off:X}")

    words = struct.unpack_from("<16I", data, rmdx_off)
    magic, version, unk08, flags, unk10, unk14, data_rel_off, uncomp_size = words[:8]

    if magic != RMDX_MAGIC:
        raise ValueError(f"Bad RMDX magic: 0x{magic:08X}")
    if not (flags & RMDX_FLAG_VERIFIED):
        raise ValueError(f"RMDX flags 0x{flags:08X}: bit21 (verified) not set")

    return {
        "version": version,
        "flags": flags,
        "data_rel_off": data_rel_off,
        "uncomp_size": uncomp_size,
        "words": words,
    }


def _print_rmdx_header(hdr: dict, rmdx_off: int) -> None:
    """Print the full 64-byte RMDX header in a readable form."""
    flags = hdr["flags"]
    flag_bits = ["compressed" if (flags & RMDX_FLAG_COMPRESSED) else "plain"]
    flag_bits.append("verified" if (flags & RMDX_FLAG_VERIFIED) else "not verified")

    debug("[RMDX] header @ 0x%X(0x40 bytes)", rmdx_off)
    for offset, name in _RMDX_HEADER_FIELDS:
        value = hdr["words"][offset // 4]
        print(f"    +0x{offset:02x} {name:<12s} = 0x{value:08x}")

    debug("flags= %s", ", ".join(flag_bits))


def _extract_stream(data: bytes, rmdx_off: int, hdr: dict) -> bytes:
    """Read the data descriptor and decompress (or read plain) the payload."""
    flags = hdr["flags"]
    data_rel_off = hdr["data_rel_off"]
    uncomp_size = hdr["uncomp_size"]

    desc_off = rmdx_off + data_rel_off
    if desc_off + 8 > len(data):
        raise ValueError("File truncated before data descriptor")

    stream_size, _crc32 = struct.unpack_from("<II", data, desc_off)
    payload_off = desc_off + 8

    if payload_off + stream_size > len(data):
        raise ValueError(
            f"File truncated: need {stream_size} bytes at 0x{payload_off:X}, "
            f"have {len(data) - payload_off}"
        )

    payload = data[payload_off : payload_off + stream_size]

    if flags & RMDX_FLAG_COMPRESSED:
        # zlib-compressed; try standard header first, fall back to raw deflate
        try:
            decompressed = zlib.decompress(payload, wbits=15)
        except zlib.error:
            decompressed = zlib.decompress(payload, wbits=-15)
    else:
        # Plain / "scrambled": leading 4 bytes are a CRC seed, skip them
        decompressed = payload[4:]

    if len(decompressed) != uncomp_size:
        warn(
            "Decompressed size mismatch: got %d bytes, header says %d",
            len(decompressed),
            uncomp_size,
        )

    return decompressed


def _count_records(stream: bytes) -> int:
    """Count the number of records in a raw signature stream."""
    pos = 0
    n = 0
    end = len(stream)

    while pos + 4 <= end:
        size_bytes = stream[pos + 1 : pos + 4]
        size = size_bytes[0] | (size_bytes[1] << 8) | (size_bytes[2] << 16)

        if size == 0xFFFFFF:
            if pos + 8 > end:
                break
            size = struct.unpack_from("<I", stream, pos + 4)[0]
            pos += 8 + size
        else:
            pos += 4 + size

        n += 1

    return n


def extract_vdm(path: str) -> bytes:
    """Load a VDM file and return its raw decompressed signature record stream."""
    data = Path(path).read_bytes()
    info(f"{path} size={_human_size(len(data))}")

    rmdx_off = _find_rmdx_offset(data)
    hdr = _parse_rmdx_header(data, rmdx_off)
    # _print_rmdx_header(hdr, rmdx_off)

    compressed = "zlib" if (hdr["flags"] & RMDX_FLAG_COMPRESSED) else "plain"
    info(
        "[RMDX] version=0x%08X flags=0x%08X uncomp=%s [%s]",
        hdr["version"],
        hdr["flags"],
        _human_size(hdr["uncomp_size"]),
        compressed,
    )

    stream = _extract_stream(data, rmdx_off, hdr)
    n_recs = _count_records(stream)
    ok(f"{n_recs} records, {_human_size(len(stream))}")
    return stream


def _human_size(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024
    return ""


def _derive_output_name(paths: list[str]) -> str:
    stem = Path(paths[0]).stem.lower()
    for suffix in _VDM_SUFFIXES:
        if stem.endswith(suffix):
            stem = stem[: -len(suffix)]
            break
    return stem + ".sig"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract and merge signatures from VDM files into a .sig file."
    )
    parser.add_argument("vdm", nargs="+", metavar="file.vdm", help="Input VDM file(s)")
    parser.add_argument("-o", "--output", metavar="output.sig", help="Output .sig path")
    args = parser.parse_args()

    out_path = args.output or _derive_output_name(args.vdm)

    streams: list[bytes] = []
    for path in args.vdm:
        try:
            streams.append(extract_vdm(path))
        except (OSError, ValueError) as exc:
            error("%s: %s", path, exc)
            raise SystemExit(1)

    merged = b"".join(streams)
    total_recs = _count_records(merged)
    Path(out_path).write_bytes(merged)
    ok(
        "Wrote %s  (%d records total, %s)",
        out_path,
        total_recs,
        _human_size(len(merged)),
    )


if __name__ == "__main__":
    main()
