"""THREAT_BEGIN payload parsing helpers."""

from __future__ import annotations


def parse_threat_name(payload: bytes) -> str:
    """Extract the display name from a THREAT_BEGIN (0x5C) payload.

    Payload layout (confirmed by RE of threat_info_receiver @ 0x1809EB590):

        +0x00  4B  threat_id   (LE uint32)
        +0x04  2B  dep_count
        +0x06  2B  ext_count
        +0x08  2B  category    (0x0B = generic, 0x0C = monitoring tool)
        +0x0A  2B  name_len    byte count of name_obj[]
        +0x0C  nB  name_obj[]  leading bytes >= 0x80 are internal markers;
                               first byte < 0x80 starts the display name.
    """
    if len(payload) < 0x0C:
        tid = int.from_bytes(payload[:4], "little") if len(payload) >= 4 else 0
        return f"threat_{tid:08x}"

    name_len = int.from_bytes(payload[0x0A:0x0C], "little")
    if name_len == 0 or 0x0C + name_len > len(payload):
        tid = int.from_bytes(payload[:4], "little")
        return f"threat_{tid:08x}"

    raw = payload[0x0C : 0x0C + name_len]
    while raw and raw[0] >= 0x80:
        raw = raw[1:]

    null = raw.find(b"\x00")
    if null != -1:
        raw = raw[:null]

    name = raw.decode("utf-8", errors="replace").strip()
    if not name:
        tid = int.from_bytes(payload[:4], "little")
        return f"threat_{tid:08x}"
    return name


def parse_threat_id(payload: bytes) -> int:
    """Extract the 32-bit threat_id from a THREAT_BEGIN payload."""
    if len(payload) < 4:
        return 0
    return int.from_bytes(payload[:4], "little")