from dataclasses import dataclass
from types import MappingProxyType
from typing import Final

from ..core import FamilySpec, FormatResult

THREAT_CATEGORIES = MappingProxyType(
    {
        0x01: "Adware",
        0x02: "Spyware",
        0x03: "PWS",
        0x04: "TrojanDownloader",
        0x05: "Worm",
        0x06: "Backdoor",
        0x08: "Trojan",
        0x09: "Spammer",
        0x0B: "Dialer",
        0x0C: "MonitoringTool",
        0x0D: "BrowserModifier",
        0x13: "Joke",
        0x15: "SoftwareBundler",
        0x16: "TrojanClicker",
        0x17: "SettingsModifier",
        0x1B: "PUA",
        0x1E: "Exploit",
        0x20: "VirTool",
        0x21: "RemoteAccess",
        0x22: "Tool",
        0x24: "DoS",
        0x25: "TrojanDropper",
        0x26: "Flooder",
        0x27: "TrojanSpy",
        0x28: "TrojanProxy",
        0x2A: "Virus",
        0x2B: "Known",
        0x2C: "Unknown",
        0x2D: "SPP",
        0x2E: "Behavior",
        0x2F: "Vulnerability",
        0x30: "Policy",
        0x31: "EUS",
        0x32: "Ransom",
        0x33: "HipsRule",
    }
)

# Sentinel IDs handled specially by threat_info_receiver/DispatchRecords. They
# are distinct from the 0x7FFE/0x7FFF magic-threat ranges.
MAGIC_THREAT_IDS = MappingProxyType(
    {
        0x00040E1A: "hosts_loaded",
        0x7FFFFFF0: "infrastructure",
        0x7FFFFFFA: "infrastructure",
        0x7FFFFFFE: "unknown_loaded",
        0x7FFFFFFF: "friendly_loaded",
        0xFFFFFFF0: "infrastructure",
        0xFFFFFFF9: "behaviordetection_loaded",
        0xFFFFFFFA: "infrastructure",
        0xFFFFFFFF: "avfriendly_loaded",
    }
)

THREAT_BEGIN_TYPE: Final = 0x5C
THREAT_END_TYPE: Final = 0x5D


@dataclass(frozen=True, slots=True)
class ThreatMetadata:
    """Receiver-built tail named by the engine getters that read it.

    Wire tail offsets +0..+5 map to metadata-object offsets +4..+9.
    """

    short_description_id: int
    threat_advice_id: int
    severity: int
    action: int


@dataclass(frozen=True, slots=True)
class ThreatBegin:
    raw: bytes
    threat_id: int
    dep_count: int
    ext_count: int
    category: int
    name_len: int
    name_raw: bytes
    post_name_zero: int
    dependencies: tuple[int, ...]
    ext_entries: tuple[int, ...]
    metadata: ThreatMetadata | None
    metadata_wire_size: int
    marker_raw: bytes
    display_name_raw: bytes
    name: str
    trailing_raw: bytes

    @property
    def effective_metadata(self) -> ThreatMetadata:
        """Return engine defaults for omitted or partially supplied metadata."""
        # Receiver defaults are two bytes at metadata-object +4/+5. The engine
        # getters read them together as a little-endian short-description ID.
        return self.metadata or ThreatMetadata(0x0301, 0, 0, 0)


@dataclass(frozen=True, slots=True)
class ThreatEnd:
    raw: bytes
    value: int
    trailing_raw: bytes


def threat_category_name(category: int) -> str | None:
    return THREAT_CATEGORIES.get(category)


def parse_threat_begin(payload: bytes) -> ThreatBegin:
    """Parse the THREAT_BEGIN header, name, arrays, and optional metadata."""
    if len(payload) < 0x0C:
        raise ValueError("truncated THREAT_BEGIN header")

    threat_id = int.from_bytes(payload[0:4], "little")
    dep_count = int.from_bytes(payload[4:6], "little")
    ext_count = int.from_bytes(payload[6:8], "little")
    if not 1 <= ext_count <= 507:
        raise ValueError(
            f"THREAT_BEGIN ext_count outside engine receiver range: {ext_count}"
        )
    category = int.from_bytes(payload[8:10], "little")
    name_len = int.from_bytes(payload[10:12], "little")
    name_end = 0x0C + name_len
    if name_end > len(payload):
        raise ValueError(
            f"truncated THREAT_BEGIN name: need {name_len} bytes, "
            f"have {len(payload) - 0x0C}"
        )

    name_raw = payload[0x0C:name_end]
    cursor = name_end

    if len(payload) - cursor < 2:
        raise ValueError("truncated THREAT_BEGIN post_name_zero")
    post_name_zero = int.from_bytes(payload[cursor : cursor + 2], "little")
    cursor += 2

    dependency_size = dep_count * 4
    if len(payload) - cursor < dependency_size:
        raise ValueError(
            f"truncated THREAT_BEGIN dependency_ids: need {dependency_size} bytes, "
            f"have {len(payload) - cursor}"
        )
    dependencies = tuple(
        int.from_bytes(payload[offset : offset + 4], "little")
        for offset in range(cursor, cursor + dependency_size, 4)
    )
    cursor += dependency_size

    ext_size = ext_count * 2
    if len(payload) - cursor < ext_size:
        raise ValueError(
            f"truncated THREAT_BEGIN ext_entries: need {ext_size} bytes, "
            f"have {len(payload) - cursor}"
        )
    ext_entries = tuple(
        int.from_bytes(payload[offset : offset + 2], "little")
        for offset in range(cursor, cursor + ext_size, 2)
    )
    cursor += ext_size

    remaining = len(payload) - cursor
    if 0 < remaining < 6 and remaining != 2:
        raise ValueError(
            f"truncated THREAT_BEGIN metadata tail: need 6 bytes, have {remaining}"
        )
    metadata = None
    metadata_wire_size = 0
    if remaining == 2:
        metadata = ThreatMetadata(
            short_description_id=int.from_bytes(payload[cursor : cursor + 2], "little"),
            threat_advice_id=0,
            severity=0,
            action=0,
        )
        metadata_wire_size = 2
        cursor += 2
    elif remaining >= 6:
        metadata = ThreatMetadata(
            short_description_id=int.from_bytes(payload[cursor : cursor + 2], "little"),
            threat_advice_id=int.from_bytes(payload[cursor + 2 : cursor + 4], "little"),
            severity=payload[cursor + 4],
            action=payload[cursor + 5],
        )
        metadata_wire_size = 6
        cursor += 6

    marker_len = 0
    while marker_len < len(name_raw) and name_raw[marker_len] >= 0x80:
        marker_len += 1
    marker_raw = name_raw[:marker_len]
    display_name_raw = name_raw[marker_len:]
    nul = display_name_raw.find(b"\0")
    if nul != -1:
        display_name_raw = display_name_raw[:nul]
    name = display_name_raw.decode("utf-8", errors="replace").strip()
    if not name:
        name = f"threat_{threat_id:08x}"

    return ThreatBegin(
        raw=payload,
        threat_id=threat_id,
        dep_count=dep_count,
        ext_count=ext_count,
        category=category,
        name_len=name_len,
        name_raw=name_raw,
        post_name_zero=post_name_zero,
        dependencies=dependencies,
        ext_entries=ext_entries,
        metadata=metadata,
        metadata_wire_size=metadata_wire_size,
        marker_raw=marker_raw,
        display_name_raw=display_name_raw,
        name=name,
        trailing_raw=payload[cursor:],
    )


def parse_threat_end(payload: bytes) -> ThreatEnd:
    if len(payload) < 4:
        raise ValueError("truncated THREAT_END value")
    return ThreatEnd(
        raw=payload,
        value=int.from_bytes(payload[:4], "little"),
        trailing_raw=payload[4:],
    )


def render_threat_begin(threat: ThreatBegin) -> FormatResult:
    category = threat_category_name(threat.category) or "?"
    category_display = f"{threat.category:#06x}  ({category})"
    threat_id_display = f"{threat.threat_id:#010x}"
    if magic := MAGIC_THREAT_IDS.get(threat.threat_id):
        threat_id_display += f"  [{magic}]"
    fields = [
        ("threat_id", threat_id_display),
        ("header_category", category_display),
        ("dep_count", str(threat.dep_count)),
        (
            "dependency_ids",
            f"[{', '.join(format(item, '#010x') for item in threat.dependencies)}]",
        ),
        ("ext_count", str(threat.ext_count)),
        (
            "ext_entries",
            f"[{', '.join(format(item, '#06x') for item in threat.ext_entries)}]",
        ),
        ("post_name_zero", f"{threat.post_name_zero:#06x}"),
        ("name_len", str(threat.name_len)),
        ("name", threat.name),
    ]
    if threat.metadata is not None:
        metadata = threat.metadata
        fields.append(
            (
                (
                    "wire_metadata"
                    if threat.metadata_wire_size == 6
                    else "wire_metadata_partial (2 bytes; remaining words defaulted)"
                ),
                (
                    f"short_description_id={metadata.short_description_id:#06x}, "
                    f"threat_advice_id={metadata.threat_advice_id:#06x}, "
                    f"severity={metadata.severity:#04x}, action={metadata.action:#04x}"
                ),
            )
        )
    else:
        metadata = threat.effective_metadata
        fields.append(
            (
                "effective_metadata (wire tail absent)",
                (
                    f"short_description_id={metadata.short_description_id:#06x}, "
                    f"threat_advice_id={metadata.threat_advice_id:#06x}, "
                    f"severity={metadata.severity:#04x}, action={metadata.action:#04x}"
                ),
            )
        )
    if threat.marker_raw:
        fields.append(("name_marker_raw", threat.marker_raw.hex(" ")))
    if threat.trailing_raw:
        fields.append(("trailing_raw", threat.trailing_raw.hex(" ")))
    return FormatResult(fields=tuple(fields))


def render_threat_end(threat: ThreatEnd) -> FormatResult:
    fields = [("value", f"{threat.value:#010x}")]
    if threat.trailing_raw:
        fields.append(("trailing_raw", threat.trailing_raw.hex(" ")))
    return FormatResult(fields=tuple(fields))


THREAT_BEGIN_SPEC = FamilySpec(
    THREAT_BEGIN_TYPE,
    "THREAT_BEGIN",
    parse_threat_begin,
    render_threat_begin,
)
THREAT_END_SPEC = FamilySpec(
    THREAT_END_TYPE,
    "THREAT_END",
    parse_threat_end,
    render_threat_end,
)
THREAT_SPECS = (THREAT_BEGIN_SPEC, THREAT_END_SPEC)
