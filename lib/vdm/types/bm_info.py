from dataclasses import dataclass

from ..core import FamilySpec, FormatResult

_DETECTION_FLAG_BITS = (
    (0x01, "low", 0x00000080),
    (0x02, "low", 0x00000100),
    (0x04, "low", 0x00000200),
    (0x08, "low", 0x00000400),
    (0x10, "low", 0x00000800),
    (0x20, "low", 0x00400000),
    (0x40, "low", 0x00800000),
    (0x80, "high", 0x00000010),
)


@dataclass(frozen=True, slots=True)
class BMInfo:
    """Lossless parsed fields for a BM_INFO (0xA8) payload."""

    raw: bytes
    blob_len: int
    blob: bytes
    friendly_filter_mask: int
    fidelity_raw: bytes
    actions_raw: bytes
    action_tokens: tuple[str, ...]
    trailing_raw: bytes

    @property
    def receiver_accepted(self) -> bool:
        return self.friendly_filter_mask < 0x1000

    @property
    def recid_object_raw(self) -> bytes | None:
        """Opaque payload+2 span interned only on the nonempty-blob path."""
        candidate = self.raw[2:]
        return candidate if self.blob_len and candidate and candidate[0] else None

    @property
    def detection_flags(self) -> tuple[int, int]:
        low = 0
        high = 0
        for mask, half, value in _DETECTION_FLAG_BITS:
            if self.friendly_filter_mask & mask:
                if half == "low":
                    low |= value
                else:
                    high |= value
        return low, high


def parse_bm_info(payload: bytes) -> BMInfo:
    """Parse BM_INFO's length-prefixed blob and NUL-terminated strings."""
    if len(payload) < 2:
        raise ValueError("truncated blob_len")

    blob_len = int.from_bytes(payload[0:2], "little")
    cursor = 2
    end = cursor + blob_len
    if end > len(payload):
        raise ValueError("truncated blob")
    blob = payload[cursor:end]
    cursor = end

    if cursor + 2 > len(payload):
        raise ValueError("truncated friendly_filter_mask")
    friendly_filter_mask = int.from_bytes(payload[cursor : cursor + 2], "little")
    cursor += 2

    def read_string(label: str) -> bytes:
        nonlocal cursor
        if cursor + 2 > len(payload):
            raise ValueError(f"truncated {label}_len")
        size = int.from_bytes(payload[cursor : cursor + 2], "little")
        cursor += 2
        end = cursor + size
        if end > len(payload):
            raise ValueError(f"truncated {label}")
        value = payload[cursor:end]
        cursor = end
        if not value:
            raise ValueError(f"{label} must include a terminating NUL")
        if value[-1] != 0:
            raise ValueError(f"{label} is missing terminating NUL")
        return value

    fidelity_raw = read_string("fidelity")
    actions_raw = read_string("actions")
    action_data = actions_raw[:-1]
    action_tokens = (
        tuple(token.decode("latin-1") for token in action_data.split(b"+"))
        if action_data
        else ()
    )

    return BMInfo(
        raw=payload,
        blob_len=blob_len,
        blob=blob,
        friendly_filter_mask=friendly_filter_mask,
        fidelity_raw=fidelity_raw,
        actions_raw=actions_raw,
        action_tokens=action_tokens,
        trailing_raw=payload[cursor:],
    )


def render_bm_info(info: BMInfo) -> FormatResult:
    """Render known fields while retaining byte-exact raw representations."""
    detection_low, detection_high = info.detection_flags
    return FormatResult(
        fields=(
            ("blob_len", str(info.blob_len)),
            ("blob_raw", info.blob.hex(" ") or "(empty)"),
            (
                "recid_object_span",
                (
                    f"{len(info.recid_object_raw)} B from payload+2 (opaque)"
                    if info.recid_object_raw is not None
                    else "not created"
                ),
            ),
            ("friendly_filter_mask", f"{info.friendly_filter_mask:#06x}"),
            (
                "receiver_status",
                "accepted" if info.receiver_accepted else "rejected: mask >= 0x1000",
            ),
            (
                "detection_flags",
                f"low32=0x{detection_low:08x}, high32=0x{detection_high:08x}",
            ),
            (
                "unresolved_mask_bits",
                f"0x{info.friendly_filter_mask & 0x0F00:04x}",
            ),
            ("fidelity_len", str(len(info.fidelity_raw))),
            ("fidelity_raw", info.fidelity_raw.hex(" ")),
            ("fidelity", info.fidelity_raw[:-1].decode("latin-1")),
            ("actions_len", str(len(info.actions_raw))),
            ("actions_raw", info.actions_raw.hex(" ")),
            (
                "action_tokens",
                " | ".join(info.action_tokens) or "(empty)",
            ),
            ("trailing_raw", info.trailing_raw.hex(" ") or "(empty)"),
            (
                "trailing_behavior",
                "accepted; included in full-payload CRC/SHA-1"
                + (
                    " and RecID object span"
                    if info.recid_object_raw is not None
                    else ""
                ),
            ),
        )
    )


SPEC = FamilySpec(0xA8, "BM_INFO", parse_bm_info, render_bm_info)
