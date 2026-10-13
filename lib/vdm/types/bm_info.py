from dataclasses import dataclass

from ..core import FamilySpec, FormatResult


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
    unknown_tail: bytes


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
        unknown_tail=payload[cursor:],
    )


def render_bm_info(info: BMInfo) -> FormatResult:
    """Render known fields while retaining byte-exact raw representations."""
    return FormatResult(
        fields=(
            ("blob_len", str(info.blob_len)),
            ("blob_raw", info.blob.hex(" ") or "(empty)"),
            ("friendly_filter_mask", f"{info.friendly_filter_mask:#06x}"),
            ("fidelity_len", str(len(info.fidelity_raw))),
            ("fidelity_raw", info.fidelity_raw.hex(" ")),
            ("fidelity", info.fidelity_raw[:-1].decode("latin-1")),
            ("actions_len", str(len(info.actions_raw))),
            ("actions_raw", info.actions_raw.hex(" ")),
            (
                "action_tokens",
                " | ".join(info.action_tokens) or "(empty)",
            ),
            ("unknown_tail_raw", info.unknown_tail.hex(" ") or "(empty)"),
        )
    )


SPEC = FamilySpec(0xA8, "BM_INFO", parse_bm_info, render_bm_info)
