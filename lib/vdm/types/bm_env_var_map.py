"""Parser and bounded renderer for BM_ENV_VAR_MAP (0xED) payloads."""

from dataclasses import dataclass
from typing import Final

from ..core import FamilySpec, FormatResult

BM_ENV_VAR_MAP_TYPE: Final = 0xED
_WORD_PREVIEW_COUNT: Final = 16
_NAME_PREVIEW_BYTES: Final = 32


@dataclass(frozen=True, slots=True)
class BMEnvVarMap:
    """Lossless names and word vectors from a BM_ENV_VAR_MAP payload."""

    raw: bytes
    name_len: int
    name_raw: bytes
    vector_a_count: int
    vector_a: tuple[int, ...]
    separator: int
    vector_b: tuple[int, ...]


def parse_bm_env_var_map(payload: bytes) -> BMEnvVarMap:
    """Parse the corpus-validated 0xED layout without assigning word meaning."""
    if not payload:
        raise ValueError("truncated name_len")

    name_len = payload[0]
    name_end = 1 + name_len
    if name_end > len(payload):
        raise ValueError(
            f"truncated name: need {name_len} bytes, have {len(payload) - 1}"
        )

    count_start = name_end
    count_end = count_start + 3
    if len(payload) < count_end + 1:
        raise ValueError("truncated count/separator")

    vector_a_count = int.from_bytes(payload[count_start:count_end], "little")
    vector_a_end = count_end + 2 * vector_a_count
    if vector_a_end >= len(payload):
        raise ValueError(
            "truncated vector_a: "
            f"need {vector_a_count} words and separator, "
            f"have {max(0, len(payload) - count_end)} bytes"
        )

    vector_a_raw = payload[count_end:vector_a_end]
    separator = payload[vector_a_end]
    if separator != 0:
        raise ValueError(f"invalid separator: expected 0x00, got 0x{separator:02x}")

    vector_b_raw = payload[vector_a_end + 1 :]
    if len(vector_b_raw) % 2:
        raise ValueError("odd vector_b length")

    vector_a = tuple(
        int.from_bytes(vector_a_raw[offset : offset + 2], "little")
        for offset in range(0, len(vector_a_raw), 2)
    )
    vector_b = tuple(
        int.from_bytes(vector_b_raw[offset : offset + 2], "little")
        for offset in range(0, len(vector_b_raw), 2)
    )

    return BMEnvVarMap(
        raw=payload,
        name_len=name_len,
        name_raw=payload[1:name_end],
        vector_a_count=vector_a_count,
        vector_a=vector_a,
        separator=separator,
        vector_b=vector_b,
    )


def _preview_words(words: tuple[int, ...]) -> str:
    preview = " ".join(f"0x{word:04x}" for word in words[:_WORD_PREVIEW_COUNT])
    if len(words) > _WORD_PREVIEW_COUNT:
        preview += f" … ({len(words) - _WORD_PREVIEW_COUNT} more words)"
    return preview or "(empty)"


def render_bm_env_var_map(parsed: BMEnvVarMap) -> FormatResult:
    """Render bounded metadata and previews; retain complete bytes in the model."""
    name_preview = parsed.name_raw[:_NAME_PREVIEW_BYTES].hex(" ")
    if len(parsed.name_raw) > _NAME_PREVIEW_BYTES:
        name_preview += f" … ({len(parsed.name_raw) - _NAME_PREVIEW_BYTES} more bytes)"

    return FormatResult(
        fields=(
            ("name_len", str(parsed.name_len)),
            ("name_raw", name_preview or "(empty)"),
            ("vector_a_count", str(len(parsed.vector_a))),
            ("vector_a_preview", _preview_words(parsed.vector_a)),
            ("separator", f"0x{parsed.separator:02x}"),
            ("vector_b_count", str(len(parsed.vector_b))),
            ("vector_b_preview", _preview_words(parsed.vector_b)),
            ("raw_len", str(len(parsed.raw))),
        )
    )


SPEC = FamilySpec(
    BM_ENV_VAR_MAP_TYPE,
    "BM_ENV_VAR_MAP",
    parse_bm_env_var_map,
    render_bm_env_var_map,
)
