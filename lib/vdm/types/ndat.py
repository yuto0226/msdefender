"""Lossless parser and renderer for NDAT (0xA9) payloads."""

from dataclasses import dataclass
from typing import Final, Literal

from ..core import DisplaySection, FamilySpec, FormatResult

NDAT_TYPE: Final = 0xA9
PREVIEW_SIZE: Final = 16


@dataclass(frozen=True, slots=True)
class NdatPayload:
    """Observed NDAT wire data with counted and opaque body variants."""

    raw: bytes
    callback_index_candidate: int
    variant: Literal["counted", "opaque"]
    body_raw: bytes
    data_raw: bytes | None
    declared_size: int | None


def parse_ndat(payload: bytes) -> NdatPayload:
    """Parse the trailing callback index and observed optional counted body."""
    if not payload:
        raise ValueError("truncated NDAT payload: need callback index byte, have 0")

    body_raw = payload[:-1]
    callback_index_candidate = payload[-1]
    if len(body_raw) >= 4:
        declared_size = int.from_bytes(body_raw[:4], "little")
        if declared_size == len(payload) - 5:
            return NdatPayload(
                raw=payload,
                callback_index_candidate=callback_index_candidate,
                variant="counted",
                body_raw=body_raw,
                data_raw=body_raw[4:],
                declared_size=declared_size,
            )

    return NdatPayload(
        raw=payload,
        callback_index_candidate=callback_index_candidate,
        variant="opaque",
        body_raw=body_raw,
        data_raw=None,
        declared_size=None,
    )


def _text_preview(data: bytes) -> str:
    preview = data[:PREVIEW_SIZE]
    text = "".join(chr(byte) if 0x20 <= byte <= 0x7E else "." for byte in preview)
    if len(data) > PREVIEW_SIZE:
        text += "..."
    return text or "(empty)"


def _body_rows(data: bytes, *, include_length: bool) -> tuple[tuple[str, str], ...]:
    rows = [("body_length", f"{len(data)} B")] if include_length else []
    rows.extend(
        (
            ("hex_preview", data[:PREVIEW_SIZE].hex(" ") or "(empty)"),
            ("text_preview", _text_preview(data)),
        )
    )
    return tuple(rows)


def render_ndat(parsed: NdatPayload) -> FormatResult:
    callback_candidate = parsed.callback_index_candidate
    rows = [
        ("variant", parsed.variant),
        (
            "callback_index_candidate",
            f"{callback_candidate} (0x{callback_candidate:02x})",
        ),
    ]
    if parsed.variant == "counted":
        assert parsed.data_raw is not None
        rows.append(("declared_size", f"{parsed.declared_size} B"))
        rows.append(("data_length", f"{len(parsed.data_raw)} B"))
        rows.append(
            ("data_ends_with_nul", "yes" if parsed.data_raw.endswith(b"\0") else "no")
        )
        preview_rows = _body_rows(parsed.data_raw, include_length=False)
        title = "NDAT Counted Data"
    else:
        preview_rows = _body_rows(parsed.body_raw, include_length=True)
        title = "NDAT Opaque Body"

    return FormatResult(
        sections=(
            DisplaySection("NDAT Metadata", rows=tuple(rows)),
            DisplaySection(title, rows=preview_rows),
        )
    )


NDAT_SPEC = FamilySpec(NDAT_TYPE, "NDAT", parse_ndat, render_ndat)
