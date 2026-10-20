"""Lossless typed models for kernel pattern records 0xBB and 0xBC."""

from dataclasses import dataclass

from ..bm import BmPattern, validate_bm_framing
from ..bm_yara import render_bm_yara
from ..core import DisplaySection, FamilySpec, FormatResult

_PREVIEW = 64
_TEXT_PREVIEW = 512


@dataclass(frozen=True, slots=True)
class KpatPayload:
    raw: bytes
    prefix_size: int
    key: bytes
    pattern_raw: bytes
    name_raw: bytes | None
    suffix: bytes
    pattern: BmPattern | None = None
    receiver_result: str | None = None

    @property
    def name(self) -> bytes | None:
        """Name bytes only when the runtime would retain a nonempty C name."""
        if self.name_raw is None or not self.name_raw or self.name_raw[0] == 0:
            return None
        return self.name_raw.split(b"\0", 1)[0]


def parse_kpat(payload: bytes) -> KpatPayload:
    """Parse KPAT prefix framing while keeping opaque pattern and suffix bytes."""
    if not payload:
        raise ValueError("truncated KPAT prefix size")
    prefix_size = payload[0]
    if prefix_size < 8:
        raise ValueError("KPAT prefix size must be at least 8")
    prefix_end = prefix_size + 1
    if len(payload) < prefix_end:
        raise ValueError("truncated KPAT key/pattern prefix")
    key = payload[1:9]
    pattern_raw = payload[9:prefix_end]
    cursor = prefix_end
    name_raw = None
    if cursor < len(payload):
        name_len = payload[cursor]
        cursor += 1
        if cursor + name_len > len(payload):
            raise ValueError("truncated KPAT name")
        name_raw = payload[cursor : cursor + name_len]
        cursor += name_len
    return KpatPayload(
        payload, prefix_size, key, pattern_raw, name_raw, payload[cursor:]
    )


def parse_kpatex(payload: bytes) -> KpatPayload:
    """Parse KPATEX and model the receiver's post-hook BM candidate result."""
    parsed = parse_kpat(payload)
    pattern = None
    try:
        pattern = validate_bm_framing(parsed.pattern_raw, label="KPATEX")
    except ValueError as exc:
        result = f"no_op.{exc}"
    else:
        result = "added_candidate"
    return KpatPayload(
        parsed.raw,
        parsed.prefix_size,
        parsed.key,
        parsed.pattern_raw,
        parsed.name_raw,
        parsed.suffix,
        pattern,
        result,
    )


def _preview(raw: bytes) -> str:
    return raw[:_PREVIEW].hex(" ") + (" ..." if len(raw) > _PREVIEW else "")


def _render(parsed: KpatPayload, *, extended: bool) -> FormatResult:
    rows = [
        ("prefix_size", str(parsed.prefix_size)),
        ("key", parsed.key.hex(" ")),
        ("pattern_length", str(len(parsed.pattern_raw))),
        ("pattern_preview", _preview(parsed.pattern_raw)),
        (
            "name_length",
            "absent" if parsed.name_raw is None else str(len(parsed.name_raw)),
        ),
        (
            "name_raw",
            "absent" if parsed.name_raw is None else _preview(parsed.name_raw),
        ),
        (
            "name_preview",
            "anonymous" if parsed.name is None else repr(parsed.name[:_TEXT_PREVIEW]),
        ),
        ("suffix_length", str(len(parsed.suffix))),
        ("suffix_preview", _preview(parsed.suffix)),
    ]
    if extended:
        yara = render_bm_yara(parsed.pattern) if parsed.pattern is not None else None
        rows.extend(
            (
                ("receiver_result", parsed.receiver_result or "unknown"),
                (
                    "bm_validation",
                    "available" if parsed.pattern is not None else "not_available",
                ),
                (
                    "bm_issue",
                    f"{parsed.pattern.issue.code}@{parsed.pattern.issue.offset}"
                    if parsed.pattern and parsed.pattern.issue
                    else "none",
                ),
            )
        )
        if yara is not None:
            rows.extend(
                (
                    ("bm_consumed", str(parsed.pattern.consumed)),
                    ("bm_remaining_length", str(len(parsed.pattern.remaining_raw))),
                    ("yara_fidelity", yara.fidelity.value),
                )
            )
            if yara.body:
                rows.append(("yara_like_preview", yara.body[:_TEXT_PREVIEW]))
            rows.extend(
                (f"pattern_issue[{i}]", f"{issue.code}@{issue.offset}")
                for i, issue in enumerate(yara.diagnostics[:16])
            )
            if len(yara.diagnostics) > 16:
                rows.append(("remaining_issues", str(len(yara.diagnostics) - 16)))
    return FormatResult(
        sections=(DisplaySection("KPATEX" if extended else "KPAT", rows=tuple(rows)),)
    )


def render_kpat(parsed: KpatPayload) -> FormatResult:
    return _render(parsed, extended=False)


def render_kpatex(parsed: KpatPayload) -> FormatResult:
    return _render(parsed, extended=True)


KPAT_SPEC = FamilySpec(0xBB, "KPAT", parse_kpat, render_kpat)
KPATEX_SPEC = FamilySpec(0xBC, "KPATEX", parse_kpatex, render_kpatex)
