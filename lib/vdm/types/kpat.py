"""Lossless typed models for kernel pattern records 0xBB and 0xBC."""

from dataclasses import dataclass

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
    """Parse KPATEX framing without assigning unverified matcher semantics."""
    return parse_kpat(payload)


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
        rows.append(("pattern_semantics", "unverified; raw bytes retained"))
    return FormatResult(
        sections=(DisplaySection("KPATEX" if extended else "KPAT", rows=tuple(rows)),)
    )


def render_kpat(parsed: KpatPayload) -> FormatResult:
    return _render(parsed, extended=False)


def render_kpatex(parsed: KpatPayload) -> FormatResult:
    return _render(parsed, extended=True)


KPAT_SPEC = FamilySpec(0xBB, "KPAT", parse_kpat, render_kpat)
KPATEX_SPEC = FamilySpec(0xBC, "KPATEX", parse_kpatex, render_kpatex)
