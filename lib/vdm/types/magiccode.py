"""Typed model for MAGICCODE record 0xC0."""

from dataclasses import dataclass

from ..core import DisplaySection, FamilySpec, FormatResult

_BYTE_PREVIEW = 64
_TEXT_PREVIEW = 256


@dataclass(frozen=True, slots=True)
class MagicCodePayload:
    raw: bytes
    name_raw: bytes
    code: bytes
    expression_raw: bytes
    trailing: bytes

    @property
    def name(self) -> bytes:
        """Return the runtime C-string view without imposing a wire constraint."""
        return self.name_raw.split(b"\0", 1)[0]

    @property
    def expression(self) -> bytes:
        """Return the observed C-string view of the evaluator expression."""
        return self.expression_raw.split(b"\0", 1)[0]


def _take(payload: bytes, cursor: int, size: int, label: str) -> tuple[bytes, int]:
    end = cursor + size
    if end > len(payload):
        raise ValueError(f"truncated MAGICCODE {label}")
    return payload[cursor:end], end


def parse_magiccode(payload: bytes) -> MagicCodePayload:
    """Parse the receiver's four length-prefixed fields and retain its tail."""
    if not payload:
        raise ValueError("truncated MAGICCODE name length")

    name_length = payload[0]
    name_raw, cursor = _take(payload, 1, name_length, "name")

    code_length_raw, cursor = _take(payload, cursor, 4, "code length")
    code_length = int.from_bytes(code_length_raw, "little")
    code, cursor = _take(payload, cursor, code_length, "code")

    expression_length_raw, cursor = _take(payload, cursor, 2, "expression length")
    expression_length = int.from_bytes(expression_length_raw, "little")
    expression_raw, cursor = _take(payload, cursor, expression_length, "expression")

    return MagicCodePayload(
        raw=payload,
        name_raw=name_raw,
        code=code,
        expression_raw=expression_raw,
        trailing=payload[cursor:],
    )


def _hex_preview(data: bytes) -> str:
    return data[:_BYTE_PREVIEW].hex(" ") + (" ..." if len(data) > _BYTE_PREVIEW else "")


def _text_preview(data: bytes) -> str:
    text = data[:_TEXT_PREVIEW].decode("ascii", errors="backslashreplace")
    return repr(text) + (" ..." if len(data) > _TEXT_PREVIEW else "")


def render_magiccode(parsed: MagicCodePayload) -> FormatResult:
    rows = (
        ("name_length", str(len(parsed.name_raw))),
        ("name", _text_preview(parsed.name)),
        ("name_raw", _hex_preview(parsed.name_raw)),
        ("code_length", str(len(parsed.code))),
        ("code_preview", _hex_preview(parsed.code)),
        ("expression_length", str(len(parsed.expression_raw))),
        ("expression", _text_preview(parsed.expression)),
        ("expression_raw", _hex_preview(parsed.expression_raw)),
        ("trailing_length", str(len(parsed.trailing))),
        ("trailing_preview", _hex_preview(parsed.trailing)),
    )
    return FormatResult(sections=(DisplaySection("MAGICCODE", rows=rows),))


SPEC = FamilySpec(0xC0, "MAGICCODE", parse_magiccode, render_magiccode)
