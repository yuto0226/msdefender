"""Lossless BM stream framing and conservative, descriptive pattern rendering."""

import json
from dataclasses import dataclass
from typing import Literal

_PROFILE = "1.443.903.0"

# g_bmOpcodeTable @ 0x180DBBAC0 in the documented target engine. Special
# lengths depend on dispatch ID, not raw ID. These are not matcher flags.
_BASE_LENGTHS = (
    2,
    3,
    3,
    4,
    4,
    4,
    0,
    4,
    4,
    4,
    4,
    4,
    4,
    4,
    4,
    4,
    4,
    4,
    4,
    2,
    2,
    2,
    2,
    3,
    2,
    4,
    4,
    3,
    4,
    4,
    4,
    4,
    6,
    6,
    4,
    4,
    4,
    4,
    4,
    4,
    4,
    4,
    4,
    4,
    4,
    4,
    4,
    4,
    4,
    4,
)
_DISPATCH_IDS = tuple(range(0x22)) + (
    0x04,
    0x05,
    0x0B,
    0x0C,
    0x0D,
    0x0E,
    0x0F,
    0x10,
    0x11,
    0x12,
    0x19,
    0x1A,
    0x1C,
    0x1D,
    0x1E,
    0x1F,
)
_DESCRIPTOR_FLAGS = tuple(
    2 if raw_id in (0x04, 0x05, 0x19, 0x1A) else 0 for raw_id in range(0x22)
) + (3, 3, 1, 1, 1, 1, 1, 1, 1, 1, 3, 3, 1, 1, 1, 1)
_CLASS_DISPATCH_IDS = frozenset((0x04, 0x05, 0x19, 0x1A))


@dataclass(frozen=True, slots=True)
class BmToken:
    offset: int
    raw: bytes
    kind: Literal["LITERAL", "OPCODE", "END"]
    literal: bytes | None = None
    raw_id: int | None = None
    dispatch_id: int | None = None
    descriptor_flags: int | None = None
    operands: bytes = b""


@dataclass(frozen=True, slots=True)
class BmDecodeIssue:
    code: str
    offset: int
    raw_id: int | None = None


@dataclass(frozen=True, slots=True)
class BmPattern:
    raw: bytes
    tokens: tuple[BmToken, ...]
    consumed: int
    ended: bool
    issue: BmDecodeIssue | None
    remaining_raw: bytes
    profile: str


def decode_bm_pattern(data: bytes, *, profile: str = _PROFILE) -> BmPattern:
    """Frame one stream, preserving a safe prefix on malformed input.

    Completeness validates framing only; this does not execute the BM matcher.
    Unsupported profiles raise ValueError rather than silently guessing a table.
    """
    if profile != _PROFILE:
        raise ValueError(f"unsupported BM profile {profile!r}")
    raw = bytes(data)
    tokens: list[BmToken] = []
    offset = 0
    ended = False
    issue = None
    while offset < len(raw):
        if raw[offset] != 0x90:
            end = raw.find(b"\x90", offset)
            if end < 0:
                end = len(raw)
            literal = raw[offset:end]
            tokens.append(BmToken(offset, literal, "LITERAL", literal=literal))
            offset = end
            continue
        if offset + 1 >= len(raw):
            issue = BmDecodeIssue("short_90_escape", offset)
            break
        raw_id = raw[offset + 1]
        if raw_id == 0x90:
            tokens.append(
                BmToken(offset, raw[offset : offset + 2], "LITERAL", literal=b"\x90")
            )
            offset += 2
            continue
        if raw_id == 0:
            tokens.append(BmToken(offset, raw[offset : offset + 2], "END", raw_id=0))
            offset += 2
            ended = True
            if offset != len(raw):
                issue = BmDecodeIssue("bytes_after_end", offset)
            break
        if raw_id >= len(_BASE_LENGTHS):
            issue = BmDecodeIssue("opcode_out_of_range", offset, raw_id)
            break
        length = _BASE_LENGTHS[raw_id]
        dispatch_id = _DISPATCH_IDS[raw_id]
        if length == 0:
            issue = BmDecodeIssue("zero_length_descriptor", offset, raw_id)
            break
        length_field = (
            3
            if dispatch_id in _CLASS_DISPATCH_IDS
            else 2
            if dispatch_id == 0x17
            else None
        )
        if length_field is not None:
            if offset + length_field >= len(raw):
                issue = BmDecodeIssue("short_variable_length_field", offset, raw_id)
                break
            length += raw[offset + length_field]
        if offset + length > len(raw):
            issue = BmDecodeIssue("operand_overrun", offset, raw_id)
            break
        token_raw = raw[offset : offset + length]
        tokens.append(
            BmToken(
                offset,
                token_raw,
                "OPCODE",
                raw_id=raw_id,
                dispatch_id=dispatch_id,
                descriptor_flags=_DESCRIPTOR_FLAGS[raw_id],
                operands=token_raw[2:],
            )
        )
        offset += length
    if issue is None and not ended:
        issue = BmDecodeIssue("missing_END", offset)
    return BmPattern(raw, tuple(tokens), offset, ended, issue, raw[offset:], profile)


def render_byte_fragments(data: bytes) -> str:
    """Render lossless quoted ASCII and hex fragments, without matching claims.

    Keep wholly printable literals quoted. Within mixed data, quote printable
    runs of at least three bytes; shorter runs stay with surrounding binary.
    """
    if data and all(0x20 <= byte <= 0x7E for byte in data):
        return json.dumps(data.decode("ascii"))
    parts: list[str] = []
    binary = bytearray()
    offset = 0
    while offset < len(data):
        if not 0x20 <= data[offset] <= 0x7E:
            binary.append(data[offset])
            offset += 1
            continue
        end = offset + 1
        while end < len(data) and 0x20 <= data[end] <= 0x7E:
            end += 1
        run = data[offset:end]
        if len(run) >= 3:
            if binary:
                parts.append(f"{{ {binary.hex(' ').upper()} }}")
                binary.clear()
            parts.append(json.dumps(run.decode("ascii")))
        else:
            binary.extend(run)
        offset = end
    if binary:
        parts.append(f"{{ {binary.hex(' ').upper()} }}")
    return " ".join(parts) if parts else "{ }"


def _render_opcode(token: BmToken) -> str:
    dispatch = token.dispatch_id
    operands = token.operands
    alias = f" raw=0x{token.raw_id:02X}" if token.raw_id != token.dispatch_id else ""
    if dispatch == 0x01:
        return f"[{operands[0]}]"
    if dispatch in (0x02, 0x08):
        bound = int.from_bytes(operands, "little")
        return f"[0-{bound}]"
    if dispatch in _CLASS_DISPATCH_IDS:
        # Expose count and class-spec without asserting regex quantifiers,
        # membership polarity, or mapping rules for partially decoded cases.
        spec = render_byte_fragments(operands[2:])
        return f"<CLASS_{dispatch:02X} count={operands[0]} spec={spec}{alias}>"
    if dispatch == 0x13:
        return "<FOLLOW_X86_RELATIVE_TARGET>"
    if dispatch == 0x1B:
        return f"<CAPTURE_MARKER id={operands[0]}; boundaries unresolved>"
    if dispatch == 0x1C:
        return f"<BACKREF id={operands[0]}{alias}>"
    if dispatch in (0x20, 0x21):
        width = 32 if dispatch == 0x20 else 64
        export_id = int.from_bytes(operands, "little")
        return f"<EXPORT_ADDRESS{width} id=0x{export_id:08X}>"
    ranges = {
        0x0B: ("RANGE_REPEAT", "g_NLRange"),
        0x0C: ("RANGE_SEARCH", "g_NLRange"),
        0x0D: ("RANGE_REPEAT", "g_WSRange"),
        0x0E: ("RANGE_SEARCH", "g_WSRange"),
        0x0F: ("RANGE_REPEAT", "g_NRRange"),
        0x10: ("RANGE_SEARCH", "g_NRRange"),
        0x11: ("RANGE_REPEAT", "g_ALRange"),
        0x12: ("RANGE_SEARCH", "g_ALRange"),
        0x1D: ("RANGE_REPEAT", "g_ALNRange"),
        0x1E: ("RANGE_REPEAT", "g_HexRange"),
        0x1F: ("RANGE_SEARCH", "g_HexRange"),
    }
    if dispatch in ranges:
        operation, bitmap = ranges[dispatch]
        count = int.from_bytes(operands, "little")
        effective = count * (2 if token.descriptor_flags & 1 else 1)
        return f"<{operation} bitmap={bitmap} count={effective}; mapping/flags apply{alias}>"
    # In particular, 03 and relative families 14/15/16 remain descriptive
    # opcodes. Their operand bytes must not be guessed from subsequent tokens.
    operand_text = f" {operands.hex(' ').upper()}" if operands else ""
    return f"<OP_{token.raw_id:02X}{operand_text}>"


def render_bm_pattern(pattern: BmPattern) -> str:
    """Render YARA-like human atoms with explicit Defender extensions.

    This mixed display is not a compilable YARA string or an equivalence claim.
    END is implicit in the end of a complete pattern, never a subject literal.
    """
    parts: list[str] = []
    literals: list[bytes] = []

    def flush_literals() -> None:
        if literals:
            parts.append(render_byte_fragments(b"".join(literals)))
            literals.clear()

    for token in pattern.tokens:
        if token.kind == "LITERAL":
            literals.append(token.literal)
        else:
            flush_literals()
            if token.kind != "END":
                parts.append(_render_opcode(token))
    flush_literals()
    if pattern.issue is not None:
        parts.append(f"<DECODE_ERROR {pattern.issue.code}@+0x{pattern.issue.offset:X}>")
    if pattern.remaining_raw:
        parts.append(f"<UNDECODED_HEX {pattern.remaining_raw.hex(' ').upper()}>")
    return " ".join(parts)
