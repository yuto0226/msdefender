"""Lossless BM stream framing and conservative semantic interpretation."""

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


@dataclass(frozen=True, slots=True)
class BmOperation:
    offset: int
    raw: bytes


@dataclass(frozen=True, slots=True)
class BmLiteral(BmOperation):
    value: bytes


@dataclass(frozen=True, slots=True)
class BmGap(BmOperation):
    minimum: int
    maximum: int
    bounded: bool = False


@dataclass(frozen=True, slots=True)
class BmAlternatives(BmOperation):
    token: BmToken
    widths: tuple[int, ...]
    choices: tuple[bytes, ...]


@dataclass(frozen=True, slots=True)
class BmScan(BmOperation):
    kind: Literal["fixed_skip", "forward_search", "backward_scan", "backward_search"]
    operand: int
    support_note: str


@dataclass(frozen=True, slots=True)
class BmClass(BmOperation):
    token: BmToken
    count: int
    spec: bytes


@dataclass(frozen=True, slots=True)
class BmExtension(BmOperation):
    token: BmToken
    name: str
    value: int | None = None
    bitmap: str | None = None


@dataclass(frozen=True, slots=True)
class BmOpaque(BmOperation):
    token: BmToken


@dataclass(frozen=True, slots=True)
class BmEnd(BmOperation):
    pass


BmSemanticOperation = (
    BmLiteral
    | BmGap
    | BmAlternatives
    | BmScan
    | BmClass
    | BmExtension
    | BmOpaque
    | BmEnd
)


@dataclass(frozen=True, slots=True)
class BmSemanticPattern:
    pattern: BmPattern
    operations: tuple[BmSemanticOperation, ...]


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


_RANGE_OPERATIONS = {
    0x0B: ("RANGE_REPEAT", "g_NLRange"),
    0x0C: ("RANGE_SEARCH", "g_NLRange"),
    0x0D: ("RANGE_REPEAT", "g_WSRange"),
    0x0E: ("RANGE_SEARCH", "g_WSRange"),
    0x0F: ("RANGE_REPEAT", "g_NRRange"),
    0x10: ("RANGE_SEARCH", "g_NRRange"),
    0x11: ("RANGE_REPEAT", "g_ALRange"),
    0x12: ("RANGE_SEARCH", "g_ALRange"),
    0x1C: ("RANGE_NEGATIVE_REPEAT", "g_ALNRange"),
    0x1D: ("RANGE_SEARCH", "g_ALNRange"),
    0x1E: ("RANGE_REPEAT", "g_HexRange"),
    0x1F: ("RANGE_SEARCH", "g_HexRange"),
}
_SCAN_OPERATIONS = {
    0x07: (
        "fixed_skip",
        "Buffer reader may skip mapped-zero prefix; file reader rejects this family.",
    ),
    0x08: (
        "forward_search",
        "Candidate count includes the first attempt; mapped-zero handling applies.",
    ),
    0x09: (
        "backward_scan",
        "File reader counts mapped-nonzero bytes; buffer reader rejects this family.",
    ),
    0x0A: (
        "backward_search",
        "Backward suffix retries and mapped-zero handling apply.",
    ),
}


def _interpret_opcode(token: BmToken) -> BmSemanticOperation:
    dispatch = token.dispatch_id
    operands = token.operands
    source = (token.offset, token.raw)
    if dispatch == 0x01:
        return BmGap(*source, operands[0], operands[0])
    if dispatch == 0x02:
        return BmGap(*source, 0, operands[0], bounded=True)
    if dispatch in _SCAN_OPERATIONS:
        kind, note = _SCAN_OPERATIONS[dispatch]
        return BmScan(*source, kind, int.from_bytes(operands, "little"), note)
    if dispatch in _CLASS_DISPATCH_IDS:
        # Preserve the wire count: flags and reader-specific predicates prevent
        # a general conversion to regex/YARA membership or repetition.
        return BmClass(*source, token, operands[0], operands[2:])
    if dispatch == 0x13:
        return BmExtension(*source, token, "FOLLOW_X86_RELATIVE_TARGET")
    if dispatch == 0x1B:
        return BmExtension(*source, token, "BACKREF", operands[0])
    if dispatch in (0x20, 0x21):
        width = 32 if dispatch == 0x20 else 64
        return BmExtension(
            *source, token, f"EXPORT_ADDRESS{width}", int.from_bytes(operands, "little")
        )
    if dispatch in _RANGE_OPERATIONS:
        name, bitmap = _RANGE_OPERATIONS[dispatch]
        count = int.from_bytes(operands, "little")
        effective = count * (2 if token.descriptor_flags & 1 else 1)
        return BmExtension(*source, token, name, effective, bitmap)
    return BmOpaque(*source, token)


def interpret_bm_pattern(pattern: BmPattern) -> BmSemanticPattern:
    """Interpret framed bytes without executing the matcher or parsing display text.

    Operations partition the framed raw prefix, including END. Alternatives
    consume only a shared block fully contained in the immediately following
    ordinary literal token; a common suffix remains a separate operation.
    Opaque fallbacks consume no following bytes. The original framing and
    undecoded tail remain available on ``pattern``.
    """
    operations: list[BmSemanticOperation] = []
    index = 0
    while index < len(pattern.tokens):
        token = pattern.tokens[index]
        if token.kind == "LITERAL":
            operations.append(BmLiteral(token.offset, token.raw, token.literal))
        elif token.kind == "END":
            operations.append(BmEnd(token.offset, token.raw))
        elif token.dispatch_id in (0x03, 0x17):
            widths = tuple(
                token.operands if token.dispatch_id == 0x03 else token.operands[1:]
            )
            shared_length = sum(widths)
            following = (
                pattern.tokens[index + 1] if index + 1 < len(pattern.tokens) else None
            )
            if (
                widths
                and following is not None
                and following.kind == "LITERAL"
                and following.offset == token.offset + len(token.raw)
                and following.raw == following.literal
                and shared_length <= len(following.literal)
            ):
                shared = following.literal[:shared_length]
                choices: list[bytes] = []
                start = 0
                for width in widths:
                    choices.append(shared[start : start + width])
                    start += width
                operations.append(
                    BmAlternatives(
                        token.offset,
                        token.raw + shared,
                        token,
                        widths,
                        tuple(choices),
                    )
                )
                suffix = following.literal[shared_length:]
                if suffix:
                    operations.append(
                        BmLiteral(following.offset + shared_length, suffix, suffix)
                    )
                index += 1
            else:
                operations.append(BmOpaque(token.offset, token.raw, token))
        else:
            operations.append(_interpret_opcode(token))
        index += 1
    return BmSemanticPattern(pattern, tuple(operations))


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


def render_bm_printable_preview(pattern: BmPattern) -> str | None:
    """Show printable runs from interpreted literals, without matcher claims."""
    pieces: list[str | None] = []
    for operation in interpret_bm_pattern(pattern).operations:
        if isinstance(operation, BmEnd):
            continue
        if not isinstance(operation, BmLiteral):
            _append_omitted(pieces)
            continue
        pieces.extend(_printable_byte_pieces(operation.value))
    if pattern.issue is not None or pattern.remaining_raw:
        _append_omitted(pieces)
    return _render_printable_pieces(pieces)


def render_printable_bytes_preview(data: bytes) -> str | None:
    """Show printable runs from literal bytes, marking every omitted span."""
    return _render_printable_pieces(_printable_byte_pieces(data))


def _printable_byte_pieces(data: bytes) -> list[str | None]:
    pieces: list[str | None] = []
    offset = 0
    while offset < len(data):
        printable = 0x20 <= data[offset] <= 0x7E
        end = offset + 1
        while end < len(data) and (0x20 <= data[end] <= 0x7E) == printable:
            end += 1
        if printable and end - offset >= 3:
            pieces.append(json.dumps(data[offset:end].decode("ascii")))
        else:
            _append_omitted(pieces)
        offset = end
    return pieces


def _append_omitted(pieces: list[str | None]) -> None:
    if not pieces or pieces[-1] is not None:
        pieces.append(None)


def _render_printable_pieces(pieces: list[str | None]) -> str | None:
    if not any(piece is not None for piece in pieces):
        return None
    result = "… " if pieces[0] is None else ""
    seen_fragment = False
    omitted = pieces[0] is None
    for piece in pieces:
        if piece is None:
            omitted = True
            continue
        if seen_fragment:
            result += " … " if omitted else " "
        result += piece
        seen_fragment = True
        omitted = False
    if omitted and seen_fragment:
        result += " …"
    return result
