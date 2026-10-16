"""Lossless parser for Defender's LuaQ serialized function tree.

The engine accepts a 12-byte script header beginning with either ``\x1bLua``
or the encoded marker DWORD 1, then reads one recursive prototype.  The
encoded marker does not transform the structure bytes during this step.
This module intentionally models that wire format; it does not claim that
the result is a standard Lua ``luac`` chunk.
"""

from dataclasses import dataclass
from typing import Final, Literal

LUAQ_HEADER_SIZE: Final = 12
LUAQ_MAGIC: Final = b"\x1bLua"
LUAQ_ENCODED_MARKER: Final = 1

LuaQForm = Literal["raw_lua", "encoded"]


class LuaQParseError(ValueError):
    """A malformed or truncated LuaQ wire value."""

    def __init__(self, offset: int, message: str) -> None:
        self.offset = offset
        super().__init__(f"LuaQ offset 0x{offset:X}: {message}")


@dataclass(frozen=True, slots=True)
class LuaQString:
    """A uint32-length-prefixed engine string.

    A zero length represents NULL.  For non-NULL strings the engine gives
    ``declared_length - 1`` bytes to Lua and discards the final wire byte;
    it does not validate that the discarded byte is NUL.
    """

    raw: bytes
    declared_length: int
    payload_raw: bytes
    value_raw: bytes | None
    discarded_suffix_raw: bytes

    @property
    def is_null(self) -> bool:
        return self.declared_length == 0


@dataclass(frozen=True, slots=True)
class LuaQInstruction:
    raw: bytes
    value: int


@dataclass(frozen=True, slots=True)
class LuaQConstant:
    raw: bytes
    tag: int
    payload_raw: bytes
    value: None | int | LuaQString


@dataclass(frozen=True, slots=True)
class LuaQLineInfo:
    raw: bytes
    value: int


@dataclass(frozen=True, slots=True)
class LuaQLocalVariable:
    raw: bytes
    name: LuaQString
    start_pc: int
    end_pc: int


@dataclass(frozen=True, slots=True)
class LuaQPrototype:
    raw: bytes
    source: LuaQString
    line_defined: int
    last_line_defined: int
    upvalue_count: int
    parameter_count: int
    vararg_flags: int
    max_stack_size: int
    instructions: tuple[LuaQInstruction, ...]
    constants: tuple[LuaQConstant, ...]
    children: tuple["LuaQPrototype", ...]
    line_info: tuple[LuaQLineInfo, ...]
    local_variable_count: int
    local_variables: tuple[LuaQLocalVariable, ...]
    upvalue_name_count: int
    upvalue_names: tuple[LuaQString, ...]


@dataclass(frozen=True, slots=True)
class LuaQChunk:
    raw: bytes
    header_raw: bytes
    form: LuaQForm
    prototype: LuaQPrototype
    consumed: int
    trailing_raw: bytes


type _LuaQConstantValue = None | int | LuaQString


@dataclass(slots=True)
class _Reader:
    data: bytes
    offset: int = 0

    @property
    def remaining(self) -> int:
        return len(self.data) - self.offset

    def take(self, size: int, context: str) -> bytes:
        if size < 0 or size > self.remaining:
            raise LuaQParseError(
                self.offset,
                f"truncated {context}: need {size} bytes, have {self.remaining}",
            )
        start = self.offset
        self.offset += size
        return self.data[start : self.offset]

    def read_u8(self, context: str) -> int:
        return self.take(1, context)[0]

    def read_i32(self, context: str) -> int:
        return int.from_bytes(self.take(4, context), "little", signed=True)

    def read_u32(self, context: str) -> int:
        return int.from_bytes(self.take(4, context), "little")

    def read_count(self, context: str, item_size: int = 1) -> int:
        count_offset = self.offset
        count = self.read_i32(f"{context} count")
        if count < 0:
            raise LuaQParseError(count_offset, f"negative {context} count: {count}")
        if item_size > 0 and count > self.remaining // item_size:
            raise LuaQParseError(
                count_offset,
                f"{context} count {count} exceeds remaining input",
            )
        return count

    def read_string(self, context: str) -> LuaQString:
        start = self.offset
        declared_length = self.read_u32(f"{context} length")
        payload_raw = self.take(declared_length, context)
        if declared_length == 0:
            value_raw = None
            discarded_suffix_raw = b""
        else:
            value_raw = payload_raw[:-1]
            discarded_suffix_raw = payload_raw[-1:]
        return LuaQString(
            raw=self.data[start : self.offset],
            declared_length=declared_length,
            payload_raw=payload_raw,
            value_raw=value_raw,
            discarded_suffix_raw=discarded_suffix_raw,
        )


@dataclass(slots=True)
class _PrototypeFrame:
    start: int
    context: str
    source: LuaQString
    line_defined: int
    last_line_defined: int
    upvalue_count: int
    parameter_count: int
    vararg_flags: int
    max_stack_size: int
    instructions: tuple[LuaQInstruction, ...]
    constants: tuple[LuaQConstant, ...]
    child_count: int
    children: list[LuaQPrototype]


def _parse_constant(reader: _Reader, index: int) -> LuaQConstant:
    start = reader.offset
    tag = reader.read_u8(f"constant {index} tag")
    payload_start = reader.offset
    value: _LuaQConstantValue

    if tag == 0:
        value = None
    elif tag == 1:
        value = reader.read_u8(f"constant {index} boolean")
    elif tag == 3:
        value = int.from_bytes(
            reader.take(8, f"constant {index} int64"),
            "little",
            signed=True,
        )
    elif tag == 4:
        value = reader.read_string(f"constant {index} string")
    else:
        raise LuaQParseError(start, f"unsupported constant tag {tag}")

    return LuaQConstant(
        raw=reader.data[start : reader.offset],
        tag=tag,
        payload_raw=reader.data[payload_start : reader.offset],
        value=value,
    )


def _read_prototype_prefix(reader: _Reader, context: str) -> _PrototypeFrame:
    start = reader.offset
    source = reader.read_string(f"{context} source")
    line_defined = reader.read_i32(f"{context} line_defined")
    last_line_defined = reader.read_i32(f"{context} last_line_defined")
    upvalue_count = reader.read_u8(f"{context} upvalue_count")
    parameter_count = reader.read_u8(f"{context} parameter_count")
    vararg_flags = reader.read_u8(f"{context} vararg_flags")
    max_stack_size = reader.read_u8(f"{context} max_stack_size")

    instruction_count = reader.read_count(f"{context} instruction", 4)
    instructions = tuple(
        LuaQInstruction(
            raw=(raw := reader.take(4, f"{context} instruction {index}")),
            value=int.from_bytes(raw, "little"),
        )
        for index in range(instruction_count)
    )

    constant_count = reader.read_count(f"{context} constant")
    constants = tuple(_parse_constant(reader, index) for index in range(constant_count))

    child_count = reader.read_count(f"{context} child")
    return _PrototypeFrame(
        start=start,
        context=context,
        source=source,
        line_defined=line_defined,
        last_line_defined=last_line_defined,
        upvalue_count=upvalue_count,
        parameter_count=parameter_count,
        vararg_flags=vararg_flags,
        max_stack_size=max_stack_size,
        instructions=instructions,
        constants=constants,
        child_count=child_count,
        children=[],
    )


def _finish_prototype(reader: _Reader, frame: _PrototypeFrame) -> LuaQPrototype:
    line_info_count = reader.read_count(f"{frame.context} line_info", 4)
    line_info = tuple(
        LuaQLineInfo(
            raw=(raw := reader.take(4, f"{frame.context} line_info {index}")),
            value=int.from_bytes(raw, "little", signed=True),
        )
        for index in range(line_info_count)
    )

    local_count_offset = reader.offset
    local_variable_count = reader.read_i32(f"{frame.context} local variable count")
    if local_variable_count > 0 and local_variable_count > reader.remaining // 12:
        raise LuaQParseError(
            local_count_offset,
            (
                f"{frame.context} local variable count {local_variable_count} "
                "exceeds remaining input"
            ),
        )
    local_variables: list[LuaQLocalVariable] = []
    for index in range(max(0, local_variable_count)):
        local_start = reader.offset
        name = reader.read_string(f"{frame.context} local variable {index} name")
        start_pc = reader.read_i32(f"{frame.context} local variable {index} start_pc")
        end_pc = reader.read_i32(f"{frame.context} local variable {index} end_pc")
        local_variables.append(
            LuaQLocalVariable(
                raw=reader.data[local_start : reader.offset],
                name=name,
                start_pc=start_pc,
                end_pc=end_pc,
            )
        )

    upvalue_count_offset = reader.offset
    upvalue_name_count = reader.read_i32(f"{frame.context} upvalue name count")
    if upvalue_name_count > 0 and upvalue_name_count > reader.remaining // 4:
        raise LuaQParseError(
            upvalue_count_offset,
            (
                f"{frame.context} upvalue name count {upvalue_name_count} "
                "exceeds remaining input"
            ),
        )
    upvalue_names = tuple(
        reader.read_string(f"{frame.context} upvalue name {index}")
        for index in range(max(0, upvalue_name_count))
    )

    return LuaQPrototype(
        raw=reader.data[frame.start : reader.offset],
        source=frame.source,
        line_defined=frame.line_defined,
        last_line_defined=frame.last_line_defined,
        upvalue_count=frame.upvalue_count,
        parameter_count=frame.parameter_count,
        vararg_flags=frame.vararg_flags,
        max_stack_size=frame.max_stack_size,
        instructions=frame.instructions,
        constants=frame.constants,
        children=tuple(frame.children),
        line_info=line_info,
        local_variable_count=local_variable_count,
        local_variables=tuple(local_variables),
        upvalue_name_count=upvalue_name_count,
        upvalue_names=upvalue_names,
    )


def _parse_prototype_tree(reader: _Reader) -> LuaQPrototype:
    stack = [_read_prototype_prefix(reader, "root prototype")]
    while stack:
        frame = stack[-1]
        if len(frame.children) < frame.child_count:
            child_index = len(frame.children)
            stack.append(
                _read_prototype_prefix(
                    reader,
                    f"prototype depth {len(stack)} child {child_index}",
                )
            )
            continue

        prototype = _finish_prototype(reader, frame)
        stack.pop()
        if not stack:
            return prototype
        stack[-1].children.append(prototype)

    raise LuaQParseError(reader.offset, "missing root prototype")


def parse_luaq(data: bytes) -> LuaQChunk:
    """Parse one Defender LuaQ chunk without normalizing its wire values.

    Encoded-marker chunks retain their raw body.  ``ProcessFunction`` reads
    that body directly; the engine preserves the decoding-table pointer and
    encoded flag, but their eventual consumer is not yet confirmed.
    Bytes after the root prototype are retained as ``trailing_raw`` because
    the engine's processing path does not require end-of-input there.
    """
    if len(data) < LUAQ_HEADER_SIZE:
        raise LuaQParseError(
            0,
            f"truncated header: need {LUAQ_HEADER_SIZE} bytes, have {len(data)}",
        )
    if data[: len(LUAQ_MAGIC)] == LUAQ_MAGIC:
        form: LuaQForm = "raw_lua"
    elif int.from_bytes(data[:4], "little") == LUAQ_ENCODED_MARKER:
        form = "encoded"
    else:
        raise LuaQParseError(0, "invalid header magic")

    reader = _Reader(data, LUAQ_HEADER_SIZE)
    prototype = _parse_prototype_tree(reader)
    return LuaQChunk(
        raw=data,
        header_raw=data[:LUAQ_HEADER_SIZE],
        form=form,
        prototype=prototype,
        consumed=reader.offset,
        trailing_raw=data[reader.offset :],
    )


__all__ = [
    "LUAQ_ENCODED_MARKER",
    "LUAQ_HEADER_SIZE",
    "LUAQ_MAGIC",
    "LuaQChunk",
    "LuaQConstant",
    "LuaQForm",
    "LuaQInstruction",
    "LuaQLineInfo",
    "LuaQLocalVariable",
    "LuaQParseError",
    "LuaQPrototype",
    "LuaQString",
    "parse_luaq",
]
