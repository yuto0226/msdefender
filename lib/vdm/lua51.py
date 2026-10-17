"""Export Defender LuaQ as Lua 5.1 chunks with signed int64 numbers."""

import struct
from dataclasses import dataclass
from typing import Final, Literal

from .luaq import LuaQChunk, LuaQConstant, LuaQPrototype, LuaQString

LUA51_X64_LE_INTEGRAL_HEADER: Final = b"\x1bLua\x51\x00\x01\x04\x08\x04\x08\x01"
LUA51_MAX_PROTOTYPE_DEPTH: Final = 200

Lua51WarningCode = Literal["negative_debug_count"]


@dataclass(frozen=True, slots=True)
class Lua51ExportWarning:
    code: Lua51WarningCode
    message: str
    prototype_path: tuple[int, ...] | None = None
    field: str | None = None
    original: int | None = None
    replacement: int | None = None


@dataclass(frozen=True, slots=True)
class Lua51Export:
    data: bytes
    warnings: tuple[Lua51ExportWarning, ...]


def _pack_count(value: int, field: str) -> bytes:
    return _pack_load_int(value, f"{field} count")


def _pack_load_int(value: int, field: str) -> bytes:
    if not 0 <= value <= 0x7FFFFFFF:
        raise ValueError(f"Lua 5.1 {field} must be between 0 and INT_MAX: {value}")
    return struct.pack("<i", value)


def _write_string(output: bytearray, value: LuaQString) -> None:
    if value.declared_length != len(value.payload_raw):
        raise ValueError("inconsistent LuaQ string declared length")
    if value.is_null:
        if value.payload_raw or value.value_raw is not None:
            raise ValueError("inconsistent null LuaQ string")
        output.extend(struct.pack("<Q", 0))
        return
    if value.value_raw is None:
        raise ValueError("inconsistent non-null LuaQ string")
    if value.value_raw != value.payload_raw[:-1]:
        raise ValueError("inconsistent LuaQ string value bytes")
    if value.discarded_suffix_raw != value.payload_raw[-1:]:
        raise ValueError("inconsistent LuaQ string suffix")
    output.extend(struct.pack("<Q", len(value.value_raw) + 1))
    output.extend(value.value_raw)
    output.append(0)


def _write_constant(
    output: bytearray,
    constant: LuaQConstant,
) -> None:
    output.append(constant.tag)
    if constant.tag == 0:
        if constant.value is not None:
            raise ValueError("inconsistent nil LuaQ constant")
    elif constant.tag == 1:
        if not isinstance(constant.value, int) or not 0 <= constant.value <= 0xFF:
            raise ValueError("inconsistent boolean LuaQ constant")
        output.append(constant.value)
    elif constant.tag == 3:
        if not isinstance(constant.value, int):
            raise ValueError("inconsistent int64 LuaQ constant")
        output.extend(struct.pack("<q", constant.value))
    elif constant.tag == 4:
        if not isinstance(constant.value, LuaQString):
            raise ValueError("inconsistent string LuaQ constant")
        _write_string(output, constant.value)
    else:
        raise ValueError(f"unsupported LuaQ constant tag: {constant.tag}")


def _write_prototype_prefix(
    output: bytearray,
    prototype: LuaQPrototype,
) -> None:
    _write_string(output, prototype.source)
    output.extend(_pack_load_int(prototype.line_defined, "line_defined"))
    output.extend(_pack_load_int(prototype.last_line_defined, "last_line_defined"))
    output.extend(
        bytes(
            (
                prototype.upvalue_count,
                prototype.parameter_count,
                prototype.vararg_flags,
                prototype.max_stack_size,
            )
        )
    )
    output.extend(_pack_count(len(prototype.instructions), "instruction"))
    for instruction in prototype.instructions:
        if len(instruction.raw) != 4:
            raise ValueError("LuaQ instruction is not four bytes")
        output.extend(instruction.raw)

    output.extend(_pack_count(len(prototype.constants), "constant"))
    for constant in prototype.constants:
        _write_constant(output, constant)
    output.extend(_pack_count(len(prototype.children), "child prototype"))


def _normalized_debug_count(
    declared: int,
    actual: int,
    field: str,
    path: tuple[int, ...],
    warnings: list[Lua51ExportWarning],
) -> int:
    if declared < 0:
        warnings.append(
            Lua51ExportWarning(
                code="negative_debug_count",
                message=(
                    f"prototype {path!r} {field} count {declared} is normalized to 0"
                ),
                prototype_path=path,
                field=field,
                original=declared,
                replacement=0,
            )
        )
        if actual:
            raise ValueError(f"negative {field} count has parsed entries")
        return 0
    if declared != actual:
        raise ValueError(
            f"inconsistent LuaQ {field} count: declared {declared}, have {actual}"
        )
    return declared


def _write_prototype_debug(
    output: bytearray,
    prototype: LuaQPrototype,
    *,
    path: tuple[int, ...],
    warnings: list[Lua51ExportWarning],
) -> None:
    output.extend(_pack_count(len(prototype.line_info), "line info"))
    for entry in prototype.line_info:
        if len(entry.raw) != 4:
            raise ValueError("LuaQ line-info entry is not four bytes")
        output.extend(_pack_load_int(entry.value, "line info"))

    local_count = _normalized_debug_count(
        prototype.local_variable_count,
        len(prototype.local_variables),
        "local variable",
        path,
        warnings,
    )
    output.extend(_pack_count(local_count, "local variable"))
    for local in prototype.local_variables:
        _write_string(output, local.name)
        output.extend(_pack_load_int(local.start_pc, "local start_pc"))
        output.extend(_pack_load_int(local.end_pc, "local end_pc"))

    upvalue_name_count = _normalized_debug_count(
        prototype.upvalue_name_count,
        len(prototype.upvalue_names),
        "upvalue name",
        path,
        warnings,
    )
    output.extend(_pack_count(upvalue_name_count, "upvalue name"))
    for name in prototype.upvalue_names:
        _write_string(output, name)


def export_lua51(chunk: LuaQChunk) -> Lua51Export:
    """Convert LuaQ to the x64 little-endian integral Lua 5.1 ABI."""
    if chunk.form == "encoded":
        raise ValueError("cannot export encoded LuaQ: decoder semantics are unknown")
    if chunk.trailing_raw:
        raise ValueError("cannot export LuaQ with trailing data")

    output = bytearray(LUA51_X64_LE_INTEGRAL_HEADER)
    warnings: list[Lua51ExportWarning] = []

    # LIFO actions preserve prefix -> children -> debug wire order without
    # consuming Python's recursion limit on deeply nested prototype trees.
    actions: list[
        tuple[Literal["prototype", "debug"], LuaQPrototype, tuple[int, ...]]
    ] = [("prototype", chunk.prototype, ())]
    while actions:
        action, prototype, path = actions.pop()
        if len(path) >= LUA51_MAX_PROTOTYPE_DEPTH:
            raise ValueError(
                "LuaQ prototype depth exceeds stock Lua 5.1 LUAI_MAXCCALLS"
            )
        if action == "debug":
            _write_prototype_debug(
                output,
                prototype,
                path=path,
                warnings=warnings,
            )
            continue

        _write_prototype_prefix(output, prototype)
        actions.append(("debug", prototype, path))
        actions.extend(
            ("prototype", child, (*path, index))
            for index, child in reversed(tuple(enumerate(prototype.children)))
        )

    return Lua51Export(data=bytes(output), warnings=tuple(warnings))


__all__ = [
    "LUA51_MAX_PROTOTYPE_DEPTH",
    "LUA51_X64_LE_INTEGRAL_HEADER",
    "Lua51Export",
    "Lua51ExportWarning",
    "Lua51WarningCode",
    "export_lua51",
]
