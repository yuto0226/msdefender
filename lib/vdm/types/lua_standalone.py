"""Lossless parser and concise renderer for LUASTANDALONE (0xBD)."""

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final, Literal

from ..core import DisplaySection, FamilySpec, FormatResult
from ..luaq import LuaQChunk, LuaQPrototype, parse_luaq
from ..pattern_codec import PATTERN_DECODING_TABLE_KEEP_NULL

LUASTANDALONE_TYPE: Final = 0xBD
HEADER_SIZE: Final = 8
MIN_SCRIPT_SIZE: Final = 12
RAW_LUA_MAGIC: Final = 0x61754C1B
ENCODED_LUA_MAGIC: Final = 1
METADATA_PREVIEW_BYTES: Final = 80
METADATA_PREVIEW_FIELDS: Final = 16

ScriptForm = Literal["raw_lua", "encoded"]


@dataclass(frozen=True, slots=True)
class LuaScriptCategory:
    name: str
    policy: int


LUA_SCRIPT_CATEGORIES: Mapping[int, LuaScriptCategory] = MappingProxyType(
    {
        0x00: LuaScriptCategory("Unknown", 0),
        0x01: LuaScriptCategory("Infrastructure", 6),
        0x02: LuaScriptCategory("Deprecated", 0),
        0x03: LuaScriptCategory("Deprecated", 0),
        0x04: LuaScriptCategory("Deprecated", 0),
        0x05: LuaScriptCategory("Deprecated", 0),
        0x06: LuaScriptCategory("Deprecated", 0),
        0x07: LuaScriptCategory("Deprecated", 0),
        0x08: LuaScriptCategory("PEPREEMU", 1),
        0x09: LuaScriptCategory("PEPOSTEMU", 1),
        0x0A: LuaScriptCategory("PELast", 1),
        0x0B: LuaScriptCategory("PEFinalizer", 1),
        0x0C: LuaScriptCategory("GenFirst", 3),
        0x0D: LuaScriptCategory("GenLast", 3),
        0x0E: LuaScriptCategory("PreRemediation", 6),
        0x0F: LuaScriptCategory("PostRemediation", 6),
        0x10: LuaScriptCategory("IETrigger", 1),
        0x11: LuaScriptCategory("DetectionSpecific", 6),
        0x12: LuaScriptCategory("ProcessInspector", 0),
        0x13: LuaScriptCategory("UACTrigger", 1),
        0x14: LuaScriptCategory("FFR", 4),
        0x15: LuaScriptCategory("SignatureValidator", 10),
        0x16: LuaScriptCategory("MacroSource", 2),
        0x17: LuaScriptCategory("DynamicSignature", 2),
        0x18: LuaScriptCategory("GenFinalizer", 3),
        0x19: LuaScriptCategory("HipsRuleDefinition", 0),
        0x1A: LuaScriptCategory("RtpSkipRule", 2),
        0x1B: LuaScriptCategory("RtpSkipRuleEx", 2),
        0x1C: LuaScriptCategory("OnDetection", 3),
        0x1D: LuaScriptCategory("GenConsolidator", 3),
        0x1E: LuaScriptCategory("MachOGen", 3),
        0x1F: LuaScriptCategory("MemScan", 1),
        0x20: LuaScriptCategory("GenEarly", 3),
        0x21: LuaScriptCategory("OnImageConfig", 0),
        0x22: LuaScriptCategory("MpDiag", 20),
        0x23: LuaScriptCategory("ELFGen", 3),
    }
)


@dataclass(frozen=True, slots=True)
class LuaMetadataField:
    key_raw: bytes
    key: str | None
    effective_key: str | None
    value_raw: bytes
    value_decoded: bytes
    encoded: bool


@dataclass(frozen=True, slots=True)
class LuaStandalonePayload:
    raw: bytes
    name_len: int
    category: int
    category_name: str | None
    category_policy: int | None
    metadata_len: int
    script_len: int
    name_raw: bytes
    name_effective_raw: bytes
    name: str | None
    metadata_raw: bytes
    metadata: tuple[LuaMetadataField, ...]
    metadata_unparsed_raw: bytes
    flags: int | None
    includes: bytes | None
    timestamp: int | None
    script: bytes
    script_form: ScriptForm | None
    lua_header: bytes | None
    lua_chunk: LuaQChunk | None
    trailing_raw: bytes
    receiver_ignored: bool
    ignored_body_raw: bytes


def _decode_utf8(data: bytes) -> str | None:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _parse_crt_unsigned_prefix(value: bytes, key: str, bits: int) -> int:
    """Model Windows CRT strtoul/strtoull with radix 16 and no endptr check."""
    index = 0
    while index < len(value) and value[index] in b" \t\n\v\f\r":
        index += 1

    negative = False
    if index < len(value) and value[index] in b"+-":
        negative = value[index] == ord("-")
        index += 1

    digit_start = index
    if value[index : index + 2].lower() == b"0x":
        if (
            index + 2 >= len(value)
            or chr(value[index + 2]).lower() not in "0123456789abcdef"
        ):
            raise ValueError(
                f"invalid LUASTANDALONE {key}: expected hexadecimal integer"
            )
        index += 2
        digit_start = index

    parsed = 0
    maximum = (1 << bits) - 1
    while index < len(value):
        byte = value[index]
        if 0x30 <= byte <= 0x39:
            digit = byte - 0x30
        elif 0x41 <= byte <= 0x46:
            digit = byte - 0x41 + 10
        elif 0x61 <= byte <= 0x66:
            digit = byte - 0x61 + 10
        else:
            break
        if parsed > (maximum - digit) // 16:
            raise ValueError(f"invalid LUASTANDALONE {key}: integer overflow")
        parsed = parsed * 16 + digit
        index += 1

    if index == digit_start:
        raise ValueError(f"invalid LUASTANDALONE {key}: expected hexadecimal integer")
    return (-parsed) & maximum if negative else parsed


def _parse_metadata(
    data: bytes,
) -> tuple[
    tuple[LuaMetadataField, ...],
    bytes,
    int | None,
    bytes | None,
    int | None,
]:
    fields: list[LuaMetadataField] = []
    flags: int | None = None
    includes: bytes | None = None
    timestamp: int | None = None
    offset = 0

    while offset < len(data):
        key_end = data.find(b"\0", offset)
        if key_end < 0 or key_end == len(data) - 1:
            break

        value_offset = key_end + 1
        value_end = data.find(b"\0", value_offset)
        if value_end < 0:
            raise ValueError(
                "truncated LUASTANDALONE metadata value: missing NUL terminator"
            )

        key_raw = data[offset:key_end]
        value_raw = data[value_offset:value_end]
        encoded = key_raw.startswith(b"Ob")
        effective_key_raw = key_raw[2:] if encoded else key_raw
        key = _decode_utf8(key_raw)
        effective_key = _decode_utf8(effective_key_raw)

        value_decoded = (
            value_raw.translate(PATTERN_DECODING_TABLE_KEEP_NULL)
            if encoded
            else value_raw
        )
        fields.append(
            LuaMetadataField(
                key_raw=key_raw,
                key=key,
                effective_key=effective_key,
                value_raw=value_raw,
                value_decoded=value_decoded,
                encoded=encoded,
            )
        )

        if effective_key == "Flags":
            flags = _parse_crt_unsigned_prefix(value_decoded, "Flags", 32)
            if flags == 0:
                raise ValueError("invalid LUASTANDALONE Flags: value must be nonzero")
        elif effective_key == "TimeStamp":
            try:
                timestamp = _parse_crt_unsigned_prefix(
                    value_decoded,
                    "TimeStamp",
                    64,
                )
            except ValueError:
                timestamp = 0
        elif effective_key == "Includes":
            includes = value_decoded

        offset = value_end + 1

    return tuple(fields), data[offset:], flags, includes, timestamp


def parse_lua_standalone(payload: bytes) -> LuaStandalonePayload:
    """Parse the AddScript envelope in engine validation order."""
    if len(payload) < HEADER_SIZE:
        raise ValueError(
            f"truncated LUASTANDALONE header: need {HEADER_SIZE} bytes, "
            f"have {len(payload)}"
        )

    name_len = payload[0]
    category = payload[1]
    metadata_len = int.from_bytes(payload[2:4], "little")
    script_len = int.from_bytes(payload[4:8], "little")
    category_info = LUA_SCRIPT_CATEGORIES.get(category)

    if category_info is None:
        return LuaStandalonePayload(
            raw=payload,
            name_len=name_len,
            category=category,
            category_name=None,
            category_policy=None,
            metadata_len=metadata_len,
            script_len=script_len,
            name_raw=b"",
            name_effective_raw=b"",
            name=None,
            metadata_raw=b"",
            metadata=(),
            metadata_unparsed_raw=b"",
            flags=None,
            includes=None,
            timestamp=None,
            script=b"",
            script_form=None,
            lua_header=None,
            lua_chunk=None,
            trailing_raw=b"",
            receiver_ignored=True,
            ignored_body_raw=payload[HEADER_SIZE:],
        )

    name_end = HEADER_SIZE + name_len
    if name_len == 0 and category_info.policy & 1 == 0:
        raise ValueError("invalid LUASTANDALONE name: category policy requires a name")
    if name_end > len(payload):
        raise ValueError(
            f"truncated LUASTANDALONE name: need {name_len} bytes, "
            f"have {max(0, len(payload) - HEADER_SIZE)}"
        )
    name_raw = payload[HEADER_SIZE:name_end]
    if name_raw and name_raw[-1] != 0:
        raise ValueError("invalid LUASTANDALONE name: missing NUL terminator")
    name_effective_raw = name_raw.partition(b"\0")[0]

    metadata_end = name_end + metadata_len
    if metadata_end > len(payload):
        raise ValueError(
            f"truncated LUASTANDALONE metadata: need {metadata_len} bytes, "
            f"have {max(0, len(payload) - name_end)}"
        )
    metadata_raw = payload[name_end:metadata_end]
    metadata, metadata_unparsed_raw, flags, includes, timestamp = _parse_metadata(
        metadata_raw
    )

    script_end = metadata_end + script_len
    if script_end > len(payload):
        raise ValueError(
            f"truncated LUASTANDALONE script: need {script_len} bytes, "
            f"have {max(0, len(payload) - metadata_end)}"
        )
    script = payload[metadata_end:script_end]
    if len(script) < MIN_SCRIPT_SIZE:
        raise ValueError(
            f"truncated LUASTANDALONE script header: need {MIN_SCRIPT_SIZE} bytes, "
            f"have {len(script)}"
        )
    magic = int.from_bytes(script[:4], "little")
    if magic == RAW_LUA_MAGIC:
        script_form: ScriptForm = "raw_lua"
        lua_header = script[:MIN_SCRIPT_SIZE]
    elif magic == ENCODED_LUA_MAGIC:
        script_form = "encoded"
        lua_header = None
    else:
        raise ValueError(f"invalid LUASTANDALONE script magic: 0x{magic:08X}")
    lua_chunk = None if category_info.policy & 0x10 else parse_luaq(script)

    # AddScript performs these holder-level validations only after Process.
    if flags is not None and flags > 0xFF:
        raise ValueError("invalid LUASTANDALONE Flags: value does not fit uint8")
    if category_info.policy & 8:
        category_key = _parse_crt_unsigned_prefix(
            name_effective_raw,
            "category name",
            64,
        )
        if category_key in {0, 0xFFFFFFFFFFFFFFFF}:
            raise ValueError(
                "invalid LUASTANDALONE category name: reserved numeric value"
            )

    return LuaStandalonePayload(
        raw=payload,
        name_len=name_len,
        category=category,
        category_name=category_info.name,
        category_policy=category_info.policy,
        metadata_len=metadata_len,
        script_len=script_len,
        name_raw=name_raw,
        name_effective_raw=name_effective_raw,
        name=_decode_utf8(name_effective_raw),
        metadata_raw=metadata_raw,
        metadata=metadata,
        metadata_unparsed_raw=metadata_unparsed_raw,
        flags=flags,
        includes=includes,
        timestamp=timestamp,
        script=script,
        script_form=script_form,
        lua_header=lua_header,
        lua_chunk=lua_chunk,
        trailing_raw=payload[script_end:],
        receiver_ignored=False,
        ignored_body_raw=b"",
    )


def _quoted(data: bytes) -> str:
    text = _decode_utf8(data)
    if text is None:
        return f"(non-UTF-8; {data[:32].hex(' ') or '(empty)'})"
    return json.dumps(text, ensure_ascii=True)


def _hex_preview(data: bytes, limit: int = 32) -> str:
    preview = data[:limit].hex(" ") or "(empty)"
    if len(data) > limit:
        return f"{preview} … (+{len(data) - limit} B)"
    return preview


def _text_preview(data: bytes, limit: int = METADATA_PREVIEW_BYTES) -> str:
    text = _decode_utf8(data)
    if text is None:
        return f"(non-UTF-8; {_hex_preview(data)})"
    if len(data) <= limit:
        return json.dumps(text, ensure_ascii=True)

    prefix = data[:limit]
    while prefix:
        prefix_text = _decode_utf8(prefix)
        if prefix_text is not None:
            return (
                f"{json.dumps(prefix_text, ensure_ascii=True)} … ({len(data)} B total)"
            )
        prefix = prefix[:-1]
    return f"(UTF-8; {len(data)} B total)"


def _lua_tree_counts(root: LuaQPrototype) -> tuple[int, int, int]:
    prototype_count = 0
    instruction_count = 0
    constant_count = 0
    pending = [root]
    while pending:
        prototype = pending.pop()
        prototype_count += 1
        instruction_count += len(prototype.instructions)
        constant_count += len(prototype.constants)
        pending.extend(prototype.children)
    return prototype_count, instruction_count, constant_count


def render_lua_standalone(parsed: LuaStandalonePayload) -> FormatResult:
    category = (
        f"{parsed.category_name} (0x{parsed.category:02X})"
        if parsed.category_name is not None
        else f"unsupported (0x{parsed.category:02X})"
    )
    envelope_rows = [
        ("category", category),
        (
            "category_policy",
            (
                f"0x{parsed.category_policy:08X}"
                if parsed.category_policy is not None
                else "not applicable"
            ),
        ),
        ("route", "not encoded in payload"),
        ("name_len", f"{parsed.name_len} B"),
        ("metadata_len", f"{parsed.metadata_len} B"),
        ("script_len", f"{parsed.script_len} B"),
    ]
    if parsed.receiver_ignored:
        envelope_rows.extend(
            (
                ("engine_behavior", "category >= 36; body ignored without validation"),
                ("ignored_body", f"{len(parsed.ignored_body_raw)} B"),
            )
        )
        return FormatResult(
            sections=(DisplaySection("Envelope", rows=tuple(envelope_rows)),)
        )

    envelope_rows.append(("name", _quoted(parsed.name_effective_raw)))
    if parsed.name_raw not in {b"", parsed.name_effective_raw + b"\0"}:
        envelope_rows.append(("name_wire_raw", _hex_preview(parsed.name_raw)))
    elif parsed.name is None and parsed.name_effective_raw:
        envelope_rows.append(("name_raw", _hex_preview(parsed.name_effective_raw)))
    if parsed.trailing_raw:
        envelope_rows.extend(
            (
                ("trailing_len", f"{len(parsed.trailing_raw)} B"),
                ("trailing_behavior", "ignored by engine"),
            )
        )

    sections = [DisplaySection("Envelope", rows=tuple(envelope_rows))]
    if parsed.metadata_raw:
        metadata_rows: list[tuple[str, str]] = []
        visible_fields = parsed.metadata[:METADATA_PREVIEW_FIELDS]
        for index, field in enumerate(visible_fields, 1):
            key = (
                field.key
                if field.key is not None and len(field.key_raw) <= 48
                else _text_preview(field.key_raw, 48)
            )
            if field.encoded:
                effective_raw = field.key_raw[2:]
                effective = (
                    field.effective_key
                    if field.effective_key is not None and len(effective_raw) <= 48
                    else _text_preview(effective_raw, 48)
                )
                metadata_rows.append(
                    (
                        f"{index}:{key}",
                        (
                            f"encoded {effective}; raw={_hex_preview(field.value_raw)}; "
                            f"decoded={_text_preview(field.value_decoded)}"
                        ),
                    )
                )
            else:
                metadata_rows.append((f"{index}:{key}", _text_preview(field.value_raw)))
        omitted_fields = len(parsed.metadata) - len(visible_fields)
        if omitted_fields:
            metadata_rows.append(("omitted_pairs", str(omitted_fields)))
        if parsed.metadata_unparsed_raw:
            metadata_rows.append(
                ("unparsed_raw", _hex_preview(parsed.metadata_unparsed_raw))
            )
        sections.append(DisplaySection("Metadata", rows=tuple(metadata_rows)))

    if parsed.script_form is None:
        raise ValueError("non-ignored LUASTANDALONE payload requires a script form")
    script_rows = [
        ("form", parsed.script_form),
        ("length", f"{len(parsed.script)} B"),
        ("sha256", hashlib.sha256(parsed.script).hexdigest()),
    ]
    if parsed.lua_header is not None:
        script_rows.append(("lua_header", parsed.lua_header.hex(" ")))
    if parsed.lua_chunk is not None:
        prototype_count, instruction_count, constant_count = _lua_tree_counts(
            parsed.lua_chunk.prototype
        )
        script_rows.extend(
            (
                ("prototypes", str(prototype_count)),
                ("instructions", str(instruction_count)),
                ("constants", str(constant_count)),
            )
        )
    elif parsed.category_policy is not None and parsed.category_policy & 0x10:
        script_rows.append(("processing", "deferred; full script preserved"))
    sections.append(DisplaySection("Script", rows=tuple(script_rows)))
    return FormatResult(sections=tuple(sections))


SPEC = FamilySpec(
    LUASTANDALONE_TYPE,
    "LUASTANDALONE",
    parse_lua_standalone,
    render_lua_standalone,
)
