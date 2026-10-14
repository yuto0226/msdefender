#!/usr/bin/env python3
"""
sig.py - Inspect and pretty-print records from a Microsoft Defender .sig file.

Usage:
    sig.py mpas.sig                                      # threats 列表（預設）
    sig.py threats mpas.sig -T Trojan -n 50              # 過濾威脅名稱
    sig.py threats mpas.sig -t 0x40                      # 含 SIGTREE 的 threats
    sig.py records mpas.sig -t 0x67 -n 3                 # STATIC records only
    sig.py records mpas.sig -t 0x78 -x                   # PEHSTR_EXT + hexdump
    sig.py records mpas.sig -T WannaCry --skip-framing
"""

from __future__ import annotations

import argparse
import io
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path

# Force UTF-8 on Windows
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

from lib.debug import (
    ANSI_BCYAN,
    ANSI_BLUE,
    ANSI_BOLD,
    ANSI_BWHITE,
    ANSI_BYELLOW,
    ANSI_CYAN,
    ANSI_GRAY,
    ANSI_GREEN,
    ANSI_MAGENTA,
    ANSI_RED,
    ANSI_RESET,
    ANSI_WHITE,
    ANSI_YELLOW,
    error,
    info,
)
from lib.utils import iter_records_from_file, iter_records_with_context
from lib.vdm import DEFAULT_REGISTRY, decode_payload
from lib.vdm import type_name as _type_name
from lib.vdm.bm_yara import BmYaraFidelity, BmYaraRender
from lib.vdm.types.hstr import HSTR_SPECS
from lib.vdm.types.threat import parse_threat_begin, threat_category_name

# Semantic annotation tables

# Aggregator receiver families use a different expression-buffer wire format.
_AGGREGATOR_FAMILY: dict[int, str] = {
    0x96: "aggregator",
    0xE7: "aggregator (ex)",
}

_HSTR_FAMILY_NAMES = {spec.type_byte: spec.name for spec in HSTR_SPECS}
_HSTR_PUSH_FAMILY = frozenset(_HSTR_FAMILY_NAMES)

# Aggregator flags bitmask — confirmed from aggregatorex_receiver / aggregator_receiver.
_AGGREGATOR_FLAG_BITS: list[tuple[int, str]] = [
    (0x01, "fuzzy"),
]

# Display helpers
# A formatter returns a list of (label, value) pairs.
# Return [] to fall through to raw hexdump.
Field = tuple[str, str]


@dataclass(slots=True)
class DisplaySection:
    title: str
    rows: list[Field] = field(default_factory=list)
    bm_yara: BmYaraRender | None = None
    printable_preview: str | None = None
    yara_unsupported: tuple[str, ...] = ()


@dataclass(slots=True)
class FormatResult:
    fields: list[Field] = field(default_factory=list)
    sections: list[DisplaySection] = field(default_factory=list)


INDENT = "    "
SEP_W = 72


def _hex_row(data: bytes, off: int) -> str:
    chunk = data[off : off + 16]
    hex_parts = []
    asc_parts = []
    for i, b in enumerate(chunk):
        sep = "  " if i == 8 else " "
        if i > 0:
            hex_parts.append(sep)
        color = ANSI_WHITE if 0x20 <= b <= 0x7E else ANSI_GRAY
        hex_parts.append(f"{color}{b:02x}{ANSI_RESET}")
        asc_parts.append(f"{color}{chr(b) if 0x20 <= b <= 0x7E else '.'}{ANSI_RESET}")
    # pad to full 16-byte width
    pad = 16 - len(chunk)
    if pad:
        hex_parts.append("   " * pad + (" " if len(chunk) <= 8 else ""))
    hex_str = "".join(hex_parts)
    asc_str = "".join(asc_parts)
    return f"{ANSI_RED}{off:08x}{ANSI_RESET}  {hex_str}  |{asc_str}|"


def _print_hexdump(data: bytes, indent: str = INDENT) -> None:
    for off in range(0, len(data), 16):
        print(indent + _hex_row(data, off))


def _print_fields(fields: list[Field], indent: str = INDENT) -> None:
    if not fields:
        return
    label_w = max(len(lbl) for lbl, _ in fields)
    for label, value in fields:
        print(f"{indent}{ANSI_CYAN}{label:<{label_w}}{ANSI_RESET}  {value}")


def _print_sections(sections: list[DisplaySection], indent: str = INDENT) -> None:
    if not sections:
        return
    row_indent = indent + "  "
    for idx, section in enumerate(sections):
        if idx:
            print()
        print(f"{indent}{ANSI_YELLOW}{section.title}{ANSI_RESET}")
        if not section.rows:
            continue
        label_w = max(len(label) for label, _ in section.rows)
        for label, value in section.rows:
            print(
                f"{row_indent}{ANSI_MAGENTA}· {label:<{label_w}}{ANSI_RESET} : {value}"
            )


def _print_preview(payload: bytes, indent: str = INDENT) -> None:
    """Print a 16-byte preview for partially parsed/error cases."""
    _print_hexdump(payload[:16], indent=indent)
    if len(payload) > 16:
        print(
            f"{indent}{ANSI_GRAY}… {len(payload) - 16} more bytes (use --hex to show all){ANSI_RESET}"
        )


def print_record(
    seq: int,
    type_byte: int,
    payload: bytes,
    threat_name: str,
    result: FormatResult,
    show_hex: bool,
    show_threat_heading: bool = True,
) -> None:
    """Print one record with header, parsed fields, and optional hexdump."""
    if type_byte == 0x67:
        _print_static_record(
            seq, payload, threat_name, result, show_hex, show_threat_heading
        )
        return
    if type_byte == 0x80:
        _print_structured_record(
            seq,
            0x80,
            "KCRCE",
            payload,
            threat_name,
            result,
            show_hex,
            show_threat_heading,
        )
        return
    if type_byte in _HSTR_PUSH_FAMILY:
        _print_hstr_record(
            seq, type_byte, payload, threat_name, result, show_hex, show_threat_heading
        )
        return
    name = _type_name(type_byte)
    tname = (
        f"  {ANSI_BOLD}{ANSI_BWHITE}{threat_name}{ANSI_RESET}" if threat_name else ""
    )
    sep = f"{ANSI_GRAY}{'─' * SEP_W}{ANSI_RESET}"

    print(sep)
    print(
        f"  {ANSI_BOLD}{ANSI_BYELLOW}#{seq}{ANSI_RESET}"
        f"  {ANSI_BOLD}{ANSI_BCYAN}{name}{ANSI_RESET}"
        f"  {ANSI_GRAY}({type_byte:#04x}){ANSI_RESET}"
        f"  {ANSI_GRAY}{len(payload)} B{ANSI_RESET}"
        f"{tname}"
    )

    fields = result.fields
    sections = result.sections
    has_error = any(label == "error" for label, _ in fields)

    if fields:
        _print_fields(fields)
        if sections:
            print()
    if sections:
        _print_sections(sections)
    if not show_hex and has_error:
        print()
        _print_preview(payload)
    elif not show_hex and not fields and not sections:
        # Print the first 16 bytes without --hex.
        _print_preview(payload)
        return

    if show_hex:
        if fields:
            print()  # blank line before hexdump
        _print_hexdump(payload)


def _print_static_record(
    seq: int,
    payload: bytes,
    threat_name: str,
    result: FormatResult,
    show_hex: bool,
    show_threat_heading: bool,
) -> None:
    _print_structured_record(
        seq,
        0x67,
        "STATIC",
        payload,
        threat_name,
        result,
        show_hex,
        show_threat_heading,
    )


def _print_structured_record(
    seq: int,
    type_byte: int,
    family_label: str,
    payload: bytes,
    threat_name: str,
    result: FormatResult,
    show_hex: bool,
    show_threat_heading: bool,
) -> None:
    """Print a structured family record with shared framing and sections."""
    if threat_name and show_threat_heading:
        print(f"{ANSI_GRAY}{'─' * SEP_W}{ANSI_RESET}")
        print(
            f"{ANSI_GREEN}[+]{ANSI_RESET} "
            f"{ANSI_BOLD}{ANSI_BWHITE}{threat_name}{ANSI_RESET}"
        )
    elif not show_threat_heading:
        print()

    error_value = next(
        (value for label, value in result.fields if label.lower() == "error"), None
    )
    if error_value is not None:
        print(
            f"{ANSI_RED}[-]{ANSI_RESET} "
            f"{ANSI_BOLD}{ANSI_BWHITE}{family_label}(0x{type_byte:02x}){ANSI_RESET}"
            f"  {ANSI_GRAY}#{seq} / {len(payload)} B{ANSI_RESET}"
        )
        print(
            f"{INDENT}{ANSI_RED}[-]{ANSI_RESET} "
            f"{ANSI_BOLD}{ANSI_BWHITE}Parse Error{ANSI_RESET}"
        )
        _print_fields([("error", error_value)], indent=INDENT * 2)
        if show_hex:
            print()
            _print_hexdump(payload)
        return

    print(
        f"{ANSI_BLUE}[*]{ANSI_RESET} "
        f"{ANSI_BOLD}{ANSI_BWHITE}{family_label}(0x{type_byte:02x}){ANSI_RESET}"
        f"  {ANSI_GRAY}#{seq} / {len(payload)} B{ANSI_RESET}"
    )
    for section_index, section in enumerate(result.sections):
        # STATIC's first section is its primary info section; later sections are detail.
        is_primary_section = section_index == 0
        icon = "[*]" if is_primary_section else "[>]"
        color = ANSI_BLUE if is_primary_section else ANSI_GRAY
        print(
            f"{INDENT}{color}{icon}{ANSI_RESET} "
            f"{ANSI_BOLD}{ANSI_BWHITE}{section.title}{ANSI_RESET}"
        )
        _print_fields(list(section.rows), indent=INDENT * 2)
    if show_hex:
        print()
        _print_hexdump(payload)


def _print_hstr_record(
    seq: int,
    type_byte: int,
    payload: bytes,
    threat_name: str,
    result: FormatResult,
    show_hex: bool,
    show_threat_heading: bool,
) -> None:
    has_subsignature_data = False
    if threat_name and show_threat_heading:
        print(f"{ANSI_GRAY}{'─' * SEP_W}{ANSI_RESET}")
        print(
            f"{ANSI_GREEN}[+]{ANSI_RESET} "
            f"{ANSI_BOLD}{ANSI_BWHITE}{threat_name}{ANSI_RESET}"
        )
    elif not show_threat_heading:
        print()
    print(
        f"{ANSI_BLUE}[*]{ANSI_RESET} "
        f"{ANSI_BOLD}{ANSI_BWHITE}{_HSTR_FAMILY_NAMES[type_byte]}"
        f"(0x{type_byte:02X}){ANSI_RESET}"
        f"  {ANSI_GRAY}#{seq} / {len(payload)} B{ANSI_RESET}"
    )
    for section in result.sections:
        is_detail = section.title.startswith("subsig ")
        icon = "[>]" if is_detail else "[*]"
        color = ANSI_GRAY if is_detail else ANSI_BLUE
        print(
            f"{INDENT}{color}{icon}{ANSI_RESET} "
            f"{ANSI_BOLD}{ANSI_BWHITE}{section.title}{ANSI_RESET}"
        )
        rows = dict(section.rows)
        _print_hstr_fields(
            [(label, value) for label, value in section.rows if label != "raw"],
            INDENT * 2,
            bm_yara=section.bm_yara,
            printable_preview=section.printable_preview,
            yara_unsupported=section.yara_unsupported,
        )
        if is_detail and "raw" in rows:
            has_subsignature_data = True
            data = b"" if rows["raw"] == "(empty)" else bytes.fromhex(rows["raw"])
            needs_preview = (
                rows.get("matching") == "UNKNOWN"
                or "warning" in rows
                or "error" in rows
                or (
                    section.bm_yara is not None
                    and section.bm_yara.fidelity == BmYaraFidelity.UNSUPPORTED
                )
            )
            if show_hex:
                _print_hexdump(data, indent=INDENT * 2)
            elif needs_preview:
                _print_preview(data, indent=INDENT * 2)
    fields: list[Field] = []
    metadata_dumps: list[tuple[str, bytes]] = []
    for label, value in result.fields:
        if (label == "name" and value != '""') or (
            label == "tail_word0"
            and value != "NOT_PRESENT"
            and not value.startswith("0x0000")
        ):
            fields.append((label, value))
        elif label == "trailing_raw" and not value.startswith("0 B"):
            fields.append((label, value))
            if show_hex and "[" in value:
                trailing = value.split("[", 1)[1].removesuffix("]")
                metadata_dumps.append((label, bytes.fromhex(trailing)))
        elif label == "name_raw" and show_hex and value != "(empty)":
            metadata_dumps.append((label, bytes.fromhex(value)))
        elif label == "error":
            fields.append((label, value))
    if fields or metadata_dumps:
        icon = "[-]" if any(label == "error" for label, _ in fields) else "[*]"
        color = ANSI_RED if icon == "[-]" else ANSI_BLUE
        print(
            f"{INDENT}{color}{icon}{ANSI_RESET} "
            f"{ANSI_BOLD}{ANSI_BWHITE}Record Metadata{ANSI_RESET}"
        )
        _print_hstr_fields(fields, INDENT * 2)
        for label, data in metadata_dumps:
            print(f"{INDENT * 2}{ANSI_GRAY}{label}{ANSI_RESET}")
            _print_hexdump(data, indent=INDENT * 2)
    if show_hex and not has_subsignature_data:
        _print_hexdump(payload)
    elif any(label == "error" for label, _ in fields):
        _print_preview(payload)


def _highlight_bm_strings(value: str) -> str:
    """Color complete quoted segments without confusing escaped quotes."""
    parts: list[str] = []
    cursor = 0
    while cursor < len(value):
        start = value.find('"', cursor)
        if start < 0:
            parts.append(value[cursor:])
            break
        parts.append(value[cursor:start])
        end = start + 1
        while end < len(value):
            if value[end] == "\\":
                end += 2
            elif value[end] == '"':
                parts.append(f"{ANSI_YELLOW}{value[start : end + 1]}{ANSI_RESET}")
                cursor = end + 1
                break
            else:
                end += 1
        else:
            parts.append(value[start:])
            break
    return "".join(parts)


def _yara_tokens(value: str) -> list[str]:
    """Split display syntax without breaking quoted, gap, or alternative tokens."""
    tokens = []
    cursor = 0
    while cursor < len(value):
        if value[cursor].isspace():
            cursor += 1
            continue
        start = cursor
        char = value[cursor]
        if char == '"':
            cursor += 1
            while cursor < len(value):
                if value[cursor] == "\\":
                    cursor += 2
                elif value[cursor] == '"':
                    cursor += 1
                    break
                else:
                    cursor += 1
        elif char in "([":
            opening, closing = ("(", ")") if char == "(" else ("[", "]")
            depth = 0
            while cursor < len(value):
                if value[cursor] == opening:
                    depth += 1
                elif value[cursor] == closing:
                    depth -= 1
                    if depth == 0:
                        cursor += 1
                        break
                cursor += 1
        elif char in "{}":
            cursor += 1
        else:
            while cursor < len(value) and not value[cursor].isspace():
                cursor += 1
        tokens.append(value[start:cursor])
    return tokens


def _wrap_tokens(
    tokens: list[str],
    *,
    first: str,
    indent: str,
    width: int,
    continuation: str | None = None,
) -> list[str]:
    """Wrap complete syntax tokens; an oversized atomic token stays intact."""
    lines = []
    current = indent + first
    continuation = continuation or indent + "    "
    has_token = bool(first)
    for token in tokens:
        candidate = current + (" " if has_token else "") + token
        if has_token and len(candidate) > width:
            lines.append(current)
            current = continuation + token
            has_token = True
        elif not has_token and len(candidate) > width and current.strip():
            lines.append(current.rstrip())
            current = continuation + token
            has_token = True
        else:
            current = candidate
            has_token = True
    if current.strip() or not lines:
        lines.append(current.rstrip())
    return lines


def _wrap_comment_tokens(
    tokens: list[str], *, prefix: str, indent: str, width: int
) -> list[str]:
    if not tokens:
        return [indent + prefix.rstrip()]
    lines = []
    current = indent + prefix
    has_token = False
    for token in tokens:
        candidate = current + (" " if has_token else "") + token
        if has_token and len(candidate) > width:
            lines.append(current)
            current = indent + prefix + token
        else:
            current = candidate
        has_token = True
    lines.append(current)
    return lines


def _preview_tokens(preview: str) -> list[str]:
    return _yara_tokens(preview)


def _comment_lines(
    *, preview: str | None, conditional: tuple[str, ...], indent: str, width: int
) -> list[str]:
    lines = []
    if preview is not None:
        preview_tokens = _preview_tokens(preview)
        inline = f"// preview: {preview}"
        if len(indent + inline) <= width:
            lines.append(indent + inline)
        else:
            lines.append(indent + "// preview:")
            lines.extend(
                _wrap_comment_tokens(
                    preview_tokens, prefix="//   ", indent=indent, width=width
                )
            )
    if conditional:
        inline = "// conditional: " + ", ".join(conditional)
        if len(indent + inline) <= width:
            lines.append(indent + inline)
        else:
            lines.append(indent + "// conditional:")
            requirements = []
            for index, requirement in enumerate(conditional):
                words = requirement.split()
                if words and index + 1 < len(conditional):
                    words[-1] += ","
                requirements.extend(words or (requirement,))
            lines.extend(
                _wrap_comment_tokens(
                    requirements, prefix="//   ", indent=indent, width=width
                )
            )
    return lines


def _format_yara_declaration(
    *,
    identifier: str | None,
    rhs: str | None,
    indent: str,
    width: int,
    preview: str | None = None,
    conditional: tuple[str, ...] = (),
    unsupported: tuple[str, ...] | None = None,
) -> list[str]:
    """Format one YARA-like declaration and its terminal-only annotations."""
    if unsupported is not None:
        codes = unsupported or ("unsupported",)
        lines = []
        current = indent + "yara: "
        has_code = False
        continuation = indent + "      "
        for index, code in enumerate(codes):
            token = code + ("," if index + 1 < len(codes) else "")
            candidate = current + (" " if has_code else "") + token
            if has_code and len(candidate) > width:
                lines.append(current.rstrip())
                current = continuation + token
            else:
                current = candidate
            has_code = True
        lines.append(current.rstrip())

        if preview is not None:
            comment = "// preview: " + preview
            if len(lines) == 1 and len(lines[0] + "  " + comment) <= width:
                return [_highlight_bm_strings(lines[0] + "  " + comment)]
            lines.extend(
                _comment_lines(
                    preview=preview, conditional=(), indent=indent, width=width
                )
            )
        return [_highlight_bm_strings(line) for line in lines]

    prefix = f"{identifier} = "
    body = rhs or ""
    base = prefix + body
    clauses = []
    if preview is not None:
        clauses.append("preview: " + preview)
    if conditional:
        clauses.append("conditional: " + ", ".join(conditional))
    full = indent + base
    if clauses:
        full += "  // " + "; ".join(clauses)
    if len(full) <= width:
        return [_highlight_bm_strings(full)]

    if body.startswith("{") and body.endswith("}"):
        tokens = _yara_tokens(body)
        if len(indent + prefix + body) > width:
            inner = [token for token in tokens if token not in ("{", "}")]
            lines = [indent + prefix.rstrip() + " {"]
            if inner:
                lines.extend(
                    _wrap_tokens(
                        inner,
                        first="",
                        indent=indent + "    ",
                        width=width,
                        continuation=indent + "    ",
                    )
                )
            lines.append(indent + "}")
        else:
            lines = [indent + base]
    else:
        lines = _wrap_tokens(
            _yara_tokens(body), first=prefix.rstrip(), indent=indent, width=width
        )
    lines.extend(
        _comment_lines(
            preview=preview, conditional=conditional, indent=indent, width=width
        )
    )
    return [_highlight_bm_strings(line) for line in lines]


def _terminal_width() -> int:
    columns = shutil.get_terminal_size(fallback=(100, 24)).columns
    return max(80, min(160, columns or 100))


def _print_hstr_fields(
    fields: list[Field],
    indent: str,
    *,
    bm_yara: BmYaraRender | None = None,
    printable_preview: str | None = None,
    yara_unsupported: tuple[str, ...] = (),
) -> None:
    if fields:
        values = dict(fields)
        metadata = ("tag", "flags", "matching")
        if all(label in values for label in metadata):
            icon = (
                f"{ANSI_YELLOW}[!]{ANSI_RESET} "
                if "UNKNOWN_BITS(" in values["flags"]
                else ""
            )
            detail = ", ".join(f"{label}={values[label]}" for label in metadata)
            print(f"{indent}{icon}{ANSI_GRAY}{detail}{ANSI_RESET}")
            fields = [
                (label, value) for label, value in fields if label not in metadata
            ]
        identifier = values.get("identifier")
        display = values.get("display")
        if identifier is not None and display is not None:
            if yara_unsupported:
                lines = _format_yara_declaration(
                    identifier=None,
                    rhs=None,
                    indent=indent,
                    width=_terminal_width(),
                    preview=printable_preview,
                    unsupported=yara_unsupported,
                )
            elif bm_yara is None:
                lines = _format_yara_declaration(
                    identifier=identifier,
                    rhs=display,
                    indent=indent,
                    width=_terminal_width(),
                    preview=printable_preview,
                )
            elif bm_yara.body is None:
                codes = tuple(issue.code for issue in bm_yara.diagnostics)
                lines = _format_yara_declaration(
                    identifier=None,
                    rhs=None,
                    indent=indent,
                    width=_terminal_width(),
                    preview=bm_yara.printable_preview,
                    unsupported=codes,
                )
            else:
                conditional = (
                    bm_yara.requirements
                    if bm_yara.fidelity == BmYaraFidelity.CONDITIONAL
                    else ()
                )
                lines = _format_yara_declaration(
                    identifier=identifier,
                    rhs=bm_yara.body,
                    indent=indent,
                    width=_terminal_width(),
                    preview=bm_yara.printable_preview,
                    conditional=conditional,
                )
            for line in lines:
                print(line)
            fields = [
                (label, value)
                for label, value in fields
                if label not in ("identifier", "display")
            ]
        if not fields:
            return
        width = max(len(label) for label, _ in fields)
        for label, value in fields:
            if label == "display":
                value = _highlight_bm_strings(value)
            icon = ""
            if label == "error":
                icon = f"{ANSI_RED}[!]{ANSI_RESET} "
            elif (
                label in ("warning", "tail_word0")
                or (label == "flags" and "UNKNOWN_BITS(" in value)
                or (label == "trailing_raw" and not value.startswith("0 B"))
            ):
                icon = f"{ANSI_YELLOW}[!]{ANSI_RESET} "
            print(f"{indent}{icon}{ANSI_BWHITE}{label:<{width}}{ANSI_RESET} : {value}")


# Per-type formatters
# Each function receives the raw payload bytes and returns a list of Fields.
# Return [] to trigger hexdump fallback in print_record().
_FPATH_KIND: dict[int, str] = {
    0x5F: "filepath",
    0x60: "foldername",
    0x71: "asep_filepath",
    0x75: "asep_foldername",
}

_REG_HIVES = (
    "HKCR",
    "HKCU",
    "HKLM",
    "HKU",
    "HKCC",
    "HKEY_CLASSES_ROOT",
    "HKEY_CURRENT_USER",
    "HKEY_LOCAL_MACHINE",
    "HKEY_USERS",
    "HKEY_CURRENT_CONFIG",
)

_TRUSTED_PUBLISHER_PREFIXES = ("HASH:", "BADHASH:", "BY:", "TO:", "TEAMID:")

# Publisher labels are confirmed from the string-prefix table in the signature
# docs. REGKEY labels are inferred from observed
# payload shapes and receiver behavior, not official enum names.
_CSIDL_LABELS: dict[int, str] = {
    0x001A: "CSIDL_APPDATA",
    0x0024: "CSIDL_WINDOWS",
    0x0025: "CSIDL_SYSTEM",
}

_REGKEY_TYPE_LABELS: dict[int, str] = {
    0x0001: "hive",
    0x0002: "subkey",
    0x0003: "root-path",
    0x0004: "value",
}

_TRUSTED_PUBLISHER_KEY_TYPES: dict[int, str] = {
    0x01: "HASH",
    0x02: "BY",
    0x03: "TO",
    0x04: "BADHASH",
    0x05: "TEAMID",
}


def _split_path_and_tail(data: bytes) -> tuple[bytes, bytes]:
    end = len(data)
    tail_off = len(data)
    for marker in (b"|", b"\x00"):
        pos = data.find(marker)
        if pos != -1 and pos < end:
            end = pos
            tail_off = pos + len(marker)
    return data[:end], data[tail_off:]


def _decode_single_byte_text(data: bytes) -> str:
    return data.decode("latin-1", errors="replace")


def _format_labeled_hex(value: int, width: int, labels: dict[int, str]) -> str:
    raw = f"{value:#0{width}x}"
    label = labels.get(value)
    if label is None:
        return raw
    return f"{raw} ({label})"


def _format_aggregator_flags(flags: int) -> str:
    if flags == 0:
        return "0x00"
    unsupported = flags & ~0x01
    if unsupported:
        return f"{flags:#04x} (unsupported_bits={unsupported:#04x})"
    return f"{flags:#04x} (fuzzy)"


def _split_registry_hive(path: str) -> tuple[str | None, str | None]:
    upper_path = path.upper()
    for hive in _REG_HIVES:
        if upper_path == hive.upper():
            return hive, ""
        prefix = hive + "\\"
        if upper_path.startswith(prefix.upper()):
            return hive, path[len(prefix) :]
    return None, None


def fmt_fpath_like(p: bytes, type_byte: int = 0) -> list[Field]:
    """FILEPATH/FOLDERNAME/ASEP path family."""
    if len(p) < 2:
        return [
            ("kind", _FPATH_KIND.get(type_byte, f"type={type_byte:#04x}")),
            ("error", "truncated payload"),
        ]

    csidl_flags = int.from_bytes(p[0:2], "little")
    path_bytes, pcode = _split_path_and_tail(p[2:])
    path = _decode_single_byte_text(path_bytes)

    fields: list[Field] = [
        ("kind", _FPATH_KIND.get(type_byte, f"type={type_byte:#04x}")),
        ("csidl_flags", _format_labeled_hex(csidl_flags, 6, _CSIDL_LABELS)),
        ("path_bytes_len", str(len(path_bytes))),
        ("path", path if path else "(empty)"),
    ]
    if pcode:
        fields.append(("pcode_len", f"{len(pcode)} B"))
    return fields


def fmt_regkey(p: bytes) -> list[Field]:
    """REGKEY (0x63) — registry IOC path/value record."""
    if len(p) < 4:
        return [("error", "truncated header")]

    key_type = int.from_bytes(p[0:2], "little")
    key_path_len = int.from_bytes(p[2:4], "little")
    path_end = 4 + key_path_len
    if path_end > len(p):
        return [
            ("key_type", _format_labeled_hex(key_type, 6, _REGKEY_TYPE_LABELS)),
            ("key_path_len", str(key_path_len)),
            ("error", "truncated key_path"),
        ]

    key_path_bytes = p[4:path_end]
    key_path = _decode_single_byte_text(key_path_bytes)
    if path_end + 2 > len(p):
        return [
            ("key_type", _format_labeled_hex(key_type, 6, _REGKEY_TYPE_LABELS)),
            ("key_path_len", str(key_path_len)),
            ("key_path", key_path if key_path else "(empty)"),
            ("error", "truncated value_len"),
        ]

    value_len = int.from_bytes(p[path_end : path_end + 2], "little")
    value_off = path_end + 2
    value_end = value_off + value_len
    if value_end > len(p):
        return [
            ("key_type", _format_labeled_hex(key_type, 6, _REGKEY_TYPE_LABELS)),
            ("key_path_len", str(key_path_len)),
            ("key_path", key_path if key_path else "(empty)"),
            ("value_len", str(value_len)),
            ("error", "truncated value"),
        ]

    value_bytes = p[value_off:value_end]
    value = _decode_single_byte_text(value_bytes)
    pcode = p[value_end:]
    hive, subkey = _split_registry_hive(key_path)

    fields: list[Field] = [
        ("key_type", _format_labeled_hex(key_type, 6, _REGKEY_TYPE_LABELS)),
        ("key_path_len", str(key_path_len)),
        ("key_path", key_path if key_path else "(empty)"),
    ]
    if hive is not None:
        fields.append(("hive", hive))
        fields.append(("subkey", subkey if subkey else "(empty)"))
    fields.append(("value_len", str(value_len)))
    if value_len:
        fields.append(("value", value if value else "(empty)"))
    if pcode:
        fields.append(("pcode_len", f"{len(pcode)} B"))
    if not (1 <= key_type <= 4):
        fields.append(("error", f"unexpected key_type {key_type:#06x}"))
    return fields


def fmt_trusted_publisher(p: bytes) -> list[Field]:
    """TRUSTED_PUBLISHER (0x70) — binary or UTF-16LE key payload."""
    if len(p) < 2:
        return [("error", "truncated header")]

    key_len = int.from_bytes(p[0:2], "little")
    if key_len > len(p) - 2:
        return [("key_len", str(key_len)), ("error", "truncated key_data")]

    key_data = p[2 : 2 + key_len]
    pcode = p[2 + key_len :]
    fields: list[Field] = [("key_len", str(key_len))]

    if not key_data:
        fields.extend([("mode", "binary"), ("error", "empty key_data")])
        return fields

    if key_data[0] >= 0x20:
        try:
            key_text = key_data.decode("utf-16le")
        except UnicodeDecodeError:
            fields.extend(
                [
                    ("mode", "string"),
                    ("error", "invalid UTF-16LE key_data"),
                    ("key_data", key_data.hex(" ")),
                ]
            )
            if pcode:
                fields.append(("pcode_len", f"{len(pcode)} B"))
            return fields

        prefix = next(
            (
                label[:-1]
                for label in _TRUSTED_PUBLISHER_PREFIXES
                if key_text.startswith(label)
            ),
            "UNKNOWN",
        )
        fields.extend(
            [
                ("mode", "string"),
                ("prefix", prefix),
                ("key_text", key_text),
            ]
        )
    else:
        key_type = key_data[0]
        fields.extend(
            [
                ("mode", "binary"),
                (
                    "key_type",
                    _format_labeled_hex(key_type, 4, _TRUSTED_PUBLISHER_KEY_TYPES),
                ),
                ("key_data", key_data[1:].hex(" ") if len(key_data) > 1 else "(empty)"),
            ]
        )

    if pcode:
        fields.append(("pcode_len", f"{len(pcode)} B"))
    return fields


def fmt_latent_threat(p: bytes) -> list[Field]:
    """LATENT_THREAT (0x69) — §2.7.  Exactly 8B."""
    if len(p) < 8:
        return []
    latent_id = int.from_bytes(p[0:4], "little")
    flags = int.from_bytes(p[4:8], "little")
    return [
        ("latent_id", f"{latent_id:#010x}"),
        ("flags", f"{flags:#010x}"),
    ]


def fmt_common_code(p: bytes) -> list[Field]:
    """COMMON_CODE (0xAF) — §2.8."""
    if len(p) < 4:
        return []
    type_flags = int.from_bytes(p[0:2], "little")
    code_len = int.from_bytes(p[2:4], "little")
    return [
        ("type_flags", f"{type_flags:#06x}"),
        ("code_len", str(code_len)),
        ("code", p[4 : 4 + code_len].hex(" ")),
    ]


def fmt_versioncheck(p: bytes) -> list[Field]:
    """VERSIONCHECK (0x7A) — 8B."""
    if len(p) < 8:
        return []
    op = int.from_bytes(p[0:4], "little")
    ver = int.from_bytes(p[4:8], "little")
    return [
        ("operator", f"{op:#010x}"),
        ("version", f"{ver:#010x}"),
    ]


def fmt_aggregator(p: bytes, type_byte: int) -> FormatResult | list[Field]:
    """AAGGREGATOR/AAGGREGATOREX receiver expression-buffer layout."""
    family = _AGGREGATOR_FAMILY[type_byte]
    if len(p) < 4:
        return []

    flags = p[0]
    name_len = p[1]
    sig_len = int.from_bytes(p[2:4], "little")
    hdr_end = 4 + name_len + sig_len
    if hdr_end > len(p):
        return [
            ("family", f"{ANSI_GREEN}{family}{ANSI_RESET}"),
            ("flags", f"{flags:#04x}"),
            ("name_len", str(name_len)),
            ("sig_len", str(sig_len)),
            ("error", "payload truncated"),
        ]

    name = p[4 : 4 + name_len]
    sig_data = p[4 + name_len : hdr_end]
    trailing = p[hdr_end:]
    name_str = name.decode("utf-8", errors="replace") if name else "(empty)"

    show_limit = 8
    if sig_data and len(sig_data) % 4 == 0:
        n = len(sig_data) // 4
        entries = [
            int.from_bytes(sig_data[i * 4 : (i + 1) * 4], "little") for i in range(n)
        ]
        shown = [f"{v:#010x}" for v in entries[:show_limit]]
        tail = f", … +{n - show_limit} more" if n > show_limit else ""
        sig_data_str = (
            f"[{', '.join(shown)}{tail}]"
            f"  {ANSI_GRAY}({n} DWORDs, XOR-encoded){ANSI_RESET}"
        )
    elif sig_data:
        sig_data_str = sig_data.hex(" ")
    else:
        sig_data_str = "(empty)"

    fields: list[Field] = [
        ("family", f"{ANSI_GREEN}{family}{ANSI_RESET}"),
        ("flags", _format_aggregator_flags(flags)),
        ("name_len", str(name_len)),
        ("sig_len", str(sig_len)),
        ("name", name_str),
        ("sig_data_raw", sig_data_str),
        ("decode_status", "unavailable"),
    ]
    if flags & ~0x01:
        fields.append(("error", "receiver rejects flags outside bit0"))
    if trailing:
        preview = trailing[:8].hex(" ")
        ellipsis = "…" if len(trailing) > 8 else ""
        fields.append(("trailing_bytes", f"{len(trailing)} B [{preview}{ellipsis}]"))
    return FormatResult(fields=fields)


# Formatter dispatch table
FORMATTERS: dict[int, object] = {
    0x5F: fmt_fpath_like,  # FILEPATH
    0x60: fmt_fpath_like,  # FOLDERNAME
    0x63: fmt_regkey,
    0x70: fmt_trusted_publisher,
    0x71: fmt_fpath_like,  # ASEP_FILEPATH
    0x75: fmt_fpath_like,  # ASEP_FOLDERNAME
    0x69: fmt_latent_threat,
    0xAF: fmt_common_code,
    0x7A: fmt_versioncheck,
    0x96: fmt_aggregator,  # AAGGREGATOR
    0xE7: fmt_aggregator,  # AAGGREGATOREX
}

# Formatters that accept (payload, type_byte) instead of (payload).
_TYPE_AWARE_FORMATTERS: frozenset = frozenset({fmt_fpath_like, fmt_aggregator})


def format_payload(type_byte: int, payload: bytes) -> FormatResult:
    if type_byte in DEFAULT_REGISTRY:
        rendered = decode_payload(type_byte, payload)
        return FormatResult(
            fields=[
                ("error" if label == "Error" else label, value)
                for label, value in rendered.fields
            ],
            sections=[
                DisplaySection(
                    title=section.title,
                    rows=list(section.rows),
                    bm_yara=section.bm_yara,
                    printable_preview=section.printable_preview,
                    yara_unsupported=section.yara_unsupported,
                )
                for section in rendered.sections
            ],
        )

    fn = FORMATTERS.get(type_byte)
    if fn is None:
        return FormatResult()
    raw_result: list[Field] | FormatResult
    if fn in _TYPE_AWARE_FORMATTERS:
        raw_result = fn(payload, type_byte)  # type: ignore[call-arg]
    else:
        raw_result = fn(payload)  # type: ignore
    if isinstance(raw_result, FormatResult):
        return raw_result
    return FormatResult(fields=raw_result)


# File banner
def _print_file_banner(path: Path) -> None:
    size_mb = path.stat().st_size / 1_048_576
    info("%s  %.1f MB", path.name, size_mb)


# List-threats mode
def run_list_threats(
    path: Path,
    filter_name: str | None,
    filter_type: int | None,
    limit: int,
) -> None:
    """Print one line per threat with threat_id, category, record count, and type summary."""
    from collections import Counter

    sep = f"{ANSI_GRAY}{'─' * SEP_W}{ANSI_RESET}"

    # Column header: # | THREAT_ID | CAT | RECS | NAME  (TYPE SUMMARY appended inline)
    print(
        f"\n{ANSI_BOLD}{'#':<5}{'THREAT_ID':<12}{'CAT':<18}{'RECS':>5}  NAME{ANSI_RESET}"
    )
    print(sep)

    shown = 0
    in_block = False
    cur_name = ""
    cur_id = 0
    cur_cat = 0
    cur_counts: Counter[int] = Counter()

    def _flush(idx: int) -> bool:
        """Print one threat line; return False if limit reached."""
        nonlocal shown
        if filter_name and filter_name not in cur_name.lower():
            return True
        if filter_type is not None and filter_type not in cur_counts:
            return True
        cat_name = threat_category_name(cur_cat) or f"0x{cur_cat:02x}"
        top = "  " + ", ".join(
            f"{ANSI_WHITE}{_type_name(t)}{ANSI_RESET}{ANSI_GRAY}×{c}{ANSI_RESET}"
            for t, c in cur_counts.most_common(4)
        )
        total = sum(cur_counts.values())
        print(
            f"  {ANSI_YELLOW}{idx:<4}{ANSI_RESET}"
            f" {ANSI_GRAY}{cur_id:#010x}{ANSI_RESET}"
            f"  {ANSI_MAGENTA}{cat_name:<16}{ANSI_RESET}"
            f"  {ANSI_CYAN}{total:>4}{ANSI_RESET}  "
            f"{ANSI_BOLD}{ANSI_BWHITE}{cur_name}{ANSI_RESET}{top}"
        )
        shown += 1
        return limit == 0 or shown < limit

    threat_idx = 0
    for type_byte, payload in iter_records_from_file(path):
        if type_byte == 0x5C:
            if in_block:
                threat_idx += 1
                if not _flush(threat_idx):
                    break
            threat = parse_threat_begin(payload)
            cur_name = threat.name
            cur_id = threat.threat_id
            cur_cat = threat.category
            cur_counts = Counter()
            in_block = True
        elif type_byte == 0x5D:
            if in_block:
                threat_idx += 1
                if not _flush(threat_idx):
                    in_block = False
                    break
            in_block = False
        elif in_block:
            cur_counts[type_byte] += 1

    if in_block:
        threat_idx += 1
        _flush(threat_idx)

    print(sep)
    if limit > 0 and shown >= limit:
        print(
            f"{ANSI_GRAY}  … stopped after {shown} threats  (use -n 0 for unlimited){ANSI_RESET}"
        )
    print()


# Records mode
def run_records(
    path: Path,
    filter_type: int | None,
    filter_name: str | None,
    limit: int,
    show_hex: bool,
    skip_framing: bool,
) -> None:
    """Stream records from path, applying filters and printing each match."""
    framing = {0x5C, 0x5D}
    shown = 0
    seq_total = 0
    current_threat = ""
    prev_threat = ""
    last_hstr_threat: str | None = None

    for type_byte, payload, threat_name, _sig_idx in iter_records_with_context(path):
        if type_byte in framing:
            last_hstr_threat = None
        if type_byte == 0x5C:
            current_threat = threat_name

        # Name filter: skip entire threat block (including framing)
        if filter_name and filter_name not in current_threat.lower():
            continue

        # Type filter
        if filter_type is not None and type_byte != filter_type:
            continue

        # Skip framing records; print separator on threat transition instead
        if skip_framing and type_byte in framing:
            if (
                type_byte == 0x5C
                and threat_name
                and threat_name != prev_threat
                and filter_type not in _HSTR_PUSH_FAMILY
            ):
                name_part = f"── {threat_name} "
                line = name_part + "─" * max(0, SEP_W - len(name_part))
                print(f"\n{ANSI_GRAY}{line}{ANSI_RESET}")
                prev_threat = threat_name
            continue

        seq_total += 1
        result = format_payload(type_byte, payload)
        print_record(
            seq=seq_total,
            type_byte=type_byte,
            payload=payload,
            threat_name=threat_name,
            result=result,
            show_hex=show_hex,
            show_threat_heading=threat_name != last_hstr_threat,
        )
        if type_byte in _HSTR_PUSH_FAMILY:
            last_hstr_threat = threat_name

        shown += 1
        if limit > 0 and shown >= limit:
            print(
                f"\n{ANSI_GRAY}── stopped after {shown} record(s) "
                f"(use -n 0 for unlimited) ──{ANSI_RESET}"
            )
            break

    if shown == 0:
        print(f"{ANSI_YELLOW}[!] no matching records found{ANSI_RESET}")


# CLI dispatch
def _parse_type_arg(args: argparse.Namespace) -> int | None:
    if not args.type:
        return None
    try:
        return int(args.type, 0)
    except ValueError:
        error("invalid --type value %r (use hex like 0x67)", args.type)
        raise SystemExit(1)


def cmd_threats(args: argparse.Namespace, path: Path) -> None:
    filter_type = _parse_type_arg(args)
    filter_name = args.threat.lower() if args.threat else None
    if filter_type is not None:
        info("filter: type=%s (%s)", f"{filter_type:#04x}", _type_name(filter_type))
    run_list_threats(path, filter_name, filter_type, args.limit)


def cmd_records(args: argparse.Namespace, path: Path) -> None:
    filter_type = _parse_type_arg(args)
    filter_name = args.threat.lower() if args.threat else None
    if filter_type is not None:
        info("filter: type=%s (%s)", f"{filter_type:#04x}", _type_name(filter_type))
    run_records(
        path,
        filter_type,
        filter_name,
        args.limit,
        getattr(args, "hex", False),
        getattr(args, "skip_framing", False),
    )


_SUBCOMMANDS = {"threats", "records"}


def build_parser() -> argparse.ArgumentParser:
    # Shared positional + options inherited by both subcommands via parents=
    shared = argparse.ArgumentParser(add_help=False)
    shared.add_argument("sig", metavar="file.sig", help="Input .sig file")
    shared.add_argument(
        "--type", "-t", metavar="HEX", help="Filter by record type (hex, e.g. 0x67)"
    )
    shared.add_argument(
        "--threat",
        "-T",
        metavar="SUBSTR",
        help="Filter by threat name substring (case-insensitive)",
    )
    shared.add_argument(
        "--limit",
        "-n",
        type=int,
        default=20,
        metavar="N",
        help="Max threats/records to display (default: 20; 0 = unlimited)",
    )

    top = argparse.ArgumentParser(
        description="Inspect Microsoft Defender .sig signature files.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = top.add_subparsers(dest="subcommand", metavar="{threats,records}")

    p_threats = sub.add_parser(
        "threats", parents=[shared], help="List threats (default view)"
    )
    p_threats.set_defaults(func=cmd_threats)

    p_records = sub.add_parser(
        "records", parents=[shared], help="Inspect individual records"
    )
    p_records.add_argument(
        "--hex", "-x", action="store_true", help="Show full hexdump for each record"
    )
    p_records.add_argument(
        "--skip-framing",
        action="store_true",
        help="Suppress THREAT_BEGIN/END; show threat separator instead",
    )
    p_records.set_defaults(func=cmd_records)

    return top


# Main
def main() -> None:
    import sys

    ap = build_parser()

    # Bare invocation: `sig.py file.sig` → default to `threats` subcommand.
    # Leave help flags and empty argv for top-level parser to handle.
    argv = sys.argv[1:]
    if argv and argv[0] not in _SUBCOMMANDS and argv[0] not in {"-h", "--help"}:
        argv = ["threats"] + argv

    args = ap.parse_args(argv)
    if not hasattr(args, "func"):
        ap.print_help()
        raise SystemExit(0)

    path = Path(args.sig)
    if not path.exists():
        error("%s: file not found", args.sig)
        raise SystemExit(1)
    _print_file_banner(path)
    args.func(args, path)


if __name__ == "__main__":
    main()
