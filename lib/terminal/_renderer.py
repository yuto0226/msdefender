from __future__ import annotations

import shutil
from dataclasses import dataclass
from typing import TYPE_CHECKING

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
)
from lib.vdm import type_name
from lib.vdm.bm_yara import BmYaraFidelity
from lib.vdm.core import DisplaySection, Field, FormatResult
from lib.vdm.types.hstr import HSTR_SPECS, HstrPayload

from ._hstr import render_fields as render_hstr_fields

if TYPE_CHECKING:
    from lib.vdm.record import DecodedRecord

INDENT = "    "
SEP_W = 72

_STRUCTURED_LOG_TYPES = {
    0xAF: "COMMON_CODE",
    0x7A: "VERSIONCHECK",
    0x69: "LATENT_THREAT",
    0x70: "TRUSTED_PUBLISHER",
    0x6C: "REVOKED_CERTIFICATE",
    0x96: "AAGGREGATOR",
    0xE7: "AAGGREGATOREX",
    0x63: "REGKEY",
    0x80: "KCRCE",
    0x87: "PESTATIC",
    0x5F: "FILEPATH",
    0x60: "FOLDERNAME",
    0x71: "ASEP_FILEPATH",
    0x75: "ASEP_FOLDERNAME",
    0x55: "NID",
    0x7E: "SNID",
    0xCE: "NID64",
}
_HSTR_FAMILY_NAMES = {spec.type_byte: spec.name for spec in HSTR_SPECS}
_HSTR_SPECS_BY_TYPE = {spec.type_byte: spec for spec in HSTR_SPECS}
HSTR_RECORD_TYPES = frozenset(_HSTR_FAMILY_NAMES)


@dataclass(frozen=True, slots=True)
class RenderContext:
    sequence: int
    threat_name: str = ""
    show_hex: bool = False
    show_threat_heading: bool = True
    width: int | None = None

    @property
    def terminal_width(self) -> int:
        if self.width is not None:
            return max(80, min(160, self.width))
        columns = shutil.get_terminal_size(fallback=(100, 24)).columns
        return max(80, min(160, columns or 100))


def _hex_row(data: bytes, off: int) -> str:
    chunk = data[off : off + 16]
    hex_parts: list[str] = []
    asc_parts: list[str] = []
    for index, byte in enumerate(chunk):
        sep = "  " if index == 8 else " "
        if index > 0:
            hex_parts.append(sep)
        color = ANSI_WHITE if 0x20 <= byte <= 0x7E else ANSI_GRAY
        hex_parts.append(f"{color}{byte:02x}{ANSI_RESET}")
        char = chr(byte) if 0x20 <= byte <= 0x7E else "."
        asc_parts.append(f"{color}{char}{ANSI_RESET}")
    pad = 16 - len(chunk)
    if pad:
        hex_parts.append("   " * pad + (" " if len(chunk) <= 8 else ""))
    return (
        f"{ANSI_RED}{off:08x}{ANSI_RESET}  {''.join(hex_parts)}  |{''.join(asc_parts)}|"
    )


def _hexdump(data: bytes, indent: str = INDENT) -> list[str]:
    return [indent + _hex_row(data, off) for off in range(0, len(data), 16)]


def _fields(fields: tuple[Field, ...] | list[Field], indent: str = INDENT) -> list[str]:
    if not fields:
        return []
    label_width = max(len(label) for label, _ in fields)
    return [
        f"{indent}{ANSI_CYAN}{label:<{label_width}}{ANSI_RESET}  {value}"
        for label, value in fields
    ]


def _sections(sections: tuple[DisplaySection, ...], indent: str = INDENT) -> list[str]:
    lines: list[str] = []
    row_indent = indent + "  "
    for index, section in enumerate(sections):
        if index:
            lines.append("")
        lines.append(f"{indent}{ANSI_YELLOW}{section.title}{ANSI_RESET}")
        if not section.rows:
            continue
        label_width = max(len(label) for label, _ in section.rows)
        lines.extend(
            f"{row_indent}{ANSI_MAGENTA}· {label:<{label_width}}{ANSI_RESET} : {value}"
            for label, value in section.rows
        )
    return lines


def _preview(payload: bytes, indent: str = INDENT) -> list[str]:
    lines = _hexdump(payload[:16], indent=indent)
    if len(payload) > 16:
        lines.append(
            f"{indent}{ANSI_GRAY}… {len(payload) - 16} more bytes "
            f"(use --hex to show all){ANSI_RESET}"
        )
    return lines


def _generic(
    record: DecodedRecord, result: FormatResult, context: RenderContext
) -> list[str]:
    threat = (
        f"  {ANSI_BOLD}{ANSI_BWHITE}{context.threat_name}{ANSI_RESET}"
        if context.threat_name
        else ""
    )
    lines = [
        f"{ANSI_GRAY}{'─' * SEP_W}{ANSI_RESET}",
        (
            f"  {ANSI_BOLD}{ANSI_BYELLOW}#{context.sequence}{ANSI_RESET}"
            f"  {ANSI_BOLD}{ANSI_BCYAN}{type_name(record.type_byte)}{ANSI_RESET}"
            f"  {ANSI_GRAY}({record.type_byte:#04x}){ANSI_RESET}"
            f"  {ANSI_GRAY}{len(record.raw)} B{ANSI_RESET}{threat}"
        ),
    ]
    has_error = any(label.lower() == "error" for label, _ in result.fields)
    if result.fields:
        normalized = tuple(
            ("error" if label == "Error" else label, value)
            for label, value in result.fields
        )
        lines.extend(_fields(normalized))
        if result.sections:
            lines.append("")
    if result.sections:
        lines.extend(_sections(result.sections))
    if not context.show_hex and has_error:
        lines.append("")
        lines.extend(_preview(record.raw))
    elif not context.show_hex and not result.fields and not result.sections:
        lines.extend(_preview(record.raw))
        return lines
    if context.show_hex:
        if result.fields:
            lines.append("")
        lines.extend(_hexdump(record.raw))
    return lines


def _structured(
    record: DecodedRecord,
    result: FormatResult,
    context: RenderContext,
    family_label: str,
) -> list[str]:
    lines: list[str] = []
    if context.threat_name and context.show_threat_heading:
        lines.extend(
            (
                f"{ANSI_GRAY}{'─' * SEP_W}{ANSI_RESET}",
                (
                    f"{ANSI_GREEN}[+]{ANSI_RESET} "
                    f"{ANSI_BOLD}{ANSI_BWHITE}{context.threat_name}{ANSI_RESET}"
                ),
            )
        )
    elif not context.show_threat_heading:
        lines.append("")

    error_value = next(
        (value for label, value in result.fields if label.lower() == "error"), None
    )
    if error_value is not None:
        lines.extend(
            (
                (
                    f"{ANSI_RED}[-]{ANSI_RESET} "
                    f"{ANSI_BOLD}{ANSI_BWHITE}{family_label}"
                    f"(0x{record.type_byte:02x}){ANSI_RESET}"
                    f"  {ANSI_GRAY}#{context.sequence} / "
                    f"{len(record.raw)} B{ANSI_RESET}"
                ),
                (
                    f"{INDENT}{ANSI_RED}[-]{ANSI_RESET} "
                    f"{ANSI_BOLD}{ANSI_BWHITE}Parse Error{ANSI_RESET}"
                ),
            )
        )
        lines.extend(_fields([("error", error_value)], indent=INDENT * 2))
        if context.show_hex:
            lines.append("")
            lines.extend(_hexdump(record.raw))
        return lines

    lines.append(
        f"{ANSI_BLUE}[*]{ANSI_RESET} "
        f"{ANSI_BOLD}{ANSI_BWHITE}{family_label}"
        f"(0x{record.type_byte:02x}){ANSI_RESET}"
        f"  {ANSI_GRAY}#{context.sequence} / {len(record.raw)} B{ANSI_RESET}"
    )
    for section_index, section in enumerate(result.sections):
        is_primary = section_index == 0
        icon = "[*]" if is_primary else "[>]"
        color = ANSI_BLUE if is_primary else ANSI_GRAY
        lines.append(
            f"{INDENT}{color}{icon}{ANSI_RESET} "
            f"{ANSI_BOLD}{ANSI_BWHITE}{section.title}{ANSI_RESET}"
        )
        lines.extend(_fields(section.rows, indent=INDENT * 2))
    if context.show_hex:
        lines.append("")
        lines.extend(_hexdump(record.raw))
    return lines


def _hstr(
    record: DecodedRecord, result: FormatResult, context: RenderContext
) -> list[str]:
    lines: list[str] = []
    has_subsignature_data = False
    parsed = record.value
    if not isinstance(parsed, HstrPayload) and record.error is None:
        raise TypeError("HSTR renderer requires an HstrPayload")
    subsignature_index = 0
    if context.threat_name and context.show_threat_heading:
        lines.extend(
            (
                f"{ANSI_GRAY}{'─' * SEP_W}{ANSI_RESET}",
                (
                    f"{ANSI_GREEN}[+]{ANSI_RESET} "
                    f"{ANSI_BOLD}{ANSI_BWHITE}{context.threat_name}{ANSI_RESET}"
                ),
            )
        )
    elif not context.show_threat_heading:
        lines.append("")
    lines.append(
        f"{ANSI_BLUE}[*]{ANSI_RESET} "
        f"{ANSI_BOLD}{ANSI_BWHITE}{_HSTR_FAMILY_NAMES[record.type_byte]}"
        f"(0x{record.type_byte:02X}){ANSI_RESET}"
        f"  {ANSI_GRAY}#{context.sequence} / {len(record.raw)} B{ANSI_RESET}"
    )
    for section in result.sections:
        is_detail = section.title.startswith("subsig ")
        icon = "[>]" if is_detail else "[*]"
        color = ANSI_GRAY if is_detail else ANSI_BLUE
        lines.append(
            f"{INDENT}{color}{icon}{ANSI_RESET} "
            f"{ANSI_BOLD}{ANSI_BWHITE}{section.title}{ANSI_RESET}"
        )
        rows = dict(section.rows)
        lines.extend(
            render_hstr_fields(
                [(label, value) for label, value in section.rows if label != "raw"],
                INDENT * 2,
                width=context.terminal_width,
                bm_yara=section.bm_yara,
                printable_preview=section.printable_preview,
                yara_unsupported=section.yara_unsupported,
            )
        )
        if is_detail and "raw" in rows:
            has_subsignature_data = True
            assert isinstance(parsed, HstrPayload)
            data = parsed.subsignatures[subsignature_index].data
            subsignature_index += 1
            needs_preview = (
                rows.get("matching") == "UNKNOWN"
                or "warning" in rows
                or "error" in rows
                or (
                    section.bm_yara is not None
                    and section.bm_yara.fidelity == BmYaraFidelity.UNSUPPORTED
                )
            )
            if context.show_hex:
                lines.extend(_hexdump(data, indent=INDENT * 2))
            elif needs_preview:
                lines.extend(_preview(data, indent=INDENT * 2))
    fields: list[Field] = []
    metadata_dumps: list[tuple[str, bytes]] = []
    for label, value in result.fields:
        lower_label = label.lower()
        if (label == "name" and value != '""') or (
            label == "tail_word0"
            and value != "NOT_PRESENT"
            and not value.startswith("0x0000")
        ):
            fields.append((label, value))
        elif label == "trailing_raw" and not value.startswith("0 B"):
            fields.append((label, value))
            if context.show_hex:
                assert isinstance(parsed, HstrPayload)
                metadata_dumps.append((label, parsed.trailing_raw))
        elif label == "name_raw" and context.show_hex and value != "(empty)":
            assert isinstance(parsed, HstrPayload)
            metadata_dumps.append((label, parsed.name_raw))
        elif lower_label == "error":
            fields.append(("error", value))
    if fields or metadata_dumps:
        icon = "[-]" if any(label == "error" for label, _ in fields) else "[*]"
        color = ANSI_RED if icon == "[-]" else ANSI_BLUE
        lines.append(
            f"{INDENT}{color}{icon}{ANSI_RESET} "
            f"{ANSI_BOLD}{ANSI_BWHITE}Record Metadata{ANSI_RESET}"
        )
        lines.extend(
            render_hstr_fields(fields, INDENT * 2, width=context.terminal_width)
        )
        for label, data in metadata_dumps:
            lines.append(f"{INDENT * 2}{ANSI_GRAY}{label}{ANSI_RESET}")
            lines.extend(_hexdump(data, indent=INDENT * 2))
    if context.show_hex and not has_subsignature_data:
        lines.extend(_hexdump(record.raw))
    elif any(label == "error" for label, _ in fields):
        lines.extend(_preview(record.raw))
    return lines


def render_record(record: DecodedRecord, context: RenderContext) -> str:
    result = record._format_result()
    if record.spec is None:
        lines = _generic(record, result, context)
    elif record.type_byte == 0x67:
        lines = _structured(record, result, context, "STATIC")
    elif record.type_byte in _STRUCTURED_LOG_TYPES:
        lines = _structured(
            record,
            result,
            context,
            _STRUCTURED_LOG_TYPES[record.type_byte],
        )
    elif record.spec is _HSTR_SPECS_BY_TYPE.get(record.type_byte):
        lines = _hstr(record, result, context)
    else:
        lines = _generic(record, result, context)
    return "\n".join(lines) + "\n"
