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
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path

# Force UTF-8 on Windows
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

from lib.debug import (
    ANSI_RESET,
    ANSI_BOLD,
    ANSI_GRAY,
    ANSI_WHITE,
    ANSI_BWHITE,
    ANSI_CYAN,
    ANSI_GREEN,
    ANSI_YELLOW,
    ANSI_MAGENTA,
    ANSI_RED,
    ANSI_BLUE,
    ANSI_BRED,
    ANSI_BCYAN,
    ANSI_BYELLOW,
    info,
    warn,
    error,
)
from lib.threat import parse_threat_name, parse_threat_id
from lib.utils import iter_records_from_file, iter_records_with_context

# ─── Type name table ──────────────────────────────────────────────────────── #
# Short names (without SIGNATURE_TYPE_ prefix) for compact display.
# fmt: off
TYPE_NAMES: dict[int, str] = {
    0x01: "RESERVED",               0x02: "VOLATILE_THREAT_INFO",
    0x03: "VOLATILE_THREAT_ID",     0x11: "CKOLDREC",
    0x20: "KVIR32",                 0x21: "POLYVIR32",
    0x27: "NSCRIPT_NORMAL",         0x28: "NSCRIPT_SP",
    0x29: "NSCRIPT_BRUTE",          0x2C: "NSCRIPT_CURE",
    0x30: "TITANFLT",               0x3D: "PEFILE_CURE",
    0x3E: "MAC_CURE",               0x40: "SIGTREE",
    0x41: "SIGTREE_EXT",            0x42: "MACRO_PCODE",
    0x43: "MACRO_SOURCE",           0x44: "BOOT",
    0x49: "CLEANSCRIPT",            0x4A: "TARGET_SCRIPT",
    0x50: "CKSIMPLEREC",            0x51: "PATTMATCH",
    0x53: "RPFROUTINE",             0x55: "NID",
    0x56: "GENSFX",                 0x57: "UNPLIB",
    0x58: "DEFAULTS",               0x5B: "DBVAR",
    0x5C: "THREAT_BEGIN",           0x5D: "THREAT_END",
    0x5E: "FILENAME",               0x5F: "FILEPATH",
    0x60: "FOLDERNAME",             0x61: "PEHSTR",
    0x62: "LOCALHASH",              0x63: "REGKEY",
    0x64: "HOSTSENTRY",             0x67: "STATIC",
    0x69: "LATENT_THREAT",          0x6A: "REMOVAL_POLICY",
    0x6B: "WVT_EXCEPTION",          0x6C: "REVOKED_CERTIFICATE",
    0x70: "TRUSTED_PUBLISHER",      0x71: "ASEP_FILEPATH",
    0x73: "DELTA_BLOB",             0x74: "DELTA_BLOB_RECINFO",
    0x75: "ASEP_FOLDERNAME",        0x77: "PATTMATCH_V2",
    0x78: "PEHSTR_EXT",             0x79: "VDLL_X86",
    0x7A: "VERSIONCHECK",           0x7B: "SAMPLE_REQUEST",
    0x7C: "VDLL_X64",               0x7E: "SNID",
    0x7F: "FOP",                    0x80: "KCRCE",
    0x83: "VFILE",                  0x84: "SIGFLAGS",
    0x85: "PEHSTR_EXT2",            0x86: "PEMAIN_LOCATOR",
    0x87: "PESTATIC",               0x88: "UFSP_DISABLE",
    0x89: "FOPEX",                  0x8A: "PEPCODE",
    0x8B: "IL_PATTERN",             0x8C: "ELFHSTR_EXT",
    0x8D: "MACHOHSTR_EXT",          0x8E: "DOSHSTR_EXT",
    0x8F: "MACROHSTR_EXT",          0x90: "TARGET_SCRIPT_PCODE",
    0x91: "VDLL_ARM64",             0x92: "ASCRIPTHSTR_EXT",
    0x95: "PEBMPAT",                0x96: "AAGGREGATOR",
    0x97: "SAMPLE_REQUEST_BY_NAME", 0x98: "REMOVAL_POLICY_BY_NAME",
    0x99: "TUNNEL_X86",             0x9A: "TUNNEL_X64",
    0x9B: "TUNNEL_ARM64",           0x9C: "VDLL_ARM",
    0x9D: "THREAD_X86",             0x9E: "THREAD_X64",
    0x9F: "THREAD_ARM64",           0xA0: "FRIENDLYFILE_SHA256",
    0xA1: "FRIENDLYFILE_SHA512",    0xA2: "SHARED_THREAT",
    0xA3: "VDM_METADATA",           0xA4: "VSTORE",
    0xA5: "VDLL_SYMINFO",           0xA6: "IL2_PATTERN",
    0xA7: "BM_STATIC",              0xA8: "BM_INFO",
    0xA9: "NDAT",                   0xAA: "FASTPATH_DATA",
    0xAB: "FASTPATH_SDN",           0xAC: "DATABASE_CERT",
    0xAD: "SOURCE_INFO",            0xAE: "HIDDEN_FILE",
    0xAF: "COMMON_CODE",            0xB0: "VREG",
    0xB1: "NISBLOB",                0xB2: "VFILEEX",
    0xB3: "SIGTREE_BM",             0xB4: "VBFOP",
    0xB5: "VDLL_META",              0xB6: "TUNNEL_ARM",
    0xB7: "THREAD_ARM",             0xB8: "PCODEVALIDATOR",
    0xBA: "MSILFOP",                0xBB: "KPAT",
    0xBC: "KPATEX",                 0xBD: "LUASTANDALONE",
    0xBE: "DEXHSTR_EXT",            0xBF: "JAVAHSTR_EXT",
    0xC0: "MAGICCODE",              0xC1: "CLEANSTORE_RULE",
    0xC2: "VDLL_CHECKSUM",          0xC3: "THREAT_UPDATE_STATUS",
    0xC4: "VDLL_MSIL",              0xC5: "ARHSTR_EXT",
    0xC6: "MSILFOPEX",              0xC7: "VBFOPEX",
    0xC8: "FOP64",                  0xC9: "FOPEX64",
    0xCA: "JSINIT",                 0xCB: "PESTATICEX",
    0xCC: "KCRCEX",                 0xCD: "FTRIE_POS",
    0xCE: "NID64",                  0xCF: "MACRO_PCODE64",
    0xD0: "BRUTE",                  0xD1: "SWFHSTR_EXT",
    0xD2: "REWSIGS",                0xD3: "AUTOITHSTR_EXT",
    0xD4: "INNOHSTR_EXT",           0xD5: "CERT_STORE_ENTRY",
    0xD6: "EXPLICITRESOURCE",       0xD7: "CMDHSTR_EXT",
    0xD8: "FASTPATH_TDN",           0xD9: "EXPLICITRESOURCEHASH",
    0xDA: "FASTPATH_SDN_EX",        0xDB: "BLOOM_FILTER",
    0xDC: "RESEARCH_TAG",           0xDE: "ENVELOPE",
    0xDF: "REMOVAL_POLICY64",       0xE0: "REMOVAL_POLICY64_BY_NAME",
    0xE1: "VDLL_META_X64",          0xE2: "VDLL_META_ARM",
    0xE3: "VDLL_META_MSIL",         0xE4: "MDBHSTR_EXT",
    0xE5: "SNIDEX",                 0xE6: "SNIDEX2",
    0xE7: "AAGGREGATOREX",          0xE8: "PUA_APPMAP",
    0xE9: "PROPERTY_BAG",           0xEA: "DMGHSTR_EXT",
    0xEB: "DATABASE_CATALOG",       0xEC: "DATABASE_CERT2",
    0xED: "BM_ENV_VAR_MAP",         0xEE: "DATABASE_CERT3",
    0xEF: "ARHSTR_POSIX_EXT",
}
# fmt: on


def type_name(tb: int) -> str:
    return TYPE_NAMES.get(tb, f"TYPE_{tb:#04x}")


# ─── Semantic annotation tables ───────────────────────────────────────────── #

# THREAT_BEGIN: category WORD → __mpthreat_category_t enum label.
# Fully reversed from get_category_from_name @ 0x180131108 (Table1/Table2 + switch),
# cross-validated against category distribution in mpas.sig (17,989 threats).
# fmt: off
_THREAT_CATEGORY: dict[int, str] = {
    0x01: "Adware",           # ~10%  in mpas.sig
    0x02: "Spyware",
    0x03: "PWS",              # Password Stealer; 0 in mpas.sig (in mpav.sig)
    0x04: "TrojanDownloader", # ~6%
    0x05: "Worm",             # ~11%
    0x06: "Backdoor",
    0x08: "Trojan",           # ~16%  generic malware fallback
    0x09: "Spammer",          # EmailFlooder / Spammer
    0x0B: "Dialer",           # ~1%   adult-content / premium-rate dialers
    0x0C: "MonitoringTool",   # ~5%
    0x0D: "BrowserModifier",  # ~4%
    0x13: "Joke",
    0x15: "SoftwareBundler",  # ~1%
    0x16: "TrojanClicker",
    0x17: "SettingsModifier", # ~4%
    0x1B: "PUA",              # ~16%  Potentially Unwanted Application
    0x1E: "Exploit",
    0x20: "VirTool",          # also: Constructor
    0x21: "RemoteAccess",
    0x22: "Tool",             # HackTool / Program / EICAR test files
    0x24: "DoS",              # also: DDoS
    0x25: "TrojanDropper",
    0x26: "Flooder",
    0x27: "TrojanSpy",
    0x28: "TrojanProxy",
    0x2A: "Virus",            # 0 in mpas.sig (in mpav.sig)
    0x2B: "PseudoThreat",     # ~19%  synthetic test threats (!PseudoThreat_XXXXXXXX)
    0x2D: "SPP",              # Software Protection Platform; 0 in mpas.sig
    0x31: "EUS",              # End-User Software; 0 in mpas.sig
    0x32: "Ransom",           # 0 in mpas.sig (in mpav.sig)
    0x33: "HipsRule",         # Behavioral/HIPS rule; 0 in mpas.sig
}
# fmt: on

# THREAT_BEGIN: sentinel threat_id values that set engine global flags.
# Reversed from threat_info_receiver @ 0x1809EB590 / DispatchRecords @ 0x1800F99A8.
# Note: these are NOT in the magic threat range (0x7FFE0000–0x7FFE9FFF /
# 0x7FFF0000–0x7FFF9FFF) — they are a distinct category of special IDs.
_MAGIC_THREAT_ID: dict[int, str] = {
    0x00040E1A: "hosts_loaded",
    0x7FFFFFFE: "unknown_loaded",
    0x7FFFFFFF: "friendly_loaded",
    0xFFFFFFF0: "infrastructure",
    0xFFFFFFF9: "behaviordetection_loaded",
    0xFFFFFFFA: "infrastructure",
    0x7FFFFFF0: "infrastructure",
    0x7FFFFFFA: "infrastructure",
    0xFFFFFFFF: "avfriendly_loaded",
}

# PEHSTR family: type_byte → file-format family being scanned.
# Confirmed from aggregatorex_receiver receiver table in DispatchRecords.
_PEHSTR_FAMILY: dict[int, str] = {
    0x61: "PE",
    0x78: "PE (ext)",
    0x85: "PE (ext2)",
    0x8C: "ELF",
    0x8D: "Mach-O",
    0x8E: "DOS",
    0x8F: "Macro/Office",
    0x92: "ActiveScript",
    0x96: "aggregator",
    0xE7: "aggregator (ex)",
}

_HSTR_PUSH_FAMILY: frozenset[int] = frozenset(
    {0x61, 0x78, 0x85, 0x8C, 0x8D, 0x8E, 0x8F, 0x92, 0xBE, 0xBF, 0xC5, 0xEF}
)
_AGGREGATOR_EXPR_FAMILY: frozenset[int] = frozenset({0x96, 0xE7})

# Aggregator flags bitmask — confirmed from aggregatorex_receiver / aggregator_receiver.
_AGGREGATOR_FLAG_BITS: list[tuple[int, str]] = [
    (0x01, "fuzzy"),
]

# hstr_internal_push_ex / add_sstring_internal per-subsignature flags.
# Only the bits below are currently supported by direct IDA evidence.
_HSTR_SUBSIG_FLAG_BITS: list[tuple[int, str]] = [
    (0x0001, "preserve_case"),
    (0x0002, "bm_pattern"),
    (0x0100, "emit_wide_copy"),
]

# SIGTREE: type_word → combination logic label.
# LE uint16: wire bytes 01 03 → 0x0301, 01 05 → 0x0501.
# High byte (p[3]) = SigtreeHandlerInstance index (0–6); 0xF0 = special.
# Confirmed from siga_cksig_impl @ 0x18013d6a0.
_SIGTREE_TYPE_WORD: dict[int, str] = {
    0x0301: "any-of",
    0x0501: "all-of",
    0xF000: "special/wildcard",  # special value; handled differently in siga_cksig_impl
}

# SIGTREE: fid_hi byte → field family (empirically observed; gktab confirmation pending).
_SIGTREE_FID_HI: dict[int, str] = {
    0x70: "PE attrs",
    0x60: "generic attrs",
    0x30: "family_0x30",
}

# SIGTREE: entry_flags bitmask (wire DWORD at entry[0..3]).
# IDA-confirmed from SigtreeHandlerInstance::push @ 0x1800f1d84
# and MatchParameter @ 0x1800ec6b0.
#
# Runtime 64B slot layout (after push()):
#   +0  packed DWORD:  [fid_lo][fid_hi][sub_lo][sub_hi]
#   +4  entry_flags DWORD
#   +8  n3_ext slot A (0 if n3<1)      +16  val_A (primary CRC target)
#   +24 BM ptr A (initially 0)          +32  n3_ext slot B (0 if n3<2)
#   +40 val_B (secondary CRC target)   +48  BM ptr B (initially 0)
#   +56 1
#
# entry_flags split:
#   byte 0 (bits 0–7)  → "A-side" param dispatch  (flags_A)
#   byte 1 (bits 8–15) → "B-side" param dispatch  (flags_B)
#
# Confirmed bits:
#   0x0002  always_match_A  — MatchParameter returns true immediately (no CRC check) for A-side
#   0x0010  ext_bm_A       — BM string matcher data follows for A-side (secondary slot +40)
#   0x1000  ext_bm_B       — BM string matcher data follows for B-side (primary slot +16)
#                            (prev. documented as "ext_hash"; both bits call process_extended_param)
_SIGTREE_ENTRY_FLAG_BITS: list[tuple[int, str]] = [
    (0x0002, "always_match_A"),  # A-side param always passes (MatchParameter early-return 1)
    (0x0010, "ext_bm_A"),        # extended BM data follows for A-side (secondary param slot)
    (0x1000, "ext_bm_B"),        # extended BM data follows for B-side (primary param slot)
]

# SIGTREE: n3 (high byte of entry_count_word) → extra bytes appended per entry
# beyond the base 16B.  n3=0..3 confirmed from SigtreeHandlerInstance::push disasm;
# n3=4 empirically confirmed (TelnetoverNonStandardPort.A: 27×24B=648, body=652).
# These extra bytes encode secondary parameter values for MatchParameter's
# secondary slot — discovered via port-number inspection of n3=4 records.
_SIGTREE_N3_EXTRA: dict[int, int] = {0: 0, 1: 4, 2: 8, 3: 9, 4: 8}


def _annotate_bits(value: int, bit_table: list[tuple[int, str]]) -> str:
    """Return a parenthesised annotation for a bitmask value.

    Known bits are listed by name; unknown set bits shown as 'unk_bitN'.
    Returns '' when value is 0.
    """
    if value == 0:
        return ""
    parts: list[str] = []
    known_mask = 0
    for bit, name in bit_table:
        known_mask |= bit
        if value & bit:
            parts.append(name)
    for n in range(32):
        if (value & ~known_mask) & (1 << n):
            parts.append(f"unk_bit{n}")
    return f"  ({', '.join(parts)})" if parts else ""


# ─── Display helpers ──────────────────────────────────────────────────────── #
# A formatter returns a list of (label, value) pairs.
# Return [] to fall through to raw hexdump.
Field = tuple[str, str]


@dataclass(slots=True)
class DisplaySection:
    title: str
    rows: list[Field] = field(default_factory=list)


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
) -> None:
    """Print one record with header, parsed fields, and optional hexdump."""
    name = type_name(type_byte)
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
        # Print first 16 bytes as a quick preview even without --hex
        _print_preview(payload)
        return

    if show_hex:
        if fields:
            print()  # blank line before hexdump
        _print_hexdump(payload)


# ─── Per-type formatters ──────────────────────────────────────────────────── #
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
# docs. REGKEY labels are conservative descriptors inferred from observed
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


def _looks_ascii_blob(data: bytes) -> bool:
    if not data:
        return False
    if any(b >= 0x80 for b in data):
        return False
    printable = sum(1 for b in data if b in (0x09, 0x0A, 0x0D) or 0x20 <= b <= 0x7E)
    return printable / len(data) >= 0.85


def _looks_utf16le_blob(data: bytes) -> bool:
    if len(data) < 4 or len(data) % 2:
        return False
    pairs = len(data) // 2
    odd_nulls = sum(1 for i in range(1, len(data), 2) if data[i] == 0)
    even_printable = sum(1 for i in range(0, len(data), 2) if 0x20 <= data[i] <= 0x7E)
    return odd_nulls / pairs >= 0.6 and even_printable / pairs >= 0.6


def _decode_pehstr_subsig_text(data: bytes) -> tuple[str | None, str | None]:
    if len(data) >= 2 and data[0] == len(data) - 1:
        ascii_body = data[1:]
        ascii_trimmed = ascii_body[:-1] if ascii_body.endswith(b"\x00") else ascii_body
        if b"\x00" not in ascii_trimmed and _looks_ascii_blob(ascii_body):
            return ascii_body.decode("latin-1", errors="replace").rstrip("\x00"), "ascii"
    if _looks_utf16le_blob(data):
        return data.decode("utf-16le", errors="replace").rstrip("\x00"), "wide"
    ascii_trimmed = data[:-1] if data.endswith(b"\x00") else data
    if b"\x00" not in ascii_trimmed and _looks_ascii_blob(data):
        return data.decode("latin-1", errors="replace").rstrip("\x00"), "ascii"
    return None, None


def _escape_yara_text(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"').replace("\r", "\\r").replace("\n", "\\n")


def _format_hstr_yara_hex(data: bytes) -> str:
    return data.hex(" ").upper()


def _format_hstr_raw_preview(data: bytes, max_bytes: int = 24) -> str:
    preview = _format_hstr_yara_hex(data[:max_bytes])
    if len(data) > max_bytes:
        preview += "…"
    return preview


def _format_hstr_bm_preview(data: bytes) -> str:
    safe_ascii = set(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ./\\:_-")
    parts: list[str] = []
    for byte in data:
        if byte in safe_ascii:
            parts.append(chr(byte))
        else:
            parts.append(f"[BM:{byte:02X}]")
    return " ".join(parts)


def _format_hstr_pattern_value(
    idx: int,
    data: bytes,
    text: str | None,
    text_modifier: str | None,
    flags_raw: int | None,
) -> str:
    if text is not None:
        yara_modifier = _decode_hstr_string_modifier(text_modifier, flags_raw)
        if yara_modifier is not None:
            return f'$s{idx} = "{_escape_yara_text(text)}" {yara_modifier}'
        return f'$s{idx} = "{_escape_yara_text(text)}"'
    if flags_raw is not None and (flags_raw & 0x0002):
        return _format_hstr_bm_preview(data)
    return _format_hstr_raw_preview(data)


def _format_hstr_subsig_flags(flags: int) -> str:
    annot = _annotate_bits(flags, _HSTR_SUBSIG_FLAG_BITS)
    if annot.startswith("  ("):
        annot = " (" + annot[3:]
    return f"{flags:#06x}{annot}"


def _format_hstr_subsig_flags_for_title(flags: int) -> str:
    known_mask = 0
    for bit, _name in _HSTR_SUBSIG_FLAG_BITS:
        known_mask |= bit
    if flags & ~known_mask:
        return f"{flags:#06x}"
    return _format_hstr_subsig_flags(flags)


def _read_hstr_varflags(data: bytes, off: int) -> tuple[int, int] | None:
    if off >= len(data):
        return None
    flags = data[off]
    off += 1
    if flags & 0x80:
        if off >= len(data):
            return None
        flags |= data[off] << 8
        off += 1
    if flags & ~0x03FF:
        return None
    return flags, off


def _decode_hstr_string_modifier(text_modifier: str | None, flags_raw: int | None) -> str | None:
    if text_modifier == "wide":
        return "wide"
    if text_modifier == "ascii":
        if flags_raw is not None and (flags_raw & 0x0100):
            return "ascii wide"
        return "ascii"
    return None


def _parse_hstr_signature_payload(
    payload: bytes, type_byte: int
) -> tuple[dict[str, object] | None, str | None]:
    if len(payload) < 7:
        return None, "payload too short"

    header_word0 = int.from_bytes(payload[0:2], "little")
    header_word1 = int.from_bytes(payload[2:4], "little")
    subsig_count = int.from_bytes(payload[4:6], "little")
    off = 6

    name_end = payload.find(b"\x00", off)
    if name_end == -1:
        return None, "unterminated name"
    if name_end - off > 0x40:
        return None, "name too long"
    name_bytes = payload[off:name_end]
    off = name_end + 1

    ext_mode = type_byte != 0x61
    records: list[dict[str, object]] = []
    for _ in range(subsig_count):
        if off + 3 > len(payload):
            return None, "truncated sub-signature header"
        tag = int.from_bytes(payload[off : off + 2], "little")
        ln = payload[off + 2]
        off += 3

        flags_raw: int | None = None
        if ext_mode:
            parsed_flags = _read_hstr_varflags(payload, off)
            if parsed_flags is None:
                return None, "invalid sub-signature flags"
            flags_raw, off = parsed_flags

        end = off + ln
        if end > len(payload):
            return None, "truncated sub-signature data"
        data = payload[off:end]
        off = end
        records.append({"tag": tag, "len": ln, "flags_raw": flags_raw, "data": data})

    tail_word0: int | None = None
    tail_word1: int | None = None
    trailing = b""
    remaining = len(payload) - off
    if remaining in (0, 2, 4) or remaining > 4:
        if remaining >= 2:
            tail_word0 = int.from_bytes(payload[off : off + 2], "little")
            off += 2
        if remaining >= 4:
            tail_word1 = int.from_bytes(payload[off : off + 2], "little")
            off += 2
        if off < len(payload):
            trailing = payload[off:]
    elif remaining:
        trailing = payload[off:]

    return (
        {
            "header_word0": header_word0,
            "header_word1": header_word1,
            "subsig_count": subsig_count,
            "name_bytes": name_bytes,
            "records": records,
            "tail_word0": tail_word0,
            "tail_word1": tail_word1,
            "trailing": trailing,
        },
        None,
    )


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
        return [("kind", _FPATH_KIND.get(type_byte, f"type={type_byte:#04x}")), ("error", "truncated payload")]

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
            (label[:-1] for label in _TRUSTED_PUBLISHER_PREFIXES if key_text.startswith(label)),
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
                ("key_type", _format_labeled_hex(key_type, 4, _TRUSTED_PUBLISHER_KEY_TYPES)),
                ("key_data", key_data[1:].hex(" ") if len(key_data) > 1 else "(empty)"),
            ]
        )

    if pcode:
        fields.append(("pcode_len", f"{len(pcode)} B"))
    return fields


def fmt_friendlyfile_sha256(p: bytes) -> list[Field]:
    """FRIENDLYFILE_SHA256 (0xA0) — fixed SHA-256 with optional PCode."""
    if len(p) < 32:
        return [("error", f"payload too short for sha256 ({len(p)} B)")]

    sha256 = p[:32]
    pcode = p[32:]
    fields: list[Field] = [
        ("sha256", sha256.hex()),
        ("usage", "friendly/allowlist"),
    ]
    if pcode:
        fields.append(("pcode_len", f"{len(pcode)} B"))
    return fields


def fmt_threat_begin(p: bytes) -> list[Field]:
    """THREAT_BEGIN (0x5C) — documented in §4.1."""
    if len(p) < 0x0C:
        return []
    threat_id = int.from_bytes(p[0:4], "little")
    dep_count = int.from_bytes(p[4:6], "little")
    ext_count = int.from_bytes(p[6:8], "little")
    category  = int.from_bytes(p[8:10], "little")
    name_len  = int.from_bytes(p[10:12], "little")
    name      = parse_threat_name(p)

    cat_label = _THREAT_CATEGORY.get(category, "?")
    cat_str   = f"{category:#06x}  ({cat_label})"

    magic_label = _MAGIC_THREAT_ID.get(threat_id, "")
    tid_str = f"{threat_id:#010x}" + (
        f"  {ANSI_YELLOW}[{magic_label}]{ANSI_RESET}" if magic_label else ""
    )

    return [
        ("threat_id", tid_str),
        ("category",  cat_str),
        ("dep_count", str(dep_count)),
        ("ext_count", str(ext_count)),
        ("name_len",  str(name_len)),
        ("name",      f"{ANSI_BOLD}{name}{ANSI_RESET}"),
    ]


def fmt_threat_end(p: bytes) -> list[Field]:
    """THREAT_END (0x5D) — 4-byte checksum."""
    if len(p) < 4:
        return []
    csum = int.from_bytes(p[:4], "little")
    return [("checksum", f"{csum:#010x}")]


def fmt_snid(p: bytes) -> list[Field]:
    """SNID (0x7E) / NID (0x55) — §1.1.  5B min payload."""
    if len(p) < 5:
        return []
    key = int.from_bytes(p[0:4], "little")
    category = p[4]
    raw = p[5:] if len(p) > 5 else b""
    null_pos = raw.find(b"\x00")       # null-terminated string
    if null_pos != -1:
        raw = raw[:null_pos]
    while raw and raw[0] >= 0x80:     # skip internal category marker prefix
        raw = raw[1:]
    name = raw.decode("utf-8", errors="replace")
    fields: list[Field] = [
        ("snid/nid", f"{key:#010x}"),
        ("category", f"{category:#04x}"),
    ]
    if name:
        fields.append(("name", name))
    return fields


def fmt_kcrce(p: bytes) -> list[Field]:
    """KCRCE (0x80) — §1.3.  16B min, 4×DWORD CRC key."""
    if len(p) < 16:
        return []
    crcs = struct.unpack_from("<4I", p, 0)
    fields: list[Field] = [(f"crc[{i}]", f"{c:#010x}") for i, c in enumerate(crcs)]
    if len(p) > 16:
        fields.append(("pcode_len", f"{len(p) - 16} B (tail)"))
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


def fmt_pehstr_ext(p: bytes, type_byte: int = 0) -> FormatResult:
    """PEHSTR/HSTR family.

    0x96 / 0xE7 keep the aggregator receiver layout.
    The rest use hstr_push_ext -> hstr_internal_push_ex.
    """
    family = _PEHSTR_FAMILY.get(type_byte, f"type={type_byte:#04x}")

    if type_byte in _AGGREGATOR_EXPR_FAMILY:
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

        _HSTR_SHOW_LIMIT = 8
        if sig_data and len(sig_data) % 4 == 0:
            n = len(sig_data) // 4
            entries = [int.from_bytes(sig_data[i * 4 : (i + 1) * 4], "little") for i in range(n)]
            shown = [f"{v:#010x}" for v in entries[:_HSTR_SHOW_LIMIT]]
            tail = f", … +{n - _HSTR_SHOW_LIMIT} more" if n > _HSTR_SHOW_LIMIT else ""
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

    parsed, error_text = _parse_hstr_signature_payload(p, type_byte)
    if parsed is None:
        return FormatResult(
            fields=[
                ("family", f"{ANSI_GREEN}{family}{ANSI_RESET}"),
                ("error", error_text or "failed to parse hstr payload"),
            ]
        )

    name_bytes = parsed["name_bytes"]
    assert isinstance(name_bytes, bytes)
    records = parsed["records"]
    assert isinstance(records, list)
    trailing = parsed["trailing"]
    assert isinstance(trailing, bytes)
    tail_word0 = parsed["tail_word0"]
    tail_word1 = parsed["tail_word1"]

    fields: list[Field] = [
        ("family", f"{ANSI_GREEN}{family}{ANSI_RESET}"),
        ("header_word0", f"{parsed['header_word0']:#06x}"),
        ("header_word1", f"{parsed['header_word1']:#06x}"),
        ("subsig_count", str(parsed["subsig_count"])),
        ("name", name_bytes.decode("latin-1", errors="replace") if name_bytes else "(empty)"),
    ]
    sections: list[DisplaySection] = []

    for idx, rec in enumerate(records, 1):
        tag = rec["tag"]
        ln = rec["len"]
        flags_raw = rec["flags_raw"]
        data = rec["data"]
        assert isinstance(tag, int)
        assert isinstance(ln, int)
        assert isinstance(data, bytes)
        assert flags_raw is None or isinstance(flags_raw, int)

        title = f"> SubSig #{idx}: tag={tag:#06x}, len={ln}"
        if flags_raw is not None:
            title += f", flags={_format_hstr_subsig_flags_for_title(flags_raw)}"

        text, text_modifier = _decode_pehstr_subsig_text(data)
        rows: list[Field] = []
        rows.append(
            (
                "Pattern",
                _format_hstr_pattern_value(idx, data, text, text_modifier, flags_raw),
            )
        )
        if any(not (0x20 <= byte <= 0x7E) for byte in data):
            rows.append(("Yara Hex", _format_hstr_yara_hex(data)))
        sections.append(DisplaySection(title=title, rows=rows))

    if tail_word0 is not None:
        fields.append(("tail_word0", f"{tail_word0:#06x}"))
    if tail_word1 is not None:
        fields.append(("tail_word1", f"{tail_word1:#06x}"))
    if trailing:
        preview = trailing[:8].hex(" ")
        ellipsis = "…" if len(trailing) > 8 else ""
        fields.append(("trailing_bytes", f"{len(trailing)} B [{preview}{ellipsis}]"))

    return FormatResult(fields=fields, sections=sections)


def fmt_static(p: bytes) -> list[Field]:
    """STATIC (0x67) — IDA-confirmed via staticrec_t::Load (0x1800faabc).

    Confirmed layout (minimum 18 bytes):
        +0    4B  key[0]       — DWORD
        +4    4B  key[1]       — DWORD
        +8    4B  key[2]       — DWORD
        +12   4B  score_flags  — DWORD: bits 0..27 = score (28-bit), bits 28..31 = upper flags
        +16   2B  ext_word     — WORD: bits 13..15 = ext_type (0..4), bits 0..12 = misc flags
        -- min 18 B --
        Extension layout depends on ext_type (bits 13..15 of ext_word):
          ext_type 0:  +18  16B  extra   (stored via MpSignatureExtraStore)
                       +34  var  class_name
          ext_type 1:  +18  20B  extra
                       +38  var  class_name
          ext_type 2:  +18   4B  sub_key (DWORD)
          ext_type 3:  +18   4B  sub_key (DWORD)
                       +22  var  class_name
          ext_type 4:  +18  32B  extra
                       +50  var  class_name
    """
    if len(p) < 18:
        return []

    k0, k1, k2 = struct.unpack_from("<3I", p, 0)
    score_flags = int.from_bytes(p[12:16], "little")
    score       = score_flags & 0x0FFFFFFF          # bits 0..27
    ext_word    = int.from_bytes(p[16:18], "little")
    ext_type    = (ext_word >> 13) & 0x7             # bits 13..15

    ext_label = {0: "no-extra", 1: "extra-20B", 2: "sub_key", 3: "sub_key", 4: "extra-32B"}.get(
        ext_type, "?"
    )

    fields: list[Field] = [
        ("key[0]",      f"{k0:#010x}"),
        ("key[1]",      f"{k1:#010x}"),
        ("key[2]",      f"{k2:#010x}"),
        ("score_flags", f"{score_flags:#010x}"),
        ("score",       f"{score:#08x}  {ANSI_GRAY}(28-bit){ANSI_RESET}"),
        ("ext_word",    f"{ext_word:#06x}"),
        ("ext_type",    f"{ext_type}  {ANSI_GRAY}({ext_label}){ANSI_RESET}"),
    ]

    # Extension-specific fields
    if ext_type in (2, 3):
        if len(p) >= 22:
            sub_key = int.from_bytes(p[18:22], "little")
            fields.append(("sub_key", f"{sub_key:#010x}"))
        off = 22
    elif ext_type == 0:
        if len(p) >= 34:
            fields.append(("extra", p[18:34].hex(" ")))
        off = 34
    elif ext_type == 1:
        if len(p) >= 38:
            fields.append(("extra", p[18:38].hex(" ")))
        off = 38
    elif ext_type == 4:
        if len(p) >= 50:
            fields.append(("extra", p[18:50].hex(" ")))
        off = 50
    else:
        off = 18

    if off < len(p):
        tail = p[off:]
        null_pos = tail.find(b"\x00")
        class_name = tail[:null_pos].decode("utf-8", errors="replace") if null_pos != -1 else tail.decode("utf-8", errors="replace")
        if class_name:
            fields.append(("class_name", class_name))

    return fields


def fmt_sigtree(p: bytes) -> list[Field]:
    """SIGTREE (0x40) / SIGTREE_EXT (0x41).

    IDA-confirmed layout (SigtreeHandlerInstance::push @ 0x1800f1d84,
    siga_cksig_impl @ 0x18013d6a0, MatchParameter @ 0x1800ec6b0):

        +0  2B  entry_count_word — low byte = entry count; high byte = n3 (per-entry
                                   size modifier: 0→+0B, 1→+4B, 2→+8B, 3→+9B)
        +2  2B  type_word        — high byte = SigtreeHandlerInstance index (0–6);
                                   0x0301 = any-of, 0x0501 = all-of
        +4  ?B  attr_name[]      — null-terminated; p[4]==0x00 means unnamed
        +?  entry_count × (16 + n3_extra) B entries:
              [0..3]  4B  entry_flags  — bit 0x0002: always_match_A (A-side trivially passes),
                                         bit 0x0010: ext_bm_A (BM data follows for A-side),
                                         bit 0x1000: ext_bm_B (BM data follows for B-side)
              [4]     1B  fid_lo       — field sub-code (gktab lookup key)
              [5]     1B  fid_hi       — field family (0x70=PE, 0x60=generic, 0x30=?)
              [6]     1B  sub_lo       — A-side comparison data length (bytes to CRC; 0=full)
              [7]     1B  sub_hi       — B-side comparison data length (bytes to CRC; 0=full)
              [8..11] 4B  val_lo       — match value low DWORD
              [12..15]4B  val_hi       — match value high DWORD (0x00 = single DWORD)
              [16..]  n3_extra B       — n3-driven fixed extension (semantics TBD)
        After all fixed entries: optional variable-length BM matcher / hash data
        per entry (presence gated by entry_flags; size requires gktab at runtime).
    """
    if len(p) < 5:
        return []

    entry_count_word = int.from_bytes(p[0:2], "little")
    entry_count = entry_count_word & 0xFF           # low byte
    n3          = (entry_count_word >> 8) & 0xFF    # high byte: per-entry size modifier
    n3_extra    = _SIGTREE_N3_EXTRA.get(n3, 0)
    entry_stride = 16 + n3_extra

    type_word    = int.from_bytes(p[2:4], "little")
    tw_label     = _SIGTREE_TYPE_WORD.get(type_word, "?")
    instance_idx = (type_word >> 8) & 0xFF           # p[3] = SigtreeHandlerInstance index

    n3_note = f"  {ANSI_GRAY}(n3={n3}, stride={entry_stride}B/entry){ANSI_RESET}" if n3 else ""
    inst_note = f"  {ANSI_GRAY}inst={instance_idx}{ANSI_RESET}"

    fields: list[Field] = [
        ("entry_count", f"{entry_count}{n3_note}"),
        ("type_word",
         f"{type_word:#06x}  {ANSI_YELLOW}({tw_label}){ANSI_RESET}{inst_note}"),
    ]

    # p[4] is the first byte of null-terminated attr_name; 0x00 = no name
    off = 5
    if p[4] != 0 and len(p) > 4:
        end = p.find(b"\x00", 4)
        if end != -1:
            attr_name = p[4:end].decode("utf-8", errors="replace")
            off = end + 1
        else:
            attr_name = p[4:].decode("utf-8", errors="replace")
            off = len(p)
        fields.append(("attr_name", f"{ANSI_GREEN}{attr_name}{ANSI_RESET}"))

    # Iterate entries; track whether any entry has variable-length extended params
    has_ext_data = False
    for i in range(entry_count):
        eoff = off + i * entry_stride
        if eoff + 16 > len(p):
            fields.append((f"entry[{i}]", f"{ANSI_YELLOW}truncated{ANSI_RESET}"))
            break
        e         = p[eoff : eoff + 16]
        eflags    = int.from_bytes(e[0:4], "little")
        fid_lo    = e[4]
        fid_hi    = e[5]
        sub_lo    = e[6]   # A-side comparison data size (MatchParameter, a8[0]==0 path)
        sub_hi    = e[7]   # B-side comparison data size (MatchParameter, a8[0]!=0 path)
        val_lo    = int.from_bytes(e[8:12], "little")
        val_hi    = int.from_bytes(e[12:16], "little")
        fhi_label = _SIGTREE_FID_HI.get(fid_hi, "?")

        # val display: omit val_hi when it is zero (common single-DWORD case)
        if val_hi == 0:
            val_str = f"{val_lo:#010x}"
        else:
            val_str = f"{val_lo:#010x}|{val_hi:#010x}"

        # sub_lo / sub_hi: show concisely; suppress zero bytes when both are 0
        if sub_lo == 0 and sub_hi == 0:
            sub_str = f"{ANSI_GRAY}0x00:0x00{ANSI_RESET}"
        else:
            sub_str = f"{sub_lo:#04x}:{sub_hi:#04x}"

        flag_annot = _annotate_bits(eflags, _SIGTREE_ENTRY_FLAG_BITS)
        if eflags & (0x0010 | 0x1000):
            has_ext_data = True

        fields.append((
            f"entry[{i}]",
            f"flags={eflags:#010x}{flag_annot}"
            f"  fid={fid_hi:02x}{ANSI_GRAY}({fhi_label}){ANSI_RESET}:{fid_lo:02x}"
            f"  sub={sub_str}"
            f"  val={val_str}",
        ))

        # Show n3 extension bytes when present
        if n3_extra and eoff + entry_stride <= len(p):
            ext_bytes = p[eoff + 16 : eoff + entry_stride]
            fields.append((f"entry[{i}].n3_ext", ext_bytes.hex(" ")))

    # Payload size annotation
    expected_base = off + entry_count * entry_stride
    remaining     = len(p) - expected_base
    if has_ext_data and remaining > 0:
        fields.append((
            "payload_size",
            f"{len(p)} B"
            f"  {ANSI_GRAY}(base {expected_base} B + {remaining} B extended params){ANSI_RESET}",
        ))
    elif remaining != 0:
        fields.append((
            "payload_size",
            f"{len(p)} B  (expected {expected_base} B)"
            + (f"  {ANSI_YELLOW}← MISMATCH{ANSI_RESET}" if remaining != 0 else ""),
        ))

    return fields


# ─── Formatter dispatch table ─────────────────────────────────────────────── #
FORMATTERS: dict[int, object] = {
    0x5C: fmt_threat_begin,
    0x5D: fmt_threat_end,
    0x5F: fmt_fpath_like,  # FILEPATH
    0x60: fmt_fpath_like,  # FOLDERNAME
    0x63: fmt_regkey,
    0x70: fmt_trusted_publisher,
    0x71: fmt_fpath_like,  # ASEP_FILEPATH
    0x75: fmt_fpath_like,  # ASEP_FOLDERNAME
    0x55: fmt_snid,       # NID
    0x7E: fmt_snid,       # SNID
    0x80: fmt_kcrce,
    0xA0: fmt_friendlyfile_sha256,
    0x69: fmt_latent_threat,
    0xAF: fmt_common_code,
    0x7A: fmt_versioncheck,
    0x61: fmt_pehstr_ext,  # PEHSTR
    0x78: fmt_pehstr_ext,  # PEHSTR_EXT
    0x85: fmt_pehstr_ext,  # PEHSTR_EXT2
    0x8C: fmt_pehstr_ext,  # ELFHSTR_EXT
    0x8D: fmt_pehstr_ext,  # MACHOHSTR_EXT
    0x8E: fmt_pehstr_ext,  # DOSHSTR_EXT
    0x8F: fmt_pehstr_ext,  # MACROHSTR_EXT
    0x92: fmt_pehstr_ext,  # ASCRIPTHSTR_EXT
    0x96: fmt_pehstr_ext,  # AAGGREGATOR
    0xE7: fmt_pehstr_ext,  # AAGGREGATOREX
    0x67: fmt_static,
    0x40: fmt_sigtree,    # SIGTREE
    0x41: fmt_sigtree,    # SIGTREE_EXT
}

# Formatters that accept (payload, type_byte) instead of just (payload).
_TYPE_AWARE_FORMATTERS: frozenset = frozenset({fmt_fpath_like, fmt_pehstr_ext})


def format_payload(type_byte: int, payload: bytes) -> FormatResult:
    fn = FORMATTERS.get(type_byte)
    if fn is None:
        return FormatResult()
    raw_result: list[Field] | FormatResult
    if fn in _TYPE_AWARE_FORMATTERS:
        raw_result = fn(payload, type_byte)  # type: ignore[call-arg]
    else:
        raw_result = fn(payload) # type: ignore
    if isinstance(raw_result, FormatResult):
        return raw_result
    return FormatResult(fields=raw_result)


# ─── File banner ─────────────────────────────────────────────────────────── #
def _print_file_banner(path: Path) -> None:
    size_mb = path.stat().st_size / 1_048_576
    info("%s  %.1f MB", path.name, size_mb)


# ─── List-threats mode ────────────────────────────────────────────────────── #
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
        cat_name = _THREAT_CATEGORY.get(cur_cat, f"0x{cur_cat:02x}")
        top = "  " + ", ".join(
            f"{ANSI_WHITE}{type_name(t)}{ANSI_RESET}{ANSI_GRAY}×{c}{ANSI_RESET}"
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
            cur_name = parse_threat_name(payload)
            cur_id = parse_threat_id(payload)
            cur_cat = int.from_bytes(payload[8:10], "little") if len(payload) >= 10 else 0
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
        print(f"{ANSI_GRAY}  … stopped after {shown} threats  (use -n 0 for unlimited){ANSI_RESET}")
    print()


# ─── Records mode ─────────────────────────────────────────────────────────── #
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

    for type_byte, payload, threat_name, _sig_idx in iter_records_with_context(path):
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
            if type_byte == 0x5C and threat_name and threat_name != prev_threat:
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
        )

        shown += 1
        if limit > 0 and shown >= limit:
            print(
                f"\n{ANSI_GRAY}── stopped after {shown} record(s) "
                f"(use -n 0 for unlimited) ──{ANSI_RESET}"
            )
            break

    if shown == 0:
        print(f"{ANSI_YELLOW}[!] no matching records found{ANSI_RESET}")


# ─── CLI dispatch ─────────────────────────────────────────────────────────── #
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
        info("filter: type=%s (%s)", f"{filter_type:#04x}", type_name(filter_type))
    run_list_threats(path, filter_name, filter_type, args.limit)


def cmd_records(args: argparse.Namespace, path: Path) -> None:
    filter_type = _parse_type_arg(args)
    filter_name = args.threat.lower() if args.threat else None
    if filter_type is not None:
        info("filter: type=%s (%s)", f"{filter_type:#04x}", type_name(filter_type))
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
    shared.add_argument("--type", "-t", metavar="HEX",
                        help="Filter by record type (hex, e.g. 0x67)")
    shared.add_argument("--threat", "-T", metavar="SUBSTR",
                        help="Filter by threat name substring (case-insensitive)")
    shared.add_argument("--limit", "-n", type=int, default=20, metavar="N",
                        help="Max threats/records to display (default: 20; 0 = unlimited)")

    top = argparse.ArgumentParser(
        description="Inspect Microsoft Defender .sig signature files.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = top.add_subparsers(dest="subcommand", metavar="{threats,records}")

    p_threats = sub.add_parser("threats", parents=[shared],
                               help="List threats (default view)")
    p_threats.set_defaults(func=cmd_threats)

    p_records = sub.add_parser("records", parents=[shared],
                               help="Inspect individual records")
    p_records.add_argument("--hex", "-x", action="store_true",
                           help="Show full hexdump for each record")
    p_records.add_argument("--skip-framing", action="store_true",
                           help="Suppress THREAT_BEGIN/END; show threat separator instead")
    p_records.set_defaults(func=cmd_records)

    return top


# ─── Main ─────────────────────────────────────────────────────────────────── #
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
