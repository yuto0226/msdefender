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

# PEHSTR flags bitmask — confirmed from aggregatorex_receiver @ 0x1800FE270.
_PEHSTR_FLAG_BITS: list[tuple[int, str]] = [
    (0x01, "fuzzy"),      # partial match: not all hashes need to match
    (0x02, "has_extra"),  # extra TLV sub-records follow sig_data
]

# PEHSTR extra sub-record types (inner TLV after sig_data).
# TODO: fill in from IDA analysis of aggregatorex_receiver extra TLV dispatch.
_PEHSTR_EXTRA_SUB_TYPES: dict[int, str] = {}

# SIGTREE: type_word → combination logic label (empirically observed).
# Values are LE uint16 reads: wire bytes 01 03 → 0x0301, 01 05 → 0x0501.
_SIGTREE_TYPE_WORD: dict[int, str] = {
    0x0301: "any-of",
    0x0501: "all-of",
}

# SIGTREE: fid_hi byte → field family (empirically observed; gktab confirmation pending).
_SIGTREE_FID_HI: dict[int, str] = {
    0x70: "PE attrs",
    0x60: "generic attrs",
    0x30: "family_0x30",
}


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
    for n in range(8):
        if (value & ~known_mask) & (1 << n):
            parts.append(f"unk_bit{n}")
    return f"  ({', '.join(parts)})" if parts else ""


# ─── Display helpers ──────────────────────────────────────────────────────── #
# A formatter returns a list of (label, value) pairs.
# Return [] to fall through to raw hexdump.
Field = tuple[str, str]

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
        hex_parts.append("   " * pad + ("  " if len(chunk) <= 8 else ""))
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


def print_record(
    seq: int,
    type_byte: int,
    payload: bytes,
    threat_name: str,
    fields: list[Field],
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

    if fields:
        _print_fields(fields)
    elif not show_hex:
        # Print first 16 bytes as a quick preview even without --hex
        _print_hexdump(payload[:16])
        if len(payload) > 16:
            print(
                f"{INDENT}{ANSI_GRAY}… {len(payload) - 16} more bytes (use --hex to show all){ANSI_RESET}"
            )
        return

    if show_hex:
        if fields:
            print()  # blank line before hexdump
        _print_hexdump(payload)


# ─── Per-type formatters ──────────────────────────────────────────────────── #
# Each function receives the raw payload bytes and returns a list of Fields.
# Return [] to trigger hexdump fallback in print_record().
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
    name = p[5:].rstrip(b"\x00").decode("utf-8", errors="replace") if len(p) > 5 else ""
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


def fmt_pehstr_ext(p: bytes, type_byte: int = 0) -> list[Field]:
    """PEHSTR_EXT (0x78) and sibling HSTR types — §2.1.

    Top-level layout (aggregatorex_receiver @ 0x1800FE270):
        +0  1B   flags     — bitmask; gates extra sub-records
        +1  1B   name_len  — byte length of name[]
        +2  2B   sig_len   — byte length of sig_data[] (LE)
        +4  name_len B   name[]     — UTF-8 label (may be empty)
        +4+name_len  sig_len B  sig_data[]  — XOR-encoded pattern data
        remainder  extra[]  — TLV sub-records: (pad:1B)(count:1B) + count×(type:1B)(len:1B)(data)
    """
    if len(p) < 4:
        return []

    flags    = p[0]
    name_len = p[1]
    sig_len  = int.from_bytes(p[2:4], "little")
    hdr_end  = 4 + name_len + sig_len

    if hdr_end > len(p):
        return [
            ("flags", f"{flags:#04x}"),
            ("name_len", str(name_len)),
            ("sig_len", str(sig_len)),
            ("error", "payload truncated"),
        ]

    name     = p[4 : 4 + name_len]
    sig_data = p[4 + name_len : hdr_end]
    extra    = p[hdr_end:]

    family    = _PEHSTR_FAMILY.get(type_byte, f"type={type_byte:#04x}")
    name_str  = name.decode("utf-8", errors="replace") if name else "(empty)"
    hash_hint = (
        f"  {ANSI_GRAY}(≈{sig_len // 4} DWORD entries, XOR-encoded){ANSI_RESET}"
        if sig_len > 0 else ""
    )

    fields: list[Field] = [
        ("family",   f"{ANSI_GREEN}{family}{ANSI_RESET}"),
        ("flags",    f"{flags:#04x}{_annotate_bits(flags, _PEHSTR_FLAG_BITS)}"),
        ("name_len", str(name_len)),
        ("sig_len",  f"{sig_len}{hash_hint}"),
        ("name",     name_str),
        ("sig_data", sig_data.hex(" ") if sig_data else "(empty)"),
    ]

    # extra: empirically (pad:1B)(sub_count:1B) + sub_count×(type:1B)(len:1B)(data)
    # This TLV layout is only confirmed for flags=0x02; other flags values may differ.
    # We validate the parsed sub-record lengths sum to avoid printing garbage.
    if len(extra) >= 2:
        pad, sub_count = extra[0], extra[1]
        # Validate: walk ahead to check the sub-record lengths are consistent
        total_needed = 2
        valid = True
        for _ in range(sub_count):
            if total_needed + 2 > len(extra):
                valid = False
                break
            total_needed += 2 + extra[total_needed + 1]
        if valid and total_needed <= len(extra):
            fields.append(("extra.pad",       f"{pad:#04x}"))
            fields.append(("extra.sub_count", str(sub_count)))
            eoff = 2
            for i in range(sub_count):
                st = extra[eoff]
                sl = extra[eoff + 1]
                sd = extra[eoff + 2 : eoff + 2 + sl]
                st_label = _PEHSTR_EXTRA_SUB_TYPES.get(st, "?")
                if len(sd) == 4:
                    detail = f"{int.from_bytes(sd, 'little'):#010x}  {ANSI_GRAY}({st_label}){ANSI_RESET}"
                elif len(sd) == 2:
                    detail = f"{int.from_bytes(sd, 'little'):#06x}  {ANSI_GRAY}({st_label}){ANSI_RESET}"
                else:
                    detail = sd.hex(" ") if len(sd) <= 8 else sd[:8].hex(" ") + "…"
                fields.append((f"sub[{i}] type={st:#04x} len={sl}", detail))
                eoff += 2 + sl
            if eoff < len(extra):
                fields.append((
                    "extra.tail",
                    f"{len(extra) - eoff} B remaining: " + extra[eoff : eoff + 8].hex(" "),
                ))
        else:
            # Unknown extra format for this flags value — show raw
            fields.append((
                "extra",
                f"{len(extra)} B  [{extra[:16].hex(' ')}{'…' if len(extra) > 16 else ''}]  (format TBD for flags={flags:#04x})",
            ))
    elif extra:
        fields.append(("extra", extra.hex(" ")))

    return fields


def fmt_static(p: bytes) -> list[Field]:
    """STATIC (0x67) — §1.2  (empirically derived; awaiting IDA confirmation).

    Empirically confirmed layout:
        +0   12B  key[0..2]  — 3×DWORD primary CRC/hash key
        +12   2B  score      — WORD
        +14   2B  ext_flags  — WORD (lower 6 bits observed; upper always 0)
        +16   1B  sub_flag   — 0x00 or 0x01
        +17   1B  ext_type   — 0x20=base, 0x10=+16B hash, 0x00=rare
        +18   4B  sub_key    — secondary DWORD
        +22  16B  hash16     — optional; present when ext_type == 0x10
        +?   var  class_name — optional '#'-prefixed label (e.g. "#ClnFile")
    """
    if len(p) < 22:
        return []

    k0, k1, k2 = struct.unpack_from("<3I", p, 0)
    score = int.from_bytes(p[12:14], "little")
    ext_flags = int.from_bytes(p[14:16], "little")
    sub_flag = p[16]
    ext_type = p[17]
    sub_key = int.from_bytes(p[18:22], "little")

    ext_label = {0x10: "ext_hash", 0x20: "base", 0x00: "rare"}.get(ext_type, "?")

    fields: list[Field] = [
        ("key[0]", f"{k0:#010x}"),
        ("key[1]", f"{k1:#010x}"),
        ("key[2]", f"{k2:#010x}"),
        ("score", f"{score:#06x}"),
        ("ext_flags", f"{ext_flags:#06x}"),
        ("sub_flag", f"{sub_flag:#04x}"),
        ("ext_type", f"{ext_type:#04x}  ({ext_label})"),
        ("sub_key", f"{sub_key:#010x}"),
    ]

    off = 22
    if ext_type == 0x10 and len(p) >= 38:
        fields.append(("hash16", p[22:38].hex(" ")))
        off = 38

    if off < len(p):
        tail = p[off:]
        # '#'-prefixed class label; strip trailing null bytes
        class_name = tail.rstrip(b"\x00").decode("utf-8", errors="replace")
        fields.append(("class_name", class_name))

    return fields


def fmt_sigtree(p: bytes) -> list[Field]:
    """SIGTREE (0x40) / SIGTREE_EXT (0x41) — §3.2.

    Empirically observed layout:
        +0  2B  entry_count  — WORD LE
        +2  2B  type_word    — sub-type (0x0103, 0x0105, ...)
        +4  1B  format_flag  — 0x00=unnamed, 0x21=attr_name string follows
        +5  ?B  attr_name[]  — null-terminated '#'-prefixed label (format_flag==0x21 only)
        +?  entry_count × 16B entries:
              [0..3]  4B  entry_flags  — DWORD per-entry mask
              [4]     1B  field_id_lo  — type sub-code
              [5]     1B  field_id_hi  — family code (0x70=PE, 0x60=?, 0x30=?)
              [6..7]  2B  sub_field    — WORD
              [8..15] 8B  value        — QWORD or two DWORDs (semantics TBD via gktab)
    """
    if len(p) < 5:
        return []
    entry_count = int.from_bytes(p[0:2], "little")
    type_word   = int.from_bytes(p[2:4], "little")
    fmt_flag    = p[4]
    tw_label    = _SIGTREE_TYPE_WORD.get(type_word, "?")
    fields: list[Field] = [
        ("entry_count", str(entry_count)),
        ("type_word",   f"{type_word:#06x}  {ANSI_YELLOW}({tw_label}){ANSI_RESET}"),
        ("format_flag", f"{fmt_flag:#04x}" + (" (named)" if fmt_flag == 0x21 else "")),
    ]
    off = 5
    if fmt_flag == 0x21 and len(p) > 5:
        end = p.find(b"\x00", 5)
        if end != -1:
            attr_name = p[5:end].decode("utf-8", errors="replace")
            fields.append(("attr_name", attr_name))
            off = end + 1
    expected = off + entry_count * 16
    mismatch = len(p) != expected
    fields.append((
        "payload_size",
        f"{len(p)} B  (expected {expected} B)"
        + (f"  {ANSI_YELLOW}← MISMATCH{ANSI_RESET}" if mismatch else ""),
    ))

    # Print each 16B entry inline
    for i in range(entry_count):
        eoff = off + i * 16
        if eoff + 16 > len(p):
            fields.append((f"entry[{i}]", f"{ANSI_YELLOW}truncated{ANSI_RESET}"))
            break
        e         = p[eoff : eoff + 16]
        eflags    = int.from_bytes(e[0:4], "little")
        fid_lo    = e[4]
        fid_hi    = e[5]
        sub_field = int.from_bytes(e[6:8], "little")
        val_lo    = int.from_bytes(e[8:12], "little")
        val_hi    = int.from_bytes(e[12:16], "little")
        fhi_label = _SIGTREE_FID_HI.get(fid_hi, "?")
        fields.append((
            f"entry[{i}]",
            f"flags={eflags:#010x}"
            f"  id={fid_hi:02x}{ANSI_GRAY}({fhi_label}){ANSI_RESET}:{fid_lo:02x}"
            f"  sub={sub_field:#06x}"
            f"  val={val_lo:#010x}|{val_hi:#010x}",
        ))
    return fields


# ─── Formatter dispatch table ─────────────────────────────────────────────── #
FORMATTERS: dict[int, object] = {
    0x5C: fmt_threat_begin,
    0x5D: fmt_threat_end,
    0x55: fmt_snid,       # NID
    0x7E: fmt_snid,       # SNID
    0x80: fmt_kcrce,
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
_TYPE_AWARE_FORMATTERS: frozenset = frozenset({fmt_pehstr_ext})


def format_payload(type_byte: int, payload: bytes) -> list[Field]:
    fn = FORMATTERS.get(type_byte)
    if fn is None:
        return []
    if fn in _TYPE_AWARE_FORMATTERS:
        return fn(payload, type_byte)  # type: ignore[call-arg]
    return fn(payload) # type: ignore


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
        return shown < limit

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
    if shown >= limit:
        print(f"{ANSI_GRAY}  … stopped after {shown} threats  (use -n to see more){ANSI_RESET}")
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
        fields = format_payload(type_byte, payload)
        print_record(
            seq=seq_total,
            type_byte=type_byte,
            payload=payload,
            threat_name=threat_name,
            fields=fields,
            show_hex=show_hex,
        )

        shown += 1
        if shown >= limit:
            print(
                f"\n{ANSI_GRAY}── stopped after {shown} record(s) "
                f"(use -n to show more) ──{ANSI_RESET}"
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
                        help="Max threats/records to display (default: 20)")

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
