#!/usr/bin/env python3
"""
sigstats.py - Show signature type distribution from a .sig file.

Usage:
    python sigstats.py <file.sig> [file.sig ...]
    python sigstats.py mpav.sig --top 20
    python sigstats.py mpav.sig mpas.sig --width 60
"""

from __future__ import annotations

import argparse
import io
import struct
import sys
from collections import Counter
from pathlib import Path

# Force UTF-8 output on Windows so Unicode box-drawing chars render correctly
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

from lib.debug import (
    ANSI_RESET,
    ANSI_BOLD,
    ANSI_CYAN,
    ANSI_GREEN,
    ANSI_YELLOW,
    ANSI_BLUE,
    ANSI_MAGENTA,
    ANSI_GRAY,
    ANSI_WHITE,
    ANSI_BWHITE,
    ok,
    info,
    error,
)

# --------------------------------------------------------------------- #
# Known type labels (best-effort from public VDM research)               #
# --------------------------------------------------------------------- #
# Source: reverse-engineered from getsigtype @ 0x180468C40 in
#         mpengine.dll v1.443.903.0 (see docs/getsigtype_analysis.md)
TYPE_NAMES: dict[int, str] = {
    # 0x01–0x6B
    0x01: "SIGNATURE_TYPE_RESERVED",
    0x02: "SIGNATURE_TYPE_VOLATILE_THREAT_INFO",
    0x03: "SIGNATURE_TYPE_VOLATILE_THREAT_ID",
    0x11: "SIGNATURE_TYPE_CKOLDREC",
    0x20: "SIGNATURE_TYPE_KVIR32",
    0x21: "SIGNATURE_TYPE_POLYVIR32",
    0x27: "SIGNATURE_TYPE_NSCRIPT_NORMAL",
    0x28: "SIGNATURE_TYPE_NSCRIPT_SP",
    0x29: "SIGNATURE_TYPE_NSCRIPT_BRUTE",
    0x2C: "SIGNATURE_TYPE_NSCRIPT_CURE",
    0x30: "SIGNATURE_TYPE_TITANFLT",
    0x3D: "SIGNATURE_TYPE_PEFILE_CURE",
    0x3E: "SIGNATURE_TYPE_MAC_CURE",
    0x40: "SIGNATURE_TYPE_SIGTREE",
    0x41: "SIGNATURE_TYPE_SIGTREE_EXT",
    0x42: "SIGNATURE_TYPE_MACRO_PCODE",
    0x43: "SIGNATURE_TYPE_MACRO_SOURCE",
    0x44: "SIGNATURE_TYPE_BOOT",
    0x49: "SIGNATURE_TYPE_CLEANSCRIPT",
    0x4A: "SIGNATURE_TYPE_TARGET_SCRIPT",
    0x50: "SIGNATURE_TYPE_CKSIMPLEREC",
    # ASCII printable range 0x51–0x6B
    0x51: "SIGNATURE_TYPE_PATTMATCH",
    0x53: "SIGNATURE_TYPE_RPFROUTINE",
    0x55: "SIGNATURE_TYPE_NID",
    0x56: "SIGNATURE_TYPE_GENSFX",
    0x57: "SIGNATURE_TYPE_UNPLIB",
    0x58: "SIGNATURE_TYPE_DEFAULTS",
    0x5B: "SIGNATURE_TYPE_DBVAR",
    0x5C: "SIGNATURE_TYPE_THREAT_BEGIN",
    0x5D: "SIGNATURE_TYPE_THREAT_END",
    0x5E: "SIGNATURE_TYPE_FILENAME",
    0x5F: "SIGNATURE_TYPE_FILEPATH",
    0x60: "SIGNATURE_TYPE_FOLDERNAME",
    0x61: "SIGNATURE_TYPE_PEHSTR",
    0x62: "SIGNATURE_TYPE_LOCALHASH",
    0x63: "SIGNATURE_TYPE_REGKEY",
    0x64: "SIGNATURE_TYPE_HOSTSENTRY",
    0x67: "SIGNATURE_TYPE_STATIC",
    0x69: "SIGNATURE_TYPE_LATENT_THREAT",
    0x6A: "SIGNATURE_TYPE_REMOVAL_POLICY",
    0x6B: "SIGNATURE_TYPE_WVT_EXCEPTION",
    # 0x6C–0x9D
    0x6C: "SIGNATURE_TYPE_REVOKED_CERTIFICATE",
    0x70: "SIGNATURE_TYPE_TRUSTED_PUBLISHER",
    0x71: "SIGNATURE_TYPE_ASEP_FILEPATH",
    0x73: "SIGNATURE_TYPE_DELTA_BLOB",
    0x74: "SIGNATURE_TYPE_DELTA_BLOB_RECINFO",
    0x75: "SIGNATURE_TYPE_ASEP_FOLDERNAME",
    0x77: "SIGNATURE_TYPE_PATTMATCH_V2",
    0x78: "SIGNATURE_TYPE_PEHSTR_EXT",
    0x79: "SIGNATURE_TYPE_VDLL_X86",
    0x7A: "SIGNATURE_TYPE_VERSIONCHECK",
    0x7B: "SIGNATURE_TYPE_SAMPLE_REQUEST",
    0x7C: "SIGNATURE_TYPE_VDLL_X64",
    0x7E: "SIGNATURE_TYPE_SNID",
    0x7F: "SIGNATURE_TYPE_FOP",
    0x80: "SIGNATURE_TYPE_KCRCE",
    0x83: "SIGNATURE_TYPE_VFILE",
    0x84: "SIGNATURE_TYPE_SIGFLAGS",
    0x85: "SIGNATURE_TYPE_PEHSTR_EXT2",
    0x86: "SIGNATURE_TYPE_PEMAIN_LOCATOR",
    0x87: "SIGNATURE_TYPE_PESTATIC",
    0x88: "SIGNATURE_TYPE_UFSP_DISABLE",
    0x89: "SIGNATURE_TYPE_FOPEX",
    0x8A: "SIGNATURE_TYPE_PEPCODE",
    0x8B: "SIGNATURE_TYPE_IL_PATTERN",
    0x8C: "SIGNATURE_TYPE_ELFHSTR_EXT",
    0x8D: "SIGNATURE_TYPE_MACHOHSTR_EXT",
    0x8E: "SIGNATURE_TYPE_DOSHSTR_EXT",
    0x8F: "SIGNATURE_TYPE_MACROHSTR_EXT",
    0x90: "SIGNATURE_TYPE_TARGET_SCRIPT_PCODE",
    0x91: "SIGNATURE_TYPE_VDLL_ARM64",
    0x92: "SIGNATURE_TYPE_ASCRIPTHSTR_EXT",
    0x95: "SIGNATURE_TYPE_PEBMPAT",
    0x96: "SIGNATURE_TYPE_AAGGREGATOR",
    0x97: "SIGNATURE_TYPE_SAMPLE_REQUEST_BY_NAME",
    0x98: "SIGNATURE_TYPE_REMOVAL_POLICY_BY_NAME",
    0x99: "SIGNATURE_TYPE_TUNNEL_X86",
    0x9A: "SIGNATURE_TYPE_TUNNEL_X64",
    0x9B: "SIGNATURE_TYPE_TUNNEL_ARM64",
    0x9C: "SIGNATURE_TYPE_VDLL_ARM",
    0x9D: "SIGNATURE_TYPE_THREAD_X86",
    # 0x9E–0xEF
    0x9E: "SIGNATURE_TYPE_THREAD_X64",
    0x9F: "SIGNATURE_TYPE_THREAD_ARM64",
    0xA0: "SIGNATURE_TYPE_FRIENDLYFILE_SHA256",
    0xA1: "SIGNATURE_TYPE_FRIENDLYFILE_SHA512",
    0xA2: "SIGNATURE_TYPE_SHARED_THREAT",
    0xA3: "SIGNATURE_TYPE_VDM_METADATA",
    0xA4: "SIGNATURE_TYPE_VSTORE",
    0xA5: "SIGNATURE_TYPE_VDLL_SYMINFO",
    0xA6: "SIGNATURE_TYPE_IL2_PATTERN",
    0xA7: "SIGNATURE_TYPE_BM_STATIC",
    0xA8: "SIGNATURE_TYPE_BM_INFO",
    0xA9: "SIGNATURE_TYPE_NDAT",
    0xAA: "SIGNATURE_TYPE_FASTPATH_DATA",
    0xAB: "SIGNATURE_TYPE_FASTPATH_SDN",
    0xAC: "SIGNATURE_TYPE_DATABASE_CERT",
    0xAD: "SIGNATURE_TYPE_SOURCE_INFO",
    0xAE: "SIGNATURE_TYPE_HIDDEN_FILE",
    0xAF: "SIGNATURE_TYPE_COMMON_CODE",
    0xB0: "SIGNATURE_TYPE_VREG",
    0xB1: "SIGNATURE_TYPE_NISBLOB",
    0xB2: "SIGNATURE_TYPE_VFILEEX",
    0xB3: "SIGNATURE_TYPE_SIGTREE_BM",
    0xB4: "SIGNATURE_TYPE_VBFOP",
    0xB5: "SIGNATURE_TYPE_VDLL_META",
    0xB6: "SIGNATURE_TYPE_TUNNEL_ARM",
    0xB7: "SIGNATURE_TYPE_THREAD_ARM",
    0xB8: "SIGNATURE_TYPE_PCODEVALIDATOR",
    0xBA: "SIGNATURE_TYPE_MSILFOP",
    0xBB: "SIGNATURE_TYPE_KPAT",
    0xBC: "SIGNATURE_TYPE_KPATEX",
    0xBD: "SIGNATURE_TYPE_LUASTANDALONE",
    0xBE: "SIGNATURE_TYPE_DEXHSTR_EXT",
    0xBF: "SIGNATURE_TYPE_JAVAHSTR_EXT",
    0xC0: "SIGNATURE_TYPE_MAGICCODE",
    0xC1: "SIGNATURE_TYPE_CLEANSTORE_RULE",
    0xC2: "SIGNATURE_TYPE_VDLL_CHECKSUM",
    0xC3: "SIGNATURE_TYPE_THREAT_UPDATE_STATUS",
    0xC4: "SIGNATURE_TYPE_VDLL_MSIL",
    0xC5: "SIGNATURE_TYPE_ARHSTR_EXT",
    0xC6: "SIGNATURE_TYPE_MSILFOPEX",
    0xC7: "SIGNATURE_TYPE_VBFOPEX",
    0xC8: "SIGNATURE_TYPE_FOP64",
    0xC9: "SIGNATURE_TYPE_FOPEX64",
    0xCA: "SIGNATURE_TYPE_JSINIT",
    0xCB: "SIGNATURE_TYPE_PESTATICEX",
    0xCC: "SIGNATURE_TYPE_KCRCEX",
    0xCD: "SIGNATURE_TYPE_FTRIE_POS",
    0xCE: "SIGNATURE_TYPE_NID64",
    0xCF: "SIGNATURE_TYPE_MACRO_PCODE64",
    0xD0: "SIGNATURE_TYPE_BRUTE",
    0xD1: "SIGNATURE_TYPE_SWFHSTR_EXT",
    0xD2: "SIGNATURE_TYPE_REWSIGS",
    0xD3: "SIGNATURE_TYPE_AUTOITHSTR_EXT",
    0xD4: "SIGNATURE_TYPE_INNOHSTR_EXT",
    0xD5: "SIGNATURE_TYPE_CERT_STORE_ENTRY",
    0xD6: "SIGNATURE_TYPE_EXPLICITRESOURCE",
    0xD7: "SIGNATURE_TYPE_CMDHSTR_EXT",
    0xD8: "SIGNATURE_TYPE_FASTPATH_TDN",
    0xD9: "SIGNATURE_TYPE_EXPLICITRESOURCEHASH",
    0xDA: "SIGNATURE_TYPE_FASTPATH_SDN_EX",
    0xDB: "SIGNATURE_TYPE_BLOOM_FILTER",
    0xDC: "SIGNATURE_TYPE_RESEARCH_TAG",
    0xDE: "SIGNATURE_TYPE_ENVELOPE",
    0xDF: "SIGNATURE_TYPE_REMOVAL_POLICY64",
    0xE0: "SIGNATURE_TYPE_REMOVAL_POLICY64_BY_NAME",
    0xE1: "SIGNATURE_TYPE_VDLL_META_X64",
    0xE2: "SIGNATURE_TYPE_VDLL_META_ARM",
    0xE3: "SIGNATURE_TYPE_VDLL_META_MSIL",
    0xE4: "SIGNATURE_TYPE_MDBHSTR_EXT",
    0xE5: "SIGNATURE_TYPE_SNIDEX",
    0xE6: "SIGNATURE_TYPE_SNIDEX2",
    0xE7: "SIGNATURE_TYPE_AAGGREGATOREX",
    0xE8: "SIGNATURE_TYPE_PUA_APPMAP",
    0xE9: "SIGNATURE_TYPE_PROPERTY_BAG",
    0xEA: "SIGNATURE_TYPE_DMGHSTR_EXT",
    0xEB: "SIGNATURE_TYPE_DATABASE_CATALOG",
    0xEC: "SIGNATURE_TYPE_DATABASE_CERT2",
    0xED: "SIGNATURE_TYPE_BM_ENV_VAR_MAP",
    0xEE: "SIGNATURE_TYPE_DATABASE_CERT3",
    0xEF: "SIGNATURE_TYPE_ARHSTR_POSIX_EXT",
}

BAR_CHAR = "█"
BAR_COLORS = [ANSI_CYAN, ANSI_GREEN, ANSI_YELLOW, ANSI_BLUE, ANSI_MAGENTA]


def format_type_label(type_byte: int) -> str:
    label = TYPE_NAMES.get(type_byte, f"TYPE_0x{type_byte:02X}")
    return label.removeprefix("SIGNATURE_TYPE_")


def iter_records(stream: bytes):
    """Yield (type_byte, payload_bytes) for every record in the stream."""
    pos = 0
    end = len(stream)

    while pos + 4 <= end:
        type_byte = stream[pos]
        b1, b2, b3 = stream[pos + 1], stream[pos + 2], stream[pos + 3]
        size = b1 | (b2 << 8) | (b3 << 16)

        if size == 0xFFFFFF:
            if pos + 8 > end:
                break
            size = struct.unpack_from("<I", stream, pos + 4)[0]
            data_off = pos + 8
        else:
            data_off = pos + 4

        payload = stream[data_off : data_off + size]
        yield type_byte, payload
        pos = data_off + size


def count_types(stream: bytes) -> Counter:
    counts: Counter = Counter()
    for type_byte, _ in iter_records(stream):
        counts[type_byte] += 1
    return counts


def render_bar(count: int, max_count: int, width: int, color: str) -> str:
    filled = round(count / max_count * width) if max_count else 0
    return f"{color}{BAR_CHAR * filled}{ANSI_RESET}"


def print_chart(
    counts: Counter,
    top: int | None,
    bar_width: int,
    title: str,
) -> None:
    total = sum(counts.values())
    ranked = counts.most_common() if top is None else counts.most_common(top)
    max_count = ranked[0][1] if ranked else 1

    label_w = max((len(format_type_label(t)) for t, _ in ranked), default=4)
    count_w = len(f"{max_count:,}")

    sep = f"{ANSI_GRAY}{'─' * (label_w + count_w + bar_width + 21)}{ANSI_RESET}"

    print(f"\n{ANSI_BOLD}{ANSI_BWHITE}{title}{ANSI_RESET}")
    print(f"{ANSI_GRAY}total records: {total:,}{ANSI_RESET}")
    print(sep)
    print(
        f"  {ANSI_BOLD}{'TYPE':<{label_w}}  {'COUNT':>{count_w}}  {'PCT':>6}  BAR{ANSI_RESET}"
    )
    print(sep)

    for i, (type_byte, count) in enumerate(ranked):
        label = format_type_label(type_byte)
        pct = count / total * 100
        color = BAR_COLORS[i % len(BAR_COLORS)]
        bar = render_bar(count, max_count, bar_width, color)
        type_hex = f"{ANSI_GRAY}0x{type_byte:02X}{ANSI_RESET}"
        print(
            f"  {ANSI_WHITE}{label:<{label_w}}{ANSI_RESET}"
            f"  {color}{count:>{count_w},}{ANSI_RESET}"
            f"  {ANSI_GRAY}{pct:5.1f}%{ANSI_RESET}"
            f"  {bar} {type_hex}"
        )

    print(sep)

    if top is not None and len(counts) > top:
        other = sum(v for _, v in counts.most_common()[top:])
        print(
            f"  {ANSI_GRAY}… {len(counts) - top} more types, "
            f"{other:,} records ({other / total * 100:.1f}%){ANSI_RESET}"
        )

    print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Show signature type distribution from .sig files."
    )
    parser.add_argument("sig", nargs="+", metavar="file.sig")
    parser.add_argument(
        "--top",
        type=int,
        default=30,
        metavar="N",
        help="Show only the top N types (default: 30)",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Show all types",
    )
    parser.add_argument(
        "--width",
        type=int,
        default=40,
        metavar="W",
        help="Bar width in characters (default: 40)",
    )
    args = parser.parse_args()

    combined: Counter = Counter()

    for path_str in args.sig:
        path = Path(path_str)
        try:
            stream = path.read_bytes()
        except OSError as exc:
            error("%s: %s", path_str, exc)
            raise SystemExit(1)

        counts = count_types(stream)
        info(
            "%s: %d records, %d unique types",
            path.name,
            sum(counts.values()),
            len(counts),
        )

        if len(args.sig) > 1:
            print_chart(counts, args.top, args.width, f"[{path.name}]")

        combined += counts

    if len(args.sig) > 1:
        ok("Combined stats:")
        print_chart(combined, None if args.all else args.top, args.width, "[combined]")
    else:
        print_chart(combined, None if args.all else args.top, args.width, f"[{Path(args.sig[0]).name}]")


if __name__ == "__main__":
    main()
