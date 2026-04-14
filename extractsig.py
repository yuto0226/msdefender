#!/usr/bin/env python3
"""
extractsig.py - Extract individual signatures from a Microsoft Defender .sig file.

Usage:
    python extractsig.py <file.sig>              # analyse only (no files written)
    python extractsig.py <file.sig> -o ./out/    # extract to output directory
    python extractsig.py mpas.sig -n 50          # show up to 50 threats in analyse mode
    python extractsig.py mpas.sig -o ./out/ --no-orphans
"""

from __future__ import annotations

import argparse
import io
import re
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
    ANSI_YELLOW,
    ANSI_GRAY,
    ANSI_WHITE,
    ANSI_BWHITE,
    ok,
    info,
    warn,
    error,
)

# ─── Constants ────────────────────────────────────────────────────────────── #

SIG_THREAT_BEGIN = 0x5C
SIG_THREAT_END = 0x5D

# Minimal set needed here; the full table is in sigstats.py
TYPE_NAMES: dict[int, str] = {
    0x01: "RESERVED",
    0x02: "VOLATILE_THREAT_INFO",
    0x03: "VOLATILE_THREAT_ID",
    0x11: "CKOLDREC",
    0x20: "KVIR32",
    0x21: "POLYVIR32",
    0x27: "NSCRIPT_NORMAL",
    0x28: "NSCRIPT_SP",
    0x29: "NSCRIPT_BRUTE",
    0x2C: "NSCRIPT_CURE",
    0x30: "TITANFLT",
    0x3D: "PEFILE_CURE",
    0x3E: "MAC_CURE",
    0x40: "SIGTREE",
    0x41: "SIGTREE_EXT",
    0x42: "MACRO_PCODE",
    0x43: "MACRO_SOURCE",
    0x44: "BOOT",
    0x49: "CLEANSCRIPT",
    0x4A: "TARGET_SCRIPT",
    0x50: "CKSIMPLEREC",
    0x51: "PATTMATCH",
    0x53: "RPFROUTINE",
    0x55: "NID",
    0x56: "GENSFX",
    0x57: "UNPLIB",
    0x58: "DEFAULTS",
    0x5B: "DBVAR",
    0x5C: "THREAT_BEGIN",
    0x5D: "THREAT_END",
    0x5E: "FILENAME",
    0x5F: "FILEPATH",
    0x60: "FOLDERNAME",
    0x61: "PEHSTR",
    0x62: "LOCALHASH",
    0x63: "REGKEY",
    0x64: "HOSTSENTRY",
    0x67: "STATIC",
    0x69: "LATENT_THREAT",
    0x6A: "REMOVAL_POLICY",
    0x6B: "WVT_EXCEPTION",
    0x6C: "REVOKED_CERTIFICATE",
    0x70: "TRUSTED_PUBLISHER",
    0x71: "ASEP_FILEPATH",
    0x73: "DELTA_BLOB",
    0x74: "DELTA_BLOB_RECINFO",
    0x75: "ASEP_FOLDERNAME",
    0x77: "PATTMATCH_V2",
    0x78: "PEHSTR_EXT",
    0x79: "VDLL_X86",
    0x7A: "VERSIONCHECK",
    0x7B: "SAMPLE_REQUEST",
    0x7C: "VDLL_X64",
    0x7E: "SNID",
    0x7F: "FOP",
    0x80: "KCRCE",
    0x83: "VFILE",
    0x84: "SIGFLAGS",
    0x85: "PEHSTR_EXT2",
    0x86: "PEMAIN_LOCATOR",
    0x87: "PESTATIC",
    0x88: "UFSP_DISABLE",
    0x89: "FOPEX",
    0x8A: "PEPCODE",
    0x8B: "IL_PATTERN",
    0x8C: "ELFHSTR_EXT",
    0x8D: "MACHOHSTR_EXT",
    0x8E: "DOSHSTR_EXT",
    0x8F: "MACROHSTR_EXT",
    0x90: "TARGET_SCRIPT_PCODE",
    0x91: "VDLL_ARM64",
    0x92: "ASCRIPTHSTR_EXT",
    0x95: "PEBMPAT",
    0x96: "AAGGREGATOR",
    0x97: "SAMPLE_REQUEST_BY_NAME",
    0x98: "REMOVAL_POLICY_BY_NAME",
    0x99: "TUNNEL_X86",
    0x9A: "TUNNEL_X64",
    0x9B: "TUNNEL_ARM64",
    0x9C: "VDLL_ARM",
    0x9D: "THREAD_X86",
    0x9E: "THREAD_X64",
    0x9F: "THREAD_ARM64",
    0xA0: "FRIENDLYFILE_SHA256",
    0xA1: "FRIENDLYFILE_SHA512",
    0xA2: "SHARED_THREAT",
    0xA3: "VDM_METADATA",
    0xA4: "VSTORE",
    0xA5: "VDLL_SYMINFO",
    0xA6: "IL2_PATTERN",
    0xA7: "BM_STATIC",
    0xA8: "BM_INFO",
    0xA9: "NDAT",
    0xAA: "FASTPATH_DATA",
    0xAB: "FASTPATH_SDN",
    0xAC: "DATABASE_CERT",
    0xAD: "SOURCE_INFO",
    0xAE: "HIDDEN_FILE",
    0xAF: "COMMON_CODE",
    0xB0: "VREG",
    0xB1: "NISBLOB",
    0xB2: "VFILEEX",
    0xB3: "SIGTREE_BM",
    0xB4: "VBFOP",
    0xB5: "VDLL_META",
    0xB6: "TUNNEL_ARM",
    0xB7: "THREAD_ARM",
    0xB8: "PCODEVALIDATOR",
    0xBA: "MSILFOP",
    0xBB: "KPAT",
    0xBC: "KPATEX",
    0xBD: "LUASTANDALONE",
    0xBE: "DEXHSTR_EXT",
    0xBF: "JAVAHSTR_EXT",
    0xC0: "MAGICCODE",
    0xC1: "CLEANSTORE_RULE",
    0xC2: "VDLL_CHECKSUM",
    0xC3: "THREAT_UPDATE_STATUS",
    0xC4: "VDLL_MSIL",
    0xC5: "ARHSTR_EXT",
    0xC6: "MSILFOPEX",
    0xC7: "VBFOPEX",
    0xC8: "FOP64",
    0xC9: "FOPEX64",
    0xCA: "JSINIT",
    0xCB: "PESTATICEX",
    0xCC: "KCRCEX",
    0xCD: "FTRIE_POS",
    0xCE: "NID64",
    0xCF: "MACRO_PCODE64",
    0xD0: "BRUTE",
    0xD1: "SWFHSTR_EXT",
    0xD2: "REWSIGS",
    0xD3: "AUTOITHSTR_EXT",
    0xD4: "INNOHSTR_EXT",
    0xD5: "CERT_STORE_ENTRY",
    0xD6: "EXPLICITRESOURCE",
    0xD7: "CMDHSTR_EXT",
    0xD8: "FASTPATH_TDN",
    0xD9: "EXPLICITRESOURCEHASH",
    0xDA: "FASTPATH_SDN_EX",
    0xDB: "BLOOM_FILTER",
    0xDC: "RESEARCH_TAG",
    0xDE: "ENVELOPE",
    0xDF: "REMOVAL_POLICY64",
    0xE0: "REMOVAL_POLICY64_BY_NAME",
    0xE1: "VDLL_META_X64",
    0xE2: "VDLL_META_ARM",
    0xE3: "VDLL_META_MSIL",
    0xE4: "MDBHSTR_EXT",
    0xE5: "SNIDEX",
    0xE6: "SNIDEX2",
    0xE7: "AAGGREGATOREX",
    0xE8: "PUA_APPMAP",
    0xE9: "PROPERTY_BAG",
    0xEA: "DMGHSTR_EXT",
    0xEB: "DATABASE_CATALOG",
    0xEC: "DATABASE_CERT2",
    0xED: "BM_ENV_VAR_MAP",
    0xEE: "DATABASE_CERT3",
    0xEF: "ARHSTR_POSIX_EXT",
}


def fmt_type(type_byte: int) -> str:
    return TYPE_NAMES.get(type_byte, f"TYPE_0x{type_byte:02X}")


# ─── Record I/O ───────────────────────────────────────────────────────────── #
def iter_records(stream: bytes):
    """Yield (type_byte, payload_bytes) for every record in the stream.

    Record wire format:
        [type: 1B] [size: 3B LE] [payload: size B]

    Special case: size == 0xFFFFFF means read an additional 4-byte LE uint32
    as the real payload length (payload starts 8 bytes after record start).
    """
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


def encode_record(type_byte: int, payload: bytes) -> bytes:
    """Re-encode a (type, payload) pair back into wire-format bytes.

    This lets output .sig files remain parseable by sigstats.py and other tools
    that consume the same format.
    """
    size = len(payload)
    if size < 0xFFFFFF:
        return bytes([type_byte]) + size.to_bytes(3, "little") + payload
    else:
        return (
            bytes([type_byte]) + b"\xff\xff\xff" + size.to_bytes(4, "little") + payload
        )


# ─── Threat name extraction ────────────────────────────────────────────────── #
def parse_threat_name(payload: bytes) -> str:
    """Extract the human-readable threat name from a THREAT_BEGIN (0x5C) payload.

    Confirmed payload layout (RE of threat_info_receiver @ 0x1809EB590):

        Offset   Size   Field
        ───────  ─────  ──────────────────────────────────────────────────────
        +0x00    4      threat_id      (LE uint32) → dword_18127F9A8
        +0x04    2      dep_count      (LE uint16) number of 4-byte dep IDs
        +0x06    2      ext_count      (LE uint16) number of 2-byte ext entries
        +0x08    2      category       (LE uint16) 0x0B=generic, 0x0C=monitool
        +0x0A    2      name_len       (LE uint16) byte count of name_obj[]
        +0x0C    n      name_obj[]     n = name_len bytes:
                          if name_obj[0] >= 0x80 → internal category marker (skip)
                                        else      → first char of display name
                          remainder: ASCII/UTF-8, NOT null-terminated in these n bytes
        +0x0C+n  2      post_name_pad  = 0x0000 (null terminator lives here)
        …               dep_ids[], ext_entries[], trailing 6-byte metadata

    Full struct documented in docs/signature_payload_formats.md §4.1.
    """
    # Minimum payload size check (confirmed: cmp rdi, 0Ch @ 0x1809EB66A)
    if len(payload) < 0x0C:
        tid = int.from_bytes(payload[:4], "little") if len(payload) >= 4 else 0
        return f"threat_{tid:08x}"

    name_len = int.from_bytes(payload[0x0A:0x0C], "little")

    if name_len == 0 or 0x0C + name_len > len(payload):
        tid = int.from_bytes(payload[:4], "little")
        return f"threat_{tid:08x}"

    raw = payload[0x0C : 0x0C + name_len]

    # name_obj may start with 0, 1, or 2 bytes >= 0x80 (internal category/encoding
    # markers).  Skip all of them; the display name begins at the first byte < 0x80.
    # Observed: 0xF4 (1 byte) for "!Aconti"-style names,
    #           0xC0 0xE1 (2 bytes) for "WsTunnel.A"-style names,
    #           no prefix for "MonitoringTool:Win32/..."-style names.
    while raw and raw[0] >= 0x80:
        raw = raw[1:]

    # name_str is NOT null-terminated within name_len bytes (null lives in post_name_pad).
    # Guard against malformed payloads with an embedded null.
    null_pos = raw.find(b"\x00")
    if null_pos != -1:
        raw = raw[:null_pos]

    name = raw.decode("utf-8", errors="replace").strip()
    if not name:
        tid = int.from_bytes(payload[:4], "little")
        return f"threat_{tid:08x}"
    return name


# ─── Stream partitioning ──────────────────────────────────────────────────── #
# A Threat groups the THREAT_BEGIN record, all interior records, and the
# THREAT_END record so they can be written out as a self-contained .sig file.
type Threat = tuple[str, list[tuple[int, bytes]]]  # (name, [(type, payload), ...])
type Record = tuple[int, bytes]  # (type_byte, payload)


def partition_stream(stream: bytes) -> tuple[list[Threat], list[Record]]:
    """Single-pass split of the stream into threat blocks and orphan records.

    Returns:
        threats  - list of (name, records) where records includes the
                   THREAT_BEGIN and THREAT_END entries.
        orphans  - records that appear outside any THREAT_BEGIN / THREAT_END
                   bracket.
    """
    threats: list[Threat] = []
    orphans: list[Record] = []

    in_block = False
    current_name = ""
    current_recs: list[Record] = []

    for type_byte, payload in iter_records(stream):
        if type_byte == SIG_THREAT_BEGIN:
            if in_block:
                # Unclosed previous block — emit what we have so far
                warn(
                    "THREAT_BEGIN without matching THREAT_END before '%s'; flushing",
                    current_name,
                )
                threats.append((current_name, current_recs))
            current_name = parse_threat_name(payload)
            current_recs = [(type_byte, payload)]
            in_block = True

        elif type_byte == SIG_THREAT_END:
            if in_block:
                current_recs.append((type_byte, payload))
                threats.append((current_name, current_recs))
            else:
                warn("THREAT_END without preceding THREAT_BEGIN — skipping")
            in_block = False
            current_name = ""
            current_recs = []

        else:
            if in_block:
                current_recs.append((type_byte, payload))
            else:
                orphans.append((type_byte, payload))

    if in_block:
        warn("Unterminated THREAT_BEGIN for '%s' at end of stream", current_name)
        threats.append((current_name, current_recs))

    return threats, orphans


# ─── Name sanitisation ────────────────────────────────────────────────────── #
_UNSAFE_CHARS = re.compile(r'[\\/:*?"<>|\x00-\x1f]')


def sanitize_name(name: str) -> str:
    """Replace filesystem-unsafe characters with underscores."""
    sanitized = _UNSAFE_CHARS.sub("_", name)
    # Collapse multiple consecutive underscores that would look ugly
    sanitized = re.sub(r"_+", "_", sanitized).strip("_")
    return sanitized or "unnamed"


# ─── Analyse mode ─────────────────────────────────────────────────────────── #
def _human_size(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def print_analysis(
    path: Path,
    threats: list[Threat],
    orphans: list[Record],
    max_threats: int,
) -> None:
    stream_size = path.stat().st_size
    total_recs = sum(len(recs) for _, recs in threats) + len(orphans)
    orphan_type_counts: Counter[int] = Counter(t for t, _ in orphans)

    sep = f"{ANSI_GRAY}{'─' * 72}{ANSI_RESET}"

    print(f"\n{ANSI_BOLD}{ANSI_BWHITE}[{path.name}]{ANSI_RESET}")
    print(sep)
    print(f"  {ANSI_GRAY}file size   :{ANSI_RESET} {_human_size(stream_size)}")
    print(f"  {ANSI_GRAY}total recs  :{ANSI_RESET} {total_recs:,}")
    print(f"  {ANSI_GRAY}threats     :{ANSI_RESET} {len(threats):,}")
    print(
        f"  {ANSI_GRAY}orphan recs :{ANSI_RESET} {len(orphans):,} "
        f"({len(orphan_type_counts)} unique types)"
    )
    print(sep)

    # ── Threat list ──
    shown = threats[:max_threats]
    print(
        f"\n{ANSI_BOLD}  Threats (first {len(shown)} of {len(threats):,}){ANSI_RESET}"
    )
    name_w = max((len(n) for n, _ in shown), default=4)
    for name, recs in shown:
        inner = [r for r in recs if r[0] not in (SIG_THREAT_BEGIN, SIG_THREAT_END)]
        type_ct = Counter(t for t, _ in inner)
        top3 = ", ".join(f"{fmt_type(t)} × {c}" for t, c in type_ct.most_common(3))
        print(
            f"    {ANSI_CYAN}{name:<{name_w}}{ANSI_RESET}"
            f"  {ANSI_GRAY}{len(inner):4d} sig(s){ANSI_RESET}"
            f"  {ANSI_WHITE}{top3}{ANSI_RESET}"
        )

    if len(threats) > max_threats:
        print(f"    {ANSI_GRAY}... {len(threats) - max_threats} more{ANSI_RESET}")

    # ── Orphan breakdown ──
    if orphans:
        print(f"\n{ANSI_BOLD}  Orphan record types{ANSI_RESET}")
        for type_byte, count in orphan_type_counts.most_common(10):
            print(
                f"    {ANSI_YELLOW}{fmt_type(type_byte):<32}{ANSI_RESET}"
                f"  {ANSI_GRAY}{count:,}{ANSI_RESET}"
            )
        if len(orphan_type_counts) > 10:
            print(
                f"    {ANSI_GRAY}... {len(orphan_type_counts) - 10} more types{ANSI_RESET}"
            )

    print()


# ─── Extract mode ─────────────────────────────────────────────────────────── #
def extract(
    path: Path,
    out_dir: Path,
    threats: list[Threat],
    orphans: list[Record],
    write_orphans: bool,
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    written_threats = 0
    name_seen: Counter[str] = Counter()

    for name, records in threats:
        safe = sanitize_name(name)
        name_seen[safe] += 1
        count = name_seen[safe]
        fname = f"{safe}.sig" if count == 1 else f"{safe}__{count}.sig"
        (out_dir / fname).write_bytes(b"".join(encode_record(t, p) for t, p in records))
        written_threats += 1

    written_orphans = 0
    if write_orphans and orphans:
        orphan_dir = out_dir / "__orphan__"
        orphan_dir.mkdir(exist_ok=True)
        seq_by_type: Counter[int] = Counter()

        for type_byte, payload in orphans:
            seq_by_type[type_byte] += 1
            fname = f"{fmt_type(type_byte)}_{seq_by_type[type_byte]:06d}.sig"
            (orphan_dir / fname).write_bytes(encode_record(type_byte, payload))
            written_orphans += 1

    ok(
        "wrote %d threat file(s) + %d orphan file(s) -> %s",
        written_threats,
        written_orphans,
        out_dir,
    )


# ─── CLI ──────────────────────────────────────────────────────────────────── #
def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Extract signatures from a Microsoft Defender .sig file.\n"
            "Without --output, analyse and print a summary to stdout.\n"
            "With --output, write one .sig file per threat (and optionally per orphan record)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("sig", metavar="file.sig", help="Input .sig file")
    parser.add_argument(
        "-o",
        "--output",
        metavar="DIR",
        help="Output directory. If omitted, only print analysis.",
    )
    parser.add_argument(
        "-n",
        type=int,
        default=20,
        metavar="N",
        dest="max_threats",
        help="Analysis mode: max threats to list (default: 20)",
    )
    parser.add_argument(
        "--no-orphans",
        action="store_true",
        help="Extract mode: skip orphan records outside any THREAT block",
    )
    args = parser.parse_args()

    path = Path(args.sig)
    try:
        stream = path.read_bytes()
    except OSError as exc:
        error("%s: %s", args.sig, exc)
        raise SystemExit(1)

    info("parsing %s (%s) ...", path.name, _human_size(len(stream)))
    threats, orphans = partition_stream(stream)
    info("found %d threats, %d orphan records", len(threats), len(orphans))

    print_analysis(path, threats, orphans, args.max_threats)

    if args.output is not None:
        extract(
            path,
            out_dir=Path(args.output),
            threats=threats,
            orphans=orphans,
            write_orphans=not args.no_orphans,
        )


if __name__ == "__main__":
    main()
