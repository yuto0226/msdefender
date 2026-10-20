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
import sys
from pathlib import Path

# Force UTF-8 on Windows
if sys.platform == "win32":
    for stream in (sys.stdout, sys.stderr):
        if reconfigure := getattr(stream, "reconfigure", None):
            reconfigure(encoding="utf-8", errors="replace")

from lib.debug import (
    ANSI_BOLD,
    ANSI_BWHITE,
    ANSI_CYAN,
    ANSI_GRAY,
    ANSI_MAGENTA,
    ANSI_RESET,
    ANSI_WHITE,
    ANSI_YELLOW,
    error,
    info,
)
from lib.terminal import RenderContext
from lib.utils import iter_records_from_file, iter_records_with_context
from lib.vdm import decode_record
from lib.vdm import type_name as _type_name
from lib.vdm.types.hstr import HSTR_SPECS
from lib.vdm.types.threat import parse_threat_begin, threat_category_name

HSTR_RECORD_TYPES = frozenset(spec.type_byte for spec in HSTR_SPECS)
SEP_W = 72


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
                and filter_type not in HSTR_RECORD_TYPES
            ):
                name_part = f"── {threat_name} "
                line = name_part + "─" * max(0, SEP_W - len(name_part))
                print(f"\n{ANSI_GRAY}{line}{ANSI_RESET}")
                prev_threat = threat_name
            continue

        seq_total += 1
        record = decode_record(type_byte, payload)
        sys.stdout.write(
            record.render(
                RenderContext(
                    sequence=seq_total,
                    threat_name=threat_name,
                    show_hex=show_hex,
                    show_threat_heading=threat_name != last_hstr_threat,
                )
            )
        )
        if type_byte in HSTR_RECORD_TYPES:
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
