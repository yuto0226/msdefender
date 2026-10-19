#!/usr/bin/env python3
"""Stream and extract individual signatures from a Microsoft Defender .sig."""

from __future__ import annotations

import argparse
import io
import re
import sys
from collections import Counter
from pathlib import Path

from lib.debug import (
    ANSI_BOLD,
    ANSI_BWHITE,
    ANSI_CYAN,
    ANSI_GRAY,
    ANSI_RESET,
    ANSI_WHITE,
    ANSI_YELLOW,
    error,
    info,
    ok,
    warn,
)
from lib.vdm.catalog import type_name
from lib.vdm.stream import (
    OrphanRecordEvent,
    ThreatBlock,
    ThreatBlockEvent,
    UnmatchedEndEvent,
    iter_threat_events,
)

if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")


def fmt_type(type_byte: int) -> str:
    name = type_name(type_byte)
    return f"TYPE_0x{type_byte:02X}" if name.startswith("TYPE_0x") else name


_UNSAFE_CHARS = re.compile(r'[\\/:*?"<>|\x00-\x1f]')


def sanitize_name(name: str) -> str:
    sanitized = re.sub(r"_+", "_", _UNSAFE_CHARS.sub("_", name)).strip("_")
    return sanitized or "unnamed"


def _human_size(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def _block_type_counts(block: ThreatBlock) -> Counter[int]:
    return Counter(record.type_byte for record in block.records)


def _write_block(out_dir: Path, block: ThreatBlock, names: Counter[str]) -> None:
    safe = sanitize_name(block.begin.name)
    names[safe] += 1
    index = names[safe]
    filename = f"{safe}.sig" if index == 1 else f"{safe}__{index}.sig"
    (out_dir / filename).write_bytes(block.to_bytes())


def _report_event(
    event: ThreatBlockEvent | OrphanRecordEvent | UnmatchedEndEvent,
) -> None:
    match event:
        case ThreatBlockEvent(block=block, reason="nested_begin"):
            warn(
                "THREAT_BEGIN without matching THREAT_END before '%s'; flushing",
                block.begin.name,
            )
        case ThreatBlockEvent(block=block, reason="unterminated"):
            warn(
                "Unterminated THREAT_BEGIN for '%s' at end of stream",
                block.begin.name,
            )
        case ThreatBlockEvent(block=block, reason="id_mismatch"):
            if block.end is not None:
                warn(
                    "THREAT_END ID mismatch for '%s': begin=%08X end=%08X",
                    block.begin.name,
                    block.begin.threat_id,
                    block.end.threat_id,
                )
        case UnmatchedEndEvent():
            warn("THREAT_END without preceding THREAT_BEGIN — skipping")


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Extract signatures from a Microsoft Defender .sig file.\n"
            "Without --output, analyse and print a summary to stdout.\n"
            "With --output, write one .sig file per threat and optionally per orphan."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("sig", metavar="file.sig", help="Input .sig file")
    parser.add_argument("-o", "--output", metavar="DIR", help="Output directory")
    parser.add_argument("-n", type=int, default=20, metavar="N", dest="max_threats")
    parser.add_argument("--no-orphans", action="store_true", help="Skip orphan records")
    args = parser.parse_args()
    path = Path(args.sig)
    try:
        stream_size = path.stat().st_size
        out_dir = Path(args.output) if args.output is not None else None
        if out_dir is not None:
            out_dir.mkdir(parents=True, exist_ok=True)
        info("parsing %s (%s) ...", path.name, _human_size(stream_size))

        threat_count = orphan_count = total_records = written_orphans = 0
        orphan_counts: Counter[int] = Counter()
        shown: list[tuple[str, int, Counter[int]]] = []
        name_seen: Counter[str] = Counter()
        orphan_seq: Counter[int] = Counter()

        for event in iter_threat_events(path):
            _report_event(event)
            match event:
                case ThreatBlockEvent(block=block):
                    threat_count += 1
                    total_records += (
                        len(block.records) + 1 + (block.end_record is not None)
                    )
                    counts = _block_type_counts(block)
                    if len(shown) < max(0, args.max_threats):
                        shown.append((block.begin.name, len(block.records), counts))
                    if out_dir is not None:
                        _write_block(out_dir, block, name_seen)
                case OrphanRecordEvent(record=record):
                    orphan_count += 1
                    total_records += 1
                    orphan_counts[record.type_byte] += 1
                    if out_dir is not None and not args.no_orphans:
                        orphan_seq[record.type_byte] += 1
                        orphan_dir = out_dir / "__orphan__"
                        orphan_dir.mkdir(exist_ok=True)
                        filename = f"{fmt_type(record.type_byte)}_{orphan_seq[record.type_byte]:06d}.sig"
                        (orphan_dir / filename).write_bytes(record.raw)
                        written_orphans += 1

        info("found %d threats, %d orphan records", threat_count, orphan_count)
    except (OSError, ValueError) as exc:
        error("%s: %s", args.sig, exc)
        raise SystemExit(1) from exc

    sep = f"{ANSI_GRAY}{'─' * 72}{ANSI_RESET}"
    print(f"\n{ANSI_BOLD}{ANSI_BWHITE}[{path.name}]{ANSI_RESET}")
    print(sep)
    print(f"  {ANSI_GRAY}file size   :{ANSI_RESET} {_human_size(stream_size)}")
    print(f"  {ANSI_GRAY}total recs  :{ANSI_RESET} {total_records:,}")
    print(f"  {ANSI_GRAY}threats     :{ANSI_RESET} {threat_count:,}")
    print(
        f"  {ANSI_GRAY}orphan recs :{ANSI_RESET} {orphan_count:,} ({len(orphan_counts)} unique types)"
    )
    print(sep)
    print(
        f"\n{ANSI_BOLD}  Threats (first {len(shown)} of {threat_count:,}){ANSI_RESET}"
    )
    name_width = max((len(name) for name, _, _ in shown), default=4)
    for name, inner_count, counts in shown:
        top3 = ", ".join(f"{fmt_type(t)} × {n}" for t, n in counts.most_common(3))
        print(
            f"    {ANSI_CYAN}{name:<{name_width}}{ANSI_RESET}  {ANSI_GRAY}{inner_count:4d} sig(s){ANSI_RESET}  {ANSI_WHITE}{top3}{ANSI_RESET}"
        )
    if threat_count > len(shown):
        print(f"    {ANSI_GRAY}... {threat_count - len(shown)} more{ANSI_RESET}")
    if orphan_count:
        print(f"\n{ANSI_BOLD}  Orphan record types{ANSI_RESET}")
        for type_byte, count in orphan_counts.most_common(10):
            print(
                f"    {ANSI_YELLOW}{fmt_type(type_byte):<32}{ANSI_RESET}  {ANSI_GRAY}{count:,}{ANSI_RESET}"
            )
        if len(orphan_counts) > 10:
            print(
                f"    {ANSI_GRAY}... {len(orphan_counts) - 10} more types{ANSI_RESET}"
            )
    print()
    if out_dir is not None:
        ok(
            "wrote %d threat file(s) + %d orphan file(s) -> %s",
            threat_count,
            written_orphans,
            out_dir,
        )


if __name__ == "__main__":
    main()
