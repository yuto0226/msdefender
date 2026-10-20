#!/usr/bin/env python3
"""Stream and extract individual signatures from a Microsoft Defender .sig."""

from __future__ import annotations

import argparse
import json
import os
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
from lib.vdm import decode_record, export_record_artifacts
from lib.vdm.catalog import type_name
from lib.vdm.stream import (
    OrphanRecordEvent,
    ThreatBlock,
    ThreatBlockEvent,
    UnmatchedEndEvent,
    WireRecord,
    iter_threat_events,
)
from lib.vdm.types.threat import threat_category_name

if sys.platform == "win32":
    for stream in (sys.stdout, sys.stderr):
        if reconfigure := getattr(stream, "reconfigure", None):
            reconfigure(encoding="utf-8", errors="replace")


def fmt_type(type_byte: int) -> str:
    name = type_name(type_byte)
    return f"TYPE_0x{type_byte:02X}" if name.startswith("TYPE_0x") else name


_UNSAFE_CHARS = re.compile(r'[\\/:*?"<>|\x00-\x1f]')
_MAX_NAME_PART = 120


def sanitize_name(name: str) -> str:
    sanitized = re.sub(r"_+", "_", _UNSAFE_CHARS.sub("_", name)).strip("_")
    sanitized = sanitized.rstrip(". ") or "unnamed"
    return sanitized[:_MAX_NAME_PART].rstrip(". ") or "unnamed"


def _category_dir(category: int) -> str:
    name = threat_category_name(category) or "Unknown"
    return f"0x{category:04X}_{sanitize_name(name)}"


def _threat_dir(out_dir: Path, block: ThreatBlock) -> Path:
    category_dir = out_dir / _category_dir(block.begin.category)
    category_dir.mkdir(parents=True, exist_ok=True)
    base = f"{block.begin.threat_id:08X}_{sanitize_name(block.begin.name)}"
    candidate = category_dir / base
    suffix = 2
    while candidate.exists():
        candidate = category_dir / f"{base}__{suffix}"
        suffix += 1
    candidate.mkdir()
    return candidate


def _record_manifest(record: WireRecord, index: int) -> dict[str, object]:
    return {
        "index": index,
        "type": record.type_byte,
        "type_hex": f"0x{record.type_byte:02X}",
        "type_name": fmt_type(record.type_byte),
        "offset": record.offset,
        "header_size": record.header_size,
        "payload_size": record.size,
        "wire_size": len(record.raw),
    }


def _manifest(
    block: ThreatBlock,
    reason: str | None,
    source_name: str,
    exports: list[dict[str, object]],
) -> dict[str, object]:
    begin = block.begin
    category_name = threat_category_name(begin.category)
    wire_metadata = begin.metadata
    effective = begin.effective_metadata
    end_record = block.end_record
    termination_reason = reason or "normal"
    return {
        "schema_version": 1,
        "source": source_name,
        "threat": {
            "threat_id": begin.threat_id,
            "threat_id_hex": f"0x{begin.threat_id:08X}",
            "name": begin.name,
            "category": {
                "value": begin.category,
                "hex": f"0x{begin.category:04X}",
                "name": category_name or "Unknown",
            },
            "dependencies": [
                {"threat_id": item, "hex": f"0x{item:08X}"}
                for item in begin.dependencies
            ],
            "ext_entries": list(begin.ext_entries),
            "post_name_zero": begin.post_name_zero,
        },
        "metadata": {
            "wire_present": wire_metadata is not None,
            "wire": (
                {
                    "short_description_id": wire_metadata.short_description_id,
                    "threat_advice_id": wire_metadata.threat_advice_id,
                    "severity": wire_metadata.severity,
                    "action": wire_metadata.action,
                }
                if wire_metadata is not None
                else None
            ),
            "effective": {
                "short_description_id": effective.short_description_id,
                "threat_advice_id": effective.threat_advice_id,
                "severity": effective.severity,
                "action": effective.action,
            },
        },
        "framing": {
            "begin": {
                "offset": block.begin_record.offset,
                "header_size": block.begin_record.header_size,
                "payload_size": block.begin_record.size,
                "wire_size": len(block.begin_record.raw),
            },
            "end_present": end_record is not None,
            "end": (
                {
                    "threat_id": block.end.threat_id,
                    "threat_id_hex": f"0x{block.end.threat_id:08X}",
                    "offset": end_record.offset,
                    "header_size": end_record.header_size,
                    "payload_size": end_record.size,
                    "wire_size": len(end_record.raw),
                }
                if block.end is not None and end_record is not None
                else None
            ),
            "id_matches": block.id_matches,
            "complete": (
                termination_reason == "normal"
                and end_record is not None
                and block.id_matches is True
            ),
            "termination_reason": termination_reason,
        },
        "records": [
            _record_manifest(record, index)
            for index, record in enumerate(block.records, start=1)
        ],
        "exports": exports,
    }


def _human_size(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def _block_type_counts(block: ThreatBlock) -> Counter[int]:
    return Counter(record.type_byte for record in block.records)


def _write_block(
    out_dir: Path, block: ThreatBlock, reason: str | None, source_name: str
) -> None:
    threat_dir = _threat_dir(out_dir, block)
    (threat_dir / "raw.sig").write_bytes(block.to_bytes())
    exports: list[dict[str, object]] = []
    for index, wire_record in enumerate(block.records, start=1):
        decoded = decode_record(wire_record.type_byte, wire_record.payload)
        result = export_record_artifacts(decoded)
        if result is None:
            continue
        entry: dict[str, object] = {
            "record_index": index,
            "type": wire_record.type_byte,
            "type_hex": f"0x{wire_record.type_byte:02X}",
            "type_name": fmt_type(wire_record.type_byte),
            "status": result.status,
            "artifacts": [],
        }
        if result.status == "ready":
            artifacts: list[dict[str, object]] = []
            type_part = sanitize_name(fmt_type(wire_record.type_byte))
            artifact_dir = (
                threat_dir
                / "artifacts"
                / (f"{index:06d}_{wire_record.type_byte:02X}_{type_part}")
            )
            artifact_dir.mkdir(parents=True, exist_ok=True)
            for artifact in result.artifacts:
                # Artifact names are validated by the model; exclusive creation
                # also prevents accidental overwrite within a record directory.
                destination = artifact_dir / artifact.name
                with destination.open("xb") as output:
                    output.write(artifact.data)
                artifacts.append(
                    {
                        "kind": artifact.kind,
                        "path": destination.relative_to(threat_dir).as_posix(),
                        "size": len(artifact.data),
                    }
                )
            entry["status"] = "exported"
            entry["artifacts"] = artifacts
        elif result.status == "unsupported":
            entry["reason"] = result.reason
        else:
            entry["error"] = result.error
        if result.warnings:
            entry["warnings"] = [
                {
                    "code": warning.code,
                    "message": warning.message,
                    "details": dict(warning.details),
                }
                for warning in result.warnings
            ]
        exports.append(entry)
    manifest_path = threat_dir / "manifest.json"
    temp_path = threat_dir / ".manifest.json.tmp"
    payload = (
        json.dumps(
            _manifest(block, reason, source_name, exports),
            ensure_ascii=False,
            indent=2,
        )
        + "\n"
    )
    temp_path.write_text(payload, encoding="utf-8", newline="\n")
    os.replace(temp_path, manifest_path)


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
            "With --output, write one directory per threat containing raw.sig and "
            "manifest.json; optionally write orphan .sig files."
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
        orphan_seq: Counter[int] = Counter()

        for event in iter_threat_events(path):
            _report_event(event)
            match event:
                case ThreatBlockEvent(block=block, reason=reason):
                    threat_count += 1
                    total_records += (
                        len(block.records) + 1 + (block.end_record is not None)
                    )
                    counts = _block_type_counts(block)
                    if len(shown) < max(0, args.max_threats):
                        shown.append((block.begin.name, len(block.records), counts))
                    if out_dir is not None:
                        _write_block(out_dir, block, reason, path.name)
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
            "wrote %d threat directories + %d orphan file(s) -> %s",
            threat_count,
            written_orphans,
            out_dir,
        )


if __name__ == "__main__":
    main()
