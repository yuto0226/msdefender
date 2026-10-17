#!/usr/bin/env python3
"""Extract Defender LUASTANDALONE records as integral Lua 5.1 chunks.

Without --output, validate matching records and print what can be exported.
With --output, write one .luac file per matching record.
"""

from __future__ import annotations

import argparse
import io
import re
import sys
from pathlib import Path

from lib.debug import error, info, ok, warn
from lib.utils import iter_records_with_context
from lib.vdm import LUASTANDALONE_TYPE, export_lua51, parse_lua_standalone

_UNSAFE_FILENAME_CHARS = re.compile(r'[\\/:*?"<>|\x00-\x1f]')
_MAX_NAME_PART = 80


def _safe_name_part(value: str, fallback: str) -> str:
    value = _UNSAFE_FILENAME_CHARS.sub("_", value)
    value = re.sub(r"_+", "_", value).strip(" ._")
    return (value or fallback)[:_MAX_NAME_PART].rstrip(" .") or fallback


def _output_name(sequence: int, threat_name: str, script_name: str | None) -> str:
    threat = _safe_name_part(threat_name, "orphan")
    script = _safe_name_part(script_name or "unnamed", "unnamed")
    return f"{sequence:06d}_{threat}__{script}.luac"


def _record_label(
    sequence: int,
    threat_name: str,
    sig_index: int,
    script_name: str | None,
    category_name: str | None,
) -> str:
    threat = threat_name or "<orphan>"
    script = script_name or "<unnamed>"
    category = category_name or "unknown category"
    return f"#{sequence} {threat} / record {sig_index} / {script} [{category}]"


def extract_lua(
    path: Path,
    *,
    output_dir: Path | None,
    threat_filter: str | None,
) -> int:
    matched = 0
    exported = 0
    failed = 0
    warning_count = 0
    normalized_filter = threat_filter.casefold() if threat_filter else None

    if output_dir is not None:
        try:
            output_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            error("%s: %s", output_dir, exc)
            return 1

    try:
        records = iter_records_with_context(path)
        for type_byte, payload, threat_name, sig_index in records:
            if type_byte != LUASTANDALONE_TYPE:
                continue
            if normalized_filter and normalized_filter not in threat_name.casefold():
                continue

            matched += 1
            try:
                parsed = parse_lua_standalone(payload)
                label = _record_label(
                    matched,
                    threat_name,
                    sig_index,
                    parsed.name,
                    parsed.category_name,
                )
                if parsed.lua_chunk is None:
                    if parsed.receiver_ignored:
                        reason = "category is ignored by the engine receiver"
                    elif parsed.script_form == "encoded":
                        reason = "encoded LuaQ is not decoded"
                    else:
                        reason = "category policy defers LuaQ parsing"
                    raise ValueError(reason)

                result = export_lua51(parsed.lua_chunk)
                warning_count += len(result.warnings)
                for export_warning in result.warnings:
                    warn("%s: %s", label, export_warning.message)

                if output_dir is None:
                    ok("%s: exportable (%d B)", label, len(result.data))
                else:
                    destination = output_dir / _output_name(
                        matched, threat_name, parsed.name
                    )
                    destination.write_bytes(result.data)
                    ok("%s -> %s (%d B)", label, destination, len(result.data))
                exported += 1
            except (OSError, ValueError) as exc:
                failed += 1
                error("#%d %s / record %d: %s", matched, threat_name, sig_index, exc)
    except OSError as exc:
        error("%s: %s", path, exc)
        return 1

    info(
        "matched=%d exportable=%d failed=%d warnings=%d",
        matched,
        exported,
        failed,
        warning_count,
    )
    if matched == 0:
        warn("no matching LUASTANDALONE records found")
    return 1 if failed else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sig", metavar="file.sig", help="Input .sig file")
    parser.add_argument(
        "-o",
        "--output",
        metavar="DIR",
        help="Write .luac files to DIR; omit to validate only",
    )
    parser.add_argument(
        "-T",
        "--threat",
        metavar="SUBSTR",
        help="Filter by threat name substring (case-insensitive)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    if sys.platform == "win32" and argv is None:
        sys.stdout = io.TextIOWrapper(
            sys.stdout.buffer, encoding="utf-8", errors="replace"
        )
        sys.stderr = io.TextIOWrapper(
            sys.stderr.buffer, encoding="utf-8", errors="replace"
        )

    args = build_parser().parse_args(argv)
    path = Path(args.sig)
    if not path.is_file():
        error("%s: file not found", path)
        return 1

    info("scanning %s", path)
    return extract_lua(
        path,
        output_dir=Path(args.output) if args.output is not None else None,
        threat_filter=args.threat,
    )


if __name__ == "__main__":
    raise SystemExit(main())
