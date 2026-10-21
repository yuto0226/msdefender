#!/usr/bin/env python3
"""Emit a machine-readable evidence inventory for one or more VDM .sig files."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from lib.vdm.inventory import build_semantic_inventory


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+", type=Path)
    parser.add_argument(
        "--sample-limit",
        type=int,
        default=64,
        help="distinct payload shapes per type; 0 exports every record",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="write JSON to this path instead of stdout",
    )
    args = parser.parse_args()

    try:
        inventory = build_semantic_inventory(
            args.paths,
            sample_limit_per_type=args.sample_limit,
        )
    except (OSError, ValueError) as error:
        print(f"semantic inventory failed: {error}", file=sys.stderr)
        return 2

    rendered = json.dumps(inventory, indent=2, ensure_ascii=False) + "\n"
    if args.output is None:
        sys.stdout.write(rendered)
    else:
        args.output.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
