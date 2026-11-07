"""Run the loading pipeline from the command line.

Usage:
    python -m cloudtrail_mapper data/synthetic
    python -m cloudtrail_mapper path/to/file.json --show 10
"""

from __future__ import annotations

import argparse
import sys

from .loader import load_events


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cloudtrail_mapper",
        description="Load and validate local CloudTrail JSON files (no AWS access needed).",
    )
    parser.add_argument("paths", nargs="+", help="CloudTrail JSON files or directories")
    parser.add_argument("--show", type=int, default=5, help="number of events to print (default: 5)")
    args = parser.parse_args(argv)

    result = load_events(args.paths)

    print("=== Load summary ===")
    print(f"Files read:      {result.files_read}")
    print(f"Records seen:    {result.records_seen}")
    print(f"Events loaded:   {len(result.events)}")
    print(f"Errors:          {len(result.errors)}")
    print(f"Warnings:        {len(result.warnings)}")

    if result.issues:
        print("\n=== Issues ===")
        for issue in result.issues:
            print(issue)

    if result.events and args.show > 0:
        print(f"\n=== First {min(args.show, len(result.events))} events (sorted by time) ===")
        for e in sorted(result.events, key=lambda ev: ev.event_time)[: args.show]:
            print(
                f"{e.event_time.isoformat()}  {e.service}:{e.event_name}  "
                f"identity={e.identity_name}  ip={e.source_ip}  region={e.aws_region}"
            )

    # Exit code 1 only if nothing at all could be loaded and something went wrong.
    return 1 if not result.events and result.errors else 0


if __name__ == "__main__":
    sys.exit(main())
