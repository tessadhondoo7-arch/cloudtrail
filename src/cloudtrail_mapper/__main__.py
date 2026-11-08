"""Run the loading pipeline from the command line.

Usage:
    python -m cloudtrail_mapper data/synthetic
    python -m cloudtrail_mapper path/to/file.json --show 10
"""

from __future__ import annotations

import argparse
import sys

from .detect import run_rules
from .loader import load_events
from .schemas import FINDING_DISCLAIMER, Finding


def print_finding(number: int, f: Finding) -> None:
    refs = ", ".join(f"{r.event_id or '(no eventID)'}" for r in f.event_refs)
    print(f"\n[{number}] {f.severity.upper()} severity / {f.confidence} confidence  |  {f.rule_id}")
    print(f"    {f.title}")
    print(f"    time:       {f.first_seen.isoformat()}")
    print(f"    events:     {refs}")
    print(f"    source ip:  {f.evidence.get('source_ip')}")
    print("    why it triggered:")
    for reason in f.reasons:
        print(f"      - {reason}")
    print(f"    severity:   {f.severity_reason}")
    print(f"    confidence: {f.confidence_reason}")
    print(f"    MITRE ATT&CK: {f.mitre_status}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cloudtrail_mapper",
        description="Load and validate local CloudTrail JSON files (no AWS access needed).",
    )
    parser.add_argument("paths", nargs="+", help="CloudTrail JSON files or directories")
    parser.add_argument("--show", type=int, default=5, help="number of events to print (default: 5)")
    parser.add_argument("--detect", action="store_true", help="run detection rules and print findings")
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

    if args.detect:
        findings = run_rules(result.events)
        print(f"\n=== Findings: {len(findings)} ===")
        print(f"Note: {FINDING_DISCLAIMER}")
        for number, finding in enumerate(findings, start=1):
            print_finding(number, finding)
        if findings:
            print("\nCommon benign explanations (per rule):")
            for rule_id in sorted({f.rule_id for f in findings}):
                example = next(f for f in findings if f.rule_id == rule_id)
                print(f"  {rule_id}:")
                for text in example.benign_explanations:
                    print(f"    - {text}")

    # Exit code 1 only if nothing at all could be loaded and something went wrong.
    return 1 if not result.events and result.errors else 0


if __name__ == "__main__":
    sys.exit(main())
