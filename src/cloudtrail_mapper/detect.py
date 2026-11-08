"""Run detection rules over normalized events."""

from __future__ import annotations

from typing import Callable, Iterable

from .rules import ALL_RULES
from .schemas import Finding, NormalizedEvent

RuleFunction = Callable[[Iterable[NormalizedEvent]], list[Finding]]


def run_rules(
    events: Iterable[NormalizedEvent],
    rules: dict[str, RuleFunction] | None = None,
) -> list[Finding]:
    """Run every rule (or the given ones) and return findings sorted by time."""
    events = sorted(events, key=lambda e: e.event_time)  # never trust file order
    rules = ALL_RULES if rules is None else rules
    findings: list[Finding] = []
    for detect in rules.values():
        findings.extend(detect(events))
    return sorted(findings, key=lambda f: (f.first_seen, f.rule_id))
