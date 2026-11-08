"""Data shapes used throughout the pipeline.

This module contains no processing logic. It only describes what a
normalized event, a validation issue, and a load result look like, so the
rest of the code (and later the detection rules) can rely on them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal

# Fields a record MUST have to be usable. Without them we cannot say what
# happened (eventName), in which service (eventSource), or when (eventTime).
REQUIRED_FIELDS: tuple[str, ...] = ("eventTime", "eventName", "eventSource")

Severity = Literal["error", "warning"]


@dataclass
class ValidationIssue:
    """One problem found while loading or normalizing.

    severity:
        "error"   -> the record (or whole file) was skipped.
        "warning" -> the record was kept, but something looked wrong.
    """

    severity: Severity
    message: str
    source_file: str | None = None
    record_index: int | None = None  # position in the Records array (0-based)
    event_id: str | None = None

    def __str__(self) -> str:
        location = self.source_file or "<unknown file>"
        if self.record_index is not None:
            location += f" record #{self.record_index}"
        if self.event_id:
            location += f" (eventID={self.event_id})"
        return f"[{self.severity.upper()}] {location}: {self.message}"


@dataclass
class NormalizedEvent:
    """A cleaned-up CloudTrail event with consistent types and formats."""

    # --- Required (always present) ---
    event_time: datetime  # timezone-aware, always UTC
    event_name: str  # API name, e.g. "ConsoleLogin" (case preserved)
    event_source: str  # lowercase, e.g. "signin.amazonaws.com"
    service: str  # short service name, e.g. "signin"

    # --- Optional (None when missing in the original record) ---
    event_id: str | None = None
    aws_region: str | None = None
    source_ip: str | None = None
    source_is_aws_service: bool = False  # True for e.g. "ec2.amazonaws.com"
    user_agent: str | None = None
    identity_type: str | None = None  # IAMUser, AssumedRole, Root, ...
    identity_name: str | None = None  # best human-readable name we can find
    identity_arn: str | None = None
    identity_account_id: str | None = None
    recipient_account_id: str | None = None
    error_code: str | None = None
    error_message: str | None = None
    read_only: bool | None = None
    event_type: str | None = None

    # --- Where it came from (useful for explaining findings later) ---
    source_file: str | None = None
    record_index: int | None = None

    # The original record, kept for reference. Excluded from repr/compare
    # so printing an event stays readable.
    raw: dict[str, Any] = field(default_factory=dict, repr=False, compare=False)


@dataclass
class LoadResult:
    """Everything the pipeline produced: usable events plus all issues."""

    events: list[NormalizedEvent] = field(default_factory=list)
    issues: list[ValidationIssue] = field(default_factory=list)
    files_read: int = 0
    records_seen: int = 0

    @property
    def errors(self) -> list[ValidationIssue]:
        return [i for i in self.issues if i.severity == "error"]

    @property
    def warnings(self) -> list[ValidationIssue]:
        return [i for i in self.issues if i.severity == "warning"]


# ---------------------------------------------------------------------------
# Detection output
# ---------------------------------------------------------------------------

Level = Literal["low", "medium", "high"]

FINDING_DISCLAIMER = (
    "A match means this activity deserves review. It does not prove malicious intent."
)


@dataclass
class EventRef:
    """Points back to the exact record a finding is based on.

    eventID alone is not enough: some records have none, so we also keep the
    file and position (the same key used in data/labels/ground_truth.csv).
    """

    source_file: str | None
    record_index: int | None
    event_id: str | None


@dataclass
class Finding:
    """One result produced by a detection rule, with the evidence behind it."""

    rule_id: str  # stable identifier, also used in ground_truth.csv
    rule_name: str  # human-readable name
    title: str  # one-line summary of what happened
    severity: Level  # potential impact IF the activity were misused
    severity_reason: str
    confidence: Level  # how strongly the evidence suggests it is not routine
    confidence_reason: str
    first_seen: datetime
    last_seen: datetime
    identity: str | None  # who performed the activity
    event_ids: list[str]  # eventIDs involved (records without one are omitted)
    event_refs: list[EventRef]  # every record involved, including ones without eventID
    reasons: list[str]  # plain-language reasons the rule triggered
    evidence: dict[str, Any]  # the CloudTrail values the decision was based on
    benign_explanations: list[str]  # common legitimate reasons for this activity
    # MITRE ATT&CK mapping is intentionally empty until it has been verified
    # against the official ATT&CK knowledge base in a later milestone.
    mitre_attack: list[dict[str, str]] = field(default_factory=list)
    mitre_status: str = "not_mapped"
    disclaimer: str = FINDING_DISCLAIMER
