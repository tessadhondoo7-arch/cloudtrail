"""Validate raw CloudTrail records and convert them into NormalizedEvent objects.

Design rule: a bad record must never crash the program. Every problem is
recorded as a ValidationIssue and processing continues with the next record.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from typing import Any

from .schemas import REQUIRED_FIELDS, NormalizedEvent, ValidationIssue

# Region names look like "us-east-1", "eu-west-2", "us-gov-west-1", "cn-north-1".
_REGION_PATTERN = re.compile(r"^[a-z]{2}(-[a-z]+)+-\d+$")


# ---------------------------------------------------------------------------
# Small helpers: each one normalizes a single field
# ---------------------------------------------------------------------------

def _clean_str(value: Any) -> str | None:
    """Return a stripped string, or None if the value is missing/blank/not text."""
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value or None


def parse_timestamp(value: Any) -> datetime | None:
    """Parse a CloudTrail eventTime into a timezone-aware UTC datetime.

    Accepts "2026-01-15T10:00:00Z", fractional seconds, and explicit offsets
    such as "+02:00" (converted to UTC). Returns None if it cannot be parsed.
    """
    text = _clean_str(value)
    if text is None:
        return None
    # Python 3.10's fromisoformat() does not understand the trailing "Z".
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        # CloudTrail times are always UTC; treat a missing zone as UTC.
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def normalize_source_ip(value: Any) -> tuple[str | None, bool, str | None]:
    """Normalize sourceIPAddress.

    Returns (normalized_value, is_aws_service, warning_message_or_None).

    CloudTrail puts either a real IP address here, or the name of an AWS
    service (e.g. "ec2.amazonaws.com", "AWS Internal") when a service acted
    on your behalf.
    """
    text = _clean_str(value)
    if text is None:
        return None, False, None
    try:
        # str(ip_address(...)) gives a canonical form, e.g. compresses IPv6.
        return str(ipaddress.ip_address(text)), False, None
    except ValueError:
        pass
    lowered = text.lower()
    if lowered.endswith(".amazonaws.com") or lowered == "aws internal":
        return text, True, None
    return text, False, f"sourceIPAddress {text!r} is neither an IP address nor an AWS service name"


def normalize_region(value: Any) -> tuple[str | None, str | None]:
    """Lowercase and validate awsRegion. Returns (region, warning_or_None)."""
    text = _clean_str(value)
    if text is None:
        return None, None
    region = text.lower()
    if not _REGION_PATTERN.match(region):
        return region, f"awsRegion {text!r} does not look like a valid AWS region"
    return region, None


def service_from_event_source(event_source: str) -> str:
    """'iam.amazonaws.com' -> 'iam'."""
    return event_source.split(".", 1)[0]


def normalize_identity(user_identity: Any) -> dict[str, str | None]:
    """Extract who performed the action from the userIdentity block.

    Different identity types store the useful name in different places,
    so we pick the best available one.
    """
    result: dict[str, str | None] = {
        "identity_type": None,
        "identity_name": None,
        "identity_arn": None,
        "identity_account_id": None,
    }
    if not isinstance(user_identity, dict):
        return result

    identity_type = _clean_str(user_identity.get("type"))
    arn = _clean_str(user_identity.get("arn"))
    result["identity_type"] = identity_type
    result["identity_arn"] = arn
    result["identity_account_id"] = _clean_str(user_identity.get("accountId"))

    name: str | None = None
    if identity_type == "Root":
        name = "root"
    elif identity_type == "AssumedRole":
        # The role name lives in sessionContext.sessionIssuer.userName.
        session = user_identity.get("sessionContext")
        issuer = session.get("sessionIssuer") if isinstance(session, dict) else None
        if isinstance(issuer, dict):
            name = _clean_str(issuer.get("userName"))
    elif identity_type == "AWSService":
        name = _clean_str(user_identity.get("invokedBy"))

    # Fallbacks, in order of usefulness.
    name = (
        name
        or _clean_str(user_identity.get("userName"))
        or (arn.rsplit("/", 1)[-1] if arn and "/" in arn else None)
        or _clean_str(user_identity.get("principalId"))
    )
    result["identity_name"] = name
    return result


def _parse_read_only(value: Any) -> bool | None:
    """readOnly is usually a bool, but tolerate "true"/"false" strings."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in ("true", "false"):
        return value.strip().lower() == "true"
    return None


# ---------------------------------------------------------------------------
# One record
# ---------------------------------------------------------------------------

def normalize_record(
    record: Any,
    record_index: int | None = None,
    source_file: str | None = None,
) -> tuple[NormalizedEvent | None, list[ValidationIssue]]:
    """Validate and normalize one raw record.

    Returns (event, issues). event is None when the record had to be skipped.
    """
    issues: list[ValidationIssue] = []

    def issue(severity: str, message: str, event_id: str | None = None) -> None:
        issues.append(ValidationIssue(severity, message, source_file, record_index, event_id))

    # 1. The record itself must be a JSON object.
    if not isinstance(record, dict):
        issue("error", f"record is a {type(record).__name__}, expected a JSON object; skipped")
        return None, issues

    event_id = _clean_str(record.get("eventID"))

    # 2. Required fields must be present, non-empty strings.
    missing = [f for f in REQUIRED_FIELDS if _clean_str(record.get(f)) is None]
    if missing:
        issue("error", f"missing or empty required field(s): {', '.join(missing)}; skipped", event_id)
        return None, issues

    # 3. The timestamp must be parseable.
    event_time = parse_timestamp(record["eventTime"])
    if event_time is None:
        issue("error", f"unparseable eventTime {record['eventTime']!r}; skipped", event_id)
        return None, issues

    # From here on the record is usable; problems below are only warnings.
    if event_id is None:
        issue("warning", "missing eventID; duplicates of this record cannot be detected")

    event_source = _clean_str(record["eventSource"]).lower()

    region, region_warning = normalize_region(record.get("awsRegion"))
    if region_warning:
        issue("warning", region_warning, event_id)

    source_ip, is_service, ip_warning = normalize_source_ip(record.get("sourceIPAddress"))
    if ip_warning:
        issue("warning", ip_warning, event_id)

    if "userIdentity" in record and not isinstance(record["userIdentity"], dict):
        issue("warning", "userIdentity is not a JSON object; identity fields left empty", event_id)

    event = NormalizedEvent(
        event_time=event_time,
        # API names are case-sensitive (e.g. "GetObject"), so only strip spaces.
        event_name=_clean_str(record["eventName"]),
        event_source=event_source,
        service=service_from_event_source(event_source),
        event_id=event_id,
        aws_region=region,
        source_ip=source_ip,
        source_is_aws_service=is_service,
        user_agent=_clean_str(record.get("userAgent")),
        recipient_account_id=_clean_str(record.get("recipientAccountId")),
        error_code=_clean_str(record.get("errorCode")),
        error_message=_clean_str(record.get("errorMessage")),
        read_only=_parse_read_only(record.get("readOnly")),
        event_type=_clean_str(record.get("eventType")),
        source_file=source_file,
        record_index=record_index,
        raw=record,
        **normalize_identity(record.get("userIdentity")),
    )
    return event, issues


# ---------------------------------------------------------------------------
# Many records
# ---------------------------------------------------------------------------

def normalize_records(
    records: list[Any],
    source_file: str | None = None,
) -> tuple[list[NormalizedEvent], list[ValidationIssue]]:
    """Normalize every record in a list, collecting all issues."""
    events: list[NormalizedEvent] = []
    issues: list[ValidationIssue] = []
    for index, record in enumerate(records):
        event, record_issues = normalize_record(record, index, source_file)
        issues.extend(record_issues)
        if event is not None:
            events.append(event)
    return events, issues


def deduplicate(
    events: list[NormalizedEvent],
) -> tuple[list[NormalizedEvent], list[ValidationIssue]]:
    """Remove events whose eventID was already seen. The first one wins.

    CloudTrail can deliver the same event more than once, so exact duplicates
    are expected and only produce a warning. Two *different* records sharing
    an eventID are suspicious data quality problems and are reported as such.
    Events without an eventID are always kept.
    """
    seen: dict[str, NormalizedEvent] = {}
    kept: list[NormalizedEvent] = []
    issues: list[ValidationIssue] = []

    for event in events:
        if event.event_id is None:
            kept.append(event)
            continue
        first = seen.get(event.event_id)
        if first is None:
            seen[event.event_id] = event
            kept.append(event)
            continue

        first_location = f"{first.source_file} record #{first.record_index}"
        if event.raw == first.raw:
            message = f"exact duplicate of {first_location}; skipped"
        else:
            message = f"duplicate eventID with DIFFERENT content than {first_location}; skipped (first kept)"
        issues.append(
            ValidationIssue("warning", message, event.source_file, event.record_index, event.event_id)
        )
    return kept, issues
