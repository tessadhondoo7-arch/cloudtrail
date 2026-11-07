"""Tests for normalize.py: validating and cleaning individual records."""

from datetime import datetime, timezone

import pytest

from cloudtrail_mapper.normalize import (
    deduplicate,
    normalize_identity,
    normalize_record,
    normalize_records,
    normalize_region,
    normalize_source_ip,
    parse_timestamp,
)


def make_record(**overrides):
    record = {
        "eventTime": "2026-01-15T10:00:00Z",
        "eventSource": "s3.amazonaws.com",
        "eventName": "ListBuckets",
        "eventID": "id-1",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "203.0.113.10",
    }
    record.update(overrides)
    return record


# ---- valid input ----

def test_valid_record_is_normalized():
    event, issues = normalize_record(make_record(), record_index=0, source_file="f.json")
    assert issues == []
    assert event.event_name == "ListBuckets"
    assert event.event_source == "s3.amazonaws.com"
    assert event.service == "s3"
    assert event.event_time == datetime(2026, 1, 15, 10, 0, tzinfo=timezone.utc)
    assert event.aws_region == "us-east-1"
    assert event.source_ip == "203.0.113.10"
    assert event.source_file == "f.json"
    assert event.record_index == 0


def test_messy_values_are_cleaned():
    event, _ = normalize_record(
        make_record(eventSource=" S3.AmazonAWS.com ", eventName="  GetObject ", awsRegion=" EU-WEST-1 ")
    )
    assert event.event_source == "s3.amazonaws.com"
    assert event.event_name == "GetObject"  # case preserved, spaces stripped
    assert event.aws_region == "eu-west-1"


# ---- timestamps ----

@pytest.mark.parametrize(
    "raw, expected",
    [
        ("2026-01-15T10:00:00Z", datetime(2026, 1, 15, 10, 0, tzinfo=timezone.utc)),
        ("2026-01-15T10:00:00.250Z", datetime(2026, 1, 15, 10, 0, 0, 250000, tzinfo=timezone.utc)),
        ("2026-01-15T12:00:00+02:00", datetime(2026, 1, 15, 10, 0, tzinfo=timezone.utc)),
        ("2026-01-15T10:00:00", datetime(2026, 1, 15, 10, 0, tzinfo=timezone.utc)),
    ],
)
def test_parse_timestamp_variants(raw, expected):
    assert parse_timestamp(raw) == expected


@pytest.mark.parametrize("raw", ["", "yesterday", "2026-13-45T99:00:00Z", None, 12345])
def test_parse_timestamp_rejects_garbage(raw):
    assert parse_timestamp(raw) is None


# ---- malformed input ----

@pytest.mark.parametrize("record", ["a string", 42, None, ["a", "list"]])
def test_non_object_record_is_skipped(record):
    event, issues = normalize_record(record)
    assert event is None
    assert issues[0].severity == "error"
    assert "expected a JSON object" in issues[0].message


def test_unparseable_time_is_skipped():
    event, issues = normalize_record(make_record(eventTime="not a time"))
    assert event is None
    assert issues[0].severity == "error"
    assert "eventTime" in issues[0].message


def test_one_bad_record_does_not_stop_the_rest():
    records = [make_record(eventID="a"), "garbage", make_record(eventID="b")]
    events, issues = normalize_records(records, source_file="f.json")
    assert [e.event_id for e in events] == ["a", "b"]
    assert len(issues) == 1
    assert issues[0].record_index == 1


# ---- missing fields ----

@pytest.mark.parametrize("field", ["eventTime", "eventName", "eventSource"])
def test_missing_required_field_is_skipped(field):
    record = make_record()
    del record[field]
    event, issues = normalize_record(record)
    assert event is None
    assert issues[0].severity == "error"
    assert field in issues[0].message


def test_blank_required_field_counts_as_missing():
    event, issues = normalize_record(make_record(eventName="   "))
    assert event is None
    assert "eventName" in issues[0].message


def test_missing_optional_fields_become_none():
    minimal = {
        "eventTime": "2026-01-15T10:00:00Z",
        "eventSource": "s3.amazonaws.com",
        "eventName": "ListBuckets",
        "eventID": "id-1",
    }
    event, issues = normalize_record(minimal)
    assert issues == []
    assert event.aws_region is None
    assert event.source_ip is None
    assert event.identity_type is None
    assert event.identity_name is None
    assert event.user_agent is None
    assert event.error_code is None
    assert event.read_only is None


def test_missing_event_id_is_warning_but_kept():
    record = make_record()
    del record["eventID"]
    event, issues = normalize_record(record)
    assert event is not None
    assert issues[0].severity == "warning"
    assert "eventID" in issues[0].message


def test_non_object_user_identity_is_warning():
    event, issues = normalize_record(make_record(userIdentity="oops"))
    assert event is not None
    assert event.identity_name is None
    assert any("userIdentity" in i.message for i in issues)


# ---- source IP ----

def test_ipv4_is_kept():
    assert normalize_source_ip("198.51.100.7") == ("198.51.100.7", False, None)


def test_ipv6_is_canonicalized():
    assert normalize_source_ip("2001:DB8:0:0:0:0:0:1") == ("2001:db8::1", False, None)


@pytest.mark.parametrize("value", ["ec2.amazonaws.com", "AWS Internal"])
def test_aws_service_source_is_flagged(value):
    ip, is_service, warning = normalize_source_ip(value)
    assert ip == value
    assert is_service is True
    assert warning is None


def test_unrecognized_source_ip_is_warning():
    ip, is_service, warning = normalize_source_ip("not-an-ip")
    assert ip == "not-an-ip"
    assert is_service is False
    assert warning is not None


# ---- region ----

@pytest.mark.parametrize("region", ["us-east-1", "eu-west-2", "us-gov-west-1", "ap-southeast-2"])
def test_valid_regions(region):
    assert normalize_region(region) == (region, None)


def test_invalid_region_is_warning():
    region, warning = normalize_region("moon-base")
    assert region == "moon-base"
    assert warning is not None


# ---- identities ----

def test_iam_user_identity():
    result = normalize_identity(
        {"type": "IAMUser", "userName": "alice", "arn": "arn:aws:iam::111122223333:user/alice",
         "accountId": "111122223333"}
    )
    assert result == {
        "identity_type": "IAMUser",
        "identity_name": "alice",
        "identity_arn": "arn:aws:iam::111122223333:user/alice",
        "identity_account_id": "111122223333",
    }


def test_assumed_role_uses_role_name():
    result = normalize_identity(
        {
            "type": "AssumedRole",
            "arn": "arn:aws:sts::111122223333:assumed-role/DeployRole/session-1",
            "sessionContext": {"sessionIssuer": {"userName": "DeployRole"}},
        }
    )
    assert result["identity_name"] == "DeployRole"


def test_assumed_role_without_session_context_falls_back_to_arn():
    result = normalize_identity(
        {"type": "AssumedRole", "arn": "arn:aws:sts::111122223333:assumed-role/DeployRole/session-1"}
    )
    assert result["identity_name"] == "session-1"


def test_root_identity():
    assert normalize_identity({"type": "Root", "arn": "arn:aws:iam::111122223333:root"})["identity_name"] == "root"


def test_aws_service_identity():
    result = normalize_identity({"type": "AWSService", "invokedBy": "ec2.amazonaws.com"})
    assert result["identity_name"] == "ec2.amazonaws.com"


def test_identity_not_a_dict():
    assert normalize_identity(None)["identity_name"] is None


# ---- readOnly ----

@pytest.mark.parametrize("raw, expected", [(True, True), (False, False), ("true", True), ("FALSE", False), ("maybe", None)])
def test_read_only_parsing(raw, expected):
    event, _ = normalize_record(make_record(readOnly=raw))
    assert event.read_only is expected


# ---- duplicate IDs ----

def _events(*records):
    events, _ = normalize_records(list(records), source_file="f.json")
    return events


def test_exact_duplicate_is_removed():
    events = _events(make_record(), make_record())
    kept, issues = deduplicate(events)
    assert len(kept) == 1
    assert kept[0].record_index == 0  # first one wins
    assert "exact duplicate" in issues[0].message


def test_conflicting_duplicate_is_reported_differently():
    events = _events(make_record(eventName="ListBuckets"), make_record(eventName="DeleteBucket"))
    kept, issues = deduplicate(events)
    assert len(kept) == 1
    assert kept[0].event_name == "ListBuckets"
    assert "DIFFERENT content" in issues[0].message


def test_events_without_id_are_never_deduplicated():
    a = make_record()
    del a["eventID"]
    kept, issues = deduplicate(_events(a, dict(a)))
    assert len(kept) == 2
    assert issues == []


def test_unique_ids_are_all_kept():
    kept, issues = deduplicate(_events(make_record(eventID="a"), make_record(eventID="b")))
    assert len(kept) == 2
    assert issues == []
