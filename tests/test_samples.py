"""End-to-end tests against the synthetic sample files in data/synthetic/."""

from datetime import datetime, timezone
from pathlib import Path

from cloudtrail_mapper.__main__ import main
from cloudtrail_mapper.loader import load_events

SAMPLES = Path(__file__).resolve().parents[1] / "data" / "synthetic"


def test_valid_basic_loads_cleanly():
    result = load_events(SAMPLES / "valid_basic.json")
    assert result.records_seen == 5
    assert len(result.events) == 5
    assert result.issues == []
    names = {e.identity_name for e in result.events}
    assert names == {"alice", "DeployRole", "ec2.amazonaws.com", "bob"}


def test_mixed_quality_file():
    result = load_events(SAMPLES / "mixed_quality.json")
    assert result.records_seen == 8
    # Kept: record 0 (GetObject), 1 (ListBuckets), 7 (GetUser).
    assert sorted(e.record_index for e in result.events) == [0, 1, 7]
    # Skipped as errors: 4 (no eventName), 5 (bad time), 6 (a string).
    assert sorted(i.record_index for i in result.errors) == [4, 5, 6]

    get_object = next(e for e in result.events if e.record_index == 0)
    assert get_object.event_name == "GetObject"
    assert get_object.event_source == "s3.amazonaws.com"
    assert get_object.aws_region == "us-west-2"
    assert get_object.source_ip == "2001:db8::1"
    assert get_object.read_only is True

    get_user = next(e for e in result.events if e.record_index == 7)
    assert get_user.event_time == datetime(2026, 1, 16, 12, 30, tzinfo=timezone.utc)

    duplicate_warnings = [w for w in result.warnings if "duplicate" in w.message and "skipped" in w.message]
    assert sorted(w.record_index for w in duplicate_warnings) == [2, 3]
    assert "exact duplicate" in duplicate_warnings[0].message
    assert "DIFFERENT content" in duplicate_warnings[1].message


def test_malformed_json_file():
    result = load_events(SAMPLES / "malformed_json.json")
    assert result.events == []
    assert len(result.errors) == 1
    assert "invalid JSON" in result.errors[0].message


def test_empty_file():
    result = load_events(SAMPLES / "empty.json")
    assert result.events == []
    assert result.errors == []
    assert len(result.warnings) == 1


def test_whole_directory():
    result = load_events(SAMPLES)
    assert result.files_read == 4
    assert result.records_seen == 13
    assert len(result.events) == 8  # 5 valid + 3 from mixed_quality


def test_cli_runs_on_samples(capsys):
    exit_code = main([str(SAMPLES)])
    output = capsys.readouterr().out
    assert exit_code == 0
    assert "Events loaded:   8" in output


def test_cli_exit_code_when_nothing_loads():
    assert main([str(SAMPLES / "malformed_json.json")]) == 1
