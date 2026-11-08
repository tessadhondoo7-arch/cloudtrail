"""Checks on the synthetic scenario dataset and its ground-truth labels.

These tests do NOT test detection (there is none yet). They make sure that:
  * every scenario file passes through the Milestone 2 pipeline,
  * every record has exactly one label, and the labels are internally consistent,
  * the labelled pipeline_outcome matches what the pipeline really does,
  * the data contains only placeholder accounts, documentation IPs and no keys.
"""

from __future__ import annotations

import csv
import ipaddress
import re
from collections import defaultdict
from datetime import timedelta, timezone
from pathlib import Path

import pytest

from cloudtrail_mapper.loader import expand_paths, load_events, read_records

REPO = Path(__file__).resolve().parents[1]
SCENARIOS_DIR = REPO / "data" / "synthetic" / "scenarios"
LABELS_FILE = REPO / "data" / "labels" / "ground_truth.csv"
SCENARIOS_FILE = REPO / "data" / "labels" / "scenarios.csv"

LABEL_COLUMNS = ["file", "record_index", "event_id", "scenario_id", "label",
                 "expected_rule", "pipeline_outcome", "notes"]
KNOWN_RULES = {
    "repeated_failed_console_login",
    "root_account_activity",
    "console_login_without_mfa",
    "cloudtrail_logging_disabled",
    "access_denied_burst",
    "iam_user_or_key_creation",
    "admin_policy_attached",
    "s3_bucket_made_public",
    "security_group_open_to_world",
}
ALLOWED_NETWORKS = [ipaddress.ip_network(n) for n in
                    ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]
ALLOWED_ACCOUNT_IDS = {"111122223333"}


# ---------------------------------------------------------------- fixtures

def rules_of(row: dict) -> set[str]:
    return {r for r in row["expected_rule"].split(";") if r}


def key_of(item) -> tuple[str, int]:
    """(file name, record index) for an event or an issue."""
    return Path(item.source_file).name, item.record_index


@pytest.fixture(scope="module")
def labels() -> list[dict]:
    with open(LABELS_FILE, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    for row in rows:
        row["record_index"] = int(row["record_index"])
    return rows


@pytest.fixture(scope="module")
def labels_by_key(labels) -> dict[tuple[str, int], dict]:
    return {(r["file"], r["record_index"]): r for r in labels}


@pytest.fixture(scope="module")
def scenarios() -> list[dict]:
    with open(SCENARIOS_FILE, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


@pytest.fixture(scope="module")
def raw_records() -> dict[tuple[str, int], object]:
    out = {}
    for path in expand_paths([SCENARIOS_DIR]):
        records, _ = read_records(path)
        for i, rec in enumerate(records):
            out[(path.name, i)] = rec
    return out


@pytest.fixture(scope="module")
def result():
    return load_events(SCENARIOS_DIR)


# ---------------------------------------------------------------- pipeline

def test_all_scenario_files_load_without_file_level_errors(result):
    assert result.files_read == 10
    file_level = [i for i in result.issues if i.record_index is None]
    assert file_level == []


def test_dataset_size(result, labels):
    assert result.records_seen == 70
    assert len(result.events) == 64
    kept = [r for r in labels if r["pipeline_outcome"] == "kept"]
    assert sum(r["label"] == "suspicious" for r in kept) == 34
    assert sum(r["label"] == "benign" for r in kept) == 30


def test_pipeline_outcomes_match_labels(result, labels_by_key):
    actual = {key_of(e): "kept" for e in result.events}
    for issue in result.errors:
        actual[key_of(issue)] = "rejected"
    for issue in result.warnings:
        if "duplicate" in issue.message and "skipped" in issue.message:
            actual[key_of(issue)] = "duplicate_dropped"
    expected = {k: r["pipeline_outcome"] for k, r in labels_by_key.items()}
    assert actual == expected


def test_files_are_read_in_sorted_order():
    names = [p.name for p in expand_paths([SCENARIOS_DIR])]
    assert names == sorted(names)
    assert names[0].startswith("s01_") and names[-1].startswith("s10_")


def test_cross_file_duplicate_keeps_the_s01_copy(result, labels):
    rows = {r["file"]: r["pipeline_outcome"] for r in labels if r["event_id"] == "s01-0003"}
    assert rows == {"s01_benign_baseline.json": "kept", "s10_edge_cases.json": "duplicate_dropped"}
    kept = [e for e in result.events if e.event_id == "s01-0003"]
    assert len(kept) == 1
    assert Path(kept[0].source_file).name == "s01_benign_baseline.json"


def test_kept_event_ids_are_unique(result):
    ids = [e.event_id for e in result.events if e.event_id is not None]
    assert len(ids) == len(set(ids))


def test_offset_timestamp_is_converted_to_utc(result):
    event = next(e for e in result.events if e.event_id == "s10-0010")
    assert event.event_time.isoformat() == "2026-02-10T11:00:00+00:00"


def test_shuffled_burst_spans_midnight_and_fits_in_ten_minutes(result):
    burst = [e for e in result.events if e.event_id and e.event_id.startswith("s10-01")]
    assert len(burst) == 5
    file_order_times = [e.event_time for e in sorted(burst, key=lambda e: e.record_index)]
    assert file_order_times != sorted(file_order_times), "burst should be shuffled in the file"
    times = sorted(file_order_times)
    assert all(t.tzinfo == timezone.utc for t in times)
    assert times[0].date() != times[-1].date(), "burst should cross midnight"
    assert times[-1] - times[0] < timedelta(minutes=10)
    assert {e.event_source for e in burst} == {"signin.amazonaws.com"}  # mixed case normalized


# ---------------------------------------------------------------- label file

def test_label_columns():
    with open(LABELS_FILE, newline="", encoding="utf-8") as fh:
        assert next(csv.reader(fh)) == LABEL_COLUMNS


def test_every_record_has_exactly_one_label(labels, raw_records):
    keys = [(r["file"], r["record_index"]) for r in labels]
    assert len(keys) == len(set(keys)), "duplicate label rows"
    assert set(keys) == set(raw_records), "labels and records do not line up"


def test_label_event_id_matches_record(labels_by_key, raw_records):
    for k, rec in raw_records.items():
        assert labels_by_key[k]["event_id"] == (rec.get("eventID") or ""), k


def test_label_values_are_valid(labels):
    for r in labels:
        where = f"{r['file']}#{r['record_index']}"
        assert r["label"] in {"benign", "suspicious", "invalid"}, where
        assert r["pipeline_outcome"] in {"kept", "rejected", "duplicate_dropped"}, where
        assert rules_of(r) <= KNOWN_RULES, where
        if r["label"] == "suspicious":
            assert rules_of(r), f"{where}: suspicious rows need an expected_rule"
        else:
            assert not rules_of(r), f"{where}: benign/invalid rows must have empty expected_rule"
        assert (r["label"] == "invalid") == (r["pipeline_outcome"] == "rejected"), where
        assert "mitre" not in r["expected_rule"].lower() and not re.search(r"\bT\d{4}", r["expected_rule"])


def test_scenario_catalog_matches_labels(labels, scenarios):
    by_scenario = defaultdict(list)
    for r in labels:
        by_scenario[r["scenario_id"]].append(r)
    assert set(by_scenario) == {s["scenario_id"] for s in scenarios}
    for s in scenarios:
        rows = by_scenario[s["scenario_id"]]
        assert (SCENARIOS_DIR / s["file"]).is_file()
        assert {r["file"] for r in rows} == {s["file"]}
        catalog_rules = {x for x in s["expected_rule"].split(";") if x}
        assert set().union(*(rules_of(r) for r in rows)) == catalog_rules, s["scenario_id"]
        if s["label"] != "mixed":
            assert {r["label"] for r in rows} == {s["label"]}, s["scenario_id"]
        if s["scenario_id"].endswith("-HN"):
            assert s["label"] == "benign"


# ------------------------------------------- label vs. documented definitions
#
# For the rules that look at ONE event, check that labels agree with the
# definitions in docs/synthetic_dataset.md. This catches missed overlaps
# (e.g. root CreateAccessKey must list BOTH root_account_activity and
# iam_user_or_key_creation). These are labeling checks, not detection code.

def _src(rec):
    return str(rec.get("eventSource", "")).lower()


def _ok(rec):
    return not rec.get("errorCode")


DEFINITIONS = {
    "root_account_activity": lambda r: (r.get("userIdentity") or {}).get("type") == "Root",
    "console_login_without_mfa": lambda r: (
        r.get("eventName") == "ConsoleLogin"
        and (r.get("responseElements") or {}).get("ConsoleLogin") == "Success"
        and (r.get("additionalEventData") or {}).get("MFAUsed") == "No"
    ),
    "cloudtrail_logging_disabled": lambda r: (
        _src(r) == "cloudtrail.amazonaws.com" and r.get("eventName") in {"StopLogging", "DeleteTrail"}
    ),
    "iam_user_or_key_creation": lambda r: (
        _src(r) == "iam.amazonaws.com"
        and r.get("eventName") in {"CreateUser", "CreateAccessKey", "CreateLoginProfile"}
        and _ok(r)
    ),
    "admin_policy_attached": lambda r: (
        r.get("eventName") in {"AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy"}
        and str((r.get("requestParameters") or {}).get("policyArn", "")).endswith("/AdministratorAccess")
        and _ok(r)
    ),
}

# Benign events that a rule matching the definition WILL flag. These are
# intentional hard negatives that will show up as false positives.
KNOWN_FALSE_POSITIVES = {("iam_user_or_key_creation", "s07-0101")}


@pytest.mark.parametrize("rule", sorted(DEFINITIONS))
def test_single_event_rule_labels_match_definition(rule, labels_by_key, raw_records):
    matches = DEFINITIONS[rule]
    for k, row in labels_by_key.items():
        if row["pipeline_outcome"] != "kept":
            continue
        rec = raw_records[k]
        if rule in rules_of(row):
            assert matches(rec), f"{k} lists {rule} but does not match its definition"
        elif matches(rec):
            assert row["label"] == "benign" and (rule, row["event_id"]) in KNOWN_FALSE_POSITIVES, (
                f"{k} matches {rule} but the label does not list it"
            )


def test_failed_logins_never_count_as_missing_mfa(labels_by_key, raw_records):
    for k, row in labels_by_key.items():
        rec = raw_records[k]
        if isinstance(rec, dict) and (rec.get("responseElements") or {}).get("ConsoleLogin") == "Failure":
            assert "console_login_without_mfa" not in rules_of(row), k


def test_daves_final_successful_login_used_mfa(labels, raw_records):
    row = next(r for r in labels if r["event_id"] == "s02-0007")
    rec = raw_records[(row["file"], row["record_index"])]
    assert rec["responseElements"]["ConsoleLogin"] == "Success"
    assert rec["additionalEventData"]["MFAUsed"] == "Yes"
    assert rules_of(row) == {"repeated_failed_console_login"}


# ---------------------------------------------------------------- safety

@pytest.fixture(scope="module")
def scenario_texts() -> dict[str, str]:
    return {p.name: p.read_text(encoding="utf-8") for p in sorted(SCENARIOS_DIR.glob("*.json"))}


def test_source_ips_are_documentation_ranges_or_aws_services(raw_records):
    for k, rec in raw_records.items():
        value = rec.get("sourceIPAddress")
        if value is None:
            continue
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            assert value.lower().endswith(".amazonaws.com") or value == "AWS Internal", (k, value)
            continue
        assert any(ip in net for net in ALLOWED_NETWORKS), (k, value)


def test_every_ipv4_literal_is_documentation_or_any(scenario_texts):
    for name, text in scenario_texts.items():
        for literal in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text):
            ip = ipaddress.ip_address(literal)
            assert literal == "0.0.0.0" or any(ip in net for net in ALLOWED_NETWORKS), (name, literal)


def test_only_placeholder_account_ids(scenario_texts):
    for name, text in scenario_texts.items():
        found = set(re.findall(r"(?<!\d)\d{12}(?!\d)", text))
        assert found <= ALLOWED_ACCOUNT_IDS, (name, found - ALLOWED_ACCOUNT_IDS)


def test_no_credentials(scenario_texts):
    for name, text in scenario_texts.items():
        assert not re.search(r"(AKIA|ASIA)[A-Z0-9]{16}", text), name
        lowered = text.lower()
        for forbidden in ("secretaccesskey", "sessiontoken", "password"):
            assert forbidden not in lowered, (name, forbidden)
