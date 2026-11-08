"""Tests for the iam_policy_modification detection rule."""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import quote

import pytest

from cloudtrail_mapper.detect import run_rules
from cloudtrail_mapper.loader import load_events
from cloudtrail_mapper.normalize import normalize_record
from cloudtrail_mapper.rules import ALL_RULES
from cloudtrail_mapper.rules import iam_policy_modification as rule

ACCOUNT = "111122223333"
SCENARIOS = Path(__file__).resolve().parents[1] / "data" / "synthetic" / "scenarios"

ALICE = {"type": "IAMUser", "userName": "alice", "accountId": ACCOUNT,
         "arn": f"arn:aws:iam::{ACCOUNT}:user/alice"}


def role_identity(role, session="session-1", with_context=True):
    identity = {"type": "AssumedRole", "accountId": ACCOUNT,
                "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/{role}/{session}"}
    if with_context:
        identity["sessionContext"] = {"sessionIssuer": {"type": "Role", "userName": role,
                                                        "arn": f"arn:aws:iam::{ACCOUNT}:role/{role}"}}
    return identity


def make_event(event_name, params=None, *, identity=ALICE, error_code=None,
               source="iam.amazonaws.com", event_id="evt-1"):
    record = {
        "eventTime": "2026-02-10T12:00:00Z",
        "eventSource": source,
        "eventName": event_name,
        "eventID": event_id,
        "sourceIPAddress": "203.0.113.10",
        "userIdentity": identity,
        "requestParameters": params,
    }
    if event_id is None:
        del record["eventID"]
    if error_code:
        record["errorCode"] = error_code
    event, _ = normalize_record(record, record_index=0, source_file="test.json")
    return event


def doc(*statements):
    return json.dumps({"Version": "2012-10-17", "Statement": list(statements)})


ALLOW_ALL = {"Effect": "Allow", "Action": "*", "Resource": "*"}


# =========================================================== rule definition

EXPECTED_APIS = {
    "AttachUserPolicy", "AttachGroupPolicy", "AttachRolePolicy",
    "PutUserPolicy", "PutGroupPolicy", "PutRolePolicy",
    "CreatePolicyVersion", "SetDefaultPolicyVersion",
    "UpdateAssumeRolePolicy",
    "DeleteUserPermissionsBoundary", "DeleteRolePermissionsBoundary",
    "AddUserToGroup",
    "DetachUserPolicy", "DetachGroupPolicy", "DetachRolePolicy",
    "DeleteUserPolicy", "DeleteGroupPolicy", "DeleteRolePolicy",
    "CreatePolicy", "DeletePolicy", "DeletePolicyVersion",
    "PutUserPermissionsBoundary", "PutRolePermissionsBoundary",
}


def test_matched_api_list_is_exactly_as_documented():
    assert rule.MATCHED_APIS == EXPECTED_APIS
    assert len(rule.MATCHED_APIS) == 23
    assert not (rule.MEDIUM_APIS & rule.LOW_APIS)


def test_rule_is_registered_with_stable_id():
    assert rule.RULE_ID == "iam_policy_modification"
    assert ALL_RULES["iam_policy_modification"] is rule.detect


# =========================================================== positive

@pytest.mark.parametrize("api", sorted(EXPECTED_APIS))
def test_every_listed_api_triggers(api):
    assert rule.evaluate(make_event(api, {})) is not None


@pytest.mark.parametrize("api", sorted(rule.MEDIUM_APIS))
def test_medium_apis_start_at_medium(api):
    finding = rule.evaluate(make_event(api, {}))
    assert finding.severity == "medium"
    assert finding.confidence == "low"


@pytest.mark.parametrize("api", sorted(rule.LOW_APIS))
def test_low_apis_start_at_low(api):
    assert rule.evaluate(make_event(api, {})).severity == "low"


def test_attach_administrator_access_is_high():
    f = rule.evaluate(make_event("AttachUserPolicy", {
        "userName": "bob", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}))
    assert (f.severity, f.confidence) == ("high", "medium")
    assert "AdministratorAccess" in f.severity_reason


def test_attach_iam_full_access_is_high():
    f = rule.evaluate(make_event("AttachRolePolicy", {
        "roleName": "r", "policyArn": "arn:aws:iam::aws:policy/IAMFullAccess"}))
    assert f.severity == "high"


def test_attach_ordinary_managed_policy_is_medium():
    f = rule.evaluate(make_event("AttachRolePolicy", {
        "roleName": "r", "policyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}))
    assert (f.severity, f.confidence) == ("medium", "low")


@pytest.mark.parametrize("document", [
    doc(ALLOW_ALL),                                                    # JSON string
    json.loads(doc(ALLOW_ALL)),                                        # already a dict
    quote(doc(ALLOW_ALL)),                                             # URL-encoded
    doc({"Effect": "Allow", "Action": ["s3:GetObject", "*"], "Resource": ["*"]}),  # lists
    doc({"Effect": "Allow", "Action": "IAM:*", "Resource": "*"}),      # case-insensitive iam:*
    json.dumps({"Statement": ALLOW_ALL}),                              # single statement, not a list
])
def test_broad_inline_policy_is_high(document):
    f = rule.evaluate(make_event("PutRolePolicy", {"roleName": "other-role", "policyDocument": document}))
    assert f.severity == "high"
    assert f.evidence["policy_document_status"] == "parsed"
    assert f.evidence["broad_grants"]


@pytest.mark.parametrize("statement", [
    {"Effect": "Deny", "Action": "*", "Resource": "*"},                         # Deny, not Allow
    {"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::one-bucket/*"},  # narrow resource
    {"Effect": "Allow", "Action": "s3:*", "Resource": "*"},                      # one service only
])
def test_non_broad_inline_policy_stays_medium(statement):
    f = rule.evaluate(make_event("PutUserPolicy", {"userName": "bob", "policyDocument": doc(statement)}))
    assert f.severity == "medium"
    assert f.evidence["broad_grants"] == []


@pytest.mark.parametrize("principal", ["*", {"AWS": "*"}, {"AWS": [f"arn:aws:iam::{ACCOUNT}:root", "*"]}])
def test_trust_policy_open_to_anyone_is_high(principal):
    f = rule.evaluate(make_event("UpdateAssumeRolePolicy", {
        "roleName": "r", "policyDocument": doc({"Effect": "Allow", "Principal": principal,
                                                "Action": "sts:AssumeRole"})}))
    assert f.severity == "high"
    assert f.evidence["trust_allows_anyone"] is True


def test_trust_policy_for_specific_account_is_medium():
    f = rule.evaluate(make_event("UpdateAssumeRolePolicy", {
        "roleName": "r", "policyDocument": doc({"Effect": "Allow",
                                                "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"},
                                                "Action": "sts:AssumeRole"})}))
    assert f.severity == "medium"
    assert f.evidence["trust_allows_anyone"] is False


@pytest.mark.parametrize("set_as_default, expected", [(True, "high"), ("true", "high"), (False, "low"), (None, "low")])
def test_create_policy_version_depends_on_set_as_default(set_as_default, expected):
    params = {"policyArn": f"arn:aws:iam::{ACCOUNT}:policy/p", "policyDocument": doc(ALLOW_ALL)}
    if set_as_default is not None:
        params["setAsDefault"] = set_as_default
    f = rule.evaluate(make_event("CreatePolicyVersion", params))
    assert f.severity == expected


def test_broad_document_in_create_policy_stays_low_but_is_mentioned():
    f = rule.evaluate(make_event("CreatePolicy", {"policyName": "p", "policyDocument": doc(ALLOW_ALL)}))
    assert f.severity == "low"
    assert f.confidence == "low"
    assert any("does not make it effective" in r for r in f.reasons)


# ----------------------------------------------------- self-modification

def test_role_granting_itself_broad_access_is_high_confidence():
    f = rule.evaluate(make_event("PutRolePolicy", {"roleName": "AppServerRole", "policyDocument": doc(ALLOW_ALL)},
                                 identity=role_identity("AppServerRole")))
    assert (f.severity, f.confidence) == ("high", "high")
    assert f.evidence["self_targeted"] is True


def test_role_name_comes_from_arn_when_session_context_missing():
    # Without sessionContext the normalizer's identity_name is the SESSION name,
    # so the rule must read the role name from the ARN instead.
    event = make_event("PutRolePolicy", {"roleName": "AppServerRole", "policyDocument": doc(ALLOW_ALL)},
                       identity=role_identity("AppServerRole", session="i-0example", with_context=False))
    assert event.identity_name == "i-0example"
    f = rule.evaluate(event)
    assert f.evidence["caller"]["principal_name"] == "AppServerRole"
    assert f.evidence["self_targeted"] is True
    assert f.confidence == "high"


def test_session_name_equal_to_target_role_is_not_self():
    # Session happens to be named like the target role; caller is a different role.
    f = rule.evaluate(make_event("PutRolePolicy", {"roleName": "TargetRole", "policyDocument": doc(ALLOW_ALL)},
                                 identity=role_identity("CallerRole", session="TargetRole")))
    assert f.evidence["self_targeted"] is False
    assert f.confidence == "medium"


def test_user_granting_itself_broad_access():
    f = rule.evaluate(make_event("PutUserPolicy", {"userName": "alice", "policyDocument": doc(ALLOW_ALL)}))
    assert (f.severity, f.confidence) == ("high", "high")


def test_user_adding_itself_to_group_is_noted_but_stays_low_confidence():
    f = rule.evaluate(make_event("AddUserToGroup", {"groupName": "Admins", "userName": "alice"}))
    assert (f.severity, f.confidence) == ("medium", "low")
    assert f.evidence["self_targeted"] is True
    assert f.evidence["group_name"] == "Admins"


def test_same_name_different_kind_is_not_self():
    # IAM user "deploy" changing ROLE "deploy" is not changing itself.
    identity = {"type": "IAMUser", "userName": "deploy", "arn": f"arn:aws:iam::{ACCOUNT}:user/deploy"}
    f = rule.evaluate(make_event("PutRolePolicy", {"roleName": "deploy"}, identity=identity))
    assert f.evidence["self_targeted"] is False


# =========================================================== negative

@pytest.mark.parametrize("error_code", ["AccessDenied", "NoSuchEntity", "MalformedPolicyDocument"])
def test_failed_calls_are_ignored(error_code):
    assert rule.evaluate(make_event("PutUserPolicy", {"userName": "bob"}, error_code=error_code)) is None


@pytest.mark.parametrize("api", ["GetPolicy", "ListAttachedRolePolicies", "GetRolePolicy",
                                 "ListPolicies", "CreateUser", "CreateAccessKey", "CreateRole"])
def test_other_iam_calls_do_not_trigger(api):
    assert rule.evaluate(make_event(api, {})) is None


@pytest.mark.parametrize("source, api", [
    ("s3.amazonaws.com", "PutBucketPolicy"),
    ("s3.amazonaws.com", "PutRolePolicy"),        # right name, wrong service
    ("kms.amazonaws.com", "PutKeyPolicy"),
    ("sts.amazonaws.com", "AssumeRole"),
])
def test_non_iam_sources_do_not_trigger(source, api):
    assert rule.evaluate(make_event(api, {}, source=source)) is None


# =========================================================== edge cases

def test_mixed_case_event_source_still_matches():
    assert rule.evaluate(make_event("AttachRolePolicy", {}, source="IAM.AmazonAWS.com")) is not None


@pytest.mark.parametrize("params", [None, "not-a-dict", [], {}])
def test_missing_or_odd_request_parameters_do_not_crash(params):
    f = rule.evaluate(make_event("PutRolePolicy", params))
    assert f is not None
    assert f.severity == "medium"
    assert f.evidence["target"] == {"kind": None, "name": None}


def test_unparseable_policy_document_is_reported():
    f = rule.evaluate(make_event("PutRolePolicy", {"roleName": "r", "policyDocument": "{not json"}))
    assert f.severity == "medium"
    assert f.evidence["policy_document_status"] == "unparseable"
    assert any("could not be parsed" in r for r in f.reasons)


def test_customer_policy_named_administrator_access_is_not_treated_as_aws_managed():
    f = rule.evaluate(make_event("AttachUserPolicy", {
        "userName": "bob", "policyArn": f"arn:aws:iam::{ACCOUNT}:policy/AdministratorAccess"}))
    assert f.severity == "medium"


def test_event_without_event_id_still_has_a_reference():
    f = rule.evaluate(make_event("AttachRolePolicy", {"roleName": "r"}, event_id=None))
    assert f.event_ids == []
    assert len(f.event_refs) == 1
    assert (f.event_refs[0].source_file, f.event_refs[0].record_index) == ("test.json", 0)


def test_finding_structure_and_wording():
    f = rule.evaluate(make_event("AttachRolePolicy", {"roleName": "r"}))
    assert f.rule_id == "iam_policy_modification"
    assert f.rule_name
    assert f.event_ids == ["evt-1"]
    assert f.first_seen == f.last_seen
    assert f.benign_explanations
    assert f.severity_reason and f.confidence_reason
    assert f.mitre_attack == []
    assert f.mitre_status == "not_mapped"
    assert "does not prove" in f.disclaimer
    for text in [f.title, *f.reasons, f.severity_reason, f.confidence_reason]:
        assert "malicious" not in text.lower()
        assert "attack" not in text.lower()


# =========================================================== on the synthetic dataset

EXPECTED_ON_DATASET = {
    # event_id: (severity, confidence)
    "s07-0003": ("high", "medium"),
    "s11-0001": ("high", "high"),
    "s11-0002": ("high", "medium"),
    "s11-0003": ("high", "medium"),
    "s11-0004": ("medium", "low"),
    "s11-0005": ("medium", "low"),
    "s11-0101": ("medium", "low"),   # benign: known false positive
    "s11-0102": ("medium", "low"),   # benign: known false positive
    "s11-0103": ("low", "low"),      # benign: known false positive
    "s11-0104": ("low", "low"),      # benign: known false positive
}


def test_findings_on_synthetic_scenarios():
    findings = run_rules(load_events(SCENARIOS).events)
    actual = {f.event_ids[0]: (f.severity, f.confidence) for f in findings}
    assert actual == EXPECTED_ON_DATASET
    assert [f.first_seen for f in findings] == sorted(f.first_seen for f in findings)
