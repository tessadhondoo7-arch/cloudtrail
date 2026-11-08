"""Generate the synthetic CloudTrail scenario files and their ground-truth labels.

Writes:
    data/synthetic/scenarios/sNN_*.json   (CloudTrail-shaped {"Records": [...]})
    data/labels/ground_truth.csv          (one label row per record)
    data/labels/scenarios.csv             (one row per scenario)

Run from the project root (with .venv active):
    python scripts/generate_synthetic_dataset.py

Everything is synthetic: account 111122223333 (AWS documentation placeholder),
documentation-only IP ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24,
2001:db8::/32), made-up users, and fake key IDs such as "EXAMPLE-KEY-ID-0001".

The labels are written next to each record (in the FILES lists below) so the
two can never drift apart. Each FILES entry is a tuple:
    (record, scenario_id, label, expected_rules, pipeline_outcome, notes)
pipeline_outcome values were confirmed by running the Milestone 2 pipeline;
tests/test_synthetic_dataset.py fails if they ever stop matching.
See docs/synthetic_dataset.md for the meaning of every scenario and column.
"""
import copy
import csv
import json
import sys
from pathlib import Path
from urllib.parse import quote

# Project root: first CLI argument if given, otherwise the folder above scripts/.
ROOT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[1]
SCEN_DIR = ROOT / "data" / "synthetic" / "scenarios"
LABEL_DIR = ROOT / "data" / "labels"
ACCOUNT = "111122223333"
CLI = "aws-cli/2.15.0 (synthetic)"
BROWSER = "Mozilla/5.0 (synthetic test browser)"
D = "2026-02-10T"


# ---------------- identities ----------------
# Helpers that build the "userIdentity" block for each kind of caller.
# principalId values start with AIDA/AROA like real ones but contain "EXAMPLE",
# so they can never be confused with real IDs.
def iam_user(name):
    return {
        "type": "IAMUser",
        "principalId": f"AIDAEXAMPLE{name.upper().replace('-', '')}",
        "arn": f"arn:aws:iam::{ACCOUNT}:user/{name}",
        "accountId": ACCOUNT,
        "userName": name,
    }


def assumed_role(role, session):
    return {
        "type": "AssumedRole",
        "principalId": f"AROAEXAMPLE{role.upper()}:{session}",
        "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/{role}/{session}",
        "accountId": ACCOUNT,
        "sessionContext": {
            "sessionIssuer": {
                "type": "Role",
                "principalId": f"AROAEXAMPLE{role.upper()}",
                "arn": f"arn:aws:iam::{ACCOUNT}:role/{role}",
                "accountId": ACCOUNT,
                "userName": role,
            },
            "attributes": {"creationDate": f"{D}00:00:00Z", "mfaAuthenticated": "false"},
        },
    }


def root_identity():
    return {"type": "Root", "principalId": ACCOUNT, "arn": f"arn:aws:iam::{ACCOUNT}:root", "accountId": ACCOUNT}


def aws_service(svc):
    return {"type": "AWSService", "invokedBy": svc}


# ---------------- events ----------------
# ev() builds one CloudTrail-shaped record with fields in CloudTrail's usual order.
# errorCode/errorMessage/additionalEventData are only added when given, just like
# real CloudTrail omits them when they do not apply.
def ev(eid, time, source, name, identity, ip, *, read_only, region="us-east-1", ua=CLI,
       error_code=None, error_message=None, req=None, resp=None, extra=None, event_type="AwsApiCall"):
    r = {
        "eventVersion": "1.09",
        "userIdentity": identity,
        "eventTime": time,
        "eventSource": source,
        "eventName": name,
        "awsRegion": region,
        "sourceIPAddress": ip,
        "userAgent": ua,
    }
    if error_code:
        r["errorCode"] = error_code
    if error_message:
        r["errorMessage"] = error_message
    r["requestParameters"] = req
    r["responseElements"] = resp
    if extra is not None:
        r["additionalEventData"] = extra
    r["eventID"] = eid
    r["readOnly"] = read_only
    r["eventType"] = event_type
    r["managementEvent"] = True
    r["recipientAccountId"] = ACCOUNT
    return r


# Console sign-ins: success/failure lives in responseElements.ConsoleLogin and
# MFA use in additionalEventData.MFAUsed. Failed logins report MFAUsed "No",
# which is why console_login_without_mfa only applies to SUCCESSFUL logins.
def console_login(eid, time, identity, ip, *, success, mfa):
    return ev(
        eid, time, "signin.amazonaws.com", "ConsoleLogin", identity, ip,
        read_only=False, ua=BROWSER, event_type="AwsConsoleSignIn",
        error_message=None if success else "Failed authentication",
        resp={"ConsoleLogin": "Success" if success else "Failure"},
        extra={"LoginTo": "https://console.aws.amazon.com/console/home",
               "MobileVersion": "No", "MFAUsed": "Yes" if mfa else "No"},
    )


ALICE, BOB, CAROL = iam_user("alice"), iam_user("bob"), iam_user("carol")
CI = assumed_role("CIDeployRole", "pipeline-run-4821")

# Each scenario file: list of (record, scenario_id, label, expected_rules, pipeline_outcome, notes)
FILES = {}

# ---------------- S01 benign baseline ----------------
# A normal workday. Three people sign in WITH MFA from their usual 203.0.113.x
# addresses and read S3/EC2/CloudWatch; the CI role deploys a Lambda and uploads
# an artifact; EC2 assumes a role on its own (AWSService caller). Label: benign.
# Purpose: baseline for false positives - no future rule should fire here.
s01 = [
    console_login("s01-0001", D + "08:30:00Z", ALICE, "203.0.113.10", success=True, mfa=True),
    ev("s01-0002", D + "08:32:00Z", "s3.amazonaws.com", "ListBuckets", ALICE, "203.0.113.10", read_only=True,
       req={"Host": "s3.amazonaws.com"}),
    ev("s01-0003", D + "08:35:00Z", "s3.amazonaws.com", "GetObject", ALICE, "203.0.113.10", read_only=True,
       req={"bucketName": "synthetic-reports-bucket", "key": "weekly/report.csv"}),
    console_login("s01-0004", D + "08:45:00Z", BOB, "203.0.113.11", success=True, mfa=True),
    ev("s01-0005", D + "08:47:00Z", "ec2.amazonaws.com", "DescribeInstances", BOB, "203.0.113.11", read_only=True,
       req={"maxResults": 50}),
    ev("s01-0006", D + "08:50:00Z", "monitoring.amazonaws.com", "GetMetricData", BOB, "203.0.113.11", read_only=True,
       req={"startTime": D + "07:50:00Z", "endTime": D + "08:50:00Z"}),
    ev("s01-0007", D + "10:00:00Z", "lambda.amazonaws.com", "UpdateFunctionCode20150331v2", CI, "198.51.100.10",
       read_only=False, ua="synthetic-ci-runner/1.0", req={"functionName": "synthetic-report-builder"}),
    ev("s01-0008", D + "10:01:00Z", "s3.amazonaws.com", "PutObject", CI, "198.51.100.10", read_only=False,
       ua="synthetic-ci-runner/1.0", req={"bucketName": "synthetic-artifacts-bucket", "key": "builds/4821.zip"}),
    ev("s01-0009", D + "10:05:00Z", "sts.amazonaws.com", "AssumeRole", aws_service("ec2.amazonaws.com"),
       "ec2.amazonaws.com", read_only=True, ua="ec2.amazonaws.com",
       req={"roleArn": f"arn:aws:iam::{ACCOUNT}:role/AppServerRole", "roleSessionName": "i-0example0000000a1"}),
    console_login("s01-0010", D + "11:00:00Z", CAROL, "203.0.113.12", success=True, mfa=True),
    ev("s01-0011", D + "11:02:00Z", "iam.amazonaws.com", "ListUsers", CAROL, "203.0.113.12", read_only=True),
    ev("s01-0012", D + "12:00:00Z", "sts.amazonaws.com", "GetCallerIdentity", ALICE, "203.0.113.10", read_only=True),
]
FILES["s01_benign_baseline.json"] = [(r, "S01", "benign", "", "kept", "routine workday activity") for r in s01]

# ---------------- S02 failed console logins ----------------
# S02: dave has 6 failed console logins from 198.51.100.77 in ~4.5 minutes, then
#      a successful login (WITH MFA) from the same IP -> suspicious, tests
#      repeated_failed_console_login. The success is included because a success
#      right after guessing may mean the password was found.
# S02-HN (hard negative): alice mistypes once, then succeeds -> benign.
DAVE = iam_user("dave")
s02 = [
    (console_login("s02-0101", D + "09:00:00Z", ALICE, "203.0.113.10", success=False, mfa=False),
     "S02-HN", "benign", "", "kept", "single mistyped password from usual IP; failed login so MFA rule does not apply"),
    (console_login("s02-0102", D + "09:00:40Z", ALICE, "203.0.113.10", success=True, mfa=True),
     "S02-HN", "benign", "", "kept", "successful retry with MFA"),
]
for i, t in enumerate(["14:00:05", "14:00:48", "14:01:30", "14:02:20", "14:03:41", "14:04:30"], start=1):
    s02.append((console_login(f"s02-{i:04d}", D + t + "Z", DAVE, "198.51.100.77", success=False, mfa=False),
                "S02", "suspicious", "repeated_failed_console_login", "kept",
                f"failed login {i} of 6 within 5 minutes; failed so MFA rule does not apply"))
s02.append((console_login("s02-0007", D + "14:05:10Z", DAVE, "198.51.100.77", success=True, mfa=True),
            "S02", "suspicious", "repeated_failed_console_login", "kept",
            "success right after the burst from same IP (possible guessed password); MFA was used"))
FILES["s02_failed_console_logins.json"] = s02

# ---------------- S03 root ----------------
# The root user signs in WITHOUT MFA, lists IAM users and creates an access key.
# Root should almost never be used day to day -> suspicious. Overlaps are
# labelled on purpose: the login also matches console_login_without_mfa and the
# CreateAccessKey also matches iam_user_or_key_creation.
ROOT_ID = root_identity()
FILES["s03_root_account_usage.json"] = [
    (console_login("s03-0001", D + "15:00:00Z", ROOT_ID, "198.51.100.50", success=True, mfa=False),
     "S03", "suspicious", "root_account_activity;console_login_without_mfa", "kept", "root console login without MFA"),
    (ev("s03-0002", D + "15:02:00Z", "iam.amazonaws.com", "ListUsers", ROOT_ID, "198.51.100.50", read_only=True,
        ua=BROWSER), "S03", "suspicious", "root_account_activity", "kept", "root enumerating IAM users"),
    (ev("s03-0003", D + "15:04:00Z", "iam.amazonaws.com", "CreateAccessKey", ROOT_ID, "198.51.100.50",
        read_only=False, ua=BROWSER,
        resp={"accessKey": {"accessKeyId": "EXAMPLE-KEY-ID-ROOT", "status": "Active", "createDate": D + "15:04:00Z"}}),
     "S03", "suspicious", "root_account_activity;iam_user_or_key_creation", "kept", "root creating an access key"),
]

# ---------------- S04 no MFA ----------------
# S04: bob signs in successfully without MFA -> suspicious (console_login_without_mfa).
# S04-HN: the same user signs in with MFA -> benign.
FILES["s04_console_login_without_mfa.json"] = [
    (console_login("s04-0001", D + "13:00:00Z", BOB, "203.0.113.11", success=True, mfa=False),
     "S04", "suspicious", "console_login_without_mfa", "kept", "successful console login without MFA"),
    (console_login("s04-0101", D + "17:00:00Z", BOB, "203.0.113.11", success=True, mfa=True),
     "S04-HN", "benign", "", "kept", "same user, MFA used"),
]

# ---------------- S05 CloudTrail ----------------
# S05: carol's credentials, from an unusual IP, stop logging and delete the trail
#      -> suspicious (cloudtrail_logging_disabled): hiding further activity.
# S05-HN: carol only VIEWS the trail configuration (read-only) -> benign.
TRAIL = f"arn:aws:cloudtrail:us-east-1:{ACCOUNT}:trail/synthetic-audit-trail"
FILES["s05_cloudtrail_logging_disabled.json"] = [
    (ev("s05-0101", D + "12:30:00Z", "cloudtrail.amazonaws.com", "DescribeTrails", CAROL, "203.0.113.12",
        read_only=True), "S05-HN", "benign", "", "kept", "read-only: viewing trail configuration"),
    (ev("s05-0102", D + "12:31:00Z", "cloudtrail.amazonaws.com", "GetTrailStatus", CAROL, "203.0.113.12",
        read_only=True, req={"name": TRAIL}), "S05-HN", "benign", "", "kept", "read-only: checking trail status"),
    (ev("s05-0001", D + "18:00:00Z", "cloudtrail.amazonaws.com", "StopLogging", CAROL, "198.51.100.120",
        read_only=False, req={"name": TRAIL}),
     "S05", "suspicious", "cloudtrail_logging_disabled", "kept", "audit logging stopped from unusual IP"),
    (ev("s05-0002", D + "18:01:00Z", "cloudtrail.amazonaws.com", "DeleteTrail", CAROL, "198.51.100.120",
        read_only=False, req={"name": TRAIL}),
     "S05", "suspicious", "cloudtrail_logging_disabled", "kept", "audit trail deleted"),
]

# ---------------- S06 AccessDenied burst ----------------
# S06: AppServerRole gets 10 denied calls across 7 services in 3 minutes, using
#      several error-code spellings -> suspicious (access_denied_burst): looks
#      like stolen credentials probing what they can reach.
# S06-HN: bob gets a single AccessDenied -> benign (everyday misconfiguration).
APP = assumed_role("AppServerRole", "i-0example0000000a1")
denied = [
    ("iam.amazonaws.com", "ListUsers", "AccessDenied"),
    ("iam.amazonaws.com", "ListRoles", "AccessDenied"),
    ("s3.amazonaws.com", "ListBuckets", "AccessDenied"),
    ("s3.amazonaws.com", "GetBucketPolicy", "AccessDenied"),
    ("ec2.amazonaws.com", "DescribeInstances", "Client.UnauthorizedOperation"),
    ("ec2.amazonaws.com", "DescribeSecurityGroups", "Client.UnauthorizedOperation"),
    ("kms.amazonaws.com", "ListKeys", "AccessDeniedException"),
    ("secretsmanager.amazonaws.com", "ListSecrets", "AccessDeniedException"),
    ("lambda.amazonaws.com", "ListFunctions20150331", "AccessDeniedException"),
    ("rds.amazonaws.com", "DescribeDBInstances", "AccessDenied"),
]
s06 = []
for i, (src, name, code) in enumerate(denied, start=1):
    secs = (i - 1) * 18
    t = f"19:{secs // 60:02d}:{secs % 60:02d}"
    s06.append((ev(f"s06-{i:04d}", D + t + "Z", src, name, APP, "198.51.100.30", read_only=True,
                   ua="aws-sdk-python/1.0 (synthetic)", error_code=code,
                   error_message=f"synthetic: not authorized to perform {name}"),
                "S06", "suspicious", "access_denied_burst", "kept", f"denied call {i} of 10 within 3 minutes"))
s06.append((ev("s06-0101", D + "19:30:00Z", "iam.amazonaws.com", "ListRoles", BOB, "203.0.113.11", read_only=True,
               error_code="AccessDenied", error_message="synthetic: not authorized to perform ListRoles"),
            "S06-HN", "benign", "", "kept", "single denied call; everyday misconfiguration"))
FILES["s06_access_denied_burst.json"] = s06

# ---------------- S07 IAM persistence ----------------
# S07: alice, from an unusual IP, creates user svc-backup-tmp, gives it an access
#      key and attaches AdministratorAccess -> suspicious: a classic way to keep
#      long-term access.
# S07-HN: carol rotates her own key -> benign, but a simple
#      iam_user_or_key_creation rule WILL flag it (deliberate known false positive).
FILES["s07_iam_user_and_key_creation.json"] = [
    (ev("s07-0001", D + "16:00:00Z", "iam.amazonaws.com", "CreateUser", ALICE, "198.51.100.200", read_only=False,
        req={"userName": "svc-backup-tmp"}),
     "S07", "suspicious", "iam_user_or_key_creation", "kept", "new IAM user created from unusual IP"),
    (ev("s07-0002", D + "16:00:30Z", "iam.amazonaws.com", "CreateAccessKey", ALICE, "198.51.100.200",
        read_only=False, req={"userName": "svc-backup-tmp"},
        resp={"accessKey": {"userName": "svc-backup-tmp", "accessKeyId": "EXAMPLE-KEY-ID-0001",
                            "status": "Active", "createDate": D + "16:00:30Z"}}),
     "S07", "suspicious", "iam_user_or_key_creation", "kept", "access key created for the new user"),
    (ev("s07-0003", D + "16:01:00Z", "iam.amazonaws.com", "AttachUserPolicy", ALICE, "198.51.100.200",
        read_only=False,
        req={"userName": "svc-backup-tmp", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}),
     "S07", "suspicious", "iam_policy_modification", "kept", "full admin rights given to the new user"),
    (ev("s07-0101", D + "16:30:00Z", "iam.amazonaws.com", "CreateAccessKey", CAROL, "203.0.113.12",
        read_only=False, req={"userName": "carol"},
        resp={"accessKey": {"userName": "carol", "accessKeyId": "EXAMPLE-KEY-ID-0002",
                            "status": "Active", "createDate": D + "16:30:00Z"}}),
     "S07-HN", "benign", "", "kept",
     "routine key rotation; a naive iam_user_or_key_creation rule WILL flag this (expected false positive)"),
    (ev("s07-0102", D + "16:31:00Z", "iam.amazonaws.com", "DeleteAccessKey", CAROL, "203.0.113.12",
        read_only=False, req={"userName": "carol", "accessKeyId": "EXAMPLE-KEY-ID-OLD"}),
     "S07-HN", "benign", "", "kept", "old key deleted as part of rotation"),
]

# ---------------- S08 S3 public ----------------
# S08: bob, from an unusual IP, sets a bucket policy with Principal "*" and
#      removes the public access block -> suspicious (s3_bucket_made_public).
# S08-HN: carol sets a policy limited to the account itself -> benign.
FILES["s08_s3_bucket_made_public.json"] = [
    (ev("s08-0001", D + "20:00:00Z", "s3.amazonaws.com", "PutBucketPolicy", BOB, "198.51.100.140", read_only=False,
        req={"bucketName": "synthetic-reports-bucket", "bucketPolicy": {
            "Version": "2012-10-17",
            "Statement": [{"Sid": "PublicRead", "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
                           "Resource": "arn:aws:s3:::synthetic-reports-bucket/*"}]}}),
     "S08", "suspicious", "s3_bucket_made_public", "kept", "bucket policy allows anyone (Principal *) to read"),
    (ev("s08-0002", D + "20:01:00Z", "s3.amazonaws.com", "DeleteBucketPublicAccessBlock", BOB, "198.51.100.140",
        read_only=False, req={"bucketName": "synthetic-reports-bucket"}),
     "S08", "suspicious", "s3_bucket_made_public", "kept", "public access block removed"),
    (ev("s08-0101", D + "20:30:00Z", "s3.amazonaws.com", "PutBucketPolicy", CAROL, "203.0.113.12", read_only=False,
        req={"bucketName": "synthetic-internal-bucket", "bucketPolicy": {
            "Version": "2012-10-17",
            "Statement": [{"Sid": "AccountOnly", "Effect": "Allow",
                           "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"}, "Action": "s3:GetObject",
                           "Resource": "arn:aws:s3:::synthetic-internal-bucket/*"}]}}),
     "S08-HN", "benign", "", "kept", "policy limited to own account"),
]


# ---------------- S09 security group ----------------
# S09: the CI role opens SSH (22) to 0.0.0.0/0 -> suspicious
#      (security_group_open_to_world). "0.0.0.0/0" means "the whole internet".
# S09-HN: carol opens HTTPS (443) to one /24 documentation range -> benign.
def sg_ingress(port, cidr):
    return {"groupId": "sg-0example00000001", "ipPermissions": {"items": [
        {"ipProtocol": "tcp", "fromPort": port, "toPort": port, "ipRanges": {"items": [{"cidrIp": cidr}]}}]}}


FILES["s09_security_group_open_to_world.json"] = [
    (ev("s09-0001", D + "21:00:00Z", "ec2.amazonaws.com", "AuthorizeSecurityGroupIngress", CI, "198.51.100.10",
        read_only=False, ua="synthetic-ci-runner/1.0", req=sg_ingress(22, "0.0.0.0/0"), resp={"_return": True}),
     "S09", "suspicious", "security_group_open_to_world", "kept", "SSH (22) opened to 0.0.0.0/0"),
    (ev("s09-0101", D + "21:30:00Z", "ec2.amazonaws.com", "AuthorizeSecurityGroupIngress", CAROL, "203.0.113.12",
        read_only=False, req=sg_ingress(443, "203.0.113.0/24"), resp={"_return": True}),
     "S09-HN", "benign", "", "kept", "HTTPS (443) from one narrow range"),
]

# ---------------- S10 edge cases ----------------
# Robustness cases for the pipeline and future rules (one per record, see the
# notes column): only required fields; missing eventName and a non-ISO time
# (both rejected); exact, conflicting and cross-file duplicates; no eventID;
# uppercase IPv6; "AWS Internal" source; a key spelled "EventName" (rejected);
# mixed-case values; a +02:00 timestamp; and frank's 5-failure brute-force burst
# stored OUT OF ORDER across midnight with some +02:00 times. The burst is
# suspicious (repeated_failed_console_login); a rule that assumes sorted input
# or compares local time strings would miss it.
minimal = {"eventTime": D + "10:15:00Z", "eventSource": "s3.amazonaws.com", "eventName": "ListBuckets",
           "eventID": "s10-0001"}

missing_name = ev("s10-0002", D + "10:16:00Z", "s3.amazonaws.com", "ListBuckets", ALICE, "203.0.113.10",
                  read_only=True)
del missing_name["eventName"]

bad_time = ev("s10-0003", "02/10/2026 10:20", "s3.amazonaws.com", "ListBuckets", ALICE, "203.0.113.10",
              read_only=True)

dup_a = ev("s10-0004", D + "10:25:00Z", "s3.amazonaws.com", "GetObject", ALICE, "203.0.113.10", read_only=True,
           req={"bucketName": "synthetic-reports-bucket", "key": "daily/summary.csv"})

conf_a = ev("s10-0005", D + "10:30:00Z", "ec2.amazonaws.com", "DescribeInstances", BOB, "203.0.113.11",
            read_only=True)
conf_b = copy.deepcopy(conf_a)
conf_b["eventName"] = "DescribeVolumes"

no_id = ev("XX", D + "10:40:00Z", "s3.amazonaws.com", "ListBuckets", CAROL, "203.0.113.12", read_only=True)
del no_id["eventID"]

ipv6 = ev("s10-0006", D + "10:45:00Z", "s3.amazonaws.com", "ListBuckets", ALICE, "2001:DB8:0:0:0:0:0:10",
          read_only=True)

aws_internal = ev("s10-0007", D + "10:47:00Z", "s3.amazonaws.com", "GetBucketLocation", aws_service("AWS Internal"),
                  "AWS Internal", read_only=True, ua="AWS Internal",
                  req={"bucketName": "synthetic-reports-bucket"})

mixed_key = ev("s10-0008", D + "10:48:00Z", "s3.amazonaws.com", "ListBuckets", BOB, "203.0.113.11", read_only=True)
mixed_key = {("EventName" if k == "eventName" else k): v for k, v in mixed_key.items()}

mixed_val = ev("s10-0009", D + "10:50:00Z", "EC2.AmazonAWS.com", "DescribeRegions", BOB, "203.0.113.11",
               read_only=True, region=" US-EAST-1 ")

offset = ev("s10-0010", "2026-02-10T13:00:00+02:00", "iam.amazonaws.com", "ListUsers", CAROL, "203.0.113.12",
            read_only=True)

FRANK = iam_user("frank")
burst = {
    "s10-0101": D + "23:58:10Z",
    "s10-0102": D + "23:58:50Z",
    "s10-0103": "2026-02-11T01:59:30+02:00",  # = 23:59:30 UTC on Feb 10
    "s10-0104": "2026-02-11T00:00:15Z",
    "s10-0105": "2026-02-11T02:01:05+02:00",  # = 00:01:05 UTC on Feb 11
}
burst_records = {eid: console_login(eid, t, FRANK, "192.0.2.66", success=False, mfa=False) for eid, t in burst.items()}
burst_records["s10-0104"]["eventSource"] = "SIGNIN.AmazonAWS.com"  # mixed case inside the burst
burst_order = ["s10-0104", "s10-0102", "s10-0105", "s10-0101", "s10-0103"]  # deliberately shuffled

BURST_NOTE = "frank burst (5 fails in ~3 min across midnight, shuffled file order, some +02:00 times)"
s10 = [
    (minimal, "S10", "benign", "", "kept", "only the 3 required fields + eventID; all optional fields missing"),
    (missing_name, "S10", "invalid", "", "rejected", "missing required eventName"),
    (bad_time, "S10", "invalid", "", "rejected", "eventTime not ISO 8601"),
    (dup_a, "S10", "benign", "", "kept", "first copy of s10-0004 (kept)"),
    (copy.deepcopy(dup_a), "S10", "benign", "", "duplicate_dropped", "exact duplicate of record 3 (first copy kept)"),
    (conf_a, "S10", "benign", "", "kept", "first copy of s10-0005 (kept)"),
    (conf_b, "S10", "benign", "", "duplicate_dropped",
     "same eventID as record 5 but eventName differs (conflicting duplicate); first copy kept"),
    (copy.deepcopy(s01[2]), "S10", "benign", "", "duplicate_dropped",
     "exact copy of s01-0003; S01 copy kept because s01_*.json is read before s10_*.json"),
    (no_id, "S10", "benign", "", "kept", "no eventID; kept with a warning, cannot be de-duplicated"),
    (ipv6, "S10", "benign", "", "kept", "IPv6 source from 2001:db8::/32 documentation range, uppercase"),
    (aws_internal, "S10", "benign", "", "kept", "source is 'AWS Internal' (AWS acting on your behalf)"),
    (mixed_key, "S10", "invalid", "", "rejected", "key spelled 'EventName' instead of 'eventName'"),
    (mixed_val, "S10", "benign", "", "kept", "mixed-case eventSource and padded uppercase region"),
    (offset, "S10", "benign", "", "kept", "+02:00 offset; 11:00 UTC"),
]
for eid in burst_order:
    s10.append((burst_records[eid], "S10", "suspicious", "repeated_failed_console_login", "kept", BURST_NOTE))
FILES["s10_edge_cases.json"] = s10

# ---------------- S11 IAM policy modification ----------------
# Tests the iam_policy_modification rule (Milestone 4).
# S11 (suspicious) - the rule should fire; each is a true positive:
#   0001 AppServerRole gives ITSELF an inline "*:*" policy, 7 min after the S06
#        AccessDenied burst, from the same IP -> self-escalation (high/high).
#   0002 alice (unusual IP from S07) makes a new "iam:*" policy version the
#        default. policyDocument is URL-encoded, as some logs record it (high/medium).
#   0003 alice changes AuditReadRole's trust policy so ANYONE (*) may assume it (high/medium).
#   0004 alice removes CIDeployRole's permissions boundary (guardrail) (medium/low).
#   0005 alice adds HERSELF to the Admins group; the group's permissions are not
#        visible in the event, so it stays medium/low (self-targeted is noted).
# S11-HN (benign) - hard negatives the rule WILL flag (documented false positives):
#   0101 approved ReadOnlyAccess attach; 0102 CI pipeline adds a bucket-scoped
#   inline policy to another role; 0103 detach from a departing user; 0104
#   delete an old policy version.
# S11-HN (benign) - true negatives the rule must NOT flag:
#   0201 GetPolicy and 0202 ListAttachedRolePolicies (read-only);
#   0203 PutUserPolicy that FAILED with AccessDenied (failed calls are ignored).
DEV_POLICY = f"arn:aws:iam::{ACCOUNT}:policy/synthetic-dev-policy"


def policy_json(statements):
    return json.dumps({"Version": "2012-10-17", "Statement": statements})


ALICE_ODD_IP = "198.51.100.200"
FILES["s11_iam_policy_modification.json"] = [
    (ev("s11-0101", D + "09:30:00Z", "iam.amazonaws.com", "AttachRolePolicy", CAROL, "203.0.113.12",
        read_only=False,
        req={"roleName": "AuditReadRole", "policyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}),
     "S11-HN", "benign", "", "kept",
     "approved read-only access for auditors; iam_policy_modification WILL flag this (expected false positive)"),
    (ev("s11-0102", D + "10:02:00Z", "iam.amazonaws.com", "PutRolePolicy", CI, "198.51.100.10", read_only=False,
        ua="synthetic-ci-runner/1.0",
        req={"roleName": "synthetic-report-builder-role", "policyName": "artifact-read",
             "policyDocument": policy_json([{"Effect": "Allow", "Action": "s3:GetObject",
                                             "Resource": "arn:aws:s3:::synthetic-artifacts-bucket/*"}])}),
     "S11-HN", "benign", "", "kept",
     "CI deployment adds a bucket-scoped policy; iam_policy_modification WILL flag this (expected false positive)"),
    (ev("s11-0103", D + "11:10:00Z", "iam.amazonaws.com", "DetachUserPolicy", CAROL, "203.0.113.12",
        read_only=False, req={"userName": "former-contractor", "policyArn": DEV_POLICY}),
     "S11-HN", "benign", "", "kept",
     "access removed from a departing user; iam_policy_modification WILL flag this (expected false positive)"),
    (ev("s11-0104", D + "11:15:00Z", "iam.amazonaws.com", "DeletePolicyVersion", CAROL, "203.0.113.12",
        read_only=False, req={"policyArn": DEV_POLICY, "versionId": "v1"}),
     "S11-HN", "benign", "", "kept",
     "old policy version cleaned up; iam_policy_modification WILL flag this (expected false positive)"),
    (ev("s11-0201", D + "11:20:00Z", "iam.amazonaws.com", "GetPolicy", CAROL, "203.0.113.12", read_only=True,
        req={"policyArn": DEV_POLICY}),
     "S11-HN", "benign", "", "kept", "read-only IAM call; must not be flagged"),
    (ev("s11-0202", D + "11:21:00Z", "iam.amazonaws.com", "ListAttachedRolePolicies", CAROL, "203.0.113.12",
        read_only=True, req={"roleName": "AuditReadRole"}),
     "S11-HN", "benign", "", "kept", "read-only IAM call with a policy-like name; must not be flagged"),
    (ev("s11-0203", D + "11:25:00Z", "iam.amazonaws.com", "PutUserPolicy", BOB, "203.0.113.11", read_only=False,
        error_code="AccessDenied", error_message="synthetic: not authorized to perform PutUserPolicy",
        req={"userName": "bob", "policyName": "self-grant",
             "policyDocument": policy_json([{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}])}),
     "S11-HN", "benign", "", "kept", "FAILED policy change (AccessDenied); failed calls must not be flagged"),
    (ev("s11-0002", D + "16:03:00Z", "iam.amazonaws.com", "CreatePolicyVersion", ALICE, ALICE_ODD_IP,
        read_only=False,
        req={"policyArn": DEV_POLICY, "setAsDefault": True,
             "policyDocument": quote(policy_json([{"Effect": "Allow", "Action": ["iam:*"], "Resource": "*"}]))},
        resp={"policyVersion": {"versionId": "v3", "isDefaultVersion": True, "createDate": D + "16:03:00Z"}}),
     "S11", "suspicious", "iam_policy_modification", "kept",
     "new default policy version grants iam:* on *; document is URL-encoded"),
    (ev("s11-0003", D + "16:04:00Z", "iam.amazonaws.com", "UpdateAssumeRolePolicy", ALICE, ALICE_ODD_IP,
        read_only=False,
        req={"roleName": "AuditReadRole",
             "policyDocument": policy_json([{"Effect": "Allow", "Principal": {"AWS": "*"},
                                             "Action": "sts:AssumeRole"}])}),
     "S11", "suspicious", "iam_policy_modification", "kept", "trust policy now lets anyone (*) assume the role"),
    (ev("s11-0004", D + "16:05:00Z", "iam.amazonaws.com", "DeleteRolePermissionsBoundary", ALICE, ALICE_ODD_IP,
        read_only=False, req={"roleName": "CIDeployRole"}),
     "S11", "suspicious", "iam_policy_modification", "kept", "permissions boundary (guardrail) removed"),
    (ev("s11-0005", D + "16:06:00Z", "iam.amazonaws.com", "AddUserToGroup", ALICE, ALICE_ODD_IP,
        read_only=False, req={"groupName": "Admins", "userName": "alice"}),
     "S11", "suspicious", "iam_policy_modification", "kept", "user adds herself to the Admins group"),
    (ev("s11-0001", D + "19:10:00Z", "iam.amazonaws.com", "PutRolePolicy", APP, "198.51.100.30", read_only=False,
        ua="aws-sdk-python/1.0 (synthetic)",
        req={"roleName": "AppServerRole", "policyName": "synthetic-maintenance",
             "policyDocument": policy_json([{"Effect": "Allow", "Action": "*", "Resource": "*"}])}),
     "S11", "suspicious", "iam_policy_modification", "kept",
     "role grants itself *:* right after the S06 AccessDenied burst (self-escalation)"),
]

# ---------------- write ----------------
# Write each scenario file and one label row per record. The label key is
# (file, record_index) because duplicates share eventIDs and one record has none.
SCEN_DIR.mkdir(parents=True, exist_ok=True)
LABEL_DIR.mkdir(parents=True, exist_ok=True)
rows = []
for fname, items in FILES.items():
    records = [item[0] for item in items]
    (SCEN_DIR / fname).write_text(json.dumps({"Records": records}, indent=2) + "\n", encoding="utf-8")
    for idx, (rec, sid, label, rules, outcome, notes) in enumerate(items):
        rows.append({"file": fname, "record_index": idx, "event_id": rec.get("eventID", ""),
                     "scenario_id": sid, "label": label, "expected_rule": rules,
                     "pipeline_outcome": outcome, "notes": notes})

with open(LABEL_DIR / "ground_truth.csv", "w", newline="", encoding="utf-8") as fh:
    w = csv.DictWriter(fh, fieldnames=list(rows[0]))
    w.writeheader()
    w.writerows(rows)

SCENARIOS = [
    ("S01", "s01_benign_baseline.json", "Normal workday", "benign", "",
     "MFA console logins, S3/EC2/CloudWatch reads, CI role deployments, AWS-service calls"),
    ("S02", "s02_failed_console_logins.json", "Repeated failed console logins then success", "suspicious",
     "repeated_failed_console_login", "6 failed logins for dave in 5 minutes from one IP, then a successful login with MFA"),
    ("S02-HN", "s02_failed_console_logins.json", "Single mistyped password", "benign", "",
     "alice fails once then succeeds with MFA from her usual IP"),
    ("S03", "s03_root_account_usage.json", "Root account usage", "suspicious",
     "root_account_activity;console_login_without_mfa;iam_user_or_key_creation",
     "root logs in without MFA, lists users and creates an access key"),
    ("S04", "s04_console_login_without_mfa.json", "Console login without MFA", "suspicious",
     "console_login_without_mfa", "bob signs in successfully without MFA"),
    ("S04-HN", "s04_console_login_without_mfa.json", "Console login with MFA", "benign", "", "bob signs in with MFA"),
    ("S05", "s05_cloudtrail_logging_disabled.json", "CloudTrail logging disabled", "suspicious",
     "cloudtrail_logging_disabled", "StopLogging then DeleteTrail from an unusual IP"),
    ("S05-HN", "s05_cloudtrail_logging_disabled.json", "CloudTrail configuration viewed", "benign", "",
     "read-only DescribeTrails and GetTrailStatus"),
    ("S06", "s06_access_denied_burst.json", "AccessDenied burst", "suspicious", "access_denied_burst",
     "one role gets 10 denied calls across 7 services in 3 minutes"),
    ("S06-HN", "s06_access_denied_burst.json", "Single AccessDenied", "benign", "", "bob gets one denied call"),
    ("S07", "s07_iam_user_and_key_creation.json", "New admin user with access key", "suspicious",
     "iam_user_or_key_creation;iam_policy_modification",
     "CreateUser, CreateAccessKey and AttachUserPolicy(AdministratorAccess) from an unusual IP"),
    ("S07-HN", "s07_iam_user_and_key_creation.json", "Routine access key rotation", "benign", "",
     "carol creates a new key for herself and deletes the old one (expected false positive)"),
    ("S08", "s08_s3_bucket_made_public.json", "S3 bucket made public", "suspicious", "s3_bucket_made_public",
     "bucket policy with Principal * and public access block removed"),
    ("S08-HN", "s08_s3_bucket_made_public.json", "S3 policy limited to own account", "benign", "",
     "bucket policy granting access only to the account itself"),
    ("S09", "s09_security_group_open_to_world.json", "Security group open to world", "suspicious",
     "security_group_open_to_world", "SSH port 22 opened to 0.0.0.0/0"),
    ("S09-HN", "s09_security_group_open_to_world.json", "Narrow security group rule", "benign", "",
     "HTTPS port 443 opened to one /24 range"),
    ("S10", "s10_edge_cases.json", "Edge cases", "mixed", "repeated_failed_console_login",
     "missing/invalid fields, duplicates (exact, conflicting, cross-file), no eventID, IPv6, AWS Internal, "
     "mixed case, +02:00 offsets, and a shuffled brute-force burst across midnight"),
    ("S11", "s11_iam_policy_modification.json", "Risky IAM policy and permission changes", "suspicious",
     "iam_policy_modification",
     "self-granted *:* inline policy, iam:* default policy version, trust open to *, boundary removed, "
     "user adds herself to Admins"),
    ("S11-HN", "s11_iam_policy_modification.json", "Routine IAM policy changes and look-alikes", "benign", "",
     "approved attach, CI bucket-scoped policy, detach, version cleanup (flagged: known false positives); "
     "read-only IAM calls and a failed PutUserPolicy (must not be flagged)"),
]
with open(LABEL_DIR / "scenarios.csv", "w", newline="", encoding="utf-8") as fh:
    w = csv.writer(fh)
    w.writerow(["scenario_id", "file", "title", "label", "expected_rule", "description"])
    w.writerows(SCENARIOS)

print(f"wrote {len(FILES)} scenario files, {len(rows)} label rows")
