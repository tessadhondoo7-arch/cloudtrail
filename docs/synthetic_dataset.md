# Synthetic dataset and ground-truth labels

This document describes the synthetic CloudTrail scenarios in
`data/synthetic/scenarios/`, the label files in `data/labels/`, and how the labels
will be used to score detection rules in a later milestone.

> **Everything here is synthetic.** The events imitate the *shape* of real
> CloudTrail records but are simplified and hand-made. They are test fixtures,
> not real logs, and not an authoritative reference for CloudTrail's format.

## Safety placeholders

| Kind | Values used |
|---|---|
| Account ID | `111122223333` only (AWS documentation placeholder) |
| IPv4 | `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` (RFC 5737 documentation ranges) |
| IPv6 | `2001:db8::/32` (RFC 3849 documentation range) |
| Users / roles | made up: alice, bob, carol, dave, frank, `CIDeployRole`, `AppServerRole` |
| Access key IDs | obviously fake strings such as `EXAMPLE-KEY-ID-0001`; no secrets |

`tests/test_synthetic_dataset.py` enforces these rules automatically: any other
account ID, a non-documentation IP, or an AWS-key-shaped string fails the tests.

## Directory layout

```
data/
├── synthetic/
│   ├── valid_basic.json, mixed_quality.json, ...   ← Milestone 2 pipeline fixtures
│   └── scenarios/                                   ← this dataset
│       ├── s01_benign_baseline.json
│       ├── s02_failed_console_logins.json
│       ├── ...
│       ├── s10_edge_cases.json
│       └── s11_iam_policy_modification.json
└── labels/
    ├── ground_truth.csv     ← one row per record
    └── scenarios.csv        ← one row per scenario
```

The loader only searches the folder you give it (it does not look inside
subfolders), so `load_events("data/synthetic")` still loads only the four
Milestone 2 fixtures. The scenarios are loaded with
`load_events("data/synthetic/scenarios")`.

All scenario events take place on one fictional day, **2026-02-10** (UTC), with
one brute-force burst crossing midnight into 2026-02-11.

## Label format

### `ground_truth.csv`: one row per physical record

| Column | Meaning |
|---|---|
| `file` | scenario file name, e.g. `s02_failed_console_logins.json` |
| `record_index` | 0-based position in that file's `Records` array |
| `event_id` | the record's `eventID` (empty if the record has none) |
| `scenario_id` | `S01`–`S10`; a `-HN` suffix marks a *hard negative* |
| `label` | `suspicious`, `benign`, or `invalid` (the pipeline should reject it) |
| `expected_rule` | **every** future rule that should fire on this event, separated by `;` (order does not matter). Empty for benign and invalid rows. |
| `pipeline_outcome` | what Milestone 2 does with it: `kept`, `rejected`, or `duplicate_dropped` |
| `notes` | short human explanation |

**Why the key is `(file, record_index)` and not `event_id`:** duplicates share an
eventID, and one edge-case record has no eventID at all. Using the file plus
position gives every record exactly one row, so the labels can say which copy
of a duplicate is kept. Every `NormalizedEvent` already carries `source_file`
and `record_index`, so future findings can be matched to these rows.

MITRE ATT&CK technique IDs are **deliberately not included yet**. They will
be added and checked against the official ATT&CK site in a later milestone.

### `scenarios.csv`: one row per scenario

`scenario_id, file, title, label, expected_rule, description`. Here
`expected_rule` is the union of the rules across that scenario's rows, and
`label` is `mixed` for S10.

## Future rule definitions (not implemented yet)

These are the definitions the labels are based on. They will be implemented
in the detection milestone; if a definition changes, the labels must be
reviewed too.

| Rule | Fires on |
|---|---|
| `repeated_failed_console_login` | ≥ 5 failed `ConsoleLogin` events for the same user within 10 minutes (times compared in UTC, regardless of file order). Flags the failed attempts **and** a successful login by that user from the same IP within 10 minutes after the burst. |
| `root_account_activity` | any event where `userIdentity.type` is `Root`. |
| `console_login_without_mfa` | **successful** `ConsoleLogin` only (`responseElements.ConsoleLogin == "Success"`) with `additionalEventData.MFAUsed == "No"`. Failed logins never count, because failed logins usually report `MFAUsed: "No"` even when the user has MFA. |
| `cloudtrail_logging_disabled` | `cloudtrail.amazonaws.com` events `StopLogging` or `DeleteTrail`. |
| `access_denied_burst` | ≥ 8 events from the same identity ARN within 5 minutes with `errorCode` in `AccessDenied`, `AccessDeniedException`, `UnauthorizedOperation`, `Client.UnauthorizedOperation`. |
| `iam_user_or_key_creation` | successful (no `errorCode`) IAM `CreateUser`, `CreateAccessKey` or `CreateLoginProfile`. |
| `iam_policy_modification` | successful IAM call from a fixed list of 23 policy and permission APIs (attach/detach, put/delete inline policy, policy versions, trust policy, permissions boundaries, `AddUserToGroup`). **Implemented**; see [rules/iam_policy_modification.md](rules/iam_policy_modification.md). Replaced the earlier `admin_policy_attached` label: admin grants are now this rule's *high* severity. |
| `s3_bucket_made_public` | `PutBucketPolicy` with an `Allow` statement whose principal is `*` (or `{"AWS": "*"}`), or `DeleteBucketPublicAccessBlock`. |
| `security_group_open_to_world` | `AuthorizeSecurityGroupIngress` with a source of `0.0.0.0/0` or `::/0`. |

**Overlaps:** one event can match several rules. Every matching rule is listed in
`expected_rule`, e.g. root's `CreateAccessKey` is
`root_account_activity;iam_user_or_key_creation`. The tests re-check this for
every rule that looks at a single event.

## Scenarios

Each scenario answers four questions: **what it simulates**, **why it has this label**,
**which future rule it tests**, and **the expected outcome**.

A **hard negative (`-HN`)** is benign activity that looks similar to the
suspicious scenario. It checks that a rule is precise and not just "fires on that
API name".

| ID | What it simulates | Why this label | Rule(s) tested | Expected outcome |
|---|---|---|---|---|
| S01 | A normal workday: alice, bob, carol sign in with MFA; S3/EC2/CloudWatch reads; `CIDeployRole` deploys a Lambda and uploads an artifact; EC2 assumes a role (AWS service); `GetCallerIdentity`. 12 events. | Routine, expected activity. | All (baseline for false positives) | No rule fires on any of the 12 events. |
| S02 | dave: 6 failed console logins from `198.51.100.77` in ~4.5 min, then a successful login (with MFA) from the same IP. | Pattern of password guessing; the success right after may mean the password was guessed. | `repeated_failed_console_login` | All 7 events flagged. The success used MFA, so `console_login_without_mfa` must **not** fire; the failures don't count for that rule either. |
| S02-HN | alice mistypes her password once, then succeeds with MFA from her usual IP. | One failure is normal. | `repeated_failed_console_login`, `console_login_without_mfa` | Nothing fires. |
| S03 | The root user signs in **without MFA**, lists IAM users, and creates an access key. | Root should almost never be used day to day; root access keys are especially risky. | `root_account_activity`, `console_login_without_mfa`, `iam_user_or_key_creation` | Login: root + no-MFA. ListUsers: root. CreateAccessKey: root + key creation. |
| S04 | bob signs in successfully without MFA. | Sign-in without MFA weakens account security. | `console_login_without_mfa` | 1 event flagged. |
| S04-HN | bob signs in with MFA. | Correct behavior. | `console_login_without_mfa` | Nothing fires. |
| S05 | carol's credentials, from an unusual IP, call `StopLogging` then `DeleteTrail`. | Turning off audit logging hides further activity. | `cloudtrail_logging_disabled` | Both events flagged. |
| S05-HN | carol views trail configuration (`DescribeTrails`, `GetTrailStatus`). | Read-only; no change to logging. | `cloudtrail_logging_disabled` | Nothing fires. |
| S06 | `AppServerRole` gets 10 denied calls across IAM, S3, EC2, KMS, Secrets Manager, Lambda and RDS in 3 minutes, using several error code spellings. | Looks like stolen credentials probing what they can access. | `access_denied_burst` | All 10 flagged. |
| S06-HN | bob gets one `AccessDenied` on `ListRoles`. | Single denial is an everyday misconfiguration. | `access_denied_burst` | Nothing fires. |
| S07 | alice, from an unusual IP, creates user `svc-backup-tmp`, creates an access key for it, attaches `AdministratorAccess`. | Classic way to keep long-term access. | `iam_user_or_key_creation`, `iam_policy_modification` | CreateUser and CreateAccessKey: key creation. AttachUserPolicy: policy modification (high severity). |
| S07-HN | carol rotates her own access key (create new, delete old). | Routine security hygiene. | `iam_user_or_key_creation` | Ideally nothing fires, **but** the rule as defined above *will* flag `CreateAccessKey`. This is a deliberate, known false positive (`s07-0101`) that shows the precision cost of a simple rule. |
| S08 | bob, from an unusual IP, sets a bucket policy with `Principal: "*"` and removes the bucket's public access block. | Makes data readable by anyone on the internet. | `s3_bucket_made_public` | Both flagged. |
| S08-HN | carol sets a bucket policy that grants access only to the account itself. | Tightening, not exposing. | `s3_bucket_made_public` | Nothing fires. |
| S09 | `CIDeployRole` opens SSH (port 22) to `0.0.0.0/0`. | Exposes servers to the whole internet. | `security_group_open_to_world` | 1 event flagged. |
| S09-HN | carol opens HTTPS (443) to one `/24` documentation range. | Narrow, expected rule. | `security_group_open_to_world` | Nothing fires. |
| S10 | Edge cases (below). | Tests the pipeline and how robust the future rules are. | pipeline; `repeated_failed_console_login` | Per row; see the table below. |
| S11 | `AppServerRole` gives **itself** an inline `*:*` policy right after the S06 burst; alice (unusual IP) makes an `iam:*` policy version the default (URL-encoded document), opens `AuditReadRole`'s trust to `*`, removes `CIDeployRole`'s permissions boundary, and adds herself to `Admins`. | Privilege escalation and guardrail removal. | `iam_policy_modification` | All 5 flagged (severity/confidence: high/high, high/medium, high/medium, medium/low, medium/low). |
| S11-HN | Approved `ReadOnlyAccess` attach; CI adds a bucket-scoped inline policy to another role; detach from a departing user; old policy version deleted; read-only `GetPolicy` / `ListAttachedRolePolicies`; a **failed** `PutUserPolicy`. | Routine administration and look-alikes. | `iam_policy_modification` | The 4 changes **will** be flagged (known false positives `s11-0101`–`0104`). The 2 read-only calls and the failed call must not be. |

### S10 edge cases, with observed pipeline behaviour

The `pipeline_outcome` values below were taken from **running the unchanged
Milestone 2 code**, not assumed. The tests fail if the code's behaviour
ever stops matching them.

| Index | event_id | Edge case | Label | Observed pipeline outcome |
|---|---|---|---|---|
| 0 | s10-0001 | only `eventTime`, `eventSource`, `eventName`, `eventID`; every optional field missing | benign | kept; region, IP and identity are `None`; no warning |
| 1 | s10-0002 | `eventName` missing | invalid | rejected: "missing or empty required field(s): eventName" |
| 2 | s10-0003 | `eventTime` = `02/10/2026 10:20` (not ISO 8601) | invalid | rejected: "unparseable eventTime" |
| 3 | s10-0004 | first copy | benign | kept |
| 4 | s10-0004 | exact duplicate of index 3 | benign | duplicate_dropped ("exact duplicate … skipped") |
| 5 | s10-0005 | first copy (`DescribeInstances`) | benign | kept |
| 6 | s10-0005 | **conflicting duplicate**: same ID, `eventName` = `DescribeVolumes` | benign | duplicate_dropped ("DIFFERENT content … first kept"); the first copy wins |
| 7 | s01-0003 | **cross-file** exact copy of an S01 event | benign | duplicate_dropped; the S01 copy is kept |
| 8 | *(none)* | **no eventID** | benign | kept, with warning "missing eventID; duplicates of this record cannot be detected" |
| 9 | s10-0006 | uppercase IPv6 `2001:DB8:0:0:0:0:0:10` | benign | kept; IP normalized to `2001:db8::10` |
| 10 | s10-0007 | source is `AWS Internal` | benign | kept; `source_is_aws_service = True` |
| 11 | s10-0008 | **mixed-case key**: `EventName` instead of `eventName` | invalid | rejected as "missing … eventName". Keys are matched exactly (case-sensitive). |
| 12 | s10-0009 | **mixed-case values**: `EC2.AmazonAWS.com`, region `" US-EAST-1 "` | benign | kept; normalized to `ec2.amazonaws.com`, `us-east-1` |
| 13 | s10-0010 | **+02:00 timestamp** `2026-02-10T13:00:00+02:00` | benign | kept; converted to `11:00:00+00:00` UTC |
| 14–18 | s10-0101 … 0105 | **shuffled burst**: frank, 5 failed logins from `192.0.2.66` between 23:58:10 and 00:01:05 UTC, crossing midnight. Stored out of order, two times written as `+02:00`, one `eventSource` in mixed case. | suspicious, `repeated_failed_console_login` | all kept and converted to UTC. A rule that assumes sorted input or compares local time strings would miss it. |

### Duplicates across files and reading order

`expand_paths()` sorts a folder's files by name, so `s01_…` is read before
`s10_…`, and de-duplication keeps the **first** copy it sees. When the whole
`scenarios/` folder is loaded, the S01 copy of `s01-0003` is kept and the S10
copy is dropped, which is what the labels say. If `s10_edge_cases.json` were
loaded **on its own**, its copy would be kept instead. The labels assume the
whole folder is loaded.

## Dataset totals (checked by the tests)

| | Count |
|---|---|
| Scenario files | 11 |
| Records | 82 |
| Kept by the pipeline | 76 |
| Rejected (`invalid`) | 3 |
| Duplicates dropped | 3 |
| Kept and `suspicious` | 39 |
| Kept and `benign` | 37 |

## How the labels will be used to score detections

Only rows with `pipeline_outcome = kept` are scored. Rejected and dropped
records never reach the detection rules, so counting them would be unfair.

Each kept event ends up in one of four boxes, which together form the
**confusion matrix**:

| | Flagged | Not flagged |
|---|---|---|
| **Actually positive** | True Positive (TP) | False Negative (FN) |
| **Actually negative** | False Positive (FP) | True Negative (TN) |

From those counts:

- **Precision** = TP / (TP + FP). *"When we raise an alert, how often is it right?"* Hard negatives push this down if rules are too broad.
- **Recall** = TP / (TP + FN). *"Of the real suspicious events, how many did we catch?"*
- **F1** = 2 × Precision × Recall / (Precision + Recall). Combines both into one number; it is high only if both are high.

What "positive" and "flagged" mean depends on the scoring mode.

### Mode 1: "any rule"

*Was a suspicious event flagged at all?*

- **Positive** = row labeled `suspicious`.
- **Flagged** = at least one rule produced a finding that includes this event.
- Which rule fired does not matter.

This answers: "would an analyst have been alerted to this event?"

### Mode 2: "per rule"

*Was it flagged by the expected rule?* This is computed separately for each rule R.

- **Positive for R** = row whose `expected_rule` contains R.
- **Flagged by R** = rule R produced a finding that includes this event.
- TP = R fired and R was expected. FP = R fired but R was not expected,
  even if the event is suspicious for a *different* reason. FN = R was expected
  but did not fire.

This answers: "is each individual rule doing its own job?" One event can be
a positive for several rules (S03's `CreateAccessKey` counts for both
`root_account_activity` and `iam_user_or_key_creation`).

### Why both modes

A suspicious event caught by the "wrong" rule counts as a **TP in any-rule**
mode, but as an **FP for the rule that fired** and an **FN for the rule that
should have fired** in per-rule mode. Any-rule mode measures the overall alert
coverage; per-rule mode shows which specific rules need work.

**Arithmetic illustration only:** these are made-up numbers, not results. If a
rule fired on 10 events, 8 of them correct, and there were 16 events it should
have caught: precision = 8/10 = 0.80, recall = 8/16 = 0.50,
F1 = 2 × 0.80 × 0.50 / 1.30 ≈ 0.62.

For multi-event rules (`repeated_failed_console_login`, `access_denied_burst`),
"flagged" means the event is listed in the finding's evidence, so every
event in the burst is scored individually.

## Known limitations

- Small and hand-made: 82 records. Metrics from it show whether rules behave as
  designed; they say nothing about real-world accuracy.
- Field contents are simplified approximations of CloudTrail; not every field a
  real event would carry is present.
- Each label reflects the definitions above. Change a rule definition and the
  labels must be reviewed (the single-event checks in the tests help with that).
- Labels assume the whole `scenarios/` folder is loaded at once (see the duplicates
  section above).

## To-do

- [ ] **Data-integrity warning for conflicting duplicate eventIDs.** Today the
  pipeline keeps the first copy and drops the later one with a warning (S10,
  index 6). If the dropped copy were the malicious one, for example in a
  tampered log, detection would never see it. Later, raise a dedicated
  data-integrity warning (for example `integrity: conflicting_duplicate_event_id`)
  that names both copies and the fields that differ. Consider keeping both copies
  available to the rules. This requires changing `normalize.py`, so it will be
  agreed before it is implemented, and the S10 labels and tests updated with it.
- [ ] Clearer message when a required key exists with different capitalization
  (e.g. `EventName`): today it is reported as "missing eventName".

## Regenerating the dataset

The files are produced by `scripts/generate_synthetic_dataset.py`, which keeps
each record and its label side by side:

```powershell
python scripts/generate_synthetic_dataset.py
pytest tests/test_synthetic_dataset.py
```

Edit the script, not the JSON or CSV files directly, then re-run the tests.
