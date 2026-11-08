# Rule: `iam_policy_modification`

| | |
|---|---|
| Rule ID (stable) | `iam_policy_modification` |
| Name | IAM policy or permission modification |
| Code | `src/cloudtrail_mapper/rules/iam_policy_modification.py` |
| Tests | `tests/test_rule_iam_policy_modification.py` |
| Scope | one finding per matching event |
| MITRE ATT&CK | `not_mapped`: will be added after verification against the official ATT&CK site |

## What it detects

**Successful** calls to `iam.amazonaws.com` that change what an identity is
allowed to do, or who may assume a role. It matches these 23 `eventName` values:

| Starting severity | API names |
|---|---|
| medium: can grant or widen access | `AttachUserPolicy`, `AttachGroupPolicy`, `AttachRolePolicy`, `PutUserPolicy`, `PutGroupPolicy`, `PutRolePolicy`, `SetDefaultPolicyVersion`, `UpdateAssumeRolePolicy`, `DeleteUserPermissionsBoundary`, `DeleteRolePermissionsBoundary`, `AddUserToGroup` |
| medium if `setAsDefault` is true, otherwise low | `CreatePolicyVersion` |
| low: removes access or has no immediate effect | `DetachUserPolicy`, `DetachGroupPolicy`, `DetachRolePolicy`, `DeleteUserPolicy`, `DeleteGroupPolicy`, `DeleteRolePolicy`, `CreatePolicy`, `DeletePolicy`, `DeletePolicyVersion`, `PutUserPermissionsBoundary`, `PutRolePermissionsBoundary` |

Read-only IAM calls (`Get*`, `List*`) and calls to other services
(e.g. S3 `PutBucketPolicy`) never match.

## Why it matters, and why a match is not proof

Changing permissions is how someone who already has a foothold widens their access
(escalation) or makes sure they keep it (persistence). The same calls are
everyday administration. **A match means "this permission change deserves a
look", never "this is an attack".** Every finding carries that disclaimer.

## Evidence used

`eventSource`, `eventName`, `errorCode`, `eventTime`, `eventID` (+ file and
record index), `userIdentity` (type, ARN, name; for assumed roles the role
name from `sessionContext.sessionIssuer.userName`), `sourceIPAddress`,
`userAgent`, `awsRegion`, and from `requestParameters`: `userName`,
`roleName`, `groupName`, `policyArn`, `policyName`, `versionId`,
`setAsDefault`, `policyDocument`.

`policyDocument` is usually a JSON string and may be URL-encoded. Both are
decoded. If it cannot be parsed, the finding says so and the contents are not assessed.

## Severity: potential impact if misused

1. Start from the table above.
2. **Raise medium to high** if the change is a *broad grant*:
   - an AWS-managed `AdministratorAccess` or `IAMFullAccess` policy is attached
     (the full `arn:aws:iam::aws:policy/...` ARN is required; a customer policy
     with the same name is not assumed to be the real one);
   - a policy document has an `Allow` statement with `Action` `*` or `iam:*`
     on `Resource` `*`;
   - a trust policy (`UpdateAssumeRolePolicy`) allows principal `*`.
3. Low-severity calls are **not** raised even if their document is broad
   (e.g. `CreatePolicy`), because nothing becomes effective yet. The reason
   text notes the broad document.

## Confidence: how strongly the evidence suggests "not routine"

Confidence is **not** a probability of malicious intent.

| Confidence | When |
|---|---|
| high | effective broad grant **and** the caller changed its own permissions (self-escalation pattern) |
| medium | effective broad grant |
| low | everything else: most policy changes are routine |

"Changed its own permissions" compares the caller with the target of the same
kind: IAM user with `userName`, or assumed role (role name from `sessionIssuer`,
or from the ARN `assumed-role/<role>/<session>` if `sessionContext` is missing)
with `roleName`. The normalized `identity_name` is **not** used for roles because
it falls back to the *session* name when `sessionContext` is missing.

## Failed calls

Events with any `errorCode` are ignored: nothing was changed. Repeated
failures are the job of the future `access_denied_burst` rule.

## Common benign explanations

- An administrator granting or removing access as part of normal duties.
- Infrastructure-as-code (Terraform, CloudFormation, CDK) applying policies during a deployment.
- A scheduled access review or clean-up detaching unused permissions.
- An approved, time-limited break-glass permission grant.
- Onboarding a person or vendor (adding them to a group or a role trust).

## Limitations

- **No baseline.** Routine changes produce findings. On the synthetic data, 4 of the
  10 findings are benign hard negatives (`s11-0101` to `s11-0104`).
- **The wildcard check is simple.** It misses dangerous non-wildcard combinations
  (e.g. `iam:PassRole` + `lambda:CreateFunction`) and ignores `NotAction`,
  `NotResource` and `Condition`.
- **Policy contents are often not in the event.** `Attach*` only names the policy,
  `SetDefaultPolicyVersion` does not show the version, and `AddUserToGroup` does not show
  the group's permissions. These stay medium.
- **"Low" can still widen access.** Detaching a policy that contained a `Deny`, or
  replacing a boundary with a looser one.
- **Self-targeting via groups is not detected.** Changing the policy of a group the
  caller belongs to is not recognised as self-modification.
- **Each event is judged alone.** Sequences such as create user, then attach admin,
  then create key are not linked.
- **Only IAM is covered.** Resource policies (S3, KMS, ...) and Organizations SCPs are out of scope.
