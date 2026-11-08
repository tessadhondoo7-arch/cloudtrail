"""Rule: IAM policy or permission modification.

Flags SUCCESSFUL IAM calls that change what an identity may do (policies,
permissions boundaries, group membership) or who may assume a role (trust
policy). Such changes are how an attacker escalates or keeps access, but they
are also everyday administration, so a match only means "worth a look".

See docs/rules/iam_policy_modification.md for the full reasoning.
"""

from __future__ import annotations

import json
import re
from typing import Any, Iterable
from urllib.parse import unquote

from ..schemas import EventRef, Finding, NormalizedEvent

RULE_ID = "iam_policy_modification"
RULE_NAME = "IAM policy or permission modification"
IAM_SOURCE = "iam.amazonaws.com"

# --- Which API calls match, grouped by their starting severity -------------

# Calls that can GRANT or WIDEN permissions (or remove a guardrail).
MEDIUM_APIS = frozenset({
    "AttachUserPolicy", "AttachGroupPolicy", "AttachRolePolicy",
    "PutUserPolicy", "PutGroupPolicy", "PutRolePolicy",
    "SetDefaultPolicyVersion",
    "UpdateAssumeRolePolicy",
    "DeleteUserPermissionsBoundary", "DeleteRolePermissionsBoundary",
    "AddUserToGroup",
})

# Calls that REDUCE permissions or have no immediate effect on anyone.
LOW_APIS = frozenset({
    "DetachUserPolicy", "DetachGroupPolicy", "DetachRolePolicy",
    "DeleteUserPolicy", "DeleteGroupPolicy", "DeleteRolePolicy",
    "CreatePolicy", "DeletePolicy", "DeletePolicyVersion",
    "PutUserPermissionsBoundary", "PutRolePermissionsBoundary",
})

# Medium only when the new version becomes the active (default) one.
CONDITIONAL_APIS = frozenset({"CreatePolicyVersion"})

MATCHED_APIS = MEDIUM_APIS | LOW_APIS | CONDITIONAL_APIS

# AWS-managed policies that grant (near) full control. Matched on the full
# AWS-managed ARN so a customer policy that merely has the same name is not
# mistaken for the real one.
_PRIVILEGED_MANAGED_POLICY = re.compile(
    r"^arn:aws[a-z-]*:iam::aws:policy/(AdministratorAccess|IAMFullAccess)$"
)
_ASSUMED_ROLE_ARN = re.compile(r":assumed-role/([^/]+)/")

BENIGN_EXPLANATIONS = [
    "An administrator granting or removing access as part of normal duties.",
    "Infrastructure-as-code (Terraform, CloudFormation, CDK) applying policies during a deployment.",
    "A scheduled access review or clean-up detaching unused permissions.",
    "An approved, time-limited break-glass permission grant.",
    "Onboarding a person or vendor (e.g. adding them to a group or a role trust).",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _as_list(value: Any) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _truthy(value: Any) -> bool:
    return value is True or (isinstance(value, str) and value.strip().lower() == "true")


def parse_policy_document(value: Any) -> tuple[dict | None, str]:
    """Return (document, status). status is 'absent', 'parsed' or 'unparseable'.

    CloudTrail usually records policyDocument as a JSON *string*; some logs
    URL-encode it. We try plain JSON first, then URL-decoded JSON.
    """
    if value is None:
        return None, "absent"
    if isinstance(value, dict):
        return value, "parsed"
    if isinstance(value, str):
        for candidate in (value, unquote(value)):
            try:
                doc = json.loads(candidate)
            except ValueError:
                continue
            if isinstance(doc, dict):
                return doc, "parsed"
    return None, "unparseable"


def find_broad_statements(document: dict) -> list[str]:
    """Allow statements granting every action ('*') or all IAM ('iam:*') on every resource."""
    found = []
    for statement in _as_list(document.get("Statement")):
        if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
            continue
        actions = [a for a in _as_list(statement.get("Action")) if isinstance(a, str)]
        broad = [a for a in actions if a == "*" or a.lower() == "iam:*"]
        if broad and "*" in _as_list(statement.get("Resource")):
            found.append(f"Allow {', '.join(broad)} on Resource *")
    return found


def trust_allows_anyone(document: dict) -> bool:
    """True if a trust policy lets ANY principal assume the role."""
    for statement in _as_list(document.get("Statement")):
        if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
            continue
        principal = statement.get("Principal")
        if principal == "*":
            return True
        if isinstance(principal, dict) and any("*" in _as_list(v) for v in principal.values()):
            return True
    return False


def caller_principal(event: NormalizedEvent) -> tuple[str | None, str | None]:
    """Return (kind, name) of the caller: ('user', 'alice') or ('role', 'AppServerRole').

    For AssumedRole callers the normalized identity_name may be the SESSION
    name when sessionContext is missing, so the role name is read from the raw
    event: sessionContext.sessionIssuer.userName first, then the ARN.
    """
    if event.identity_type == "IAMUser":
        return "user", event.identity_name
    if event.identity_type == "AssumedRole":
        identity = event.raw.get("userIdentity")
        session = identity.get("sessionContext") if isinstance(identity, dict) else None
        issuer = session.get("sessionIssuer") if isinstance(session, dict) else None
        if isinstance(issuer, dict) and isinstance(issuer.get("userName"), str) and issuer["userName"]:
            return "role", issuer["userName"]
        match = _ASSUMED_ROLE_ARN.search(event.identity_arn or "")
        if match:
            return "role", match.group(1)
    return None, None


def target_principal(event_name: str, params: dict) -> tuple[str | None, str | None]:
    """Return (kind, name) of whose permissions changed."""
    if event_name == "AddUserToGroup":
        return "user", params.get("userName")
    for kind, key in (("role", "roleName"), ("user", "userName"), ("group", "groupName")):
        if params.get(key):
            return kind, params[key]
    if params.get("policyArn"):
        return "policy", params["policyArn"]
    return None, None


# ---------------------------------------------------------------------------
# Rule
# ---------------------------------------------------------------------------

def evaluate(event: NormalizedEvent) -> Finding | None:
    """Return a Finding if this single event matches the rule, otherwise None."""
    if event.event_source != IAM_SOURCE or event.event_name not in MATCHED_APIS:
        return None
    if event.error_code is not None:
        # Failed calls changed nothing; repeated failures are left to a future
        # access_denied_burst rule.
        return None

    name = event.event_name
    raw_params = event.raw.get("requestParameters")
    params = raw_params if isinstance(raw_params, dict) else {}
    reasons = [f"Successful IAM permission-management call: {name}."]

    # 1. Starting severity from the kind of call.
    if name in CONDITIONAL_APIS:
        if _truthy(params.get("setAsDefault")):
            severity, severity_reason = "medium", "New policy version was set as the active (default) version."
        else:
            severity, severity_reason = "low", "New policy version was NOT made default, so no permissions changed yet."
    elif name in MEDIUM_APIS:
        severity, severity_reason = "medium", "This call can grant or widen permissions."
    else:
        severity, severity_reason = "low", "This call removes permissions or has no immediate effect."

    # 2. Look at what was granted.
    document, doc_status = parse_policy_document(params.get("policyDocument"))
    broad: list[str] = []
    anyone_can_assume = False
    policy_arn = params.get("policyArn")

    if name == "UpdateAssumeRolePolicy":
        anyone_can_assume = document is not None and trust_allows_anyone(document)
    elif document is not None:
        broad = find_broad_statements(document)
    if isinstance(policy_arn, str) and _PRIVILEGED_MANAGED_POLICY.match(policy_arn) and name.startswith("Attach"):
        broad.append(f"AWS-managed privileged policy {policy_arn.rsplit('/', 1)[-1]} attached")

    if doc_status == "unparseable":
        reasons.append("Policy document could not be parsed, so its contents were not assessed.")

    broad_grant = bool(broad) or anyone_can_assume
    if broad_grant:
        detail = "; ".join(broad) if broad else "trust policy allows any principal (*) to assume the role"
        if severity == "medium":
            severity = "high"
            severity_reason = f"Broad grant: {detail}."
            reasons.append(f"Grants broad access: {detail}.")
        else:
            reasons.append(f"Document is broad ({detail}) but this call does not make it effective.")

    # 3. Is the caller changing its own permissions?
    target_kind, target_name = target_principal(name, params)
    caller_kind, caller_name = caller_principal(event)
    self_targeted = bool(caller_name) and (caller_kind, caller_name) == (target_kind, target_name)
    if self_targeted:
        reasons.append(f"The caller changed its own permissions ({caller_kind} {caller_name}).")

    # 4. Confidence = how strongly the evidence suggests this is not routine.
    effective_broad = broad_grant and severity == "high"
    if effective_broad and self_targeted:
        confidence, confidence_reason = "high", "Broad grant made by the caller to itself (self-escalation pattern)."
    elif effective_broad:
        confidence, confidence_reason = "medium", "Broad grants are uncommon in routine administration."
    else:
        confidence, confidence_reason = "low", "Policy changes like this are common in routine administration."

    target_text = f"{target_kind} {target_name}" if target_name else "an unknown target"
    title = f"{name} on {target_text} by {caller_name or event.identity_name or 'unknown caller'}"

    evidence = {
        "event_name": name,
        "event_source": event.event_source,
        "event_time": event.event_time.isoformat(),
        "event_id": event.event_id,
        "caller": {"name": event.identity_name, "type": event.identity_type, "arn": event.identity_arn,
                   "principal_kind": caller_kind, "principal_name": caller_name},
        "source_ip": event.source_ip,
        "user_agent": event.user_agent,
        "aws_region": event.aws_region,
        "target": {"kind": target_kind, "name": target_name},
        "group_name": params.get("groupName"),
        "policy_arn": policy_arn,
        "policy_name": params.get("policyName"),
        "version_id": params.get("versionId"),
        "set_as_default": params.get("setAsDefault"),
        "policy_document_status": doc_status,
        "broad_grants": broad,
        "trust_allows_anyone": anyone_can_assume,
        "self_targeted": self_targeted,
    }

    return Finding(
        rule_id=RULE_ID,
        rule_name=RULE_NAME,
        title=title,
        severity=severity,
        severity_reason=severity_reason,
        confidence=confidence,
        confidence_reason=confidence_reason,
        first_seen=event.event_time,
        last_seen=event.event_time,
        identity=caller_name or event.identity_name,
        event_ids=[event.event_id] if event.event_id else [],
        event_refs=[EventRef(event.source_file, event.record_index, event.event_id)],
        reasons=reasons,
        evidence=evidence,
        benign_explanations=list(BENIGN_EXPLANATIONS),
    )


def detect(events: Iterable[NormalizedEvent]) -> list[Finding]:
    """Run the rule over many events. One finding per matching event."""
    return [f for f in (evaluate(e) for e in events) if f is not None]
