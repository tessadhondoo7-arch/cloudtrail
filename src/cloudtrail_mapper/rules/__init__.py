"""Detection rules.

Each rule module exposes RULE_ID, RULE_NAME and detect(events) -> list[Finding].
ALL_RULES maps the stable rule ID to its detect function.
"""

from . import iam_policy_modification

ALL_RULES = {
    iam_policy_modification.RULE_ID: iam_policy_modification.detect,
}
