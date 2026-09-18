# risk_scoring.py
#
# This file adds a simple "risk check" to the auto-fix system.
# It looks at what happened in one Lambda run and decides
# whether the situation looks LOW, MEDIUM, or HIGH risk.
#
# This is not complex machine learning.
# It is a simple scoring approach based on patterns and counts.

from collections import Counter


def score_risk(all_results):
    """
    all_results is a list of dictionaries returned from the
    S3, EC2, and IAM auto-fix functions.

    Example item:
    {
        "resource_type": "s3_bucket",
        "action": "remediated"
    }
    """

    # If nothing happened, there is no risk
    if not all_results:
        return {
            "risk_level": "LOW",
            "risk_score": 0,
            "reasons": ["No security changes were needed."],
        }

    action_counts = Counter()
    resource_counts = Counter()

    # Count what happened during this run
    for result in all_results:
        action = result.get("action", "unknown")
        resource = result.get("resource_type", "unknown")

        action_counts[action] += 1
        resource_counts[resource] += 1

    remediated_count = action_counts.get("remediated", 0)
    error_count = action_counts.get("error", 0)

    score = 0
    reasons = []

    # Rule 1: errors are important
    if error_count > 0:
        score += 3
        reasons.append("Errors occurred while fixing security issues.")

    # Rule 2: many fixes at once can be unusual
    if remediated_count >= 5:
        score += 3
        reasons.append("A large number of resources were fixed at once.")
    elif remediated_count >= 2:
        score += 2
        reasons.append("Multiple resources required fixing.")
    elif remediated_count == 1:
        score += 1
        reasons.append("A single resource required fixing.")

    # Rule 3: IAM changes are sensitive
    if resource_counts.get("iam_role", 0) > 0:
        score += 2
        reasons.append("IAM role permissions were modified.")

    # Rule 4: EC2 SSH exposure matters
    if resource_counts.get("ec2_security_group", 0) > 0:
        score += 1
        reasons.append("EC2 security group rules were modified.")

    # Decide final risk level
    if score >= 6:
        risk_level = "HIGH"
    elif score >= 3:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "risk_level": risk_level,
        "risk_score": score,
        "reasons": reasons,
    }
