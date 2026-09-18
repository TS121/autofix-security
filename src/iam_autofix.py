# iam_autofix.py
#
# Auto-fix for IAM roles with tag AutoFix=True.
# Lists all inline policies on the role
# Deletes those inline policies

from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError
from metrics_utils import record_fix   # from metrics_utils import record_fix

iam = boto3.client("iam")

AUTOFIX_TAG_KEY = "AutoFix"
AUTOFIX_TAG_VALUE = "True"


def handle_iam_finding(finding):
    """
    Look at the finding and fix any IAM roles it mentions.
    """
    title = finding.get("Title", "No title")
    severity = finding.get("Severity", {}).get("Label", "UNKNOWN")
    resources = finding.get("Resources", [])

    print(f"[IAM] Handling finding: {title} (severity={severity})")

    results = []

    for res in resources:
        if res.get("Type") != "AwsIamRole":
            continue

        role_arn = res.get("Id", "")
        # ARN: arn:aws:iam::ACCOUNT_ID:role/role-name
        role_name = role_arn.split("/")[-1]

        result = fix_iam_role(role_name)
        results.append(result)

    return results


def fix_iam_role(role_name):
    """
    Simple IAM auto-fix for roles:

    - Only touch roles that have the tag AutoFix=True
    - List inline policies on the role
    - Delete all inline policies
    """
    print(f"[IAM] Trying to fix IAM role: {role_name}")

    if not iam_role_has_autofix_tag(role_name):
        msg = "Role is not tagged AutoFix=True, skipping"
        print(f"[IAM] {msg}")
        result = _result(
            resource_id=role_name,
            action="skipped",
            reason=msg,
            extra={"inline_policies_deleted": 0},
        )

        # Sends CloudWatch metric
        record_fix(service_name="IAM", action=result["action"])

        return result

    # List inline policy names
    try:
        resp = iam.list_role_policies(RoleName=role_name)
        inline_policies = resp.get("PolicyNames", [])
        print(f"[IAM] Inline policies on {role_name}: {inline_policies}")
    except ClientError as e:
        msg = f"Error listing inline policies for {role_name}: {e}"
        print(f"[IAM] {msg}")
        result = _result(
            resource_id=role_name,
            action="error",
            reason="list_role_policies_failed",
            extra={"error": str(e), "inline_policies_deleted": 0},
        )

        # Sends CloudWatch metric
        record_fix(service_name="IAM", action=result["action"])

        return result

    except Exception as e:
        msg = f"Unexpected error listing inline policies for {role_name}: {e}"
        print(f"[IAM] {msg}")
        result = _result(
            resource_id=role_name,
            action="error",
            reason="list_role_policies_exception",
            extra={"error": str(e), "inline_policies_deleted": 0},
        )

        # Sends CloudWatch metric
        record_fix(service_name="IAM", action=result["action"])

        return result

    deleted_count = 0

    # Delete each inline policy
    for policy_name in inline_policies:
        try:
            print(f"[IAM] Deleting inline policy '{policy_name}' from role {role_name}")
            iam.delete_role_policy(
                RoleName=role_name,
                PolicyName=policy_name,
            )
            deleted_count += 1
        except ClientError as e:
            print(f"[IAM] Error deleting inline policy {policy_name} on {role_name}: {e}")
        except Exception as e:
            print(f"[IAM] Unexpected error deleting policy {policy_name} on {role_name}: {e}")

    # Decide final action
    if deleted_count > 0:
        action = "remediated"
        reason = ""
    else:
        action = "no_issue_found"
        reason = "No inline policies to delete"

    result = _result(
        resource_id=role_name,
        action=action,
        reason=reason,
        extra={"inline_policies_deleted": deleted_count},
    )

    # Sends CloudWatch metric
    record_fix(service_name="IAM", action=result["action"])

    return result


def iam_role_has_autofix_tag(role_name):
    """Return True if an IAM role has the tag AutoFix=True."""
    try:
        resp = iam.list_role_tags(RoleName=role_name)
        tags = resp.get("Tags", [])
        print(f"[IAM] Tags for role {role_name}: {tags}")

        for tag in tags:
            if (
                tag.get("Key") == AUTOFIX_TAG_KEY
                and tag.get("Value") == AUTOFIX_TAG_VALUE
            ):
                return True
    except ClientError as e:
        print(f"[IAM] Error reading tags for role {role_name}: {e}")
    except Exception as e:
        print(f"[IAM] Unexpected error reading tags for role {role_name}: {e}")

    return False


def _result(resource_id, action, reason, extra):
    """Make IAM results look the same as S3 / EC2."""
    base = {
        "resource_type": "iam_role",
        "resource_id": resource_id,
        "action": action,
        "reason": reason,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }
    base.update(extra)
    return base
