# ec2_autofix.py
#
# Auto-fix for EC2 security groups.
# - Normal Security Hub flow: only remediate if AutoFix=True
# - EC2 launch validation flow: can optionally skip the tag check
# - Looks for inbound SSH (port 22) open to 0.0.0.0/0
# - Removes those rules

from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError
from metrics_utils import record_fix

ec2 = boto3.client("ec2")

AUTOFIX_TAG_KEY = "AutoFix"
AUTOFIX_TAG_VALUE = "True"


def handle_ec2_finding(finding, require_autofix_tag=True):
    """
    Look at the finding and fix any EC2 security groups it mentions.

    require_autofix_tag=True:
        normal Security Hub flow

    require_autofix_tag=False:
        launch-validation flow for new EC2 instances
    """
    title = finding.get("Title", "No title")
    severity = finding.get("Severity", {}).get("Label", "UNKNOWN")
    resources = finding.get("Resources", [])

    print(f"[EC2] Handling finding: {title} (severity={severity})")

    results = []

    for res in resources:
        if res.get("Type") != "AwsEc2SecurityGroup":
            continue

        sg_arn = res.get("Id", "")
        security_group_id = sg_arn.split("/")[-1]

        result = fix_security_group(
            security_group_id,
            require_autofix_tag=require_autofix_tag
        )
        results.append(result)

    return results


def fix_security_group(security_group_id, require_autofix_tag=True):
    """
    Simple EC2 fix:

    - If require_autofix_tag=True:
        only run if the security group has tag AutoFix=True
    - If require_autofix_tag=False:
        skip tag check (used for EC2 launch validation path)
    - Remove inbound SSH (port 22) rules that are open to 0.0.0.0/0
    """
    print(f"[EC2] Trying to fix security group: {security_group_id}")

    if require_autofix_tag and not sg_has_autofix_tag(security_group_id):
        msg = "Security group is not tagged AutoFix=True, skipping"
        print(f"[EC2] {msg}")
        result = _result(
            resource_id=security_group_id,
            action="skipped",
            reason=msg,
            extra={"open_ssh_rule_removed": False},
        )

        record_fix(service_name="EC2", action=result["action"])
        return result

    # Get details for the security group
    try:
        resp = ec2.describe_security_groups(GroupIds=[security_group_id])
    except ClientError as e:
        msg = f"Error describing security group {security_group_id}: {e}"
        print(f"[EC2] {msg}")
        result = _result(
            resource_id=security_group_id,
            action="error",
            reason="describe_security_groups_failed",
            extra={"error": str(e), "open_ssh_rule_removed": False},
        )

        record_fix(service_name="EC2", action=result["action"])
        return result

    sg = resp["SecurityGroups"][0]
    ip_permissions = sg.get("IpPermissions", [])

    bad_rules = []
    removed_any = False

    # Look through inbound rules
    for perm in ip_permissions:
        from_port = perm.get("FromPort")
        to_port = perm.get("ToPort")
        ip_ranges = perm.get("IpRanges", [])

        if from_port is None or to_port is None:
            continue

        # Check if port 22 is inside this range
        if not (from_port <= 22 <= to_port):
            continue

        for r in ip_ranges:
            if r.get("CidrIp") == "0.0.0.0/0":
                print(f"[EC2] Found open SSH rule in {security_group_id}, marking to remove")
                removed_any = True
                bad_rule = {
                    "IpProtocol": perm.get("IpProtocol"),
                    "FromPort": from_port,
                    "ToPort": to_port,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
                bad_rules.append(bad_rule)

    # Remove the bad rules
    if bad_rules:
        try:
            ec2.revoke_security_group_ingress(
                GroupId=security_group_id,
                IpPermissions=bad_rules,
            )
            print(f"[EC2] Removed {len(bad_rules)} open SSH rule(s) from {security_group_id}")
        except ClientError as e:
            msg = f"Error revoking rules for {security_group_id}: {e}"
            print(f"[EC2] {msg}")
            result = _result(
                resource_id=security_group_id,
                action="error",
                reason="revoke_ingress_failed",
                extra={"error": str(e), "open_ssh_rule_removed": False},
            )

            record_fix(service_name="EC2", action=result["action"])
            return result

    # Build result
    if removed_any:
        action = "remediated"
        reason = ""
    else:
        action = "no_issue_found"
        reason = "No open SSH 0.0.0.0/0 rule found"

    result = _result(
        resource_id=security_group_id,
        action=action,
        reason=reason,
        extra={"open_ssh_rule_removed": removed_any},
    )

    record_fix(service_name="EC2", action=result["action"])
    return result


def sg_has_autofix_tag(security_group_id):
    """Return True if the security group has tag AutoFix=True."""
    try:
        resp = ec2.describe_security_groups(GroupIds=[security_group_id])
        sg = resp["SecurityGroups"][0]
        tags = sg.get("Tags", [])
        print(f"[EC2] Tags for {security_group_id}: {tags}")

        for tag in tags:
            if (
                tag.get("Key") == AUTOFIX_TAG_KEY
                and tag.get("Value") == AUTOFIX_TAG_VALUE
            ):
                return True
    except ClientError as e:
        print(f"[EC2] Error checking tags for {security_group_id}: {e}")
    except Exception as e:
        print(f"[EC2] Unexpected error checking tags for {security_group_id}: {e}")

    return False


def _result(resource_id, action, reason, extra):
    """Make EC2 results look the same as S3 / IAM."""
    base = {
        "resource_type": "ec2_security_group",
        "resource_id": resource_id,
        "action": action,
        "reason": reason,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }
    base.update(extra)
    return base
