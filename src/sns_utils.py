# sns_utils.py
#
# Send a simple email summary using SNS.
# Only sends if at least one resource was actually remediated.

import os
import boto3

sns = boto3.client("sns")
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN")


def send_sns_summary(results):
    """
    results = list of result dicts from S3 / EC2 / IAM auto-fix functions.

    Only send an email if at least one has action == "remediated".
    """
    if not SNS_TOPIC_ARN:
        print("[SNS] SNS_TOPIC_ARN not set, skipping email")
        return

    if not results:
        print("[SNS] No results passed in, skipping email")
        return

    remediated = [r for r in results if r.get("action") == "remediated"]

    if not remediated:
        print("[SNS] No resources were remediated, skipping email")
        return

    lines = [
        "[Auto-Fix Agent] Resources remediated",
        "",
        f"Total fixed: {len(remediated)}",
        "",
        "Details:",
    ]

    for r in remediated:
        lines.append(
            f"- {r.get('resource_type')} {r.get('resource_id')} "
            f"(extra: {short_details(r)})"
        )

    message = "\n".join(lines)

    sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject="[Auto-Fix] S3 / EC2 / IAM fixes",
        Message=message,
    )

    print("[SNS] Notification sent.")


def short_details(r):
    """
    Build a tiny one-line description from the extra fields.
    Just to make the email a bit more helpful, but still simple.
    """
    if r.get("resource_type") == "s3_bucket":
        return f"public_access_block={r.get('block_public_access_enabled')}, removed_public_policy={r.get('policy_public_statements_removed')}"
    if r.get("resource_type") == "ec2_security_group":
        return f"open_ssh_rule_removed={r.get('open_ssh_rule_removed')}"
    if r.get("resource_type") == "iam_role":
        return f"inline_policies_deleted={r.get('inline_policies_deleted')}"

    return r.get("action")