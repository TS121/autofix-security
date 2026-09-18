import json
import boto3

from s3_autofix import handle_s3_finding
from ec2_autofix import handle_ec2_finding
from iam_autofix import handle_iam_finding
from sns_utils import send_sns_summary
from risk_scoring import score_risk

ec2 = boto3.client("ec2")


def lambda_handler(event, context):
    """
    Main Lambda function.

    Supports:
    1. Security Hub findings through EventBridge
    2. EC2 launch events from Auto Scaling / EventBridge

    For Security Hub findings:
        - S3 buckets = s3_autofix.py
        - EC2 security groups = ec2_autofix.py
        - IAM roles = iam_autofix.py

    For EC2 launch events:
        - inspects the launched EC2 instance
        - extracts its security groups
        - sends them through the existing EC2 auto-fix logic
    """
    print("Event received:")
    print(json.dumps(event, indent=2, default=str))

    all_results = []

    # Handles the EC2 launch events
    if is_ec2_launch_event(event):
        print("[EVENT] EC2 launch event detected")

        ec2_results = handle_ec2_launch_event(event)
        all_results.extend(ec2_results)

    else:
        findings = extract_findings(event)

        # Go through each finding and only run handlers that match the resources inside it
        for finding in findings:
            resource_types = get_resource_types(finding)

            if "AwsS3Bucket" in resource_types:
                s3_results = handle_s3_finding(finding)
                all_results.extend(s3_results)

            if "AwsEc2SecurityGroup" in resource_types:
                ec2_results = handle_ec2_finding(finding)
                all_results.extend(ec2_results)

            if "AwsIamRole" in resource_types:
                iam_results = handle_iam_finding(finding)
                all_results.extend(iam_results)

    # Risk scoring
    risk = score_risk(all_results)
    print("[RISK] Risk level:", risk.get("risk_level"))
    print("[RISK] Risk score:", risk.get("risk_score"))
    print("[RISK] Reasons:", risk.get("reasons"))

    # Only send SNS if something was actually remediated
    remediated_results = [r for r in all_results if r.get("action") == "remediated"]

    if remediated_results:
        send_sns_summary(remediated_results)
    else:
        print("[SNS] No remediations, skipping notification.")

    return {
        "statusCode": 200,
        "body": json.dumps(
            {
                "results": all_results,
                "risk": risk,
            },
            default=str
        ),
    }


def is_ec2_launch_event(event):
    """
    Returns True if this is an EC2 instance state-change event where the instance is running.
    """
    return (
        event.get("source") == "aws.ec2"
        and event.get("detail-type") == "EC2 Instance State-change Notification"
        and event.get("detail", {}).get("state") == "running"
    )


def handle_ec2_launch_event(event):
    """
    When a new EC2 instance launches, inspect its attached security groups
    and pass them into the existing EC2 auto-fix flow.
    """
    instance_id = event.get("detail", {}).get("instance-id")
    print(f"[EC2-LAUNCH] Instance launched: {instance_id}")

    if not instance_id:
        print("[EC2-LAUNCH] No instance-id found in event")
        return []

    try:
        resp = ec2.describe_instances(InstanceIds=[instance_id])
        reservations = resp.get("Reservations", [])

        if not reservations or not reservations[0].get("Instances"):
            print(f"[EC2-LAUNCH] Instance {instance_id} not found")
            return []

        instance = reservations[0]["Instances"][0]
        security_groups = instance.get("SecurityGroups", [])

        print(f"[EC2-LAUNCH] Security groups attached to {instance_id}: {security_groups}")

        # Build a fake finding so we can reuse the current EC2 remediation logic
        fake_finding = {
            "Title": f"EC2 launch validation for {instance_id}",
            "Severity": {"Label": "LOW"},
            "Resources": []
        }

        region = event.get("region", "eu-west-2")
        account_id = event.get("account", "")

        for sg in security_groups:
            sg_id = sg.get("GroupId")
            if not sg_id:
                continue

            fake_finding["Resources"].append(
                {
                    "Type": "AwsEc2SecurityGroup",
                    "Id": f"arn:aws:ec2:{region}:{account_id}:security-group/{sg_id}"
                }
            )

        if not fake_finding["Resources"]:
            print(f"[EC2-LAUNCH] No security groups found for {instance_id}")
            return []

        return handle_ec2_finding(fake_finding, require_autofix_tag=False)

    except Exception as e:
        print(f"[EC2-LAUNCH] Error handling launched instance {instance_id}: {e}")
        return []


def extract_findings(event):
    """
    Security Hub sends findings under:
        event['detail']['findings']

    For local/manual testing:
        event['finding']
    """
    if "detail" in event and "findings" in event["detail"]:
        findings = event["detail"]["findings"]
    elif "finding" in event:
        findings = [event["finding"]]
    else:
        findings = []

    print(f"Found {len(findings)} finding(s) to process")
    return findings


def get_resource_types(finding):
    """
    Returns a set of resource 'Type' values found inside the finding.
    """
    types = set()
    for res in finding.get("Resources", []):
        r_type = res.get("Type")
        if r_type:
            types.add(r_type)
    return types
