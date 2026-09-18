# s3_autofix.py
#
# Auto-fix for S3 buckets with tag AutoFix=True.
# - Turns Block Public Access back on (only if needed)
# - Removes public bucket policy statements (only if found)

import json
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError
from metrics_utils import record_fix 

s3 = boto3.client("s3")

AUTOFIX_TAG_KEY = "AutoFix"
AUTOFIX_TAG_VALUE = "True"


def handle_s3_finding(finding):
    """
    Look at the finding and fix any S3 buckets it mentions.
    """
    title = finding.get("Title", "No title")
    severity = finding.get("Severity", {}).get("Label", "UNKNOWN")
    resources = finding.get("Resources", [])

    print(f"[S3] Handling finding: {title} (severity={severity})")

    results = []

    for res in resources:
        if res.get("Type") != "AwsS3Bucket":
            continue

        bucket_arn = res.get("Id", "")
        # ARN format: arn:aws:s3:::bucket-name
        bucket_name = bucket_arn.split(":::")[-1]

        result = fix_s3_bucket(bucket_name)
        results.append(result)

    return results


def fix_s3_bucket(bucket_name):
    """
    Simple S3 fix:
    - Only run if bucket has tag AutoFix=True
    - Turn Block Public Access back on (if it's off)
    - Remove any public bucket policy statements (if they exist)
    """
    print(f"[S3] Trying to fix bucket: {bucket_name}")

    # Safety check: only touch buckets that are tagged
    if not bucket_has_autofix_tag(bucket_name):
        msg = "Bucket is not tagged AutoFix=True, skipping"
        print(f"[S3] {msg}")
        result = _result(
            resource_id=bucket_name,
            resource_type="s3_bucket",
            action="skipped",
            reason=msg,
            extra={}
        )

        record_fix(service_name="S3", action=result["action"])
        return result

    # Track whether we actually changed anything
    bpa_changed = False
    policy_changed = False

    # 1) Check Block Public Access first (so we only "fix" if needed)
    try:
        current_bpa = s3.get_public_access_block(Bucket=bucket_name)
        current_cfg = current_bpa.get("PublicAccessBlockConfiguration", {})

        already_on = (
            current_cfg.get("BlockPublicAcls") is True
            and current_cfg.get("IgnorePublicAcls") is True
            and current_cfg.get("BlockPublicPolicy") is True
            and current_cfg.get("RestrictPublicBuckets") is True
        )

        if already_on:
            print(f"[S3] Block Public Access already ON for {bucket_name}")
        else:
            s3.put_public_access_block(
                Bucket=bucket_name,
                PublicAccessBlockConfiguration={
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                },
            )
            bpa_changed = True
            print(f"[S3] Block Public Access turned ON for {bucket_name}")

    except ClientError as e:
        code = e.response.get("Error", {}).get("Code")

        # If the bucket has no BPA config at all, we should create it
        if code == "NoSuchPublicAccessBlockConfiguration":
            try:
                s3.put_public_access_block(
                    Bucket=bucket_name,
                    PublicAccessBlockConfiguration={
                        "BlockPublicAcls": True,
                        "IgnorePublicAcls": True,
                        "BlockPublicPolicy": True,
                        "RestrictPublicBuckets": True,
                    },
                )
                bpa_changed = True
                print(f"[S3] Block Public Access config was missing, created it for {bucket_name}")
            except ClientError as e2:
                msg = f"ClientError setting Block Public Access: {e2}"
                print(f"[S3] {msg}")

                result = _result(
                    resource_id=bucket_name,
                    resource_type="s3_bucket",
                    action="error",
                    reason="block_public_access_failed",
                    extra={"error": str(e2)},
                )

                record_fix(service_name="S3", action=result["action"])
                return result
        else:
            msg = f"ClientError reading/setting Block Public Access: {e}"
            print(f"[S3] {msg}")

            result = _result(
                resource_id=bucket_name,
                resource_type="s3_bucket",
                action="error",
                reason="block_public_access_failed",
                extra={"error": str(e)},
            )

            record_fix(service_name="S3", action=result["action"])
            return result

    except Exception as e:
        msg = f"Unexpected error setting Block Public Access: {e}"
        print(f"[S3] {msg}")

        result = _result(
            resource_id=bucket_name,
            resource_type="s3_bucket",
            action="error",
            reason="block_public_access_exception",
            extra={"error": str(e)},
        )

        record_fix(service_name="S3", action=result["action"])
        return result

    # 2) Clean up bucket policy (only if we find public statements)
    try:
        policy_resp = s3.get_bucket_policy(Bucket=bucket_name)
        policy_doc = json.loads(policy_resp["Policy"])
        statements = policy_doc.get("Statement", [])

        if not isinstance(statements, list):
            statements = [statements]

        new_statements = []

        for stmt in statements:
            principal = stmt.get("Principal")

            is_public = (
                principal == "*"
                or principal == {"AWS": "*"}
                or principal == {"Service": "*"}
            )

            if is_public:
                print("[S3] Found public statement, removing it")
                policy_changed = True
            else:
                new_statements.append(stmt)

        if policy_changed:
            if new_statements:
                policy_doc["Statement"] = new_statements
                s3.put_bucket_policy(
                    Bucket=bucket_name,
                    Policy=json.dumps(policy_doc),
                )
                print("[S3] Updated bucket policy without public statements")
            else:
                s3.delete_bucket_policy(Bucket=bucket_name)
                print("[S3] Deleted bucket policy (all statements were public)")
        else:
            print("[S3] No public statements found in bucket policy")

    except ClientError as e:
        code = e.response.get("Error", {}).get("Code")
        if code == "NoSuchBucketPolicy":
            print("[S3] Bucket has no policy, nothing to change")
        else:
            print(f"[S3] Error reading/changing bucket policy: {e}")
    except Exception as e:
        print(f"[S3] Unexpected error with bucket policy: {e}")

    # Decide action based on whether we changed anything
    if bpa_changed or policy_changed:
        action = "remediated"
        reason = ""
    else:
        action = "no_issue_found"
        reason = "Bucket already secure (no changes needed)"

    result = _result(
        resource_id=bucket_name,
        resource_type="s3_bucket",
        action=action,
        reason=reason,
        extra={
            "block_public_access_enabled": True,
            "block_public_access_changed": bpa_changed,
            "policy_public_statements_removed": policy_changed,
        },
    )

    print("Fix result:", result)

    record_fix(service_name="S3", action=result["action"])
    return result


def bucket_has_autofix_tag(bucket_name):
    """Return True if bucket has tag AutoFix=True."""
    try:
        resp = s3.get_bucket_tagging(Bucket=bucket_name)
        tags = resp.get("TagSet", [])
        print(f"[S3] Tags for {bucket_name}: {tags}")

        for tag in tags:
            if (
                tag.get("Key") == AUTOFIX_TAG_KEY
                and tag.get("Value") == AUTOFIX_TAG_VALUE
            ):
                return True
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code")
        if code in ("NoSuchTagSet", "NoSuchBucket"):
            print(f"[S3] No tags or bucket not found for {bucket_name}: {code}")
        else:
            print(f"[S3] Error getting tags for {bucket_name}: {e}")
    except Exception as e:
        print(f"[S3] Unexpected error getting tags: {e}")

    return False


def _result(resource_id, resource_type, action, reason, extra):
    """Small helper so all results look the same."""
    base = {
        "resource_type": resource_type,
        "resource_id": resource_id,
        "action": action,
        "reason": reason,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }
    base.update(extra)
    return base
