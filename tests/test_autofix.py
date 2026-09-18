# tests/test_autofix.py
#
# Unit tests for the Autonomous Cloud Security Remediation System.
# Uses pytest and moto to simulate AWS services locally.
#
# Run with: pytest tests/test_autofix.py -v

import json
import pytest
import boto3
from moto import mock_aws

# ============================================================
# FIXTURES - shared setup for tests
# ============================================================

@pytest.fixture
def aws_environment(monkeypatch):
    """Set up fake AWS credentials and environment variables."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "eu-west-2")
    monkeypatch.setenv("SNS_TOPIC_ARN", "arn:aws:sns:eu-west-2:123456789012:test-topic")


# ============================================================
# EC2 AUTOFIX TESTS
# ============================================================

class TestEC2Autofix:
    """Tests for ec2_autofix.py - security group remediation."""

    @mock_aws
    def test_removes_open_ssh_rule_when_tagged(self, aws_environment):
        """
        If a security group has SSH open to 0.0.0.0/0
        and the AutoFix=True tag, the function should
        remove the SSH rule.
        """
        ec2 = boto3.client("ec2", region_name="eu-west-2")

        # Create a VPC and security group
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        sg = ec2.create_security_group(
            GroupName="test-sg",
            Description="Test security group",
            VpcId=vpc["Vpc"]["VpcId"]
        )
        sg_id = sg["GroupId"]

        # Add the bad SSH rule
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[{
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
            }]
        )

        # Add the AutoFix tag
        ec2.create_tags(
            Resources=[sg_id],
            Tags=[{"Key": "AutoFix", "Value": "True"}]
        )

        # Run the fix
        from ec2_autofix import fix_security_group
        result = fix_security_group(sg_id, require_autofix_tag=True)

        # Check the result
        assert result["action"] == "remediated"
        assert result["open_ssh_rule_removed"] == True

        # Verify the rule was actually removed
        sg_after = ec2.describe_security_groups(GroupIds=[sg_id])
        ip_permissions = sg_after["SecurityGroups"][0]["IpPermissions"]

        ssh_rules = [
            p for p in ip_permissions
            if p.get("FromPort") == 22
            and any(r.get("CidrIp") == "0.0.0.0/0" for r in p.get("IpRanges", []))
        ]
        assert len(ssh_rules) == 0

    @mock_aws
    def test_skips_when_no_autofix_tag(self, aws_environment):
        """
        If a security group does NOT have the AutoFix=True tag,
        the function should skip it and not make any changes.
        """
        ec2 = boto3.client("ec2", region_name="eu-west-2")

        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        sg = ec2.create_security_group(
            GroupName="test-sg-no-tag",
            Description="No tag security group",
            VpcId=vpc["Vpc"]["VpcId"]
        )
        sg_id = sg["GroupId"]

        # Add the bad SSH rule but NO tag
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[{
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
            }]
        )

        from ec2_autofix import fix_security_group
        result = fix_security_group(sg_id, require_autofix_tag=True)

        # Should skip
        assert result["action"] == "skipped"
        assert result["open_ssh_rule_removed"] == False

    @mock_aws
    def test_no_issue_when_no_ssh_rule(self, aws_environment):
        """
        If a security group has the AutoFix tag but no open SSH rule,
        the function should report no issue found.
        """
        ec2 = boto3.client("ec2", region_name="eu-west-2")

        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        sg = ec2.create_security_group(
            GroupName="test-sg-clean",
            Description="Clean security group",
            VpcId=vpc["Vpc"]["VpcId"]
        )
        sg_id = sg["GroupId"]

        # Add AutoFix tag but no SSH rule
        ec2.create_tags(
            Resources=[sg_id],
            Tags=[{"Key": "AutoFix", "Value": "True"}]
        )

        from ec2_autofix import fix_security_group
        result = fix_security_group(sg_id, require_autofix_tag=True)

        assert result["action"] == "no_issue_found"
        assert result["open_ssh_rule_removed"] == False

    @mock_aws
    def test_launch_validation_skips_tag_check(self, aws_environment):
        """
        When called with require_autofix_tag=False (launch validation),
        the function should fix the security group even without the tag.
        """
        ec2 = boto3.client("ec2", region_name="eu-west-2")

        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        sg = ec2.create_security_group(
            GroupName="test-sg-no-tag-launch",
            Description="No tag but launch path",
            VpcId=vpc["Vpc"]["VpcId"]
        )
        sg_id = sg["GroupId"]

        # Add bad SSH rule, NO tag
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[{
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
            }]
        )

        from ec2_autofix import fix_security_group
        result = fix_security_group(sg_id, require_autofix_tag=False)

        # Should fix it even without tag
        assert result["action"] == "remediated"
        assert result["open_ssh_rule_removed"] == True


# ============================================================
# S3 AUTOFIX TESTS
# ============================================================

class TestS3Autofix:
    """Tests for s3_autofix.py - S3 bucket remediation."""

    @mock_aws
    def test_enables_block_public_access_when_tagged(self, aws_environment):
        """
        If a bucket has Block Public Access turned off and the
        AutoFix=True tag, the function should turn BPA back on.
        """
        s3 = boto3.client("s3", region_name="eu-west-2")

        # Create bucket with AutoFix tag
        s3.create_bucket(
            Bucket="test-bucket-insecure",
            CreateBucketConfiguration={"LocationConstraint": "eu-west-2"}
        )
        s3.put_bucket_tagging(
            Bucket="test-bucket-insecure",
            Tagging={"TagSet": [{"Key": "AutoFix", "Value": "True"}]}
        )

        # Turn off Block Public Access
        s3.put_public_access_block(
            Bucket="test-bucket-insecure",
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            }
        )

        from s3_autofix import fix_s3_bucket
        result = fix_s3_bucket("test-bucket-insecure")

        assert result["action"] == "remediated"
        assert result["block_public_access_changed"] == True

        # Verify BPA is now on
        bpa = s3.get_public_access_block(Bucket="test-bucket-insecure")
        config = bpa["PublicAccessBlockConfiguration"]
        assert config["BlockPublicAcls"] == True
        assert config["IgnorePublicAcls"] == True
        assert config["BlockPublicPolicy"] == True
        assert config["RestrictPublicBuckets"] == True

    @mock_aws
    def test_skips_bucket_without_tag(self, aws_environment):
        """
        If a bucket does NOT have the AutoFix=True tag,
        the function should skip it.
        """
        s3 = boto3.client("s3", region_name="eu-west-2")

        s3.create_bucket(
            Bucket="test-bucket-no-tag",
            CreateBucketConfiguration={"LocationConstraint": "eu-west-2"}
        )

        from s3_autofix import fix_s3_bucket
        result = fix_s3_bucket("test-bucket-no-tag")

        assert result["action"] == "skipped"

    @mock_aws
    def test_no_change_when_already_secure(self, aws_environment):
        """
        If a bucket already has BPA on and no public policy,
        the function should report no issue found.
        """
        s3 = boto3.client("s3", region_name="eu-west-2")

        s3.create_bucket(
            Bucket="test-bucket-secure",
            CreateBucketConfiguration={"LocationConstraint": "eu-west-2"}
        )
        s3.put_bucket_tagging(
            Bucket="test-bucket-secure",
            Tagging={"TagSet": [{"Key": "AutoFix", "Value": "True"}]}
        )

        # BPA is on by default in moto
        s3.put_public_access_block(
            Bucket="test-bucket-secure",
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        )

        from s3_autofix import fix_s3_bucket
        result = fix_s3_bucket("test-bucket-secure")

        assert result["action"] == "no_issue_found"


# ============================================================
# IAM AUTOFIX TESTS
# ============================================================

class TestIAMAutofix:
    """Tests for iam_autofix.py - IAM role remediation."""

    @mock_aws
    def test_deletes_inline_policy_when_tagged(self, aws_environment):
        """
        If an IAM role has an inline policy and the AutoFix=True tag,
        the function should delete the inline policy.
        """
        iam = boto3.client("iam", region_name="eu-west-2")

        # Create role with trust policy
        iam.create_role(
            RoleName="test-risky-role",
            AssumeRolePolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]
            })
        )

        # Add AutoFix tag
        iam.tag_role(
            RoleName="test-risky-role",
            Tags=[{"Key": "AutoFix", "Value": "True"}]
        )

        # Add a risky inline policy
        iam.put_role_policy(
            RoleName="test-risky-role",
            PolicyName="risky-full-access",
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
            })
        )

        from iam_autofix import fix_iam_role
        result = fix_iam_role("test-risky-role")

        assert result["action"] == "remediated"
        assert result["inline_policies_deleted"] == 1

        # Verify policy was deleted
        policies = iam.list_role_policies(RoleName="test-risky-role")
        assert len(policies["PolicyNames"]) == 0

    @mock_aws
    def test_skips_role_without_tag(self, aws_environment):
        """
        If an IAM role does NOT have the AutoFix=True tag,
        the function should skip it.
        """
        iam = boto3.client("iam", region_name="eu-west-2")

        iam.create_role(
            RoleName="test-no-tag-role",
            AssumeRolePolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]
            })
        )

        # Add inline policy but NO tag
        iam.put_role_policy(
            RoleName="test-no-tag-role",
            PolicyName="some-policy",
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
            })
        )

        from iam_autofix import fix_iam_role
        result = fix_iam_role("test-no-tag-role")

        assert result["action"] == "skipped"
        assert result["inline_policies_deleted"] == 0

        # Verify policy is still there
        policies = iam.list_role_policies(RoleName="test-no-tag-role")
        assert len(policies["PolicyNames"]) == 1

    @mock_aws
    def test_no_issue_when_no_inline_policies(self, aws_environment):
        """
        If an IAM role has the tag but no inline policies,
        the function should report no issue found.
        """
        iam = boto3.client("iam", region_name="eu-west-2")

        iam.create_role(
            RoleName="test-clean-role",
            AssumeRolePolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]
            })
        )

        iam.tag_role(
            RoleName="test-clean-role",
            Tags=[{"Key": "AutoFix", "Value": "True"}]
        )

        from iam_autofix import fix_iam_role
        result = fix_iam_role("test-clean-role")

        assert result["action"] == "no_issue_found"
        assert result["inline_policies_deleted"] == 0


# ============================================================
# RISK SCORING TESTS
# ============================================================

class TestRiskScoring:
    """Tests for risk_scoring.py - heuristic risk assessment."""

    def test_no_results_returns_low(self):
        """No results should return LOW risk with score 0."""
        from risk_scoring import score_risk
        result = score_risk([])

        assert result["risk_level"] == "LOW"
        assert result["risk_score"] == 0

    def test_single_remediation_returns_low(self):
        """A single EC2 remediation should return LOW risk."""
        from risk_scoring import score_risk
        result = score_risk([
            {"resource_type": "ec2_security_group", "action": "remediated"}
        ])

        assert result["risk_level"] == "LOW"
        assert result["risk_score"] >= 1

    def test_iam_remediation_increases_score(self):
        """IAM changes should increase the risk score."""
        from risk_scoring import score_risk
        result = score_risk([
            {"resource_type": "iam_role", "action": "remediated"}
        ])

        # IAM adds 2 points + 1 for single remediation = 3
        assert result["risk_level"] == "MEDIUM"
        assert result["risk_score"] >= 3

    def test_multiple_remediations_returns_medium(self):
        """Multiple remediations should return at least MEDIUM risk."""
        from risk_scoring import score_risk
        result = score_risk([
            {"resource_type": "s3_bucket", "action": "remediated"},
            {"resource_type": "ec2_security_group", "action": "remediated"},
            {"resource_type": "iam_role", "action": "remediated"},
        ])

        assert result["risk_level"] == "MEDIUM"
        assert result["risk_score"] >= 3

    def test_errors_increase_score(self):
        """Errors should increase the risk score significantly."""
        from risk_scoring import score_risk
        result = score_risk([
            {"resource_type": "s3_bucket", "action": "error"},
            {"resource_type": "ec2_security_group", "action": "error"},
        ])

        assert result["risk_score"] >= 3
        assert "Errors occurred" in result["reasons"][0]

    def test_high_risk_with_many_remediations(self):
        """5+ remediations with IAM and errors should return HIGH risk."""
        from risk_scoring import score_risk
        result = score_risk([
            {"resource_type": "s3_bucket", "action": "remediated"},
            {"resource_type": "s3_bucket", "action": "remediated"},
            {"resource_type": "ec2_security_group", "action": "remediated"},
            {"resource_type": "ec2_security_group", "action": "remediated"},
            {"resource_type": "iam_role", "action": "remediated"},
            {"resource_type": "s3_bucket", "action": "error"},
        ])

        assert result["risk_level"] == "HIGH"
        assert result["risk_score"] >= 6


# ============================================================
# LAMBDA HANDLER TESTS
# ============================================================

class TestLambdaHandler:
    """Tests for lambda_function.py - event routing."""

    def test_identifies_ec2_launch_event(self):
        """Should correctly identify an EC2 launch event."""
        from lambda_function import is_ec2_launch_event

        event = {
            "source": "aws.ec2",
            "detail-type": "EC2 Instance State-change Notification",
            "detail": {"state": "running"}
        }
        assert is_ec2_launch_event(event) == True

    def test_rejects_non_launch_event(self):
        """Should reject events that are not EC2 launches."""
        from lambda_function import is_ec2_launch_event

        event = {
            "source": "aws.securityhub",
            "detail-type": "Security Hub Findings - Imported",
            "detail": {}
        }
        assert is_ec2_launch_event(event) == False

    def test_extracts_findings_from_security_hub(self):
        """Should extract findings from a Security Hub event."""
        from lambda_function import extract_findings

        event = {
            "detail": {
                "findings": [
                    {"Title": "Test finding", "Severity": {"Label": "HIGH"}}
                ]
            }
        }
        findings = extract_findings(event)
        assert len(findings) == 1
        assert findings[0]["Title"] == "Test finding"

    def test_extracts_resource_types(self):
        """Should extract resource types from a finding."""
        from lambda_function import get_resource_types

        finding = {
            "Resources": [
                {"Type": "AwsS3Bucket", "Id": "arn:aws:s3:::test"},
                {"Type": "AwsEc2SecurityGroup", "Id": "arn:aws:ec2:eu-west-2:123:sg/sg-123"}
            ]
        }
        types = get_resource_types(finding)
        assert "AwsS3Bucket" in types
        assert "AwsEc2SecurityGroup" in types
