# Autonomous Cloud Security Remediation System
An event-driven, serverless cloud security remediation engine built on AWS. The system automatically detects, evaluates, and resolves cloud misconfigurations in real time while enforcing safety controls and proactive lifecycle security validation.

---

## Executive Summary

Cloud misconfigurations (e.g., publicly accessible S3 buckets, open SSH ports, over-permissive IAM policies) represent a primary attack vector in modern infrastructure. Traditional monitoring tools generate findings but leave a gap between detection and manual response—during which resources remain vulnerable.

This project eliminates that response gap by deploying an autonomous remediation pipeline using AWS serverless architecture. Key capabilities include:
* **Reactive Remediation:** Listens for AWS Security Hub findings and automatically remediates misconfigured resources.
* **Proactive Security Validation:** Validates newly launched EC2 Auto Scaling instances at the moment of creation before scheduled scans run.
* **Tag-Based Safety Controls:** Enforces an explicit consent gate (`AutoFix=True`) for reactive remediation to prevent unintended changes to sensitive production assets.
* **Heuristic Risk Assessment:** Evaluates multi-resource remediation runs using custom scoring logic to assign severity levels (`LOW`, `MEDIUM`, `HIGH`).
* **Observability & Alerting:** Generates CloudWatch custom metrics, updates an operational dashboard, and issues conditional SNS email alerts summarising action taken.

---

## Key System Architecture & Dual Event Paths

```text
  [ AWS Security Hub ]                   [ EC2 Auto Scaling ]
     (Security Finding)                     (Instance Running)
            │                                       │
            └───────────────┐       ┌───────────────┘
                            ▼       ▼
                     [ Amazon EventBridge ]
                                │
                                ▼
                      [ AWS Lambda Function ]
                     (Main Orchestrator)
                                │
                  ┌─────────────┴─────────────┐
                  ▼                           ▼
          (Path 1: Security Hub)     (Path 2: Auto Scaling Launch)
                  │                           │
          [ Tag Safety Gate ]         [ Bypass Tag Gate ]
          (Check AutoFix=True)       (Immediate Inspection)
                  │                           │
                  └─────────────┬─────────────┘
                                │
       ┌────────────────────────┼────────────────────────┐
       ▼                        ▼                        ▼
[ S3 Module ]             [ EC2 Module ]           [ IAM Module ]
• Block Public Access     • Revoke Inbound         • Delete Inline
  Enforcement               SSH (0.0.0.0/0)          Policies
• Public Policy Cleanup
       │                        │                        │
       └────────────────────────┼────────────────────────┘
                                │
                                ▼
                   [ Heuristic Risk Scoring ]
                                │
                  ┌─────────────┴─────────────┐
                  ▼                           ▼
        [ Amazon CloudWatch ]           [ Amazon SNS ]
     • Custom Metrics Namespace       • Email Summaries
     • Operational Dashboard          (Only on Remediation)
```
### Event Path 1: Reactive Security Hub Findings
1. Security Hub scans resources against CIS Benchmarks and AWS Foundational Security Best Practices.
2. EventBridge filters relevant findings and triggers the orchestrator Lambda function (`lambda_function.py`).
3. The function verifies the presence of the `AutoFix=True` tag on the target resource.
4. If tagged, the handler routes the event to the dedicated module (`s3_autofix.py`, `ec2_autofix.py`, or `iam_autofix.py`).

### Event Path 2: Proactive Auto Scaling Launch Validation
1. An Auto Scaling scale-out event launches an EC2 instance.
2. EventBridge captures the state change (`state = running`) and triggers the orchestrator Lambda.
3. The Lambda retrieves attached Security Groups and invokes the EC2 remediation module with `require_autofix_tag=False`.
4. Open SSH rules (`0.0.0.0/0` on port 22) are removed immediately at launch, bypassing the tag check to secure dynamic compute before exposure.

---

## Targeted Remediation Logic

* **Amazon S3 (`s3_autofix.py`):**
  * Verifies and enforces all four S3 Block Public Access settings (`BlockPublicAcls`, `IgnorePublicAcls`, `BlockPublicPolicy`, `RestrictPublicBuckets`).
  * Scans bucket policies for public statement principals (`*`, `{"AWS": "*"}`, `{"Service": "*"}`). Removes public statements and deletes empty policies.
* **Amazon EC2 (`ec2_autofix.py`):**
  * Inspects inbound security group permissions for port 22 access scoped to `0.0.0.0/0`.
  * Calls `revoke_security_group_ingress` to strip open SSH rules while retaining existing application configurations.
* **AWS IAM (`iam_autofix.py`):**
  * Lists and removes inline policies attached to IAM roles using `delete_role_policy`.
  * Enforces least-privilege hygiene by encouraging version-controlled managed policies over un-audited inline policies.

---

## Heuristic Risk Scoring Model (`risk_scoring.py`)

Every remediation run is evaluated using rule-based risk weighting:
* **Errors Encountered:** +3 points
* **High Fix Volume:** >= 5 remediations (+3 points), 2-4 remediations (+2 points), 1 remediation (+1 point)
* **IAM Modification:** +2 points (Weighted higher due to privilege escalation risks)
* **EC2 Rule Modification:** +1 point

**Level Mapping:** Score >= 6 -> **HIGH** | Score >= 3 -> **MEDIUM** | Score < 3 -> **LOW**

---

## Tech Stack & Project Layout

* **Language & Runtime:** Python 3.12, `boto3`
* **Infrastructure as Code:** AWS Serverless Application Model (SAM) / CloudFormation
* **Core AWS Services:** Lambda, EventBridge, Security Hub, S3, EC2, IAM, SNS, CloudWatch
* **Testing Framework:** `pytest`, `moto` (AWS API mocking)

autofix-security/
├── src/
│   ├── lambda_function.py   # Main orchestrator & event router
│   ├── s3_autofix.py        # S3 remediation logic & BPA enforcement
│   ├── ec2_autofix.py       # EC2 Security Group inbound rule parser
│   ├── iam_autofix.py       # IAM inline policy remediation
│   ├── risk_scoring.py      # Heuristic risk assessment rules
│   ├── metrics_utils.py     # CloudWatch custom metrics publisher
│   └── sns_utils.py         # SNS email summary formatting
├── tests/
│   └── test_autofix.py      # 20 pytest unit tests with local moto mocks
└── template.yaml             # AWS SAM Infrastructure-as-Code template


---

## Verification & Testing

### Unit Testing Suite
Unit tests run locally using `pytest` and `moto` to mock AWS services without making live API calls.

```bash
PYTHONPATH=src pytest tests/test_autofix.py -v
