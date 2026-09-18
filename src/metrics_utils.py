# metrics_utils.py
#
# Small helper for sending CloudWatch custom metrics
# so I can build a dashboard later.

import boto3
from datetime import datetime, timezone

# CloudWatch client
cloudwatch = boto3.client("cloudwatch")

# All my auto-fix metrics will live in this namespace
METRIC_NAMESPACE = "AutoFixSecurity"


def record_fix(service_name: str, action: str):
    """
    Send one simple metric to CloudWatch each time the Lambda
    finishes dealing with a resource.

    service_name: "S3", "EC2", "IAM", ...
    action:       "remediated", "skipped", "error", etc.
    """
    try:
        cloudwatch.put_metric_data(
            Namespace=METRIC_NAMESPACE,
            MetricData=[
                {
                    "MetricName": "FixCount",
                    "Dimensions": [
                        {"Name": "Service", "Value": service_name},
                        {"Name": "Action", "Value": action},
                    ],
                    "Unit": "Count",
                    "Value": 1,
                    "Timestamp": datetime.now(timezone.utc),
                }
            ],
        )
        print(
            f"[METRICS] Sent metric: Service={service_name}, "
            f"Action={action}, Namespace={METRIC_NAMESPACE}"
        )
    except Exception as e:
        # I don’t want metrics errors to break the Lambda
        print(f"[METRICS] Failed to send metric: {e}")