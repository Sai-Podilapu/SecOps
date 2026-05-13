"""
CloudWatch Alarms Scanner
Fetches alarms in ALARM state — active issues requiring attention
"""

import boto3
from typing import Dict


def scan_cloudwatch(session: boto3.Session, region: str) -> Dict:
    result = {
        "total_alarms":   0,
        "in_alarm":       0,
        "ok":             0,
        "insufficient":   0,
        "alarms":         [],
        "errors":         [],
    }

    try:
        cw = session.client("cloudwatch", region_name=region)

        all_alarms = []
        kwargs     = {"MaxRecords": 100}
        while True:
            resp  = cw.describe_alarms(**kwargs)
            batch = resp.get("MetricAlarms", [])
            all_alarms.extend(batch)
            next_token = resp.get("NextToken")
            if not next_token:
                break
            kwargs["NextToken"] = next_token

        for alarm in all_alarms:
            state = alarm.get("StateValue", "—")
            if state == "ALARM":
                result["in_alarm"] += 1
            elif state == "OK":
                result["ok"] += 1
            else:
                result["insufficient"] += 1

            result["alarms"].append({
                "name":        alarm.get("AlarmName", "—"),
                "state":       state,
                "metric":      alarm.get("MetricName", "—"),
                "namespace":   alarm.get("Namespace", "—"),
                "threshold":   alarm.get("Threshold", "—"),
                "operator":    alarm.get("ComparisonOperator", "—"),
                "description": alarm.get("AlarmDescription", "—") or "—",
                "updated":     str(alarm.get("StateUpdatedTimestamp", "—"))[:19],
                "actions":     len(alarm.get("AlarmActions", [])),
            })

        # Sort — ALARM state first
        state_order = {"ALARM": 0, "INSUFFICIENT_DATA": 1, "OK": 2}
        result["alarms"].sort(key=lambda x: state_order.get(x["state"], 3))
        result["total_alarms"] = len(result["alarms"])

    except Exception as e:
        result["errors"].append(str(e))

    return result
