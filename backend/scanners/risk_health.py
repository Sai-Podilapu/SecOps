"""
AWS Health Scanner
Fetches active AWS Health events affecting this account
Note: AWS Health requires Business or Enterprise Support plan for full access.
Without it, only public health events are returned.
"""

import boto3
from typing import Dict


def scan_health(session: boto3.Session, region: str) -> Dict:
    result = {
        "total_events": 0,
        "open_events":  0,
        "events":       [],
        "by_service":   {},
        "errors":       [],
    }

    try:
        # AWS Health API is only available in us-east-1
        health = session.client("health", region_name="us-east-1")

        kwargs = {
            "filter": {
                "eventStatusCodes": ["open", "upcoming"],
                "eventTypeCategories": ["issue", "scheduledChange", "accountNotification"],
            },
            "maxResults": 50,
        }

        events_raw = []
        while True:
            resp  = health.describe_events(**kwargs)
            batch = resp.get("events", [])
            events_raw.extend(batch)
            next_token = resp.get("nextToken")
            if not next_token or not batch:
                break
            kwargs["nextToken"] = next_token

        for ev in events_raw:
            service    = ev.get("service", "—")
            status     = ev.get("statusCode", "—")
            ev_type    = ev.get("eventTypeCode", "—")
            ev_cat     = ev.get("eventTypeCategory", "—")
            region_ev  = ev.get("region", "global")
            start_time = str(ev.get("startTime", "—"))[:19]
            end_time   = str(ev.get("endTime",   "—"))[:19]

            result["events"].append({
                "arn":      ev.get("arn", "—"),
                "service":  service,
                "type":     ev_type,
                "category": ev_cat,
                "status":   status,
                "region":   region_ev,
                "start":    start_time,
                "end":      end_time,
            })

            result["by_service"][service] = result["by_service"].get(service, 0) + 1

            if status == "open":
                result["open_events"] += 1

        result["total_events"] = len(result["events"])

    except health.exceptions.SubscriptionRequiredException:
        result["errors"].append(
            "AWS Health full access requires Business or Enterprise Support plan. "
            "Only public health events are visible."
        )
    except Exception as e:
        result["errors"].append(str(e))

    return result
