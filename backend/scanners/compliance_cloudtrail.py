"""
CloudTrail Compliance Scanner
Verifies CloudTrail is enabled, multi-region, log validation on, etc.
"""

import boto3
from typing import Dict


def scan_cloudtrail(session: boto3.Session, region: str) -> Dict:
    result = {
        "score": 0,
        "total_checks": 0,
        "passed": 0,
        "failed": 0,
        "checks": [],
        "trails": [],
        "errors": [],
    }

    try:
        ct = session.client("cloudtrail", region_name=region)

        # ── 1. Get all trails ────────────────────────────────────
        trails_resp = ct.describe_trails(includeShadowTrails=False)
        trails_raw  = trails_resp.get("trailList", [])

        _add_check(result, "CloudTrail is enabled",
                   len(trails_raw) > 0,
                   f"{len(trails_raw)} trail(s) found" if trails_raw else "No CloudTrail trails found",
                   "CRITICAL")

        if not trails_raw:
            result["score"] = 0
            return result

        multi_region_exists = False
        log_validation_ok   = False
        s3_logging_ok       = False
        mgmt_events_ok      = False

        for trail in trails_raw:
            trail_name = trail.get("Name", "—")
            trail_arn  = trail.get("TrailARN", "—")
            is_multi   = trail.get("IsMultiRegionTrail", False)
            log_valid  = trail.get("LogFileValidationEnabled", False)
            s3_bucket  = trail.get("S3BucketName", "—")
            has_cw     = bool(trail.get("CloudWatchLogsLogGroupArn"))

            if is_multi:
                multi_region_exists = True
            if log_valid:
                log_validation_ok = True

            # Check trail status (is it actually logging?)
            logging_on = False
            try:
                status = ct.get_trail_status(Name=trail_arn)
                logging_on = status.get("IsLogging", False)
                latest_delivery = str(status.get("LatestDeliveryTime", "—"))[:19]
            except Exception:
                latest_delivery = "—"

            # Check event selectors
            mgmt_events = False
            try:
                sel_resp = ct.get_event_selectors(TrailName=trail_arn)
                for sel in sel_resp.get("EventSelectors", []):
                    if sel.get("ReadWriteType") in ("All", "WriteOnly"):
                        mgmt_events = True
                        mgmt_events_ok = True
                        break
            except Exception:
                pass

            if s3_bucket != "—":
                s3_logging_ok = True

            result["trails"].append({
                "name":          trail_name,
                "arn":           trail_arn,
                "multi_region":  is_multi,
                "log_validation": log_valid,
                "s3_bucket":     s3_bucket,
                "cloudwatch":    has_cw,
                "logging":       logging_on,
                "mgmt_events":   mgmt_events,
                "latest_delivery": latest_delivery,
            })

        # ── 2. Compliance checks ─────────────────────────────────
        _add_check(result, "Multi-region trail exists",
                   multi_region_exists,
                   "Multi-region trail is configured" if multi_region_exists else "No multi-region trail found",
                   "HIGH")

        _add_check(result, "Log file validation enabled",
                   log_validation_ok,
                   "Log file integrity validation is on" if log_validation_ok else "Log file validation is disabled",
                   "MEDIUM")

        _add_check(result, "Trails delivering to S3",
                   s3_logging_ok,
                   "Trails are logging to S3" if s3_logging_ok else "No S3 delivery configured",
                   "HIGH")

        _add_check(result, "Management events being recorded",
                   mgmt_events_ok,
                   "Management events are captured" if mgmt_events_ok else "Management events not configured",
                   "HIGH")

        # Check if all trails are actively logging
        all_logging = all(t["logging"] for t in result["trails"])
        _add_check(result, "All trails are actively logging",
                   all_logging,
                   "All trails are logging" if all_logging else "Some trails are NOT logging",
                   "CRITICAL")

        # Score
        total = result["total_checks"]
        if total > 0:
            result["score"] = round((result["passed"] / total) * 100, 1)

    except Exception as e:
        result["errors"].append(str(e))

    return result


def _add_check(result: Dict, name: str, passed: bool, detail: str, severity: str = "MEDIUM"):
    result["total_checks"] += 1
    status = "PASS" if passed else "FAIL"
    if passed:
        result["passed"] += 1
    else:
        result["failed"] += 1
    result["checks"].append({
        "name": name, "status": status, "detail": detail, "severity": severity
    })
