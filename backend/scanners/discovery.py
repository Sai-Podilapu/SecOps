"""
AWS Config Discovery — Scanner
Uses AWS Config select_resource_config to discover ALL resources (300+ types)
Falls back to direct APIs for costs, IAM details, and S3 details
"""

import json
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Any, Optional

import boto3
from botocore.exceptions import ClientError


# ─────────────────────────────────────────────
# SESSION
# ─────────────────────────────────────────────

def build_session(access_key: str, secret_key: str, region: str = "us-east-1") -> boto3.Session:
    return boto3.Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name=region,
    )


# ─────────────────────────────────────────────
# IDENTITY
# ─────────────────────────────────────────────

def get_identity(session: boto3.Session) -> Dict:
    sts = session.client("sts")
    r = sts.get_caller_identity()
    return {
        "account_id": r["Account"],
        "user_id": r["UserId"],
        "arn": r["Arn"],
    }


# ─────────────────────────────────────────────
# REGIONS — get all enabled regions
# ─────────────────────────────────────────────

def get_regions(session: boto3.Session, selected: Optional[str] = None) -> List[str]:
    if selected:
        return [selected]
    try:
        ec2 = session.client("ec2", region_name="us-east-1")
        resp = ec2.describe_regions(
            Filters=[{"Name": "opt-in-status", "Values": ["opt-in-not-required", "opted-in"]}]
        )
        return sorted(r["RegionName"] for r in resp["Regions"])
    except Exception:
        return [
            "us-east-1", "us-east-2", "us-west-1", "us-west-2",
            "eu-west-1", "eu-west-2", "eu-central-1",
            "ap-south-1", "ap-southeast-1", "ap-northeast-1",
        ]


# ─────────────────────────────────────────────
# CONFIG RECORDER STATUS
# ─────────────────────────────────────────────

def check_config_status(session: boto3.Session, region: str) -> Dict:
    try:
        cfg = session.client("config", region_name=region)
        recorders = cfg.describe_configuration_recorder_status()
        status_list = recorders.get("ConfigurationRecordersStatus", [])
        if not status_list:
            return {"enabled": False, "recording": False}
        s = status_list[0]
        return {
            "enabled": True,
            "recording": s.get("recording", False),
            "last_status": s.get("lastStatus", "—"),
            "last_start": str(s.get("lastStartTime", "—"))[:19],
        }
    except Exception as e:
        return {"enabled": False, "recording": False, "error": str(e)}


# ─────────────────────────────────────────────
# CONFIG QUERY — core discovery engine
# ─────────────────────────────────────────────

def query_config(session: boto3.Session, region: str, expression: str) -> List[Dict]:
    """Run a SQL query against AWS Config in a region and return parsed results."""
    results = []
    try:
        cfg = session.client("config", region_name=region)
        kwargs = {"Expression": expression, "Limit": 100}
        while True:
            resp = cfg.select_resource_config(**kwargs)
            for item in resp.get("Results", []):
                try:
                    results.append(json.loads(item))
                except Exception:
                    pass
            next_token = resp.get("NextToken")
            if not next_token:
                break
            kwargs["NextToken"] = next_token
    except Exception:
        pass
    return results


def get_all_resources_in_region(session: boto3.Session, region: str) -> Dict:
    """
    Query ALL resources in a region using AWS Config.
    Returns resources grouped by resourceType.
    """
    expression = """
        SELECT
            resourceId,
            resourceType,
            resourceName,
            awsRegion,
            availabilityZone,
            configurationItemStatus,
            resourceCreationTime,
            tags,
            configuration,
            relationships
        WHERE
            configurationItemStatus != 'ResourceDeleted'
    """

    raw = query_config(session, region, expression)

    # Group by resourceType
    grouped: Dict[str, List] = {}
    for item in raw:
        rtype = item.get("resourceType", "Unknown")
        if rtype not in grouped:
            grouped[rtype] = []

        # Parse configuration JSON if it's a string
        config = item.get("configuration", {})
        if isinstance(config, str):
            try:
                config = json.loads(config)
            except Exception:
                config = {}

        # Parse tags
        tags_raw = item.get("tags", [])
        tags = {}
        if isinstance(tags_raw, list):
            for t in tags_raw:
                if isinstance(t, dict):
                    tags[t.get("key", t.get("Key", ""))] = t.get("value", t.get("Value", ""))
        elif isinstance(tags_raw, dict):
            tags = tags_raw

        grouped[rtype].append({
            "resourceId": item.get("resourceId", "—"),
            "resourceName": item.get("resourceName") or tags.get("Name", "—"),
            "region": item.get("awsRegion", region),
            "az": item.get("availabilityZone", "—"),
            "status": item.get("configurationItemStatus", "—"),
            "createdAt": str(item.get("resourceCreationTime", "—"))[:19],
            "tags": tags,
            "configuration": config,
        })

    return grouped


def get_resource_type_counts(session: boto3.Session, region: str) -> Dict[str, int]:
    """Get count of each resource type in a region."""
    expression = "SELECT resourceType, COUNT(*) WHERE configurationItemStatus != 'ResourceDeleted' GROUP BY resourceType"
    try:
        cfg = session.client("config", region_name=region)
        resp = cfg.select_resource_config(Expression=expression, Limit=500)
        counts = {}
        for item in resp.get("Results", []):
            try:
                d = json.loads(item)
                counts[d["resourceType"]] = d.get("COUNT(*)", 0)
            except Exception:
                pass
        return counts
    except Exception:
        return {}


# ─────────────────────────────────────────────
# COSTS — direct API (Config doesn't cover this)
# ─────────────────────────────────────────────

def get_costs(session: boto3.Session) -> Dict:
    ce = session.client("ce", region_name="us-east-1")
    now = datetime.now(timezone.utc)
    end = now.strftime("%Y-%m-%d")
    start = now.replace(day=1).strftime("%Y-%m-%d")
    result = {
        "by_service": {},
        "by_region": {},
        "total": 0,
        "period": f"{start} → {end}",
        "forecast": None,
    }
    try:
        resp = ce.get_cost_and_usage(
            TimePeriod={"Start": start, "End": end},
            Granularity="MONTHLY",
            Metrics=["UnblendedCost"],
            GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}],
        )
        for period in resp.get("ResultsByTime", []):
            for g in period.get("Groups", []):
                cost = float(g["Metrics"]["UnblendedCost"]["Amount"])
                if cost > 0:
                    result["by_service"][g["Keys"][0]] = round(cost, 4)
        result["total"] = round(sum(result["by_service"].values()), 4)
    except Exception as e:
        result["error"] = str(e)

    try:
        import calendar
        last_day = calendar.monthrange(now.year, now.month)[1]
        end_fc = now.replace(day=last_day).strftime("%Y-%m-%d")
        if start != end_fc:
            fc = ce.get_cost_forecast(
                TimePeriod={"Start": end, "End": end_fc},
                Metric="UNBLENDED_COST",
                Granularity="MONTHLY",
            )
            result["forecast"] = round(float(fc["Total"]["Amount"]), 2)
    except Exception:
        pass

    try:
        resp2 = ce.get_cost_and_usage(
            TimePeriod={"Start": start, "End": end},
            Granularity="MONTHLY",
            Metrics=["UnblendedCost"],
            GroupBy=[{"Type": "DIMENSION", "Key": "REGION"}],
        )
        for period in resp2.get("ResultsByTime", []):
            for g in period.get("Groups", []):
                cost = float(g["Metrics"]["UnblendedCost"]["Amount"])
                if cost > 0:
                    result["by_region"][g["Keys"][0]] = round(cost, 4)
    except Exception:
        pass

    return result


# ─────────────────────────────────────────────
# IAM SUMMARY — direct API for user details
# ─────────────────────────────────────────────

def get_iam_summary(session: boto3.Session) -> Dict:
    iam = session.client("iam")
    try:
        summary = iam.get_account_summary().get("SummaryMap", {})
        return {
            "users": summary.get("Users", 0),
            "groups": summary.get("Groups", 0),
            "roles": summary.get("Roles", 0),
            "policies": summary.get("Policies", 0),
            "mfa_devices": summary.get("MFADevices", 0),
            "access_keys": summary.get("AccessKeys", 0),
            "account_mfa_enabled": summary.get("AccountMFAEnabled", 0),
        }
    except Exception as e:
        return {"error": str(e)}


# ─────────────────────────────────────────────
# MAIN SCAN
# ─────────────────────────────────────────────

def scan_all(access_key: str, secret_key: str, region: Optional[str] = None) -> Dict:
    results = {
        "identity": {},
        "regions": [],
        "config_status": {},
        "resources": {},        # region -> resourceType -> [resources]
        "resource_counts": {},  # region -> resourceType -> count
        "summary": {},          # total counts per resourceType across all regions
        "costs": {},
        "iam_summary": {},
        "scan_time": str(datetime.now(timezone.utc))[:19],
        "errors": [],
    }

    try:
        session = build_session(access_key, secret_key)

        # Identity
        results["identity"] = get_identity(session)

        # Regions
        regions = get_regions(session, region)
        results["regions"] = regions

        # Costs + IAM (global, run in parallel with region scans)
        results["costs"] = get_costs(session)
        results["iam_summary"] = get_iam_summary(session)

        # Per-region: check Config status + query all resources
        def scan_region(reg: str):
            reg_session = build_session(access_key, secret_key, reg)
            status = check_config_status(reg_session, reg)
            resources = {}
            counts = {}
            if status.get("recording") or status.get("enabled"):
                resources = get_all_resources_in_region(reg_session, reg)
                counts = {rtype: len(items) for rtype, items in resources.items()}
            return reg, status, resources, counts

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(scan_region, reg): reg for reg in regions}
            for future in as_completed(futures):
                try:
                    reg, status, resources, counts = future.result()
                    results["config_status"][reg] = status
                    if resources:
                        results["resources"][reg] = resources
                        results["resource_counts"][reg] = counts
                except Exception as e:
                    results["errors"].append(str(e))

        # Build global summary (total per resourceType across all regions)
        summary: Dict[str, int] = {}
        for reg, counts in results["resource_counts"].items():
            for rtype, count in counts.items():
                summary[rtype] = summary.get(rtype, 0) + count
        results["summary"] = dict(sorted(summary.items(), key=lambda x: x[1], reverse=True))

    except ClientError as e:
        results["error"] = e.response["Error"]["Message"]
    except Exception as e:
        results["error"] = str(e)

    return results
