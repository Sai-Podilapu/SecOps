"""
Main Compliance Scanner Orchestrator
Runs all scanners in parallel and aggregates results
"""

import boto3
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from botocore.exceptions import ClientError

from scanners.compliance_config_rules   import scan_config_rules
from scanners.compliance_security_hub   import scan_security_hub
from scanners.compliance_iam_compliance import scan_iam_compliance
from scanners.compliance_cloudtrail     import scan_cloudtrail
from scanners.compliance_guardduty      import scan_guardduty


def build_session(access_key: str, secret_key: str, region: str = "us-east-1") -> boto3.Session:
    return boto3.Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name=region,
    )


def get_identity(session: boto3.Session) -> dict:
    try:
        sts = session.client("sts")
        r = sts.get_caller_identity()
        return {"account_id": r["Account"], "user_id": r["UserId"], "arn": r["Arn"]}
    except Exception as e:
        return {"error": str(e)}


def calculate_overall_score(results: dict) -> dict:
    """
    Calculate overall compliance score from all scanner results.
    Weighted scoring:
      Config Rules   — 35%
      Security Hub   — 30%
      IAM Compliance — 20%
      CloudTrail     — 10%
      GuardDuty      —  5%
    """
    weights = {
        "config_rules":   0.35,
        "security_hub":   0.30,
        "iam_compliance": 0.20,
        "cloudtrail":     0.10,
        "guardduty":      0.05,
    }

    scores = {}
    for key, weight in weights.items():
        data = results.get(key, {})
        score = data.get("score", None)
        if score is not None:
            scores[key] = {"score": score, "weight": weight}

    if not scores:
        return {"overall": 0, "breakdown": {}, "grade": "F"}

    weighted_sum = sum(s["score"] * s["weight"] for s in scores.values())
    total_weight = sum(s["weight"] for s in scores.values())
    overall = round(weighted_sum / total_weight, 1) if total_weight > 0 else 0

    grade = "A" if overall >= 90 else "B" if overall >= 80 else "C" if overall >= 70 else "D" if overall >= 60 else "F"

    return {
        "overall": overall,
        "grade": grade,
        "breakdown": {k: v["score"] for k, v in scores.items()},
    }


def build_summary(results: dict) -> dict:
    """Build a high-level summary of findings across all scanners."""
    critical = 0
    high     = 0
    medium   = 0
    low      = 0
    total_checks   = 0
    passed_checks  = 0
    failed_checks  = 0

    # Config rules
    cr = results.get("config_rules", {})
    total_checks  += cr.get("total_rules", 0)
    passed_checks += cr.get("compliant_count", 0)
    failed_checks += cr.get("non_compliant_count", 0)

    # Security Hub
    sh = results.get("security_hub", {})
    critical += sh.get("severity_counts", {}).get("CRITICAL", 0)
    high     += sh.get("severity_counts", {}).get("HIGH", 0)
    medium   += sh.get("severity_counts", {}).get("MEDIUM", 0)
    low      += sh.get("severity_counts", {}).get("LOW", 0)

    # IAM
    iam = results.get("iam_compliance", {})
    total_checks  += iam.get("total_checks", 0)
    passed_checks += iam.get("passed", 0)
    failed_checks += iam.get("failed", 0)

    # GuardDuty
    gd = results.get("guardduty", {})
    critical += gd.get("severity_counts", {}).get("HIGH", 0)

    return {
        "critical_findings": critical,
        "high_findings":     high,
        "medium_findings":   medium,
        "low_findings":      low,
        "total_checks":      total_checks,
        "passed_checks":     passed_checks,
        "failed_checks":     failed_checks,
    }


def run_compliance_scan(access_key: str, secret_key: str, region: str) -> dict:
    result = {
        "identity":       {},
        "region":         region,
        "scan_time":      str(datetime.now(timezone.utc))[:19],
        "score":          {},
        "summary":        {},
        "config_rules":   {},
        "security_hub":   {},
        "iam_compliance": {},
        "cloudtrail":     {},
        "guardduty":      {},
        "errors":         [],
    }

    try:
        session = build_session(access_key, secret_key, region)
        result["identity"] = get_identity(session)

        # Run all scanners in parallel
        scanners = {
            "config_rules":   lambda: scan_config_rules(session, region),
            "security_hub":   lambda: scan_security_hub(session, region),
            "iam_compliance": lambda: scan_iam_compliance(session, region),
            "cloudtrail":     lambda: scan_cloudtrail(session, region),
            "guardduty":      lambda: scan_guardduty(session, region),
        }

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(fn): name for name, fn in scanners.items()}
            for future in as_completed(futures):
                name = futures[future]
                try:
                    result[name] = future.result()
                except Exception as e:
                    result["errors"].append(f"{name}: {str(e)}")
                    result[name] = {"error": str(e), "score": 0}

        # Calculate overall score and summary after all scanners complete
        result["score"]   = calculate_overall_score(result)
        result["summary"] = build_summary(result)

    except ClientError as e:
        result["errors"].append(e.response["Error"]["Message"])
    except Exception as e:
        result["errors"].append(str(e))

    return result
