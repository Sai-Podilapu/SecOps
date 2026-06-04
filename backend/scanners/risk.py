"""
Phase 3 — Risk Dashboard Scanner Orchestrator
Aggregates findings from Inspector, Macie, Security Hub, GuardDuty,
Health, CloudWatch and builds a unified prioritized risk model.
"""

import boto3
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from botocore.exceptions import ClientError

from scanners.risk_inspector   import scan_inspector
from scanners.risk_macie       import scan_macie
from scanners.risk_securityhub import scan_securityhub
from scanners.risk_guardduty   import scan_guardduty
from scanners.risk_health      import scan_health
from scanners.risk_cloudwatch  import scan_cloudwatch
from scanners.risk_costs       import scan_costs


def build_session(access_key, secret_key, region="ap-south-1"):
    return boto3.Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name=region,
    )


def get_identity(session):
    try:
        r = session.client("sts").get_caller_identity()
        return {"account_id": r["Account"], "user_id": r["UserId"], "arn": r["Arn"]}
    except Exception as e:
        return {"error": str(e)}


# ── Risk Scoring Engine ───────────────────────────────────────────────────────
SEVERITY_SCORE = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1, "INFO": 0}

def build_risk_score(all_findings):
    """
    Aggregate all findings into a single risk score 0-100.
    Higher = more risk (inverse of compliance score).
    """
    if not all_findings:
        return {"score": 0, "level": "LOW", "total_findings": 0}

    total_weight = sum(SEVERITY_SCORE.get(f.get("severity", "LOW"), 1) for f in all_findings)
    max_possible = len(all_findings) * 10
    raw          = (total_weight / max_possible) * 100 if max_possible > 0 else 0
    score        = round(min(raw, 100), 1)
    level        = "CRITICAL" if score >= 70 else "HIGH" if score >= 40 else "MEDIUM" if score >= 20 else "LOW"
    return {"score": score, "level": level, "total_findings": len(all_findings)}


def build_unified_findings(results):
    """
    Merge findings from all scanners into one unified list with
    consistent fields: source, severity, title, resource, region, description.
    """
    unified = []

    # Inspector
    for f in results.get("inspector", {}).get("findings", []):
        unified.append({
            "source":      "Inspector",
            "severity":    f.get("severity", "MEDIUM"),
            "title":       f.get("title", "—"),
            "resource":    f.get("resource_id", "—"),
            "resource_type": f.get("resource_type", "—"),
            "description": f.get("description", "—"),
            "score":       f.get("score", 0),
            "region":      f.get("region", "—"),
            "remediation": f.get("remediation", "—"),
            "created":     f.get("created", "—"),
        })

    # Macie
    for f in results.get("macie", {}).get("findings", []):
        unified.append({
            "source":      "Macie",
            "severity":    f.get("severity", "MEDIUM"),
            "title":       f.get("title", "—"),
            "resource":    f.get("resource", "—"),
            "resource_type": "S3 Bucket",
            "description": f.get("description", "—"),
            "score":       SEVERITY_SCORE.get(f.get("severity", "LOW"), 1) * 10,
            "region":      f.get("region", "—"),
            "remediation": "Review S3 bucket access policies and encryption settings.",
            "created":     f.get("created", "—"),
        })

    # Security Hub
    for f in results.get("securityhub", {}).get("findings", []):
        unified.append({
            "source":      "Security Hub",
            "severity":    f.get("severity", "MEDIUM"),
            "title":       f.get("title", "—"),
            "resource":    f.get("resource_id", "—"),
            "resource_type": f.get("resource_type", "—"),
            "description": f.get("description", "—"),
            "score":       SEVERITY_SCORE.get(f.get("severity", "LOW"), 1) * 10,
            "region":      "—",
            "remediation": f.get("remediation", "—"),
            "created":     f.get("updated", "—"),
        })

    # GuardDuty
    for f in results.get("guardduty", {}).get("findings", []):
        unified.append({
            "source":      "GuardDuty",
            "severity":    f.get("severity", "MEDIUM"),
            "title":       f.get("title", "—"),
            "resource":    f.get("resource_id", "—"),
            "resource_type": f.get("resource_type", "—"),
            "description": f.get("description", "—"),
            "score":       round(f.get("severity_score", 5) * 10, 1),
            "region":      f.get("region", "—"),
            "remediation": "Investigate the threat and isolate the affected resource.",
            "created":     f.get("created", "—"),
        })

    # Sort by severity then score
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    unified.sort(key=lambda x: (sev_order.get(x["severity"], 5), -x.get("score", 0)))

    return unified


def build_heatmap(unified_findings, regions):
    """Build a severity heatmap: region × source."""
    sources = ["Inspector", "Macie", "Security Hub", "GuardDuty"]
    heatmap = {}
    for region in regions:
        heatmap[region] = {s: {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0} for s in sources}

    for f in unified_findings:
        reg = f.get("region", "global")
        src = f.get("source", "")
        sev = f.get("severity", "LOW")
        if reg in heatmap and src in heatmap[reg]:
            heatmap[reg][src][sev] = heatmap[reg][src].get(sev, 0) + 1
        elif "global" not in heatmap:
            heatmap["global"] = {s: {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0} for s in sources}
            if src in heatmap["global"]:
                heatmap["global"][src][sev] += 1

    return heatmap


def build_trend(unified_findings):
    """Group findings by creation date for trend line (last 30 days)."""
    from collections import defaultdict
    daily = defaultdict(lambda: {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0})
    for f in unified_findings:
        date = str(f.get("created", ""))[:10]
        if date and date != "—":
            sev = f.get("severity", "LOW")
            daily[date][sev] += 1
    return dict(sorted(daily.items())[-30:])


def run_risk_scan(access_key, secret_key, region):
    result = {
        "identity":       {},
        "region":         region,
        "scan_time":      str(datetime.now(timezone.utc))[:19],
        "risk_score":     {},
        "summary":        {},
        "unified_findings": [],
        "heatmap":        {},
        "trend":          {},
        "inspector":      {},
        "macie":          {},
        "securityhub":    {},
        "guardduty":      {},
        "health":         {},
        "cloudwatch":     {},
        "costs":          {},
        "errors":         [],
    }

    try:
        session          = build_session(access_key, secret_key, region)
        result["identity"] = get_identity(session)

        # Run all scanners in parallel
        scanners = {
            "inspector":   lambda: scan_inspector(session, region),
            "macie":       lambda: scan_macie(session, region),
            "securityhub": lambda: scan_securityhub(session, region),
            "guardduty":   lambda: scan_guardduty(session, region),
            "health":      lambda: scan_health(session, region),
            "cloudwatch":  lambda: scan_cloudwatch(session, region),
            "costs":       lambda: scan_costs(session),
        }

        with ThreadPoolExecutor(max_workers=7) as executor:
            futures = {executor.submit(fn): name for name, fn in scanners.items()}
            for future in as_completed(futures):
                name = futures[future]
                try:
                    result[name] = future.result()
                except Exception as e:
                    result["errors"].append(f"{name}: {str(e)}")
                    result[name] = {"error": str(e), "findings": []}

        # Build unified findings and risk model
        unified = build_unified_findings(result)
        result["unified_findings"] = unified
        result["risk_score"]       = build_risk_score(unified)
        result["heatmap"]          = build_heatmap(unified, [region])
        result["trend"]            = build_trend(unified)

        # Summary counts
        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        source_counts = {}
        for f in unified:
            sev = f.get("severity", "LOW")
            src = f.get("source", "Unknown")
            sev_counts[sev]    = sev_counts.get(sev, 0) + 1
            source_counts[src] = source_counts.get(src, 0) + 1

        result["summary"] = {
            "total_findings":  len(unified),
            "severity_counts": sev_counts,
            "source_counts":   source_counts,
            "top_risks":       unified[:5],
        }

    except ClientError as e:
        result["errors"].append(e.response["Error"]["Message"])
    except Exception as e:
        result["errors"].append(str(e))

    return result
