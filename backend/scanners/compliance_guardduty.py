"""
GuardDuty Scanner
Checks if GuardDuty is enabled and retrieves active threat findings
"""

import boto3
from typing import Dict


def scan_guardduty(session: boto3.Session, region: str) -> Dict:
    result = {
        "score": 100,
        "enabled": False,
        "detector_id": None,
        "total_findings": 0,
        "severity_counts": {"HIGH": 0, "MEDIUM": 0, "LOW": 0},
        "findings": [],
        "errors": [],
    }

    try:
        gd = session.client("guardduty", region_name=region)

        # ── 1. Check if GuardDuty is enabled ─────────────────────
        detectors = gd.list_detectors().get("DetectorIds", [])
        if not detectors:
            result["enabled"]   = False
            result["score"]     = 0
            result["errors"].append(
                "GuardDuty is not enabled. Enable with: "
                f"aws guardduty create-detector --enable --region {region}"
            )
            return result

        detector_id = detectors[0]
        result["detector_id"] = detector_id
        result["enabled"]     = True

        # ── 2. Get finding IDs (active findings only) ─────────────
        list_resp = gd.list_findings(
            DetectorId=detector_id,
            FindingCriteria={
                "Criterion": {
                    "service.archived": {"Eq": ["false"]},
                }
            },
            MaxResults=50,
        )
        finding_ids = list_resp.get("FindingIds", [])
        result["total_findings"] = len(finding_ids)

        if not finding_ids:
            result["score"] = 100
            return result

        # ── 3. Get finding details ────────────────────────────────
        findings_resp = gd.get_findings(
            DetectorId=detector_id,
            FindingIds=finding_ids[:50],
        )

        for f in findings_resp.get("Findings", []):
            severity_val = f.get("Severity", 0)
            if severity_val >= 7:
                sev_label = "HIGH"
                result["severity_counts"]["HIGH"] += 1
            elif severity_val >= 4:
                sev_label = "MEDIUM"
                result["severity_counts"]["MEDIUM"] += 1
            else:
                sev_label = "LOW"
                result["severity_counts"]["LOW"] += 1

            resource = f.get("Resource", {})
            resource_type = resource.get("ResourceType", "—")
            resource_id = "—"
            if resource_type == "Instance":
                resource_id = resource.get("InstanceDetails", {}).get("InstanceId", "—")
            elif resource_type == "AccessKey":
                resource_id = resource.get("AccessKeyDetails", {}).get("AccessKeyId", "—")
            elif resource_type == "S3Bucket":
                buckets = resource.get("S3BucketDetails", [])
                resource_id = buckets[0].get("Name", "—") if buckets else "—"

            result["findings"].append({
                "id":            f.get("Id", "—")[:30],
                "type":          f.get("Type", "—"),
                "title":         f.get("Title", "—"),
                "description":   f.get("Description", "—")[:200],
                "severity":      sev_label,
                "severity_score": severity_val,
                "resource_type": resource_type,
                "resource_id":   resource_id,
                "region":        f.get("Region", region),
                "created":       str(f.get("CreatedAt", "—"))[:19],
                "updated":       str(f.get("UpdatedAt", "—"))[:19],
                "count":         f.get("Service", {}).get("Count", 1),
            })

        # Sort by severity
        result["findings"].sort(key=lambda x: -x["severity_score"])

        # ── 4. Score ──────────────────────────────────────────────
        h = result["severity_counts"]["HIGH"]
        m = result["severity_counts"]["MEDIUM"]
        l = result["severity_counts"]["LOW"]
        penalty = h * 15 + m * 5 + l * 1
        result["score"] = max(0, round(100 - min(penalty, 100), 1))

    except Exception as e:
        result["errors"].append(str(e))

    return result
