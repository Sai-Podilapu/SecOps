"""
GuardDuty Scanner (Phase 3 — Risk focused)
"""

import boto3
from typing import Dict


def scan_guardduty(session: boto3.Session, region: str) -> Dict:
    result = {
        "enabled": False,
        "detector_id": None,
        "total_findings": 0,
        "severity_counts": {"HIGH": 0, "MEDIUM": 0, "LOW": 0},
        "findings": [],
        "errors": [],
    }

    try:
        gd = session.client("guardduty", region_name=region)
        detectors = gd.list_detectors().get("DetectorIds", [])
        if not detectors:
            result["errors"].append(f"GuardDuty not enabled. Run: aws guardduty create-detector --enable --region {region}")
            return result

        detector_id            = detectors[0]
        result["detector_id"]  = detector_id
        result["enabled"]      = True

        list_resp   = gd.list_findings(DetectorId=detector_id, MaxResults=50)
        finding_ids = list_resp.get("FindingIds", [])
        if not finding_ids:
            return result

        findings_resp = gd.get_findings(DetectorId=detector_id, FindingIds=finding_ids)
        for f in findings_resp.get("Findings", []):
            score = f.get("Severity", 0)
            sev   = "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW"
            result["severity_counts"][sev] += 1

            resource     = f.get("Resource", {})
            res_type     = resource.get("ResourceType", "—")
            res_id       = "—"
            if res_type == "Instance":
                res_id = resource.get("InstanceDetails", {}).get("InstanceId", "—")
            elif res_type == "AccessKey":
                res_id = resource.get("AccessKeyDetails", {}).get("AccessKeyId", "—")
            elif res_type == "S3Bucket":
                buckets = resource.get("S3BucketDetails", [])
                res_id  = buckets[0].get("Name", "—") if buckets else "—"

            result["findings"].append({
                "id":             f.get("Id", "—")[:30],
                "type":           f.get("Type", "—"),
                "title":          f.get("Title", "—"),
                "description":    f.get("Description", "—")[:200],
                "severity":       sev,
                "severity_score": score,
                "resource_id":    res_id,
                "resource_type":  res_type,
                "region":         f.get("Region", region),
                "created":        str(f.get("CreatedAt", "—"))[:19],
                "count":          f.get("Service", {}).get("Count", 1),
            })

        result["findings"].sort(key=lambda x: -x["severity_score"])
        result["total_findings"] = len(result["findings"])

    except Exception as e:
        result["errors"].append(str(e))

    return result
