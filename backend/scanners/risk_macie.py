"""
Amazon Macie Scanner
Finds sensitive data exposures in S3 buckets
"""

import boto3
from typing import Dict


def scan_macie(session: boto3.Session, region: str) -> Dict:
    result = {
        "enabled": False,
        "total_findings": 0,
        "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
        "findings": [],
        "data_categories": {},
        "jobs": [],
        "errors": [],
    }

    try:
        macie = session.client("macie2", region_name=region)

        # ── Check if Macie is enabled ──────────────────────────────
        try:
            status = macie.get_macie_session()
            result["enabled"] = status.get("status") == "ENABLED"
        except macie.exceptions.AccessDeniedException:
            result["errors"].append("Macie not enabled or insufficient permissions.")
            return result
        except Exception as e:
            result["errors"].append(f"Macie status: {str(e)}")
            return result

        if not result["enabled"]:
            result["errors"].append(
                f"Macie not enabled. Run: aws macie2 enable-macie --region {region}"
            )
            return result

        # ── Get classification jobs ───────────────────────────────
        try:
            jobs_resp = macie.list_classification_jobs()
            for job in jobs_resp.get("items", []):
                result["jobs"].append({
                    "id":      job.get("jobId", "—"),
                    "name":    job.get("name", "—"),
                    "status":  job.get("jobStatus", "—"),
                    "type":    job.get("jobType", "—"),
                    "created": str(job.get("createdAt", "—"))[:19],
                })
        except Exception as e:
            result["errors"].append(f"Macie jobs: {str(e)}")

        # ── Get findings ──────────────────────────────────────────
        try:
            list_resp = macie.list_findings(
                findingCriteria={
                    "criterion": {
                        "archived": {"eq": ["false"]},
                    }
                },
                maxResults=50,
            )
            finding_ids = list_resp.get("findingIds", [])

            if finding_ids:
                findings_resp = macie.get_findings(findingIds=finding_ids[:50])
                for f in findings_resp.get("findings", []):
                    sev_str = f.get("severity", {}).get("description", "MEDIUM").upper()
                    sev_map = {"LOW": "LOW", "MEDIUM": "MEDIUM", "HIGH": "HIGH", "CRITICAL": "CRITICAL"}
                    sev     = sev_map.get(sev_str, "MEDIUM")

                    result["severity_counts"][sev] = result["severity_counts"].get(sev, 0) + 1

                    resource_bucket = f.get("resourcesAffected", {}).get("s3Bucket", {})
                    bucket_name     = resource_bucket.get("name", "—")

                    # Data categories found
                    categories = []
                    class_detail = f.get("classificationDetails", {})
                    result_detail = class_detail.get("result", {})
                    for cat_name, cat_data in result_detail.get("sensitiveData", {}).items():
                        total_count = cat_data.get("totalCount", 0)
                        if total_count > 0:
                            categories.append(f"{cat_name}({total_count})")
                            result["data_categories"][cat_name] = \
                                result["data_categories"].get(cat_name, 0) + total_count

                    result["findings"].append({
                        "id":          f.get("id", "—")[:30],
                        "title":       f.get("title", "—"),
                        "type":        f.get("type", "—"),
                        "severity":    sev,
                        "resource":    bucket_name,
                        "description": f.get("description", "—")[:200],
                        "categories":  ", ".join(categories) or "—",
                        "region":      f.get("region", region),
                        "created":     str(f.get("createdAt", "—"))[:19],
                        "count":       f.get("count", 1),
                    })

        except Exception as e:
            result["errors"].append(f"Macie findings: {str(e)}")

        result["total_findings"] = len(result["findings"])

    except Exception as e:
        result["errors"].append(str(e))

    return result
