"""
Security Hub Scanner (Phase 3 — Risk focused)
Pulls CRITICAL and HIGH findings only for risk scoring
"""

import boto3
from typing import Dict


def scan_securityhub(session: boto3.Session, region: str) -> Dict:
    result = {
        "enabled": False,
        "total_findings": 0,
        "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
        "findings": [],
        "errors": [],
    }

    try:
        hub = session.client("securityhub", region_name=region)

        try:
            hub.describe_hub()
            result["enabled"] = True
        except Exception:
            result["errors"].append("Security Hub not enabled in this region.")
            return result

        # Only fetch CRITICAL and HIGH for risk dashboard
        filters = {
            "RecordState":    [{"Value": "ACTIVE",     "Comparison": "EQUALS"}],
            "WorkflowStatus": [{"Value": "SUPPRESSED", "Comparison": "NOT_EQUALS"}],
            "SeverityLabel":  [
                {"Value": "CRITICAL", "Comparison": "EQUALS"},
                {"Value": "HIGH",     "Comparison": "EQUALS"},
            ],
        }

        kwargs = {"Filters": filters, "MaxResults": 100}
        page   = 0
        while page < 3:
            resp  = hub.get_findings(**kwargs)
            batch = resp.get("Findings", [])
            for f in batch:
                sev = f.get("Severity", {}).get("Label", "HIGH")
                result["severity_counts"][sev] = result["severity_counts"].get(sev, 0) + 1
                resources = f.get("Resources", [])
                res_id    = resources[0].get("Id", "—").split("/")[-1] if resources else "—"
                res_type  = resources[0].get("Type", "—") if resources else "—"
                result["findings"].append({
                    "id":          f.get("Id", "—").split("/")[-1][:30],
                    "title":       f.get("Title", "—"),
                    "severity":    sev,
                    "resource_id": res_id,
                    "resource_type": res_type,
                    "description": f.get("Description", "—")[:200],
                    "remediation": f.get("Remediation", {}).get("Recommendation", {}).get("Text", "—")[:200],
                    "updated":     str(f.get("UpdatedAt", "—"))[:19],
                    "product":     f.get("ProductName", "—"),
                })
            next_token = resp.get("NextToken")
            if not next_token or not batch:
                break
            kwargs["NextToken"] = next_token
            page += 1

        result["total_findings"] = len(result["findings"])

    except Exception as e:
        result["errors"].append(str(e))

    return result
