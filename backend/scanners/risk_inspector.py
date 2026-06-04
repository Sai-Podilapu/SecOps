"""
Amazon Inspector v2 Scanner
Scans EC2, Lambda, and ECR for vulnerabilities (CVEs)
"""

import boto3
from typing import Dict


def scan_inspector(session: boto3.Session, region: str) -> Dict:
    result = {
        "enabled": False,
        "coverage": {},
        "total_findings": 0,
        "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
        "findings": [],
        "top_vulnerabilities": [],
        "errors": [],
    }

    try:
        insp = session.client("inspector2", region_name=region)

        # ── Check if Inspector is enabled ─────────────────────────
        try:
            status_resp = insp.batch_get_account_status(accountIds=[
                session.client("sts").get_caller_identity()["Account"]
            ])
            accounts = status_resp.get("accounts", [])
            if accounts:
                state = accounts[0].get("state", {})
                result["enabled"] = state.get("status") == "ENABLED"
                result["coverage"] = {
                    "ec2":    accounts[0].get("resourceState", {}).get("ec2",    {}).get("status", "DISABLED"),
                    "lambda": accounts[0].get("resourceState", {}).get("lambda", {}).get("status", "DISABLED"),
                    "ecr":    accounts[0].get("resourceState", {}).get("ecr",    {}).get("status", "DISABLED"),
                }
        except Exception as e:
            result["errors"].append(f"Inspector status: {str(e)}")
            result["enabled"] = False

        if not result["enabled"]:
            result["errors"].append(
                f"Inspector v2 not enabled. Run: aws inspector2 enable "
                f"--resource-types EC2 LAMBDA ECR --region {region}"
            )
            return result

        # ── Get findings ──────────────────────────────────────────
        filter_criteria = {
            "findingStatus": [{"comparison": "EQUALS", "value": "ACTIVE"}]
        }
        kwargs = {
            "filterCriteria": filter_criteria,
            "maxResults": 100,
            "sortCriteria": {
                "field": "INSPECTOR_SCORE",
                "sortOrder": "DESC",
            }
        }

        page = 0
        while page < 5:
            resp  = insp.list_findings(**kwargs)
            batch = resp.get("findings", [])

            for f in batch:
                sev      = f.get("severity", "MEDIUM").upper()
                score    = f.get("inspectorScore", 0) or 0
                pkg_vuln = f.get("packageVulnerability", {})
                cve_id   = pkg_vuln.get("vulnerabilityId", "—")
                resource = f.get("resources", [{}])[0]
                res_id   = resource.get("id", "—").split("/")[-1]
                res_type = resource.get("type", "—")

                result["severity_counts"][sev] = result["severity_counts"].get(sev, 0) + 1

                result["findings"].append({
                    "id":            f.get("findingArn", "—").split("/")[-1][:30],
                    "title":         f.get("title", cve_id),
                    "severity":      sev,
                    "score":         round(score, 1),
                    "cve":           cve_id,
                    "resource_id":   res_id,
                    "resource_type": res_type,
                    "description":   f.get("description", "—")[:200],
                    "remediation":   f.get("remediation", {}).get("recommendation", {}).get("text", "—")[:200],
                    "region":        region,
                    "created":       str(f.get("firstObservedAt", "—"))[:19],
                    "packages":      [p.get("name", "") for p in pkg_vuln.get("vulnerablePackages", [])[:3]],
                    "fix_available": bool(pkg_vuln.get("fixedInVersion")),
                })

            next_token = resp.get("nextToken")
            if not next_token:
                break
            kwargs["nextToken"] = next_token
            page += 1

        result["total_findings"] = len(result["findings"])

        # Top vulnerabilities (most impactful)
        result["top_vulnerabilities"] = result["findings"][:10]

    except Exception as e:
        result["errors"].append(str(e))

    return result
