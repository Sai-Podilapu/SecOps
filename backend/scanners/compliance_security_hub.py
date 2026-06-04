"""
AWS Security Hub Scanner
Fetches findings and compliance controls from Security Hub
"""

import boto3
from typing import Dict


def scan_security_hub(session: boto3.Session, region: str) -> Dict:
    result = {
        "score": 0,
        "enabled": False,
        "total_findings": 0,
        "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0},
        "findings": [],
        "standards": [],
        "top_failed_controls": [],
        "errors": [],
    }

    try:
        hub = session.client("securityhub", region_name=region)

        # ── 1. Check if Security Hub is enabled ──────────────────
        try:
            hub.describe_hub()
            result["enabled"] = True
        except hub.exceptions.InvalidAccessException:
            result["errors"].append("Security Hub is not enabled in this region. Enable it via: aws securityhub enable-security-hub --region " + region)
            return result
        except Exception as e:
            result["errors"].append(f"Security Hub check: {str(e)}")
            return result

        # ── 2. Get active standards ──────────────────────────────
        try:
            std_resp = hub.list_standards_subscriptions()
            for std in std_resp.get("StandardsSubscriptions", []):
                result["standards"].append({
                    "name": _short_standard_name(std.get("StandardsArn", "")),
                    "arn": std.get("StandardsArn", ""),
                    "status": std.get("StandardsStatus", "—"),
                })
        except Exception as e:
            result["errors"].append(f"Standards: {str(e)}")

        # ── 3. Get findings (active, non-suppressed) ─────────────
        filters = {
            "RecordState":    [{"Value": "ACTIVE",      "Comparison": "EQUALS"}],
            "WorkflowStatus": [{"Value": "SUPPRESSED",  "Comparison": "NOT_EQUALS"}],
        }

        findings_raw = []
        kwargs = {"Filters": filters, "MaxResults": 100}
        page = 0
        while page < 5:  # Max 500 findings
            resp = hub.get_findings(**kwargs)
            batch = resp.get("Findings", [])
            findings_raw.extend(batch)
            next_token = resp.get("NextToken")
            if not next_token or not batch:
                break
            kwargs["NextToken"] = next_token
            page += 1

        result["total_findings"] = len(findings_raw)

        # ── 4. Process findings ──────────────────────────────────
        failed_controls = {}

        for f in findings_raw:
            severity = f.get("Severity", {}).get("Label", "INFORMATIONAL")
            result["severity_counts"][severity] = result["severity_counts"].get(severity, 0) + 1

            # Get control info
            control_id    = ""
            control_title = f.get("Title", "—")
            for rem in f.get("Compliance", {}).get("RelatedRequirements", []):
                if rem.startswith("CIS") or rem.startswith("PCI"):
                    control_id = rem
                    break

            resource = {}
            resources = f.get("Resources", [])
            if resources:
                resource = {
                    "id":   resources[0].get("Id", "—").split("/")[-1],
                    "type": resources[0].get("Type", "—"),
                }

            finding_entry = {
                "id":            f.get("Id", "—").split("/")[-1][:40],
                "title":         control_title,
                "severity":      severity,
                "status":        f.get("Compliance", {}).get("Status", "—"),
                "workflow":      f.get("Workflow", {}).get("Status", "—"),
                "resource_id":   resource.get("id", "—"),
                "resource_type": resource.get("type", "—"),
                "description":   f.get("Description", "—")[:200],
                "remediation":   f.get("Remediation", {}).get("Recommendation", {}).get("Text", "—")[:200],
                "updated":       str(f.get("UpdatedAt", "—"))[:19],
                "product":       f.get("ProductName", "—"),
                "generator":     f.get("GeneratorId", "—").split("/")[-1][:60],
            }
            result["findings"].append(finding_entry)

            # Track failed controls for top-10
            ctrl_key = control_title[:80]
            if ctrl_key not in failed_controls:
                failed_controls[ctrl_key] = {"title": ctrl_key, "count": 0, "severity": severity}
            failed_controls[ctrl_key]["count"] += 1

        # Sort findings by severity
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4}
        result["findings"].sort(key=lambda x: sev_order.get(x["severity"], 5))

        # Top 10 most-violated controls
        result["top_failed_controls"] = sorted(
            failed_controls.values(), key=lambda x: x["count"], reverse=True
        )[:10]

        # ── 5. Calculate score ───────────────────────────────────
        total = result["total_findings"]
        critical = result["severity_counts"]["CRITICAL"]
        high     = result["severity_counts"]["HIGH"]
        medium   = result["severity_counts"]["MEDIUM"]

        if total == 0:
            result["score"] = 100.0
        else:
            # Weighted penalty: critical=10pts, high=5pts, medium=2pts, low=0.5pts
            penalty = (critical * 10 + high * 5 + medium * 2 +
                       result["severity_counts"]["LOW"] * 0.5)
            result["score"] = max(0, round(100 - min(penalty, 100), 1))

    except Exception as e:
        result["errors"].append(str(e))

    return result


def _short_standard_name(arn: str) -> str:
    if "cis-aws-foundations" in arn:
        return "CIS AWS Foundations"
    if "aws-foundational-security" in arn:
        return "AWS Foundational Security Best Practices"
    if "pci-dss" in arn:
        return "PCI DSS"
    if "nist" in arn:
        return "NIST SP 800-53"
    return arn.split("/")[-1]
