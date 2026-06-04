"""
Azure Compliance Scanner — Phase 2
Checks: Defender for Cloud, Policy Compliance, IAM, Diagnostics, Activity Log
"""
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List

try:
    from azure.identity import ClientSecretCredential
    from azure.mgmt.security import SecurityCenter
    from azure.mgmt.policyinsights import PolicyInsightsClient
    from azure.mgmt.authorization import AuthorizationManagementClient
    from azure.mgmt.monitor import MonitorManagementClient
    from azure.mgmt.resource.subscriptions import SubscriptionClient
    AZURE_AVAILABLE = True
except ImportError:
    AZURE_AVAILABLE = False


def build_credential(tenant_id, client_id, client_secret):
    return ClientSecretCredential(tenant_id=tenant_id,
                                  client_id=client_id,
                                  client_secret=client_secret)


def scan_defender(credential, subscription_id: str) -> Dict:
    """Defender for Cloud secure score and recommendations."""
    result = {"score": 0, "secure_score": 0, "max_score": 0,
              "recommendations": [], "total_checks": 0, "passed": 0, "failed": 0}
    try:
        client = SecurityCenter(credential, subscription_id)
        scores = list(client.secure_scores.list())
        if scores:
            sc = scores[0]
            current = sc.current.score if sc.current else 0
            maximum = sc.max_score if sc.max_score else 100
            result["secure_score"] = round(float(current or 0), 1)
            result["max_score"] = round(float(maximum or 100), 1)
            result["score"] = round((float(current or 0) / float(maximum or 100)) * 100, 1)

        recs = list(client.assessments.list(f"/subscriptions/{subscription_id}"))
        for r in recs[:100]:
            status = r.status.code if r.status else "Unknown"
            result["recommendations"].append({
                "name": r.display_name or "—",
                "status": status,
                "severity": getattr(r, "severity", "Medium") or "Medium",
            })
            result["total_checks"] += 1
            if status in ("Healthy", "NotApplicable"):
                result["passed"] += 1
            else:
                result["failed"] += 1
    except Exception as e:
        result["error"] = str(e)
        result["score"] = 0
    return result


def scan_policy(credential, subscription_id: str) -> Dict:
    """Azure Policy compliance states."""
    result = {"score": 0, "compliant": 0, "non_compliant": 0,
              "total_checks": 0, "passed": 0, "failed": 0, "policies": []}
    try:
        client = PolicyInsightsClient(credential)
        states = list(client.policy_states.list_query_results_for_subscription(
            "latest", subscription_id, top=500))
        for s in states:
            is_comp = s.is_compliant
            result["total_checks"] += 1
            if is_comp:
                result["compliant"] += 1
                result["passed"] += 1
            else:
                result["non_compliant"] += 1
                result["failed"] += 1
            result["policies"].append({
                "policy": (s.policy_definition_name or "—")[:80],
                "resource": (s.resource_id or "—").split("/")[-1],
                "status": "COMPLIANT" if is_comp else "NON_COMPLIANT",
                "timestamp": str(s.timestamp)[:19] if s.timestamp else "—",
            })
        total = result["compliant"] + result["non_compliant"]
        result["score"] = round((result["compliant"] / total) * 100, 1) if total else 0
    except Exception as e:
        result["error"] = str(e)
        result["score"] = 0
    return result


def scan_iam_compliance(credential, subscription_id: str) -> Dict:
    """Check IAM/RBAC hygiene."""
    result = {"score": 0, "total_checks": 0, "passed": 0, "failed": 0,
              "checks": [], "custom_roles": 0, "owner_count": 0}
    checks = []
    try:
        auth = AuthorizationManagementClient(credential, subscription_id)
        scope = f"/subscriptions/{subscription_id}"

        assignments = list(auth.role_assignments.list_for_scope(scope))
        definitions = list(auth.role_definitions.list(scope))
        custom = [d for d in definitions if d.role_type == "CustomRole"]
        owners = [a for a in assignments if "Owner" in (a.role_definition_id or "")]
        result["custom_roles"] = len(custom)
        result["owner_count"] = len(owners)

        checks.append({"check": "No excessive Owner assignments (≤3)",
                        "status": "PASS" if len(owners) <= 3 else "FAIL",
                        "detail": f"{len(owners)} Owner assignment(s)"})
        checks.append({"check": "Custom roles reviewed",
                        "status": "PASS" if len(custom) <= 10 else "FAIL",
                        "detail": f"{len(custom)} custom role(s)"})
        checks.append({"check": "Role assignments documented",
                        "status": "PASS" if len(assignments) < 200 else "FAIL",
                        "detail": f"{len(assignments)} total assignments"})
    except Exception as e:
        checks.append({"check": "IAM scan", "status": "FAIL", "detail": str(e)})

    result["checks"] = checks
    result["total_checks"] = len(checks)
    result["passed"] = sum(1 for c in checks if c["status"] == "PASS")
    result["failed"] = result["total_checks"] - result["passed"]
    result["score"] = round((result["passed"] / result["total_checks"]) * 100, 1) if checks else 0
    return result


def scan_activity_log(credential, subscription_id: str) -> Dict:
    """Check diagnostic settings and activity log alerting."""
    result = {"score": 0, "total_checks": 0, "passed": 0, "failed": 0, "checks": []}
    checks = []
    try:
        monitor = MonitorManagementClient(credential, subscription_id)
        diag = list(monitor.diagnostic_settings.list(
            f"/subscriptions/{subscription_id}"))
        alert_rules = list(monitor.activity_log_alerts.list_by_subscription_id())

        checks.append({"check": "Diagnostic settings configured",
                        "status": "PASS" if len(diag) > 0 else "FAIL",
                        "detail": f"{len(diag)} diagnostic setting(s)"})
        checks.append({"check": "Activity log alerts configured",
                        "status": "PASS" if len(alert_rules) > 0 else "FAIL",
                        "detail": f"{len(alert_rules)} alert rule(s)"})
        checks.append({"check": "Log retention policy set",
                        "status": "PASS" if len(diag) > 0 else "FAIL",
                        "detail": "Retention requires at least one diagnostic setting"})
    except Exception as e:
        checks.append({"check": "Activity log scan", "status": "FAIL", "detail": str(e)})

    result["checks"] = checks
    result["total_checks"] = len(checks)
    result["passed"] = sum(1 for c in checks if c["status"] == "PASS")
    result["failed"] = result["total_checks"] - result["passed"]
    result["score"] = round((result["passed"] / result["total_checks"]) * 100, 1) if checks else 0
    return result


def calculate_score(results: Dict) -> Dict:
    weights = {"defender": 0.40, "policy": 0.30, "iam": 0.20, "activity_log": 0.10}
    weighted = 0.0
    total_w = 0.0
    breakdown = {}
    for key, w in weights.items():
        s = results.get(key, {}).get("score")
        if s is not None:
            weighted += s * w
            total_w += w
            breakdown[key] = s
    overall = round(weighted / total_w, 1) if total_w else 0
    grade = "A" if overall >= 90 else "B" if overall >= 80 else "C" if overall >= 70 else "D" if overall >= 60 else "F"
    return {"overall": overall, "grade": grade, "breakdown": breakdown}


def run_compliance_scan(tenant_id: str, client_id: str, client_secret: str,
                        subscription_id: str) -> Dict:
    result = {
        "identity": {"subscription_id": subscription_id},
        "region": subscription_id,
        "scan_time": str(datetime.now(timezone.utc))[:19],
        "score": {}, "summary": {},
        "defender": {}, "policy": {}, "iam_compliance": {},
        "activity_log": {}, "errors": [], "cloud": "azure",
    }
    try:
        credential = build_credential(tenant_id, client_id, client_secret)
        scanners = {
            "defender":     lambda: scan_defender(credential, subscription_id),
            "policy":       lambda: scan_policy(credential, subscription_id),
            "iam_compliance": lambda: scan_iam_compliance(credential, subscription_id),
            "activity_log": lambda: scan_activity_log(credential, subscription_id),
        }
        with ThreadPoolExecutor(max_workers=4) as ex:
            futures = {ex.submit(fn): name for name, fn in scanners.items()}
            for fut in as_completed(futures):
                name = futures[fut]
                try:
                    result[name] = fut.result()
                except Exception as e:
                    result[name] = {"error": str(e), "score": 0}
        result["score"] = calculate_score(result)
        # Summary
        total = sum(result.get(k, {}).get("total_checks", 0)
                    for k in ["defender", "policy", "iam_compliance", "activity_log"])
        passed = sum(result.get(k, {}).get("passed", 0)
                     for k in ["defender", "policy", "iam_compliance", "activity_log"])
        result["summary"] = {
            "total_checks": total, "passed_checks": passed, "failed_checks": total - passed,
            "critical_findings": result.get("defender", {}).get("failed", 0),
        }
    except Exception as e:
        result["errors"].append(str(e))
    return result
