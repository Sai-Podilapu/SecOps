"""
Azure Risk Dashboard Scanner — Phase 3
Sources: Defender for Cloud alerts, Security Center recommendations,
         Microsoft Sentinel (if available), Advisor security recommendations.
"""
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List

try:
    from azure.identity import ClientSecretCredential
    from azure.mgmt.security import SecurityCenter
    from azure.mgmt.advisor import AdvisorManagementClient
    from azure.mgmt.monitor import MonitorManagementClient
    AZURE_AVAILABLE = True
except ImportError:
    AZURE_AVAILABLE = False


def build_credential(tenant_id, client_id, client_secret):
    from azure.identity import ClientSecretCredential
    return ClientSecretCredential(tenant_id=tenant_id,
                                  client_id=client_id,
                                  client_secret=client_secret)


def scan_defender_alerts(credential, subscription_id: str) -> Dict:
    """Active Defender for Cloud security alerts."""
    result = {"findings": [], "severity_counts": {}, "total": 0}
    try:
        client = SecurityCenter(credential, subscription_id)
        alerts = list(client.alerts.list())
        sev_map = {}
        for a in alerts:
            sev = (a.alert_type or "MEDIUM").upper()
            sev = "CRITICAL" if "critical" in sev.lower() else \
                  "HIGH"     if "high"     in sev.lower() else \
                  "MEDIUM"   if "medium"   in sev.lower() else "LOW"
            sev_map[sev] = sev_map.get(sev, 0) + 1
            result["findings"].append({
                "source":      "Defender",
                "severity":    sev,
                "title":       a.alert_display_name or "—",
                "resource":    (a.compromised_entity or "—")[:80],
                "description": (a.description or "—")[:200],
                "region":      a.azure_resource_id and a.azure_resource_id.split("/")[3] if a.azure_resource_id and len(a.azure_resource_id.split("/")) > 3 else "—",
                "created":     str(a.time_generated_utc)[:19] if a.time_generated_utc else "—",
                "remediation": (a.remediation_steps[0] if a.remediation_steps else "—"),
                "score":       10 if sev == "CRITICAL" else 7 if sev == "HIGH" else 4 if sev == "MEDIUM" else 1,
            })
        result["severity_counts"] = sev_map
        result["total"] = len(result["findings"])
    except Exception as e:
        result["error"] = str(e)
    return result


def scan_advisor(credential, subscription_id: str) -> Dict:
    """Azure Advisor security recommendations."""
    result = {"findings": [], "total": 0, "high_impact": 0}
    try:
        client = AdvisorManagementClient(credential, subscription_id)
        recs = list(client.recommendations.list())
        for r in recs:
            if (r.category or "").lower() != "security":
                continue
            impact = (r.impact or "Medium").title()
            sev = "HIGH" if impact == "High" else "MEDIUM" if impact == "Medium" else "LOW"
            result["findings"].append({
                "source":   "Advisor",
                "severity": sev,
                "title":    r.short_description.problem if r.short_description else "—",
                "resource": (r.resource_metadata.resource_id or "—").split("/")[-1] if r.resource_metadata else "—",
                "description": r.short_description.solution if r.short_description else "—",
                "region":   "—",
                "created":  str(r.last_updated)[:10] if r.last_updated else "—",
                "remediation": "Follow Azure Advisor recommendation",
                "score":    7 if sev == "HIGH" else 4,
            })
        result["total"] = len(result["findings"])
        result["high_impact"] = sum(1 for f in result["findings"] if f["severity"] == "HIGH")
    except Exception as e:
        result["error"] = str(e)
    return result


def scan_monitor_alerts(credential, subscription_id: str) -> Dict:
    """Active Azure Monitor metric alerts in fired state."""
    result = {"findings": [], "total": 0}
    try:
        monitor = MonitorManagementClient(credential, subscription_id)
        fired = list(monitor.alert_rules.list_by_subscription())
        for a in fired[:50]:
            result["findings"].append({
                "source":   "Monitor",
                "severity": "MEDIUM",
                "title":    a.name or "Alert rule",
                "resource": (a.id or "—").split("/")[-1],
                "description": a.description or "Active monitor alert",
                "region":   a.location or "—",
                "created":  "—",
                "remediation": "Review Azure Monitor alert",
                "score":    4,
            })
        result["total"] = len(result["findings"])
    except Exception as e:
        result["error"] = str(e)
    return result


def build_risk_score(all_findings: List) -> Dict:
    SEV = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1}
    if not all_findings:
        return {"score": 0, "level": "LOW", "total_findings": 0}
    total_w = sum(SEV.get(f.get("severity", "LOW"), 1) for f in all_findings)
    max_p = len(all_findings) * 10
    raw = (total_w / max_p) * 100 if max_p else 0
    score = round(min(raw, 100), 1)
    level = "CRITICAL" if score >= 70 else "HIGH" if score >= 40 else "MEDIUM" if score >= 20 else "LOW"
    return {"score": score, "level": level, "total_findings": len(all_findings)}


def run_risk_scan(tenant_id: str, client_id: str, client_secret: str,
                  subscription_id: str) -> Dict:
    result = {
        "identity": {"subscription_id": subscription_id},
        "scan_time": str(datetime.now(timezone.utc))[:19],
        "risk_score": {}, "all_findings": [],
        "defender": {}, "advisor": {}, "monitor": {},
        "summary": {}, "errors": [], "cloud": "azure",
    }
    try:
        credential = build_credential(tenant_id, client_id, client_secret)
        scanners = {
            "defender": lambda: scan_defender_alerts(credential, subscription_id),
            "advisor":  lambda: scan_advisor(credential, subscription_id),
            "monitor":  lambda: scan_monitor_alerts(credential, subscription_id),
        }
        with ThreadPoolExecutor(max_workers=3) as ex:
            futures = {ex.submit(fn): name for name, fn in scanners.items()}
            for fut in as_completed(futures):
                name = futures[fut]
                try:
                    result[name] = fut.result()
                except Exception as e:
                    result[name] = {"error": str(e), "findings": []}

        # Merge all findings
        all_findings = []
        source_counts: Dict[str, int] = {}
        for src in ["defender", "advisor", "monitor"]:
            for f in result.get(src, {}).get("findings", []):
                all_findings.append(f)
                source_counts[src.title()] = source_counts.get(src.title(), 0) + 1

        # Sort by severity
        sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        all_findings.sort(key=lambda f: sev_rank.get(f.get("severity", "LOW"), 3))
        result["all_findings"] = all_findings[:100]
        result["risk_score"] = build_risk_score(all_findings)

        sev_totals: Dict[str, int] = {}
        for f in all_findings:
            s = f.get("severity", "LOW")
            sev_totals[s] = sev_totals.get(s, 0) + 1

        result["summary"] = {
            "total_findings": len(all_findings),
            "severity_counts": sev_totals,
            "source_counts": source_counts,
        }
    except Exception as e:
        result["errors"].append(str(e))
    return result
