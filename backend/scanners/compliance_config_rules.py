"""
AWS Config Rules + Conformance Packs Scanner
Fetches compliance status of all Config rules and conformance packs
"""

import boto3
from typing import Dict, List


def scan_config_rules(session: boto3.Session, region: str) -> Dict:
    result = {
        "score": 0,
        "total_rules": 0,
        "compliant_count": 0,
        "non_compliant_count": 0,
        "not_applicable_count": 0,
        "insufficient_data_count": 0,
        "rules": [],
        "non_compliant_resources": [],
        "conformance_packs": [],
        "errors": [],
    }

    try:
        cfg = session.client("config", region_name=region)

        # ── 1. Get all Config rules ──────────────────────────────
        rules_raw = []
        kwargs = {}
        while True:
            resp = cfg.describe_config_rules(**kwargs)
            rules_raw.extend(resp.get("ConfigRules", []))
            next_token = resp.get("NextToken")
            if not next_token:
                break
            kwargs["NextToken"] = next_token

        if not rules_raw:
            result["errors"].append("No Config rules found. Deploy a Conformance Pack or add rules manually.")
            return result

        # ── 2. Get compliance summary for each rule ──────────────
        rule_names = [r["ConfigRuleName"] for r in rules_raw]

        # Batch in groups of 25 (API limit)
        compliance_map = {}
        for i in range(0, len(rule_names), 25):
            batch = rule_names[i:i+25]
            try:
                comp_resp = cfg.describe_compliance_by_config_rule(
                    ConfigRuleNames=batch
                )
                for item in comp_resp.get("ComplianceByConfigRules", []):
                    compliance_map[item["ConfigRuleName"]] = item.get("Compliance", {})
            except Exception as e:
                result["errors"].append(f"Compliance fetch error: {str(e)}")

        # ── 3. Build rules list with compliance ──────────────────
        for rule in rules_raw:
            name = rule["ConfigRuleName"]
            source = rule.get("Source", {})
            compliance = compliance_map.get(name, {})
            comp_type = compliance.get("ComplianceType", "INSUFFICIENT_DATA")
            counts = compliance.get("ComplianceContributorCount", {})

            rule_entry = {
                "name": name,
                "description": rule.get("Description", "—"),
                "source": source.get("Owner", "—"),
                "identifier": source.get("SourceIdentifier", "—"),
                "scope": _get_scope(rule),
                "trigger": _get_trigger(rule),
                "compliance": comp_type,
                "compliant_count": counts.get("CappedCount", 0) if comp_type == "COMPLIANT" else 0,
                "non_compliant_count": counts.get("CappedCount", 0) if comp_type == "NON_COMPLIANT" else 0,
                "severity": _infer_severity(name),
            }
            result["rules"].append(rule_entry)

            # Tally
            if comp_type == "COMPLIANT":
                result["compliant_count"] += 1
            elif comp_type == "NON_COMPLIANT":
                result["non_compliant_count"] += 1
            elif comp_type == "NOT_APPLICABLE":
                result["not_applicable_count"] += 1
            else:
                result["insufficient_data_count"] += 1

        result["total_rules"] = len(rules_raw)

        # ── 4. Get non-compliant resources (top 200) ─────────────
        non_compliant_rules = [
            r["name"] for r in result["rules"] if r["compliance"] == "NON_COMPLIANT"
        ]
        for rule_name in non_compliant_rules[:20]:  # Limit to top 20 rules
            try:
                eval_resp = cfg.get_compliance_details_by_config_rule(
                    ConfigRuleName=rule_name,
                    ComplianceTypes=["NON_COMPLIANT"],
                    Limit=10,
                )
                for ev in eval_resp.get("EvaluationResults", []):
                    qi = ev.get("EvaluationResultIdentifier", {}).get("EvaluationResultQualifier", {})
                    result["non_compliant_resources"].append({
                        "rule": rule_name,
                        "resource_type": qi.get("ResourceType", "—"),
                        "resource_id": qi.get("ResourceId", "—"),
                        "annotation": ev.get("Annotation", "—"),
                        "result_time": str(ev.get("ResultRecordedTime", "—"))[:19],
                        "severity": _infer_severity(rule_name),
                    })
            except Exception:
                pass

        # ── 5. Get Conformance Packs ─────────────────────────────
        try:
            packs_resp = cfg.describe_conformance_packs()
            for pack in packs_resp.get("ConformancePackDetails", []):
                pack_name = pack["ConformancePackName"]
                pack_entry = {
                    "name": pack_name,
                    "arn": pack.get("ConformancePackArn", "—"),
                    "status": pack.get("ConformancePackState", "—"),
                    "created": str(pack.get("CreatedBy", "—")),
                    "score": None,
                    "compliant": 0,
                    "non_compliant": 0,
                }
                # Get compliance score
                try:
                    score_resp = cfg.get_conformance_pack_compliance_scores(
                        Filters={"ConformancePackNames": [pack_name]}
                    )
                    scores = score_resp.get("ConformancePackComplianceScores", [])
                    if scores:
                        raw_score = scores[0].get("Score", "N/A")
                        pack_entry["score"] = round(float(raw_score), 1) if raw_score != "N/A" else None
                except Exception:
                    pass

                result["conformance_packs"].append(pack_entry)
        except Exception as e:
            result["errors"].append(f"Conformance packs: {str(e)}")

        # ── 6. Calculate score ───────────────────────────────────
        evaluable = result["compliant_count"] + result["non_compliant_count"]
        if evaluable > 0:
            result["score"] = round((result["compliant_count"] / evaluable) * 100, 1)

    except Exception as e:
        result["errors"].append(str(e))

    return result


def _get_scope(rule: Dict) -> str:
    scope = rule.get("Scope", {})
    types = scope.get("ComplianceResourceTypes", [])
    if types:
        return ", ".join(t.replace("AWS::", "") for t in types[:3])
    return "All Resources"


def _get_trigger(rule: Dict) -> str:
    source = rule.get("Source", {})
    details = source.get("SourceDetails", [])
    triggers = set()
    for d in details:
        msg_type = d.get("MessageType", "")
        if "ConfigurationItem" in msg_type:
            triggers.add("Change")
        elif "ScheduledNotification" in msg_type:
            triggers.add("Periodic")
    return " + ".join(triggers) if triggers else "—"


def _infer_severity(rule_name: str) -> str:
    """Infer severity from rule name keywords."""
    name = rule_name.lower()
    critical_keywords = [
        "root", "mfa", "public-access", "unrestricted", "ssh", "rdp",
        "encryption", "public-read", "public-write", "admin", "wildcard"
    ]
    high_keywords = [
        "access-key", "password", "cloudtrail", "guardduty", "logging",
        "rotation", "bucket-policy", "security-group", "vpc-flow"
    ]
    medium_keywords = [
        "backup", "multi-az", "retention", "versioning", "tag", "patch"
    ]
    if any(k in name for k in critical_keywords):
        return "CRITICAL"
    if any(k in name for k in high_keywords):
        return "HIGH"
    if any(k in name for k in medium_keywords):
        return "MEDIUM"
    return "LOW"
