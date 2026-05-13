"""
IAM Compliance Scanner
Checks IAM credential report, password policy, MFA, access keys, root account
"""

import boto3
import base64
import csv
import io
from datetime import datetime, timezone
from typing import Dict, List


def scan_iam_compliance(session: boto3.Session, region: str) -> Dict:
    result = {
        "score": 0,
        "total_checks": 0,
        "passed": 0,
        "failed": 0,
        "checks": [],
        "users": [],
        "access_keys": [],
        "password_policy": {},
        "root_account": {},
        "access_analyzer": [],
        "errors": [],
    }

    iam = session.client("iam")

    # ── 1. Root Account Checks ───────────────────────────────────
    _check_root_account(iam, result)

    # ── 2. Password Policy ───────────────────────────────────────
    _check_password_policy(iam, result)

    # ── 3. Credential Report (all users) ─────────────────────────
    _check_credential_report(iam, result)

    # ── 4. IAM Access Analyzer ───────────────────────────────────
    _check_access_analyzer(session, region, result)

    # ── Score ────────────────────────────────────────────────────
    total = result["total_checks"]
    if total > 0:
        result["score"] = round((result["passed"] / total) * 100, 1)

    return result


def _add_check(result: Dict, name: str, passed: bool, detail: str, severity: str = "MEDIUM"):
    result["total_checks"] += 1
    status = "PASS" if passed else "FAIL"
    if passed:
        result["passed"] += 1
    else:
        result["failed"] += 1
    result["checks"].append({
        "name": name,
        "status": status,
        "detail": detail,
        "severity": severity,
    })


def _check_root_account(iam, result: Dict):
    root = {"mfa_enabled": None, "access_keys": None, "last_used": "—"}
    try:
        summary = iam.get_account_summary()["SummaryMap"]
        has_keys = summary.get("AccountAccessKeysPresent", 0) > 0
        mfa_on   = summary.get("AccountMFAEnabled", 0) == 1

        root["mfa_enabled"]  = mfa_on
        root["access_keys"]  = has_keys

        _add_check(result, "Root account has no access keys",
                   not has_keys,
                   "Root account has active access keys — CRITICAL risk" if has_keys else "No root access keys found",
                   "CRITICAL")

        _add_check(result, "Root account MFA enabled",
                   mfa_on,
                   "Root account MFA is enabled" if mfa_on else "Root account has no MFA — CRITICAL risk",
                   "CRITICAL")

    except Exception as e:
        result["errors"].append(f"Root account check: {str(e)}")

    result["root_account"] = root


def _check_password_policy(iam, result: Dict):
    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]
        result["password_policy"] = policy

        _add_check(result, "Password minimum length >= 14",
                   policy.get("MinimumPasswordLength", 0) >= 14,
                   f"Minimum length: {policy.get('MinimumPasswordLength', 0)}",
                   "MEDIUM")

        _add_check(result, "Password requires uppercase",
                   policy.get("RequireUppercaseCharacters", False),
                   "Uppercase required" if policy.get("RequireUppercaseCharacters") else "Uppercase NOT required",
                   "LOW")

        _add_check(result, "Password requires lowercase",
                   policy.get("RequireLowercaseCharacters", False),
                   "Lowercase required" if policy.get("RequireLowercaseCharacters") else "Lowercase NOT required",
                   "LOW")

        _add_check(result, "Password requires numbers",
                   policy.get("RequireNumbers", False),
                   "Numbers required" if policy.get("RequireNumbers") else "Numbers NOT required",
                   "LOW")

        _add_check(result, "Password requires symbols",
                   policy.get("RequireSymbols", False),
                   "Symbols required" if policy.get("RequireSymbols") else "Symbols NOT required",
                   "LOW")

        _add_check(result, "Password expiry enabled (<= 90 days)",
                   policy.get("MaxPasswordAge", 999) <= 90,
                   f"Max age: {policy.get('MaxPasswordAge', 'Not set')} days",
                   "MEDIUM")

        _add_check(result, "Password reuse prevention (>= 24)",
                   policy.get("PasswordReusePrevention", 0) >= 24,
                   f"Reuse prevention: {policy.get('PasswordReusePrevention', 0)} passwords",
                   "MEDIUM")

    except iam.exceptions.NoSuchEntityException:
        _add_check(result, "Password policy configured",
                   False, "No password policy set — default policy in effect", "HIGH")
        result["password_policy"] = {}
    except Exception as e:
        result["errors"].append(f"Password policy: {str(e)}")


def _check_credential_report(iam, result: Dict):
    try:
        # Generate report
        iam.generate_credential_report()
        import time
        time.sleep(2)  # Wait for generation

        report_resp = iam.get_credential_report()
        content = report_resp["Content"]
        if isinstance(content, bytes):
            content = content.decode("utf-8")

        reader = csv.DictReader(io.StringIO(content))
        users_data = list(reader)

        now = datetime.now(timezone.utc)
        stale_days = 90

        unused_keys_count = 0
        no_mfa_count      = 0
        old_keys_count    = 0

        for row in users_data:
            username = row.get("user", "")
            if username == "<root_account>":
                continue

            # MFA check
            mfa_active = row.get("mfa_active", "false").lower() == "true"
            if not mfa_active:
                no_mfa_count += 1

            # Access key rotation checks
            for key_num in ["1", "2"]:
                key_active   = row.get(f"access_key_{key_num}_active", "false").lower() == "true"
                last_rotated = row.get(f"access_key_{key_num}_last_rotated", "N/A")
                last_used    = row.get(f"access_key_{key_num}_last_used_date", "N/A")

                if key_active and last_rotated not in ("N/A", "no_information"):
                    try:
                        rotated_dt = datetime.fromisoformat(last_rotated.replace("Z", "+00:00"))
                        days_old   = (now - rotated_dt).days
                        if days_old > stale_days:
                            old_keys_count += 1
                    except Exception:
                        pass

                if key_active and last_used in ("N/A", "no_information"):
                    unused_keys_count += 1

            result["users"].append({
                "username":    username,
                "mfa_active":  mfa_active,
                "password_enabled": row.get("password_enabled", "false"),
                "password_last_changed": row.get("password_last_changed", "N/A")[:10],
                "key1_active": row.get("access_key_1_active", "false"),
                "key1_last_rotated": row.get("access_key_1_last_rotated", "N/A")[:10],
                "key1_last_used": row.get("access_key_1_last_used_date", "N/A")[:10],
                "key2_active": row.get("access_key_2_active", "false"),
                "key2_last_rotated": row.get("access_key_2_last_rotated", "N/A")[:10],
            })

        real_users = [u for u in result["users"]]
        total_users = len(real_users)

        _add_check(result, "All IAM users have MFA enabled",
                   no_mfa_count == 0,
                   f"{no_mfa_count} of {total_users} users missing MFA" if no_mfa_count > 0 else "All users have MFA",
                   "HIGH")

        _add_check(result, "No access keys older than 90 days",
                   old_keys_count == 0,
                   f"{old_keys_count} access keys older than 90 days" if old_keys_count > 0 else "All keys rotated within 90 days",
                   "HIGH")

        _add_check(result, "No active but never-used access keys",
                   unused_keys_count == 0,
                   f"{unused_keys_count} active keys have never been used" if unused_keys_count > 0 else "No unused active keys",
                   "MEDIUM")

    except Exception as e:
        result["errors"].append(f"Credential report: {str(e)}")


def _check_access_analyzer(session: boto3.Session, region: str, result: Dict):
    try:
        analyzer_client = session.client("accessanalyzer", region_name=region)
        analyzers = analyzer_client.list_analyzers().get("analyzers", [])

        _add_check(result, "IAM Access Analyzer enabled",
                   len(analyzers) > 0,
                   f"{len(analyzers)} analyzer(s) active" if analyzers else "No Access Analyzer configured",
                   "MEDIUM")

        if analyzers:
            analyzer_arn = analyzers[0]["arn"]
            findings_resp = analyzer_client.list_findings(analyzerArn=analyzer_arn)
            findings = findings_resp.get("findings", [])
            active = [f for f in findings if f.get("status") == "ACTIVE"]

            for f in active[:20]:
                result["access_analyzer"].append({
                    "id":            f.get("id", "—")[:30],
                    "type":          f.get("findingType", f.get("type", "—")),
                    "resource":      f.get("resource", "—").split(":")[-1],
                    "resource_type": f.get("resourceType", "—"),
                    "status":        f.get("status", "—"),
                    "created":       str(f.get("createdAt", "—"))[:19],
                })

    except Exception as e:
        result["errors"].append(f"Access Analyzer: {str(e)}")
