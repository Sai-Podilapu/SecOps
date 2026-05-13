"""
Auto-Remediation Engine
Executes remediation actions automatically based on enabled policies.
Supports dry-run mode (preview without executing) and live mode.
Full execution history maintained.
"""

import boto3
from datetime import datetime, timezone
from typing import List, Dict, Optional
from policy_store import get_policies, get_policy_by_id, update_policy_run
from auto_scanner import (
    build_session, scan_s3, scan_security_groups, scan_iam,
    match_issues_to_policies, SEV_RANK
)

# ── Execution History ─────────────────────────────────────────────────────────
_executions: List[Dict] = []


def get_executions() -> List[Dict]:
    return list(reversed(_executions))


def _log_execution(policy_id, policy_name, action, resource_id, resource_type,
                   region, status, detail, dry_run, before=None, after=None):
    entry = {
        "id":            len(_executions) + 1,
        "timestamp":     str(datetime.now(timezone.utc))[:19],
        "policy_id":     policy_id,
        "policy_name":   policy_name,
        "action":        action,
        "resource_id":   resource_id,
        "resource_type": resource_type,
        "region":        region,
        "status":        status,
        "detail":        detail,
        "dry_run":       dry_run,
        "before_state":  before or {},
        "after_state":   after  or {},
    }
    _executions.append(entry)
    return entry


# ── Action Implementations ────────────────────────────────────────────────────

def _exec_s3_block_public(session, resource_id, dry_run):
    s3 = session.client("s3", region_name="us-east-1")
    try:
        before = s3.get_public_access_block(Bucket=resource_id).get("PublicAccessBlockConfiguration", {})
    except Exception:
        before = {}
    if dry_run:
        return True, f"[DRY RUN] Would block public access on bucket '{resource_id}'", before, {}
    s3.put_public_access_block(
        Bucket=resource_id,
        PublicAccessBlockConfiguration={"BlockPublicAcls":True,"IgnorePublicAcls":True,"BlockPublicPolicy":True,"RestrictPublicBuckets":True}
    )
    after = {"BlockPublicAcls":True,"IgnorePublicAcls":True,"BlockPublicPolicy":True,"RestrictPublicBuckets":True}
    return True, f"Blocked all public access on bucket '{resource_id}'", before, after


def _exec_s3_enable_versioning(session, resource_id, dry_run):
    s3 = session.client("s3", region_name="us-east-1")
    try:
        before = s3.get_bucket_versioning(Bucket=resource_id)
    except Exception:
        before = {}
    if dry_run:
        return True, f"[DRY RUN] Would enable versioning on bucket '{resource_id}'", before, {}
    s3.put_bucket_versioning(Bucket=resource_id, VersioningConfiguration={"Status":"Enabled"})
    return True, f"Enabled versioning on bucket '{resource_id}'", before, {"Status":"Enabled"}


def _exec_s3_enable_encryption(session, resource_id, dry_run):
    s3 = session.client("s3", region_name="us-east-1")
    before = {}
    try:
        before = s3.get_bucket_encryption(Bucket=resource_id)
    except Exception:
        pass
    if dry_run:
        return True, f"[DRY RUN] Would enable AES-256 encryption on '{resource_id}'", before, {}
    s3.put_bucket_encryption(Bucket=resource_id, ServerSideEncryptionConfiguration={"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]})
    return True, f"Enabled AES-256 encryption on bucket '{resource_id}'", before, {"SSEAlgorithm":"AES256"}


def _exec_sg_remove_ssh(session, resource_id, region, dry_run):
    ec2   = session.client("ec2", region_name=region)
    sg    = ec2.describe_security_groups(GroupIds=[resource_id])["SecurityGroups"][0]
    rules = []
    for rule in sg.get("IpPermissions", []):
        fp = rule.get("FromPort", 0)
        tp = rule.get("ToPort", 65535)
        if fp <= 22 <= tp:
            if any(r.get("CidrIp") in ("0.0.0.0/0",) for r in rule.get("IpRanges",[])):
                rules.append(rule)
    if not rules:
        return True, f"No open SSH rules on {resource_id} — already clean", {}, {}
    if dry_run:
        return True, f"[DRY RUN] Would remove {len(rules)} SSH rule(s) from {resource_id}", {"rules":rules}, {}
    ec2.revoke_security_group_ingress(GroupId=resource_id, IpPermissions=rules)
    return True, f"Removed {len(rules)} open SSH rule(s) from {resource_id}", {"rules_removed": len(rules)}, {"ssh_open":False}


def _exec_sg_remove_rdp(session, resource_id, region, dry_run):
    ec2   = session.client("ec2", region_name=region)
    sg    = ec2.describe_security_groups(GroupIds=[resource_id])["SecurityGroups"][0]
    rules = []
    for rule in sg.get("IpPermissions", []):
        fp = rule.get("FromPort", 0)
        tp = rule.get("ToPort", 65535)
        if fp <= 3389 <= tp:
            if any(r.get("CidrIp") in ("0.0.0.0/0",) for r in rule.get("IpRanges",[])):
                rules.append(rule)
    if not rules:
        return True, f"No open RDP rules on {resource_id} — already clean", {}, {}
    if dry_run:
        return True, f"[DRY RUN] Would remove {len(rules)} RDP rule(s) from {resource_id}", {"rules":rules}, {}
    ec2.revoke_security_group_ingress(GroupId=resource_id, IpPermissions=rules)
    return True, f"Removed {len(rules)} open RDP rule(s) from {resource_id}", {"rules_removed": len(rules)}, {"rdp_open":False}


def _exec_iam_password_policy(session, dry_run):
    iam = session.client("iam")
    try:
        before = iam.get_account_password_policy().get("PasswordPolicy", {})
    except Exception:
        before = {}
    policy = {"MinimumPasswordLength":14,"RequireUppercaseCharacters":True,"RequireLowercaseCharacters":True,"RequireNumbers":True,"RequireSymbols":True,"MaxPasswordAge":90,"PasswordReusePrevention":24,"AllowUsersToChangePassword":True,"HardExpiry":False}
    if dry_run:
        return True, "[DRY RUN] Would apply strong password policy to account", before, {}
    iam.update_account_password_policy(**policy)
    return True, "Strong IAM password policy applied to account", before, policy


# ── Action dispatcher ─────────────────────────────────────────────────────────

def _dispatch_action(session, action, resource_id, resource_type, region, dry_run):
    try:
        if action == "s3_block_public_access":
            return _exec_s3_block_public(session, resource_id, dry_run)
        elif action == "s3_enable_versioning":
            return _exec_s3_enable_versioning(session, resource_id, dry_run)
        elif action == "s3_enable_encryption":
            return _exec_s3_enable_encryption(session, resource_id, dry_run)
        elif action == "sg_remove_open_ssh":
            return _exec_sg_remove_ssh(session, resource_id, region, dry_run)
        elif action == "sg_remove_open_rdp":
            return _exec_sg_remove_rdp(session, resource_id, region, dry_run)
        elif action == "iam_enforce_password_policy":
            return _exec_iam_password_policy(session, dry_run)
        else:
            return False, f"Unknown action: {action}", {}, {}
    except Exception as e:
        return False, str(e), {}, {}


# ── Main engine ───────────────────────────────────────────────────────────────

def run_auto_remediation(ak, sk, region, policy_id: Optional[str] = None) -> List[Dict]:
    """
    Run auto-remediation for all enabled policies (or a specific one).
    Returns list of execution results.
    """
    session  = build_session(ak, sk, region)
    results  = []
    policies = get_policies()

    if policy_id:
        policies = [p for p in policies if p["id"] == policy_id]
    else:
        policies = [p for p in policies if p.get("enabled")]

    if not policies:
        return []

    # Collect all issues
    all_issues = []
    all_issues.extend(scan_s3(session))
    all_issues.extend(scan_security_groups(session, region))
    all_issues.extend(scan_iam(session))

    # Match issues to policies
    matches = match_issues_to_policies(all_issues, policies)

    # Track how many times each policy has been used this run
    policy_run_counts: Dict[str, int] = {}

    for match in matches:
        issue     = match["issue"]
        policy    = match["policy"]
        pid       = policy["id"]
        dry_run   = policy.get("dry_run", True)
        max_run   = policy.get("max_per_run", 5)

        # Enforce max_per_run limit
        policy_run_counts[pid] = policy_run_counts.get(pid, 0)
        if policy_run_counts[pid] >= max_run:
            continue

        success, detail, before, after = _dispatch_action(
            session,
            policy["action"],
            issue["resource_id"],
            issue["resource_type"],
            issue.get("region", region),
            dry_run,
        )

        status = "DRY_RUN" if dry_run else ("SUCCESS" if success else "FAILED")
        entry  = _log_execution(
            pid, policy["name"], policy["action"],
            issue["resource_id"], issue["resource_type"],
            issue.get("region", region),
            status, detail, dry_run, before, after,
        )
        results.append(entry)
        policy_run_counts[pid] += 1

    # Update run counts for each policy used
    for pid in policy_run_counts:
        if policy_run_counts[pid] > 0:
            update_policy_run(pid)

    return results
