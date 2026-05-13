"""
Remediation Executor
Executes individual remediation actions with full audit logging.
Each action captures before/after state and logs to audit trail.
"""

import boto3
from botocore.exceptions import ClientError
from audit import log_action


def build_session(access_key, secret_key, region):
    return boto3.Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name=region,
    )


def execute_action(access_key, secret_key, region, action_id, resource, params):
    """
    Route to the correct remediation function based on action_id.
    Returns: { success, action_id, resource_id, detail, audit_entry }
    """
    session    = build_session(access_key, secret_key, region)
    resource_id   = resource.get("resource_id", "—")
    resource_type = resource.get("resource_type", "—")

    dispatch = {
        "s3_block_public_access":      _s3_block_public_access,
        "s3_enable_versioning":        _s3_enable_versioning,
        "s3_enable_encryption":        _s3_enable_encryption,
        "sg_remove_open_ssh":          _sg_remove_open_ssh,
        "sg_remove_open_rdp":          _sg_remove_open_rdp,
        "sg_remove_open_all":          _sg_remove_open_all,
        "iam_disable_access_key":      _iam_disable_access_key,
        "iam_delete_access_key":       _iam_delete_access_key,
        "iam_enforce_password_policy": _iam_enforce_password_policy,
        "ec2_stop_instance":           _ec2_stop_instance,
        "gd_archive_finding":          _gd_archive_finding,
    }

    fn = dispatch.get(action_id)
    if not fn:
        return {"success": False, "detail": f"Unknown action: {action_id}"}

    try:
        result = fn(session, region, resource_id, resource_type, params or {})
        return result
    except ClientError as e:
        msg = e.response["Error"]["Message"]
        entry = log_action(action_id, action_id, resource_id, resource_type, region, "FAILED", msg)
        return {"success": False, "detail": msg, "audit_entry": entry}
    except Exception as e:
        entry = log_action(action_id, action_id, resource_id, resource_type, region, "FAILED", str(e))
        return {"success": False, "detail": str(e), "audit_entry": entry}


# ── S3 Remediations ───────────────────────────────────────────────────────────

def _s3_block_public_access(session, region, resource_id, resource_type, params):
    s3 = session.client("s3", region_name="us-east-1")
    # Capture before state
    try:
        before = s3.get_public_access_block(Bucket=resource_id).get("PublicAccessBlockConfiguration", {})
    except Exception:
        before = {}

    s3.put_public_access_block(
        Bucket=resource_id,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls":       True,
            "IgnorePublicAcls":      True,
            "BlockPublicPolicy":     True,
            "RestrictPublicBuckets": True,
        }
    )
    after = {"BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True}
    detail = f"All public access blocks enabled on bucket '{resource_id}'."
    entry  = log_action("s3_block_public_access", "Block S3 Public Access", resource_id, resource_type, region, "SUCCESS", detail, before, after)
    return {"success": True, "detail": detail, "audit_entry": entry}


def _s3_enable_versioning(session, region, resource_id, resource_type, params):
    s3 = session.client("s3", region_name="us-east-1")
    try:
        before = s3.get_bucket_versioning(Bucket=resource_id)
    except Exception:
        before = {}
    s3.put_bucket_versioning(Bucket=resource_id, VersioningConfiguration={"Status": "Enabled"})
    detail = f"Versioning enabled on bucket '{resource_id}'."
    entry  = log_action("s3_enable_versioning", "Enable S3 Versioning", resource_id, resource_type, region, "SUCCESS", detail, before, {"Status": "Enabled"})
    return {"success": True, "detail": detail, "audit_entry": entry}


def _s3_enable_encryption(session, region, resource_id, resource_type, params):
    s3 = session.client("s3", region_name="us-east-1")
    before = {}
    try:
        before = s3.get_bucket_encryption(Bucket=resource_id)
    except Exception:
        pass
    s3.put_bucket_encryption(
        Bucket=resource_id,
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
        }
    )
    detail = f"SSE-S3 (AES-256) encryption enabled on bucket '{resource_id}'."
    entry  = log_action("s3_enable_encryption", "Enable S3 Encryption", resource_id, resource_type, region, "SUCCESS", detail, before, {"SSEAlgorithm": "AES256"})
    return {"success": True, "detail": detail, "audit_entry": entry}


# ── Security Group Remediations ───────────────────────────────────────────────

def _get_open_rules(ec2, sg_id, port):
    """Return IpPermissions entries that expose the given port to 0.0.0.0/0."""
    sg = ec2.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0]
    to_remove = []
    for rule in sg.get("IpPermissions", []):
        fp = rule.get("FromPort", 0)
        tp = rule.get("ToPort",   65535)
        has_open_ipv4 = any(r.get("CidrIp") in ("0.0.0.0/0",) for r in rule.get("IpRanges", []))
        has_open_ipv6 = any(r.get("CidrIpv6") in ("::/0",)    for r in rule.get("Ipv6Ranges", []))
        if (has_open_ipv4 or has_open_ipv6):
            if port is None or (fp <= port <= tp):
                to_remove.append(rule)
    return to_remove


def _sg_remove_open_ssh(session, region, resource_id, resource_type, params):
    ec2 = session.client("ec2", region_name=region)
    rules = _get_open_rules(ec2, resource_id, 22)
    if not rules:
        detail = f"No open SSH rules found on {resource_id} — already clean."
        entry  = log_action("sg_remove_open_ssh", "Remove Open SSH", resource_id, resource_type, region, "SKIPPED", detail)
        return {"success": True, "detail": detail, "audit_entry": entry}
    ec2.revoke_security_group_ingress(GroupId=resource_id, IpPermissions=rules)
    detail = f"Removed {len(rules)} rule(s) allowing SSH from 0.0.0.0/0 on {resource_id}."
    entry  = log_action("sg_remove_open_ssh", "Remove Open SSH", resource_id, resource_type, region, "SUCCESS", detail, {"rules_removed": rules}, {})
    return {"success": True, "detail": detail, "audit_entry": entry}


def _sg_remove_open_rdp(session, region, resource_id, resource_type, params):
    ec2 = session.client("ec2", region_name=region)
    rules = _get_open_rules(ec2, resource_id, 3389)
    if not rules:
        detail = f"No open RDP rules found on {resource_id} — already clean."
        entry  = log_action("sg_remove_open_rdp", "Remove Open RDP", resource_id, resource_type, region, "SKIPPED", detail)
        return {"success": True, "detail": detail, "audit_entry": entry}
    ec2.revoke_security_group_ingress(GroupId=resource_id, IpPermissions=rules)
    detail = f"Removed {len(rules)} rule(s) allowing RDP from 0.0.0.0/0 on {resource_id}."
    entry  = log_action("sg_remove_open_rdp", "Remove Open RDP", resource_id, resource_type, region, "SUCCESS", detail, {"rules_removed": rules}, {})
    return {"success": True, "detail": detail, "audit_entry": entry}


def _sg_remove_open_all(session, region, resource_id, resource_type, params):
    ec2 = session.client("ec2", region_name=region)
    rules = _get_open_rules(ec2, resource_id, None)
    if not rules:
        detail = f"No open inbound rules found on {resource_id}."
        entry  = log_action("sg_remove_open_all", "Remove All Open Inbound", resource_id, resource_type, region, "SKIPPED", detail)
        return {"success": True, "detail": detail, "audit_entry": entry}
    ec2.revoke_security_group_ingress(GroupId=resource_id, IpPermissions=rules)
    detail = f"Removed {len(rules)} open inbound rule(s) from {resource_id}."
    entry  = log_action("sg_remove_open_all", "Remove All Open Inbound", resource_id, resource_type, region, "SUCCESS", detail, {"rules_removed": rules}, {})
    return {"success": True, "detail": detail, "audit_entry": entry}


# ── IAM Remediations ──────────────────────────────────────────────────────────

def _iam_disable_access_key(session, region, resource_id, resource_type, params):
    iam      = session.client("iam")
    username = params.get("username", resource_id)
    key_id   = params.get("access_key_id", resource_id)
    iam.update_access_key(UserName=username, AccessKeyId=key_id, Status="Inactive")
    detail = f"Access key {key_id} for user '{username}' disabled (not deleted)."
    entry  = log_action("iam_disable_access_key", "Disable IAM Access Key", key_id, resource_type, region, "SUCCESS", detail, {"status": "Active"}, {"status": "Inactive"})
    return {"success": True, "detail": detail, "audit_entry": entry}


def _iam_delete_access_key(session, region, resource_id, resource_type, params):
    iam      = session.client("iam")
    username = params.get("username", resource_id)
    key_id   = params.get("access_key_id", resource_id)
    iam.delete_access_key(UserName=username, AccessKeyId=key_id)
    detail = f"Access key {key_id} for user '{username}' permanently deleted."
    entry  = log_action("iam_delete_access_key", "Delete IAM Access Key", key_id, resource_type, region, "SUCCESS", detail, {"status": "Active"}, {"status": "Deleted"})
    return {"success": True, "detail": detail, "audit_entry": entry}


def _iam_enforce_password_policy(session, region, resource_id, resource_type, params):
    iam = session.client("iam")
    try:
        before = iam.get_account_password_policy().get("PasswordPolicy", {})
    except Exception:
        before = {}
    policy = {
        "MinimumPasswordLength":        14,
        "RequireUppercaseCharacters":   True,
        "RequireLowercaseCharacters":   True,
        "RequireNumbers":               True,
        "RequireSymbols":               True,
        "MaxPasswordAge":               90,
        "PasswordReusePrevention":      24,
        "AllowUsersToChangePassword":   True,
        "HardExpiry":                   False,
    }
    iam.update_account_password_policy(**policy)
    detail = "Strong password policy applied: min 14 chars, uppercase/lowercase/numbers/symbols, 90-day expiry, 24 reuse prevention."
    entry  = log_action("iam_enforce_password_policy", "Apply Strong Password Policy", "account-password-policy", resource_type, region, "SUCCESS", detail, before, policy)
    return {"success": True, "detail": detail, "audit_entry": entry}


# ── EC2 Remediations ──────────────────────────────────────────────────────────

def _ec2_stop_instance(session, region, resource_id, resource_type, params):
    ec2 = session.client("ec2", region_name=region)
    before = ec2.describe_instances(InstanceIds=[resource_id])["Reservations"][0]["Instances"][0]["State"]
    ec2.stop_instances(InstanceIds=[resource_id])
    detail = f"Stop request sent for EC2 instance {resource_id}."
    entry  = log_action("ec2_stop_instance", "Stop EC2 Instance", resource_id, resource_type, region, "SUCCESS", detail, before, {"Name": "stopping"})
    return {"success": True, "detail": detail, "audit_entry": entry}


# ── GuardDuty Remediations ────────────────────────────────────────────────────

def _gd_archive_finding(session, region, resource_id, resource_type, params):
    gd          = session.client("guardduty", region_name=region)
    detector_id = params.get("detector_id", "")
    finding_id  = params.get("finding_id", resource_id)
    if not detector_id:
        detectors   = gd.list_detectors().get("DetectorIds", [])
        detector_id = detectors[0] if detectors else ""
    gd.archive_findings(DetectorId=detector_id, FindingIds=[finding_id])
    detail = f"GuardDuty finding {finding_id[:20]}… archived."
    entry  = log_action("gd_archive_finding", "Archive GuardDuty Finding", finding_id, resource_type, region, "SUCCESS", detail, {"archived": False}, {"archived": True})
    return {"success": True, "detail": detail, "audit_entry": entry}
