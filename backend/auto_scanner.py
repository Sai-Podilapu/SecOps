"""
Auto-Remediation Scanner
Discovers issues and evaluates them against active policies.
"""

import boto3
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from botocore.exceptions import ClientError
from policy_store import get_policies


def build_session(ak, sk, region):
    return boto3.Session(aws_access_key_id=ak, aws_secret_access_key=sk, region_name=region)


def get_identity(session):
    try:
        r = session.client("sts").get_caller_identity()
        return {"account_id": r["Account"], "user_id": r["UserId"], "arn": r["Arn"]}
    except Exception as e:
        return {"error": str(e)}


# ── Issue Scanners ────────────────────────────────────────────────────────────

def scan_s3(session):
    issues = []
    try:
        s3 = session.client("s3", region_name="us-east-1")
        for b in s3.list_buckets().get("Buckets", []):
            name = b["Name"]
            # Public access
            try:
                pab = s3.get_public_access_block(Bucket=name).get("PublicAccessBlockConfiguration", {})
                if not all(pab.values()):
                    issues.append({"trigger": "s3_public_access", "severity": "CRITICAL", "resource_id": name, "resource_type": "AWS::S3::Bucket", "region": "global", "detail": f"Bucket '{name}' not fully blocking public access", "current_state": pab})
            except Exception:
                issues.append({"trigger": "s3_public_access", "severity": "CRITICAL", "resource_id": name, "resource_type": "AWS::S3::Bucket", "region": "global", "detail": f"Cannot verify public access state for '{name}'", "current_state": {}})
            # Versioning
            try:
                v = s3.get_bucket_versioning(Bucket=name)
                if v.get("Status") != "Enabled":
                    issues.append({"trigger": "s3_no_versioning", "severity": "MEDIUM", "resource_id": name, "resource_type": "AWS::S3::Bucket", "region": "global", "detail": f"Bucket '{name}' versioning is {v.get('Status','Disabled')}", "current_state": {"versioning": v.get("Status","Disabled")}})
            except Exception:
                pass
            # Encryption
            try:
                s3.get_bucket_encryption(Bucket=name)
            except ClientError as e:
                if "ServerSideEncryptionConfigurationNotFoundError" in str(e):
                    issues.append({"trigger": "s3_no_encryption", "severity": "HIGH", "resource_id": name, "resource_type": "AWS::S3::Bucket", "region": "global", "detail": f"Bucket '{name}' has no default encryption", "current_state": {"encryption": "None"}})
            except Exception:
                pass
    except Exception:
        pass
    return issues


def scan_security_groups(session, region):
    issues = []
    try:
        ec2 = session.client("ec2", region_name=region)
        pag = ec2.get_paginator("describe_security_groups")
        for page in pag.paginate():
            for sg in page.get("SecurityGroups", []):
                sg_id   = sg["GroupId"]
                sg_name = sg.get("GroupName", "—")
                open_ssh = False
                open_rdp = False
                for rule in sg.get("IpPermissions", []):
                    fp = rule.get("FromPort", 0)
                    tp = rule.get("ToPort",   65535)
                    for ip in rule.get("IpRanges", []):
                        if ip.get("CidrIp") in ("0.0.0.0/0", "::/0"):
                            if fp <= 22 <= tp:
                                open_ssh = True
                            if fp <= 3389 <= tp:
                                open_rdp = True
                if open_ssh:
                    issues.append({"trigger": "sg_open_ssh", "severity": "CRITICAL", "resource_id": sg_id, "resource_type": "AWS::EC2::SecurityGroup", "region": region, "detail": f"SG '{sg_name}' allows SSH from 0.0.0.0/0", "current_state": {"sg_name": sg_name}})
                if open_rdp:
                    issues.append({"trigger": "sg_open_rdp", "severity": "CRITICAL", "resource_id": sg_id, "resource_type": "AWS::EC2::SecurityGroup", "region": region, "detail": f"SG '{sg_name}' allows RDP from 0.0.0.0/0", "current_state": {"sg_name": sg_name}})
    except Exception:
        pass
    return issues


def scan_iam(session):
    issues = []
    try:
        iam = session.client("iam")
        try:
            iam.get_account_password_policy()
        except iam.exceptions.NoSuchEntityException:
            issues.append({"trigger": "iam_no_password_policy", "severity": "HIGH", "resource_id": "account-password-policy", "resource_type": "AWS::IAM::PasswordPolicy", "region": "global", "detail": "No IAM password policy configured", "current_state": {}})
        except Exception:
            pass
    except Exception:
        pass
    return issues


# ── Match issues to policies ──────────────────────────────────────────────────

SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

def match_issues_to_policies(issues, policies):
    """For each issue, find which enabled policies would trigger on it."""
    matches = []
    for issue in issues:
        for policy in policies:
            if not policy.get("enabled"):
                continue
            if policy.get("trigger") != issue.get("trigger"):
                continue
            # Check severity threshold
            threshold = policy.get("severity_threshold", "HIGH")
            if SEV_RANK.get(issue["severity"], 0) < SEV_RANK.get(threshold, 3):
                continue
            # Check exclusions
            if issue["resource_id"] in policy.get("exclude_resources", []):
                continue
            matches.append({
                "issue":    issue,
                "policy":   policy,
                "would_execute": not policy.get("dry_run", True),
            })
    return matches


def run_scan(ak, sk, region):
    result = {
        "identity":    {},
        "region":      region,
        "scan_time":   str(datetime.now(timezone.utc))[:19],
        "issues":      [],
        "policies":    [],
        "matches":     [],
        "summary":     {},
        "errors":      [],
    }
    try:
        session = build_session(ak, sk, region)
        result["identity"] = get_identity(session)

        # Scan all issue types in parallel
        with ThreadPoolExecutor(max_workers=3) as ex:
            f1 = ex.submit(scan_s3,              session)
            f2 = ex.submit(scan_security_groups, session, region)
            f3 = ex.submit(scan_iam,             session)
            for f in as_completed([f1, f2, f3]):
                try:
                    result["issues"].extend(f.result())
                except Exception as e:
                    result["errors"].append(str(e))

        # Sort by severity
        result["issues"].sort(key=lambda x: -SEV_RANK.get(x.get("severity","LOW"), 1))

        # Load policies and find matches
        policies = get_policies()
        result["policies"] = policies
        result["matches"]  = match_issues_to_policies(result["issues"], policies)

        # Summary
        sev_counts = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}
        for i in result["issues"]:
            sev_counts[i.get("severity","LOW")] = sev_counts.get(i.get("severity","LOW"),0)+1

        enabled_policies  = sum(1 for p in policies if p.get("enabled"))
        dry_run_policies  = sum(1 for p in policies if p.get("enabled") and p.get("dry_run"))
        live_policies     = enabled_policies - dry_run_policies
        auto_fixable      = len(result["matches"])

        result["summary"] = {
            "total_issues":     len(result["issues"]),
            "severity_counts":  sev_counts,
            "total_policies":   len(policies),
            "enabled_policies": enabled_policies,
            "dry_run_policies": dry_run_policies,
            "live_policies":    live_policies,
            "auto_fixable":     auto_fixable,
        }

    except Exception as e:
        result["errors"].append(str(e))
    return result
