"""
Remediation Scanner
Discovers issues that have available remediation actions.
Groups findings by resource type and maps each to available actions.
"""

import boto3
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from botocore.exceptions import ClientError
from typing import Dict, List


ACTION_CATALOG = {
    # S3
    "s3_block_public_access":       {"label": "Block S3 Public Access",       "risk": "CRITICAL", "category": "S3",       "description": "Enables all four public access block settings on the bucket.", "reversible": True},
    "s3_enable_versioning":         {"label": "Enable S3 Versioning",          "risk": "MEDIUM",   "category": "S3",       "description": "Enables versioning to protect against accidental deletion.", "reversible": True},
    "s3_enable_encryption":         {"label": "Enable S3 Encryption (SSE-S3)", "risk": "HIGH",     "category": "S3",       "description": "Enables server-side encryption using AES-256.", "reversible": False},
    # Security Groups
    "sg_remove_open_ssh":           {"label": "Remove Open SSH (0.0.0.0/0:22)","risk": "CRITICAL", "category": "Network",  "description": "Removes inbound rule allowing SSH from any IP.", "reversible": True},
    "sg_remove_open_rdp":           {"label": "Remove Open RDP (0.0.0.0/0:3389)","risk":"CRITICAL","category": "Network",  "description": "Removes inbound rule allowing RDP from any IP.", "reversible": True},
    "sg_remove_open_all":           {"label": "Remove All Open Inbound",        "risk": "CRITICAL", "category": "Network",  "description": "Removes all inbound rules allowing traffic from 0.0.0.0/0.", "reversible": True},
    # IAM
    "iam_disable_access_key":       {"label": "Disable IAM Access Key",         "risk": "HIGH",    "category": "IAM",      "description": "Disables an active IAM access key without deleting it.", "reversible": True},
    "iam_delete_access_key":        {"label": "Delete IAM Access Key",           "risk": "HIGH",    "category": "IAM",      "description": "Permanently deletes an IAM access key.", "reversible": False},
    "iam_enforce_password_policy":  {"label": "Apply Strong Password Policy",    "risk": "MEDIUM",  "category": "IAM",      "description": "Sets: min 14 chars, requires uppercase/lowercase/numbers/symbols, 90-day expiry, 24 reuse prevention.", "reversible": True},
    # EC2
    "ec2_stop_instance":            {"label": "Stop EC2 Instance",               "risk": "HIGH",    "category": "EC2",      "description": "Stops a running EC2 instance.", "reversible": True},
    # GuardDuty
    "gd_archive_finding":           {"label": "Archive GuardDuty Finding",       "risk": "LOW",     "category": "GuardDuty","description": "Archives a GuardDuty finding after investigation.", "reversible": True},
}


def build_session(access_key, secret_key, region):
    return boto3.Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name=region,
    )


def get_identity(session):
    try:
        r = session.client("sts").get_caller_identity()
        return {"account_id": r["Account"], "user_id": r["UserId"], "arn": r["Arn"]}
    except Exception as e:
        return {"error": str(e)}


def scan_s3_issues(session, region) -> List[Dict]:
    issues = []
    try:
        s3 = session.client("s3", region_name="us-east-1")
        buckets = s3.list_buckets().get("Buckets", [])
        for b in buckets:
            name = b["Name"]
            # Public access check
            try:
                pab = s3.get_public_access_block(Bucket=name).get("PublicAccessBlockConfiguration", {})
                if not all(pab.values()):
                    issues.append({
                        "issue_id":       f"s3-public-{name}",
                        "category":       "S3",
                        "severity":       "CRITICAL",
                        "title":          f"S3 Bucket Public Access Not Fully Blocked",
                        "description":    f"Bucket '{name}' has partial or no public access blocking.",
                        "resource_id":    name,
                        "resource_type":  "AWS::S3::Bucket",
                        "region":         "global",
                        "current_state":  pab,
                        "available_actions": ["s3_block_public_access"],
                    })
            except Exception:
                issues.append({
                    "issue_id":      f"s3-public-{name}",
                    "category":      "S3",
                    "severity":      "CRITICAL",
                    "title":         f"S3 Bucket Public Access — Unknown State",
                    "description":   f"Cannot determine public access state for '{name}'. May be exposed.",
                    "resource_id":   name,
                    "resource_type": "AWS::S3::Bucket",
                    "region":        "global",
                    "current_state": {},
                    "available_actions": ["s3_block_public_access"],
                })

            # Versioning check
            try:
                v = s3.get_bucket_versioning(Bucket=name)
                if v.get("Status") != "Enabled":
                    issues.append({
                        "issue_id":       f"s3-versioning-{name}",
                        "category":       "S3",
                        "severity":       "MEDIUM",
                        "title":          f"S3 Versioning Not Enabled",
                        "description":    f"Bucket '{name}' does not have versioning enabled.",
                        "resource_id":    name,
                        "resource_type":  "AWS::S3::Bucket",
                        "region":         "global",
                        "current_state":  {"versioning": v.get("Status", "Disabled")},
                        "available_actions": ["s3_enable_versioning"],
                    })
            except Exception:
                pass

            # Encryption check
            try:
                s3.get_bucket_encryption(Bucket=name)
            except s3.exceptions.ClientError as e:
                if "ServerSideEncryptionConfigurationNotFoundError" in str(e):
                    issues.append({
                        "issue_id":       f"s3-encryption-{name}",
                        "category":       "S3",
                        "severity":       "HIGH",
                        "title":          f"S3 Bucket Not Encrypted",
                        "description":    f"Bucket '{name}' has no default encryption configured.",
                        "resource_id":    name,
                        "resource_type":  "AWS::S3::Bucket",
                        "region":         "global",
                        "current_state":  {"encryption": "None"},
                        "available_actions": ["s3_enable_encryption"],
                    })
            except Exception:
                pass
    except Exception as e:
        pass
    return issues


def scan_sg_issues(session, region) -> List[Dict]:
    issues = []
    try:
        ec2 = session.client("ec2", region_name=region)
        sgs = []
        paginator = ec2.get_paginator("describe_security_groups")
        for page in paginator.paginate():
            sgs.extend(page.get("SecurityGroups", []))

        for sg in sgs:
            sg_id   = sg["GroupId"]
            sg_name = sg.get("GroupName", "—")
            open_ssh = False
            open_rdp = False
            open_all = []

            for rule in sg.get("IpPermissions", []):
                from_port = rule.get("FromPort", 0)
                to_port   = rule.get("ToPort",   0)
                for ip in rule.get("IpRanges", []):
                    if ip.get("CidrIp") in ("0.0.0.0/0", "::/0"):
                        if from_port <= 22 <= to_port:
                            open_ssh = True
                        if from_port <= 3389 <= to_port:
                            open_rdp = True
                        open_all.append({"port_range": f"{from_port}-{to_port}", "cidr": ip.get("CidrIp")})

            if open_ssh:
                issues.append({
                    "issue_id":       f"sg-ssh-{sg_id}",
                    "category":       "Network",
                    "severity":       "CRITICAL",
                    "title":          f"Security Group Allows SSH from Anywhere",
                    "description":    f"SG '{sg_name}' ({sg_id}) allows inbound SSH (port 22) from 0.0.0.0/0.",
                    "resource_id":    sg_id,
                    "resource_type":  "AWS::EC2::SecurityGroup",
                    "region":         region,
                    "current_state":  {"open_ports": open_all},
                    "available_actions": ["sg_remove_open_ssh", "sg_remove_open_all"],
                })

            if open_rdp:
                issues.append({
                    "issue_id":       f"sg-rdp-{sg_id}",
                    "category":       "Network",
                    "severity":       "CRITICAL",
                    "title":          f"Security Group Allows RDP from Anywhere",
                    "description":    f"SG '{sg_name}' ({sg_id}) allows inbound RDP (port 3389) from 0.0.0.0/0.",
                    "resource_id":    sg_id,
                    "resource_type":  "AWS::EC2::SecurityGroup",
                    "region":         region,
                    "current_state":  {"open_ports": open_all},
                    "available_actions": ["sg_remove_open_rdp", "sg_remove_open_all"],
                })
    except Exception:
        pass
    return issues


def scan_iam_issues(session, region) -> List[Dict]:
    issues = []
    try:
        iam = session.client("iam")

        # Root account access keys
        try:
            summary = iam.get_account_summary()["SummaryMap"]
            if summary.get("AccountAccessKeysPresent", 0) > 0:
                issues.append({
                    "issue_id":       "iam-root-keys",
                    "category":       "IAM",
                    "severity":       "CRITICAL",
                    "title":          "Root Account Has Active Access Keys",
                    "description":    "The root account has access keys which should never exist. Delete them immediately.",
                    "resource_id":    "root",
                    "resource_type":  "AWS::IAM::Root",
                    "region":         "global",
                    "current_state":  {"access_keys_present": True},
                    "available_actions": [],
                    "manual_steps":   "Go to AWS Console → IAM → Security credentials → Delete root access keys.",
                })
        except Exception:
            pass

        # Password policy
        try:
            iam.get_account_password_policy()
        except iam.exceptions.NoSuchEntityException:
            issues.append({
                "issue_id":       "iam-no-password-policy",
                "category":       "IAM",
                "severity":       "HIGH",
                "title":          "No IAM Password Policy Configured",
                "description":    "Account has no password policy. Default policy is very permissive.",
                "resource_id":    "account-password-policy",
                "resource_type":  "AWS::IAM::PasswordPolicy",
                "region":         "global",
                "current_state":  {"policy": "None"},
                "available_actions": ["iam_enforce_password_policy"],
            })

        # Access keys older than 90 days
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)
        users = []
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            users.extend(page.get("Users", []))

        for user in users:
            username = user["UserName"]
            keys = iam.list_access_keys(UserName=username).get("AccessKeyMetadata", [])
            for key in keys:
                if key["Status"] == "Active":
                    created = key["CreateDate"]
                    if hasattr(created, "replace"):
                        created = created.replace(tzinfo=timezone.utc) if created.tzinfo is None else created
                    days_old = (now - created).days
                    if days_old > 90:
                        issues.append({
                            "issue_id":       f"iam-old-key-{key['AccessKeyId']}",
                            "category":       "IAM",
                            "severity":       "HIGH",
                            "title":          f"Access Key Older Than 90 Days",
                            "description":    f"User '{username}' has key {key['AccessKeyId']} that is {days_old} days old.",
                            "resource_id":    key["AccessKeyId"],
                            "resource_type":  "AWS::IAM::AccessKey",
                            "region":         "global",
                            "current_state":  {"username": username, "days_old": days_old, "status": "Active"},
                            "available_actions": ["iam_disable_access_key", "iam_delete_access_key"],
                            "params":         {"username": username, "access_key_id": key["AccessKeyId"]},
                        })

    except Exception:
        pass
    return issues


def scan_guardduty_issues(session, region) -> List[Dict]:
    issues = []
    try:
        gd = session.client("guardduty", region_name=region)
        detectors = gd.list_detectors().get("DetectorIds", [])
        if not detectors:
            return issues
        detector_id = detectors[0]
        finding_ids = gd.list_findings(DetectorId=detector_id, MaxResults=20).get("FindingIds", [])
        if not finding_ids:
            return issues
        findings = gd.get_findings(DetectorId=detector_id, FindingIds=finding_ids).get("Findings", [])
        for f in findings:
            score = f.get("Severity", 0)
            sev   = "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW"
            issues.append({
                "issue_id":       f"gd-{f.get('Id','')[:20]}",
                "category":       "GuardDuty",
                "severity":       sev,
                "title":          f.get("Title", "—"),
                "description":    f.get("Description", "—")[:200],
                "resource_id":    f.get("Id", "—"),
                "resource_type":  "AWS::GuardDuty::Finding",
                "region":         f.get("Region", region),
                "current_state":  {"severity_score": score, "type": f.get("Type", "—")},
                "available_actions": ["gd_archive_finding"],
                "params":         {"detector_id": detector_id, "finding_id": f.get("Id", "")},
            })
    except Exception:
        pass
    return issues


def run_remediation_scan(access_key, secret_key, region):
    result = {
        "identity":  {},
        "region":    region,
        "scan_time": str(datetime.now(timezone.utc))[:19],
        "issues":    [],
        "summary":   {},
        "catalog":   ACTION_CATALOG,
        "errors":    [],
    }

    try:
        session = build_session(access_key, secret_key, region)
        result["identity"] = get_identity(session)

        def run(fn, *args):
            try:
                return fn(*args)
            except Exception as e:
                result["errors"].append(str(e))
                return []

        with ThreadPoolExecutor(max_workers=4) as ex:
            futures = {
                ex.submit(run, scan_s3_issues,        session, region): "s3",
                ex.submit(run, scan_sg_issues,        session, region): "sg",
                ex.submit(run, scan_iam_issues,       session, region): "iam",
                ex.submit(run, scan_guardduty_issues, session, region): "gd",
            }
            for future in as_completed(futures):
                result["issues"].extend(future.result())

        # Sort by severity
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        result["issues"].sort(key=lambda x: sev_order.get(x.get("severity", "LOW"), 4))

        # Summary
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        by_cat = {}
        for issue in result["issues"]:
            sev = issue.get("severity", "LOW")
            cat = issue.get("category", "Other")
            counts[sev] = counts.get(sev, 0) + 1
            by_cat[cat] = by_cat.get(cat, 0) + 1

        result["summary"] = {
            "total_issues":   len(result["issues"]),
            "severity_counts": counts,
            "by_category":    by_cat,
        }

    except ClientError as e:
        result["errors"].append(e.response["Error"]["Message"])
    except Exception as e:
        result["errors"].append(str(e))

    return result
