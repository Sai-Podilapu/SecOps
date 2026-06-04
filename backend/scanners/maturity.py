"""
SecOps Maturity Assessment Scanner
Evaluates AWS security posture across 5 domains and assigns
a maturity level (1-5) per domain, plus an overall score.

Domains:
  1. Identity & Access Management
  2. Infrastructure Protection
  3. Data Protection
  4. Detection & Monitoring
  5. Incident Response & Remediation
"""

import boto3
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List


def build_session(ak, sk, region):
    return boto3.Session(aws_access_key_id=ak, aws_secret_access_key=sk, region_name=region)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _safe(fn, default=None):
    try:
        return fn()
    except Exception:
        return default


def maturity_level(score: float) -> dict:
    if score >= 90:
        return {"level": 5, "label": "Optimized",   "color": "green"}
    if score >= 75:
        return {"level": 4, "label": "Managed",     "color": "cyan"}
    if score >= 55:
        return {"level": 3, "label": "Defined",     "color": "yellow"}
    if score >= 35:
        return {"level": 2, "label": "Developing",  "color": "orange"}
    return         {"level": 1, "label": "Initial",     "color": "red"}


def _pct(passed, total):
    return round(100 * passed / total, 1) if total else 0


# ── Domain 1: Identity & Access Management ────────────────────────────────────

def assess_iam(session, region) -> dict:
    checks = []
    iam = session.client("iam")

    # MFA on root
    summary = _safe(lambda: iam.get_account_summary()["SummaryMap"], {})
    root_mfa = summary.get("AccountMFAEnabled", 0) == 1
    checks.append({"id": "iam-root-mfa",        "title": "Root account MFA enabled",          "pass": root_mfa,  "severity": "CRITICAL"})

    # Password policy
    pp = _safe(lambda: iam.get_account_password_policy()["PasswordPolicy"], {})
    checks.append({"id": "iam-pw-length",        "title": "Password min length ≥ 14",          "pass": pp.get("MinimumPasswordLength", 0) >= 14, "severity": "HIGH"})
    checks.append({"id": "iam-pw-symbols",       "title": "Password requires symbols",         "pass": pp.get("RequireSymbols", False),          "severity": "MEDIUM"})
    checks.append({"id": "iam-pw-numbers",       "title": "Password requires numbers",         "pass": pp.get("RequireNumbers", False),           "severity": "MEDIUM"})
    checks.append({"id": "iam-pw-expiry",        "title": "Password max age ≤ 90 days",        "pass": 0 < pp.get("MaxPasswordAge", 999) <= 90,  "severity": "MEDIUM"})
    checks.append({"id": "iam-pw-reuse",         "title": "Password reuse prevention ≥ 24",   "pass": pp.get("PasswordReusePrevention", 0) >= 24,"severity": "MEDIUM"})

    # Access keys
    try:
        users = iam.list_users()["Users"]
        old_keys = 0
        mfa_missing = 0
        for u in users:
            uname = u["UserName"]
            keys = _safe(lambda: iam.list_access_keys(UserName=uname)["AccessKeyMetadata"], [])
            for k in keys:
                if k["Status"] == "Active":
                    age = (datetime.now(timezone.utc) - k["CreateDate"]).days
                    if age > 90:
                        old_keys += 1
            mfas = _safe(lambda: iam.list_mfa_devices(UserName=uname)["MFADevices"], [])
            if not mfas:
                mfa_missing += 1
        checks.append({"id": "iam-key-rotation",  "title": "No active keys older than 90 days", "pass": old_keys == 0,    "severity": "HIGH"})
        checks.append({"id": "iam-user-mfa",      "title": "All IAM users have MFA",            "pass": mfa_missing == 0, "severity": "HIGH"})
    except Exception:
        pass

    # Access Analyzer
    try:
        analyzers = session.client("accessanalyzer", region_name=region).list_analyzers()["analyzers"]
        active = [a for a in analyzers if a["status"] == "ACTIVE"]
        checks.append({"id": "iam-analyzer", "title": "IAM Access Analyzer enabled", "pass": len(active) > 0, "severity": "MEDIUM"})
    except Exception:
        checks.append({"id": "iam-analyzer", "title": "IAM Access Analyzer enabled", "pass": False, "severity": "MEDIUM"})

    passed = sum(1 for c in checks if c["pass"])
    score  = _pct(passed, len(checks))
    return {"checks": checks, "passed": passed, "total": len(checks), "score": score, **maturity_level(score)}


# ── Domain 2: Infrastructure Protection ──────────────────────────────────────

def assess_infra(session, region) -> dict:
    checks = []
    ec2 = session.client("ec2", region_name=region)

    # VPC flow logs
    vpcs = _safe(lambda: ec2.describe_vpcs()["Vpcs"], [])
    flow_logs = _safe(lambda: ec2.describe_flow_logs()["FlowLogs"], [])
    covered_vpcs = {fl["ResourceId"] for fl in flow_logs if fl.get("FlowLogStatus") == "ACTIVE"}
    all_covered = all(v["VpcId"] in covered_vpcs for v in vpcs) if vpcs else False
    checks.append({"id": "infra-vpc-flowlogs",  "title": "VPC Flow Logs enabled on all VPCs", "pass": all_covered, "severity": "HIGH"})

    # Open security groups (0.0.0.0/0 on SSH/RDP)
    sgs = _safe(lambda: ec2.describe_security_groups()["SecurityGroups"], [])
    open_ssh = open_rdp = 0
    for sg in sgs:
        for rule in sg.get("IpPermissions", []):
            cidrs = [r.get("CidrIp", "") for r in rule.get("IpRanges", [])]
            fp, tp = rule.get("FromPort", 0), rule.get("ToPort", 65535)
            if "0.0.0.0/0" in cidrs:
                if fp <= 22 <= tp:   open_ssh += 1
                if fp <= 3389 <= tp: open_rdp += 1
    checks.append({"id": "infra-sg-ssh", "title": "No SG allows 0.0.0.0/0 on SSH",  "pass": open_ssh == 0, "severity": "CRITICAL"})
    checks.append({"id": "infra-sg-rdp", "title": "No SG allows 0.0.0.0/0 on RDP",  "pass": open_rdp == 0, "severity": "CRITICAL"})

    # Default VPC not in use
    default_vpcs = [v for v in vpcs if v.get("IsDefault")]
    default_used = False
    for dv in default_vpcs:
        subs = _safe(lambda: ec2.describe_subnets(Filters=[{"Name":"vpc-id","Values":[dv["VpcId"]]}])["Subnets"], [])
        if subs:
            instances = _safe(lambda: ec2.describe_instances(Filters=[{"Name":"vpc-id","Values":[dv["VpcId"]]}])["Reservations"], [])
            if instances:
                default_used = True
    checks.append({"id": "infra-default-vpc", "title": "Default VPC not used for workloads", "pass": not default_used, "severity": "MEDIUM"})

    # WAF (check if any web ACLs exist)
    try:
        wafv2 = session.client("wafv2", region_name=region)
        acls = wafv2.list_web_acls(Scope="REGIONAL")["WebACLs"]
        checks.append({"id": "infra-waf", "title": "WAF Web ACLs configured", "pass": len(acls) > 0, "severity": "MEDIUM"})
    except Exception:
        checks.append({"id": "infra-waf", "title": "WAF Web ACLs configured", "pass": False, "severity": "MEDIUM"})

    # Shield (basic is always on; check for advanced)
    try:
        shield = session.client("shield", region_name="us-east-1")
        sub = _safe(lambda: shield.describe_subscription()["Subscription"], None)
        checks.append({"id": "infra-shield", "title": "AWS Shield Advanced enabled", "pass": sub is not None, "severity": "LOW"})
    except Exception:
        checks.append({"id": "infra-shield", "title": "AWS Shield Advanced enabled", "pass": False, "severity": "LOW"})

    passed = sum(1 for c in checks if c["pass"])
    score  = _pct(passed, len(checks))
    return {"checks": checks, "passed": passed, "total": len(checks), "score": score, **maturity_level(score)}


# ── Domain 3: Data Protection ─────────────────────────────────────────────────

def assess_data(session, region) -> dict:
    checks = []
    s3 = session.client("s3", region_name="us-east-1")

    buckets = _safe(lambda: s3.list_buckets()["Buckets"], [])
    unencrypted = public = no_versioning = no_logging = 0
    for b in buckets:
        name = b["Name"]
        # Encryption
        enc = _safe(lambda: s3.get_bucket_encryption(Bucket=name), None)
        if not enc:
            unencrypted += 1
        # Public access
        pab = _safe(lambda: s3.get_public_access_block(Bucket=name).get("PublicAccessBlockConfiguration", {}), {})
        if not all([pab.get("BlockPublicAcls"), pab.get("IgnorePublicAcls"), pab.get("BlockPublicPolicy"), pab.get("RestrictPublicBuckets")]):
            public += 1
        # Versioning
        ver = _safe(lambda: s3.get_bucket_versioning(Bucket=name).get("Status", ""), "")
        if ver != "Enabled":
            no_versioning += 1
        # Logging
        log = _safe(lambda: s3.get_bucket_logging(Bucket=name).get("LoggingEnabled"), None)
        if not log:
            no_logging += 1

    checks.append({"id": "data-s3-encrypt",    "title": "All S3 buckets encrypted",           "pass": unencrypted == 0,  "severity": "HIGH",     "detail": f"{unencrypted}/{len(buckets)} unencrypted"})
    checks.append({"id": "data-s3-public",     "title": "All S3 buckets block public access", "pass": public == 0,       "severity": "CRITICAL",  "detail": f"{public}/{len(buckets)} public"})
    checks.append({"id": "data-s3-versioning", "title": "All S3 buckets have versioning",     "pass": no_versioning == 0,"severity": "MEDIUM",    "detail": f"{no_versioning}/{len(buckets)} without versioning"})
    checks.append({"id": "data-s3-logging",    "title": "All S3 buckets have access logging", "pass": no_logging == 0,   "severity": "MEDIUM",    "detail": f"{no_logging}/{len(buckets)} without logging"})

    # EBS encryption by default
    try:
        ec2 = session.client("ec2", region_name=region)
        ebs_enc = ec2.get_ebs_encryption_by_default()["EbsEncryptionByDefault"]
        checks.append({"id": "data-ebs-default-enc", "title": "EBS encryption by default enabled", "pass": ebs_enc, "severity": "HIGH"})
    except Exception:
        checks.append({"id": "data-ebs-default-enc", "title": "EBS encryption by default enabled", "pass": False, "severity": "HIGH"})

    # RDS encryption
    try:
        rds = session.client("rds", region_name=region)
        instances = rds.describe_db_instances().get("DBInstances", [])
        unenc_rds = sum(1 for db in instances if not db.get("StorageEncrypted", False))
        checks.append({"id": "data-rds-encrypt", "title": "All RDS instances encrypted", "pass": unenc_rds == 0, "severity": "HIGH", "detail": f"{unenc_rds} unencrypted"})
    except Exception:
        pass

    # Macie enabled
    try:
        macie = session.client("macie2", region_name=region)
        status = macie.get_macie_session().get("status", "")
        checks.append({"id": "data-macie", "title": "Amazon Macie enabled for data discovery", "pass": status == "ENABLED", "severity": "MEDIUM"})
    except Exception:
        checks.append({"id": "data-macie", "title": "Amazon Macie enabled for data discovery", "pass": False, "severity": "MEDIUM"})

    # KMS CMKs in use
    try:
        kms = session.client("kms", region_name=region)
        keys = kms.list_keys()["Keys"]
        cmks = []
        for k in keys[:20]:  # limit API calls
            meta = _safe(lambda: kms.describe_key(KeyId=k["KeyId"])["KeyMetadata"], {})
            if meta.get("KeyManager") == "CUSTOMER" and meta.get("KeyState") == "Enabled":
                cmks.append(k)
        checks.append({"id": "data-kms-cmk", "title": "Customer-managed KMS keys in use", "pass": len(cmks) > 0, "severity": "MEDIUM"})
    except Exception:
        pass

    passed = sum(1 for c in checks if c["pass"])
    score  = _pct(passed, len(checks))
    return {"checks": checks, "passed": passed, "total": len(checks), "score": score, **maturity_level(score)}


# ── Domain 4: Detection & Monitoring ─────────────────────────────────────────

def assess_detection(session, region) -> dict:
    checks = []

    # CloudTrail
    try:
        ct = session.client("cloudtrail", region_name=region)
        trails = ct.describe_trails(includeShadowTrails=False)["trailList"]
        multi = [t for t in trails if t.get("IsMultiRegionTrail")]
        checks.append({"id": "detect-ct-enabled",   "title": "CloudTrail enabled",              "pass": len(trails) > 0,  "severity": "CRITICAL"})
        checks.append({"id": "detect-ct-multiregion","title": "CloudTrail is multi-region",      "pass": len(multi) > 0,   "severity": "HIGH"})
        if trails:
            validated = any(t.get("LogFileValidationEnabled") for t in trails)
            checks.append({"id": "detect-ct-validation", "title": "CloudTrail log validation on", "pass": validated, "severity": "MEDIUM"})
    except Exception:
        checks.append({"id": "detect-ct-enabled", "title": "CloudTrail enabled", "pass": False, "severity": "CRITICAL"})

    # GuardDuty
    try:
        gd = session.client("guardduty", region_name=region)
        detectors = gd.list_detectors()["DetectorIds"]
        enabled = False
        if detectors:
            det = gd.get_detector(DetectorId=detectors[0])
            enabled = det.get("Status") == "ENABLED"
        checks.append({"id": "detect-guardduty", "title": "GuardDuty enabled", "pass": enabled, "severity": "HIGH"})
    except Exception:
        checks.append({"id": "detect-guardduty", "title": "GuardDuty enabled", "pass": False, "severity": "HIGH"})

    # Security Hub
    try:
        sh = session.client("securityhub", region_name=region)
        hub = sh.describe_hub()
        checks.append({"id": "detect-securityhub", "title": "Security Hub enabled", "pass": True, "severity": "HIGH"})
    except Exception:
        checks.append({"id": "detect-securityhub", "title": "Security Hub enabled", "pass": False, "severity": "HIGH"})

    # AWS Config
    try:
        cfg = session.client("config", region_name=region)
        recorders = cfg.describe_configuration_recorders()["ConfigurationRecorders"]
        statuses = cfg.describe_configuration_recorder_status()["ConfigurationRecordersStatus"]
        recording = any(s.get("recording") for s in statuses)
        checks.append({"id": "detect-config",       "title": "AWS Config enabled & recording",  "pass": len(recorders) > 0 and recording, "severity": "HIGH"})
    except Exception:
        checks.append({"id": "detect-config",       "title": "AWS Config enabled & recording",  "pass": False, "severity": "HIGH"})

    # CloudWatch alarms
    try:
        cw = session.client("cloudwatch", region_name=region)
        alarms = cw.describe_alarms()["MetricAlarms"]
        checks.append({"id": "detect-cw-alarms",    "title": "CloudWatch alarms configured",    "pass": len(alarms) > 0, "severity": "MEDIUM"})
    except Exception:
        checks.append({"id": "detect-cw-alarms",    "title": "CloudWatch alarms configured",    "pass": False, "severity": "MEDIUM"})

    # Inspector
    try:
        insp = session.client("inspector2", region_name=region)
        status = insp.batch_get_account_status(accountIds=[session.client("sts").get_caller_identity()["Account"]])
        accounts = status.get("accounts", [])
        insp_enabled = any(a.get("state", {}).get("status") == "ENABLED" for a in accounts)
        checks.append({"id": "detect-inspector",    "title": "Amazon Inspector enabled",         "pass": insp_enabled, "severity": "MEDIUM"})
    except Exception:
        checks.append({"id": "detect-inspector",    "title": "Amazon Inspector enabled",         "pass": False, "severity": "MEDIUM"})

    passed = sum(1 for c in checks if c["pass"])
    score  = _pct(passed, len(checks))
    return {"checks": checks, "passed": passed, "total": len(checks), "score": score, **maturity_level(score)}


# ── Domain 5: Incident Response & Remediation ─────────────────────────────────

def assess_response(session, region) -> dict:
    checks = []

    # GuardDuty findings — if many HIGH/CRITICAL unarchived, response is poor
    try:
        gd = session.client("guardduty", region_name=region)
        detectors = gd.list_detectors()["DetectorIds"]
        if detectors:
            findings = gd.list_findings(DetectorId=detectors[0],
                FindingCriteria={"Criterion": {"severity": {"Gte": 7}, "service.archived": {"Eq": ["false"]}}})["FindingIds"]
            checks.append({"id": "resp-gd-unresolved", "title": "No unresolved HIGH+ GuardDuty findings", "pass": len(findings) == 0, "severity": "HIGH", "detail": f"{len(findings)} unresolved"})
    except Exception:
        pass

    # SNS topics for alerting
    try:
        sns = session.client("sns", region_name=region)
        topics = sns.list_topics()["Topics"]
        checks.append({"id": "resp-sns",       "title": "SNS topics configured for alerting",  "pass": len(topics) > 0, "severity": "MEDIUM"})
    except Exception:
        checks.append({"id": "resp-sns",       "title": "SNS topics configured for alerting",  "pass": False, "severity": "MEDIUM"})

    # CloudTrail → CloudWatch logs integration
    try:
        ct = session.client("cloudtrail", region_name=region)
        trails = ct.describe_trails(includeShadowTrails=False)["trailList"]
        cw_integrated = any(t.get("CloudWatchLogsLogGroupArn") for t in trails)
        checks.append({"id": "resp-ct-cw",     "title": "CloudTrail sends logs to CloudWatch", "pass": cw_integrated, "severity": "HIGH"})
    except Exception:
        checks.append({"id": "resp-ct-cw",     "title": "CloudTrail sends logs to CloudWatch", "pass": False, "severity": "HIGH"})

    # Security Hub auto-remediation (check if there are any EventBridge rules)
    try:
        eb = session.client("events", region_name=region)
        rules = eb.list_rules()["Rules"]
        sec_rules = [r for r in rules if "security" in r.get("Name","").lower() or "guardduty" in r.get("Name","").lower() or "remediat" in r.get("Name","").lower()]
        checks.append({"id": "resp-eventbridge", "title": "EventBridge rules for auto-response", "pass": len(sec_rules) > 0, "severity": "MEDIUM"})
    except Exception:
        checks.append({"id": "resp-eventbridge", "title": "EventBridge rules for auto-response", "pass": False, "severity": "MEDIUM"})

    # Backup plans
    try:
        backup = session.client("backup", region_name=region)
        plans = backup.list_backup_plans()["BackupPlansList"]
        checks.append({"id": "resp-backup",    "title": "AWS Backup plans configured",         "pass": len(plans) > 0, "severity": "HIGH"})
    except Exception:
        checks.append({"id": "resp-backup",    "title": "AWS Backup plans configured",         "pass": False, "severity": "HIGH"})

    passed = sum(1 for c in checks if c["pass"])
    score  = _pct(passed, len(checks))
    return {"checks": checks, "passed": passed, "total": len(checks), "score": score, **maturity_level(score)}


# ── Main ──────────────────────────────────────────────────────────────────────

def run_maturity_scan(access_key: str, secret_key: str, region: str) -> dict:
    session = build_session(access_key, secret_key, region)

    try:
        sts = session.client("sts")
        identity = sts.get_caller_identity()
        identity_out = {"account_id": identity["Account"], "user_id": identity["UserId"], "arn": identity["Arn"]}
    except Exception as e:
        identity_out = {"error": str(e)}

    domains_fns = {
        "iam":       lambda: assess_iam(session, region),
        "infra":     lambda: assess_infra(session, region),
        "data":      lambda: assess_data(session, region),
        "detection": lambda: assess_detection(session, region),
        "response":  lambda: assess_response(session, region),
    }

    domain_labels = {
        "iam":       "Identity & Access Management",
        "infra":     "Infrastructure Protection",
        "data":      "Data Protection",
        "detection": "Detection & Monitoring",
        "response":  "Incident Response",
    }

    domains = {}
    with ThreadPoolExecutor(max_workers=5) as ex:
        futures = {ex.submit(fn): key for key, fn in domains_fns.items()}
        for fut in as_completed(futures):
            key = futures[fut]
            try:
                result = fut.result()
                result["label"] = domain_labels[key]
                domains[key] = result
            except Exception as e:
                domains[key] = {"label": domain_labels[key], "score": 0, "level": 1, "label_level": "Initial", "color": "red", "checks": [], "passed": 0, "total": 0, "error": str(e)}

    # Overall score — weighted
    weights = {"iam": 0.25, "infra": 0.20, "data": 0.20, "detection": 0.20, "response": 0.15}
    overall = round(sum(domains[k]["score"] * weights[k] for k in domains if "score" in domains[k]), 1)
    overall_maturity = maturity_level(overall)

    total_checks  = sum(d.get("total", 0)  for d in domains.values())
    total_passed  = sum(d.get("passed", 0) for d in domains.values())
    total_failed  = total_checks - total_passed

    # Recommendations: top failed checks by severity
    sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    failed_checks = []
    for dkey, d in domains.items():
        for c in d.get("checks", []):
            if not c["pass"]:
                c["domain"] = domain_labels[dkey]
                failed_checks.append(c)
    failed_checks.sort(key=lambda c: sev_rank.get(c.get("severity","LOW"), 3))

    return {
        "identity":       identity_out,
        "region":         region,
        "scan_time":      str(datetime.now(timezone.utc))[:19],
        "overall_score":  overall,
        "overall_level":  overall_maturity["level"],
        "overall_label":  overall_maturity["label"],
        "overall_color":  overall_maturity["color"],
        "total_checks":   total_checks,
        "total_passed":   total_passed,
        "total_failed":   total_failed,
        "domains":        domains,
        "recommendations": failed_checks[:20],
    }
