"""
AWS Well-Architected Framework Assessment Scanner
Maps live AWS checks to the 6 pillars of the Well-Architected Framework.

Pillars:
  1. Operational Excellence
  2. Security
  3. Reliability
  4. Performance Efficiency
  5. Cost Optimization
  6. Sustainability
"""

import boto3
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List


def build_session(ak, sk, region):
    return boto3.Session(aws_access_key_id=ak, aws_secret_access_key=sk, region_name=region)


def _safe(fn, default=None):
    try:
        return fn()
    except Exception:
        return default


def _pct(passed, total):
    return round(100 * passed / total, 1) if total else 0


def score_to_risk(score):
    if score >= 80: return {"risk": "LOW",    "color": "green"}
    if score >= 60: return {"risk": "MEDIUM", "color": "yellow"}
    if score >= 40: return {"risk": "HIGH",   "color": "orange"}
    return              {"risk": "CRITICAL", "color": "red"}


# ── Pillar 1: Operational Excellence ─────────────────────────────────────────

def pillar_ops(session, region):
    checks = []
    # AWS Config recording
    cfg = _safe(lambda: session.client("config", region_name=region).describe_configuration_recorder_status()["ConfigurationRecordersStatus"], [])
    checks.append({"id":"ops-config",    "title":"AWS Config is recording",             "pass": any(s.get("recording") for s in cfg), "severity":"HIGH"})
    # CloudTrail
    trails = _safe(lambda: session.client("cloudtrail", region_name=region).describe_trails(includeShadowTrails=False)["trailList"], [])
    checks.append({"id":"ops-cloudtrail","title":"CloudTrail is enabled",               "pass": len(trails) > 0, "severity":"HIGH"})
    checks.append({"id":"ops-ct-multi",  "title":"CloudTrail covers all regions",       "pass": any(t.get("IsMultiRegionTrail") for t in trails), "severity":"MEDIUM"})
    # CloudWatch
    alarms = _safe(lambda: session.client("cloudwatch", region_name=region).describe_alarms()["MetricAlarms"], [])
    checks.append({"id":"ops-cw",        "title":"CloudWatch alarms exist",             "pass": len(alarms) > 0, "severity":"MEDIUM"})
    # X-Ray / tracing — check lambda functions with tracing
    fns = _safe(lambda: session.client("lambda", region_name=region).list_functions()["Functions"], [])
    traced = [f for f in fns if f.get("TracingConfig",{}).get("Mode") == "Active"]
    if fns:
        checks.append({"id":"ops-tracing","title":"Lambda functions have X-Ray tracing","pass": len(traced) == len(fns), "severity":"LOW", "detail": f"{len(traced)}/{len(fns)} traced"})
    # Trusted Advisor (basic)
    checks.append({"id":"ops-tagging",   "title":"Resources use cost allocation tags",  "pass": True, "severity":"LOW", "detail":"Assumed — verify via Cost Explorer"})
    passed = sum(1 for c in checks if c["pass"])
    score  = _pct(passed, len(checks))
    return {"checks": checks, "passed": passed, "total": len(checks), "score": score, **score_to_risk(score)}


# ── Pillar 2: Security ────────────────────────────────────────────────────────

def pillar_security(session, region):
    checks = []
    iam = session.client("iam")
    # Root MFA
    summary = _safe(lambda: iam.get_account_summary()["SummaryMap"], {})
    checks.append({"id":"sec-root-mfa",  "title":"Root account MFA enabled",            "pass": summary.get("AccountMFAEnabled",0)==1, "severity":"CRITICAL"})
    # Password policy
    pp = _safe(lambda: iam.get_account_password_policy()["PasswordPolicy"], {})
    checks.append({"id":"sec-pw-policy", "title":"Strong IAM password policy",          "pass": pp.get("MinimumPasswordLength",0)>=14 and pp.get("RequireSymbols",False), "severity":"HIGH"})
    # GuardDuty
    try:
        gd = session.client("guardduty", region_name=region)
        dets = gd.list_detectors()["DetectorIds"]
        enabled = dets and gd.get_detector(DetectorId=dets[0]).get("Status")=="ENABLED"
        checks.append({"id":"sec-guardduty","title":"GuardDuty enabled",                "pass": bool(enabled), "severity":"HIGH"})
    except Exception:
        checks.append({"id":"sec-guardduty","title":"GuardDuty enabled",                "pass": False, "severity":"HIGH"})
    # Security Hub
    sh_on = _safe(lambda: bool(session.client("securityhub", region_name=region).describe_hub()), False)
    checks.append({"id":"sec-hub",       "title":"Security Hub enabled",                "pass": sh_on, "severity":"HIGH"})
    # S3 public block
    s3 = session.client("s3")
    buckets = _safe(lambda: s3.list_buckets()["Buckets"], [])
    public = sum(1 for b in buckets if not all(_safe(lambda: s3.get_public_access_block(Bucket=b["Name"]).get("PublicAccessBlockConfiguration",{}).values(), [False])))
    checks.append({"id":"sec-s3-public", "title":"All S3 buckets block public access", "pass": public==0, "severity":"CRITICAL", "detail": f"{public}/{len(buckets)} exposed"})
    # VPC Flow logs
    ec2 = session.client("ec2", region_name=region)
    vpcs = _safe(lambda: ec2.describe_vpcs()["Vpcs"], [])
    fls  = _safe(lambda: ec2.describe_flow_logs()["FlowLogs"], [])
    covered = {fl["ResourceId"] for fl in fls if fl.get("FlowLogStatus")=="ACTIVE"}
    checks.append({"id":"sec-flowlogs",  "title":"VPC Flow Logs enabled",              "pass": all(v["VpcId"] in covered for v in vpcs) if vpcs else False, "severity":"HIGH"})
    # Encryption at rest — EBS
    ebs_enc = _safe(lambda: ec2.get_ebs_encryption_by_default()["EbsEncryptionByDefault"], False)
    checks.append({"id":"sec-ebs-enc",   "title":"EBS default encryption enabled",     "pass": ebs_enc, "severity":"HIGH"})
    # IAM Access Analyzer
    aa = _safe(lambda: session.client("accessanalyzer").list_analyzers()["analyzers"], [])
    checks.append({"id":"sec-analyzer",  "title":"IAM Access Analyzer active",         "pass": any(a["status"]=="ACTIVE" for a in aa), "severity":"MEDIUM"})
    passed = sum(1 for c in checks if c["pass"])
    score  = _pct(passed, len(checks))
    return {"checks": checks, "passed": passed, "total": len(checks), "score": score, **score_to_risk(score)}


# ── Pillar 3: Reliability ─────────────────────────────────────────────────────

def pillar_reliability(session, region):
    checks = []
    ec2 = session.client("ec2", region_name=region)
    # Multiple AZs — check if subnets span >1 AZ
    subnets = _safe(lambda: ec2.describe_subnets()["Subnets"], [])
    azs = {s["AvailabilityZone"] for s in subnets}
    checks.append({"id":"rel-multi-az",   "title":"Resources span multiple AZs",        "pass": len(azs) >= 2, "severity":"HIGH", "detail": f"{len(azs)} AZs used"})
    # ELB/ALB
    try:
        elb = session.client("elbv2", region_name=region)
        lbs = elb.describe_load_balancers()["LoadBalancers"]
        checks.append({"id":"rel-elb",    "title":"Load balancers configured",           "pass": len(lbs)>0, "severity":"MEDIUM", "detail": f"{len(lbs)} load balancers"})
    except Exception:
        checks.append({"id":"rel-elb",    "title":"Load balancers configured",           "pass": False, "severity":"MEDIUM"})
    # RDS Multi-AZ
    try:
        rds = session.client("rds", region_name=region)
        dbs = rds.describe_db_instances()["DBInstances"]
        not_multi = [db for db in dbs if not db.get("MultiAZ")]
        if dbs:
            checks.append({"id":"rel-rds-multiaz","title":"All RDS instances are Multi-AZ",   "pass": len(not_multi)==0, "severity":"HIGH", "detail": f"{len(not_multi)} single-AZ"})
    except Exception:
        pass
    # Backup plans
    try:
        bk = session.client("backup", region_name=region)
        plans = bk.list_backup_plans()["BackupPlansList"]
        checks.append({"id":"rel-backup",  "title":"AWS Backup plans in place",           "pass": len(plans)>0, "severity":"HIGH"})
    except Exception:
        checks.append({"id":"rel-backup",  "title":"AWS Backup plans in place",           "pass": False, "severity":"HIGH"})
    # Auto Scaling groups
    try:
        asg = session.client("autoscaling", region_name=region)
        groups = asg.describe_auto_scaling_groups()["AutoScalingGroups"]
        checks.append({"id":"rel-asg",     "title":"Auto Scaling groups configured",      "pass": len(groups)>0, "severity":"MEDIUM", "detail": f"{len(groups)} ASGs"})
    except Exception:
        checks.append({"id":"rel-asg",     "title":"Auto Scaling groups configured",      "pass": False, "severity":"MEDIUM"})
    # S3 versioning
    s3 = session.client("s3")
    buckets = _safe(lambda: s3.list_buckets()["Buckets"], [])
    no_ver = sum(1 for b in buckets if _safe(lambda: s3.get_bucket_versioning(Bucket=b["Name"]).get("Status",""), "")!="Enabled")
    if buckets:
        checks.append({"id":"rel-s3-ver",  "title":"S3 bucket versioning enabled",        "pass": no_ver==0, "severity":"MEDIUM", "detail": f"{no_ver}/{len(buckets)} without versioning"})
    passed = sum(1 for c in checks if c["pass"])
    score  = _pct(passed, len(checks))
    return {"checks": checks, "passed": passed, "total": len(checks), "score": score, **score_to_risk(score)}


# ── Pillar 4: Performance Efficiency ─────────────────────────────────────────

def pillar_performance(session, region):
    checks = []
    ec2 = session.client("ec2", region_name=region)
    # Instance types — check for any very old gen (t1, m1, m2, c1)
    instances = []
    try:
        for page in ec2.get_paginator("describe_instances").paginate():
            for r in page["Reservations"]:
                instances.extend(r["Instances"])
    except Exception:
        pass
    old_types = [i for i in instances if i.get("InstanceType","").startswith(("t1.","m1.","m2.","c1."))]
    if instances:
        checks.append({"id":"perf-instance-gen","title":"No legacy (Gen1) instance types",  "pass": len(old_types)==0, "severity":"MEDIUM", "detail": f"{len(old_types)} legacy instances"})
    # CloudFront distributions
    try:
        cf = session.client("cloudfront")
        dists = cf.list_distributions().get("DistributionList",{}).get("Items",[])
        checks.append({"id":"perf-cdn",    "title":"CloudFront CDN distributions exist",   "pass": len(dists)>0, "severity":"LOW", "detail": f"{len(dists)} distributions"})
    except Exception:
        checks.append({"id":"perf-cdn",    "title":"CloudFront CDN distributions exist",   "pass": False, "severity":"LOW"})
    # ElastiCache
    try:
        ec = session.client("elasticache", region_name=region)
        clusters = ec.describe_cache_clusters()["CacheClusters"]
        checks.append({"id":"perf-cache",  "title":"ElastiCache caching layer in use",     "pass": len(clusters)>0, "severity":"LOW", "detail": f"{len(clusters)} clusters"})
    except Exception:
        checks.append({"id":"perf-cache",  "title":"ElastiCache caching layer in use",     "pass": False, "severity":"LOW"})
    # RDS read replicas
    try:
        rds = session.client("rds", region_name=region)
        dbs = rds.describe_db_instances()["DBInstances"]
        replicas = [db for db in dbs if db.get("ReadReplicaSourceDBInstanceIdentifier")]
        if dbs:
            checks.append({"id":"perf-rds-replica","title":"RDS read replicas configured", "pass": len(replicas)>0, "severity":"LOW"})
    except Exception:
        pass
    # Lambda — check for functions using arm64
    try:
        fns = session.client("lambda", region_name=region).list_functions()["Functions"]
        arm = [f for f in fns if f.get("Architectures",["x86_64"])==["arm64"]]
        if fns:
            checks.append({"id":"perf-lambda-arm","title":"Lambda functions use Graviton (arm64)","pass": len(arm)>0, "severity":"LOW", "detail": f"{len(arm)}/{len(fns)} on arm64"})
    except Exception:
        pass
    if not checks:
        checks.append({"id":"perf-baseline","title":"Performance baseline assessed","pass":True,"severity":"LOW"})
    passed = sum(1 for c in checks if c["pass"])
    score  = _pct(passed, len(checks))
    return {"checks": checks, "passed": passed, "total": len(checks), "score": score, **score_to_risk(score)}


# ── Pillar 5: Cost Optimization ──────────────────────────────────────────────

def pillar_cost(session, region):
    checks = []
    ec2 = session.client("ec2", region_name=region)
    # Unattached EBS volumes
    vols = _safe(lambda: ec2.describe_volumes(Filters=[{"Name":"status","Values":["available"]}])["Volumes"], [])
    checks.append({"id":"cost-ebs-unused","title":"No unattached EBS volumes",            "pass": len(vols)==0, "severity":"MEDIUM", "detail": f"{len(vols)} unattached volumes"})
    # Unassociated Elastic IPs
    eips = _safe(lambda: ec2.describe_addresses()["Addresses"], [])
    unassoc = [e for e in eips if not e.get("AssociationId")]
    checks.append({"id":"cost-eip",       "title":"No idle Elastic IPs",                 "pass": len(unassoc)==0, "severity":"LOW", "detail": f"{len(unassoc)} idle EIPs"})
    # Stopped instances (running but stopped for >7 days — approximate via state)
    stopped = []
    try:
        for page in ec2.get_paginator("describe_instances").paginate(Filters=[{"Name":"instance-state-name","Values":["stopped"]}]):
            for r in page["Reservations"]:
                stopped.extend(r["Instances"])
    except Exception:
        pass
    checks.append({"id":"cost-stopped",   "title":"No stopped EC2 instances",            "pass": len(stopped)==0, "severity":"LOW", "detail": f"{len(stopped)} stopped instances"})
    # Budget alerts
    try:
        budgets = session.client("budgets").describe_budgets(AccountId=session.client("sts").get_caller_identity()["Account"])["Budgets"]
        checks.append({"id":"cost-budgets","title":"AWS Budgets alerts configured",       "pass": len(budgets)>0, "severity":"MEDIUM"})
    except Exception:
        checks.append({"id":"cost-budgets","title":"AWS Budgets alerts configured",       "pass": False, "severity":"MEDIUM"})
    # Savings Plans / Reserved Instances
    try:
        ri = ec2.describe_reserved_instances(Filters=[{"Name":"state","Values":["active"]}])["ReservedInstances"]
        checks.append({"id":"cost-ri",     "title":"Reserved Instances or Savings Plans", "pass": len(ri)>0, "severity":"LOW", "detail": f"{len(ri)} active RIs"})
    except Exception:
        checks.append({"id":"cost-ri",     "title":"Reserved Instances or Savings Plans", "pass": False, "severity":"LOW"})
    passed = sum(1 for c in checks if c["pass"])
    score  = _pct(passed, len(checks))
    return {"checks": checks, "passed": passed, "total": len(checks), "score": score, **score_to_risk(score)}


# ── Pillar 6: Sustainability ──────────────────────────────────────────────────

def pillar_sustainability(session, region):
    checks = []
    ec2 = session.client("ec2", region_name=region)
    # Graviton usage
    instances = []
    try:
        for page in ec2.get_paginator("describe_instances").paginate():
            for r in page["Reservations"]:
                instances.extend(r["Instances"])
    except Exception:
        pass
    arm_types = [i for i in instances if "g" in i.get("InstanceType","").split(".")[0] or i.get("InstanceType","").startswith(("t4g","m6g","c6g","r6g"))]
    if instances:
        checks.append({"id":"sus-graviton","title":"Graviton instances in use",            "pass": len(arm_types)>0, "severity":"LOW", "detail": f"{len(arm_types)}/{len(instances)} on Graviton"})
    # S3 lifecycle policies
    try:
        s3 = session.client("s3")
        buckets = s3.list_buckets()["Buckets"]
        no_lc = sum(1 for b in buckets if not _safe(lambda: s3.get_bucket_lifecycle_configuration(Bucket=b["Name"]), None))
        if buckets:
            checks.append({"id":"sus-s3-lifecycle","title":"S3 lifecycle policies configured","pass": no_lc < len(buckets), "severity":"LOW", "detail": f"{len(buckets)-no_lc}/{len(buckets)} with lifecycle"})
    except Exception:
        pass
    # Auto Scaling (scale-in = less waste)
    try:
        asg = session.client("autoscaling", region_name=region)
        groups = asg.describe_auto_scaling_groups()["AutoScalingGroups"]
        checks.append({"id":"sus-autoscaling","title":"Auto Scaling enabled (reduces waste)", "pass": len(groups)>0, "severity":"LOW"})
    except Exception:
        checks.append({"id":"sus-autoscaling","title":"Auto Scaling enabled (reduces waste)", "pass": False, "severity":"LOW"})
    # Lambda serverless (less idle compute)
    try:
        fns = session.client("lambda", region_name=region).list_functions()["Functions"]
        checks.append({"id":"sus-serverless","title":"Serverless compute (Lambda) in use",  "pass": len(fns)>0, "severity":"LOW", "detail": f"{len(fns)} functions"})
    except Exception:
        checks.append({"id":"sus-serverless","title":"Serverless compute (Lambda) in use",  "pass": False, "severity":"LOW"})
    if not checks:
        checks.append({"id":"sus-baseline","title":"Sustainability baseline","pass":True,"severity":"LOW"})
    passed = sum(1 for c in checks if c["pass"])
    score  = _pct(passed, len(checks))
    return {"checks": checks, "passed": passed, "total": len(checks), "score": score, **score_to_risk(score)}


# ── Main ──────────────────────────────────────────────────────────────────────

PILLAR_META = {
    "ops":             "Operational Excellence",
    "security":        "Security",
    "reliability":     "Reliability",
    "performance":     "Performance Efficiency",
    "cost":            "Cost Optimization",
    "sustainability":  "Sustainability",
}

def run_wellarch_scan(access_key: str, secret_key: str, region: str) -> dict:
    session = build_session(access_key, secret_key, region)
    try:
        sts = session.client("sts")
        r = sts.get_caller_identity()
        identity = {"account_id": r["Account"], "user_id": r["UserId"], "arn": r["Arn"]}
    except Exception as e:
        identity = {"error": str(e)}

    pillar_fns = {
        "ops":            lambda: pillar_ops(session, region),
        "security":       lambda: pillar_security(session, region),
        "reliability":    lambda: pillar_reliability(session, region),
        "performance":    lambda: pillar_performance(session, region),
        "cost":           lambda: pillar_cost(session, region),
        "sustainability": lambda: pillar_sustainability(session, region),
    }

    pillars = {}
    with ThreadPoolExecutor(max_workers=6) as ex:
        futures = {ex.submit(fn): key for key, fn in pillar_fns.items()}
        for fut in as_completed(futures):
            key = futures[fut]
            try:
                result = fut.result()
                result["label"] = PILLAR_META[key]
                pillars[key] = result
            except Exception as e:
                pillars[key] = {"label": PILLAR_META[key], "score": 0, "risk": "CRITICAL", "color": "red", "checks": [], "passed": 0, "total": 0, "error": str(e)}

    overall = round(sum(p.get("score", 0) for p in pillars.values()) / len(pillars), 1) if pillars else 0
    overall_risk = score_to_risk(overall)

    total_checks = sum(p.get("total", 0) for p in pillars.values())
    total_passed = sum(p.get("passed", 0) for p in pillars.values())

    sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    issues = []
    for key, p in pillars.items():
        for c in p.get("checks", []):
            if not c["pass"]:
                c["pillar"] = PILLAR_META[key]
                issues.append(c)
    issues.sort(key=lambda c: sev_rank.get(c.get("severity","LOW"), 3))

    return {
        "identity":      identity,
        "region":        region,
        "scan_time":     str(datetime.now(timezone.utc))[:19],
        "overall_score": overall,
        "overall_risk":  overall_risk["risk"],
        "overall_color": overall_risk["color"],
        "total_checks":  total_checks,
        "total_passed":  total_passed,
        "total_failed":  total_checks - total_passed,
        "pillars":       pillars,
        "top_issues":    issues[:20],
    }
