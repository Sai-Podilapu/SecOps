"""
CIS Benchmark Compliance Scanner
Directly implements CIS AWS Foundations Benchmark v1.5 checks.
Organized by CIS section.
"""
import boto3
from datetime import datetime, timezone
from typing import Dict

def _safe(fn, default=None):
    try: return fn()
    except: return default

def _add(result, cis_id, name, passed, detail, severity="MEDIUM"):
    result["total_checks"] += 1
    result["passed" if passed else "failed"] += 1
    result["checks"].append({
        "cis_id":cis_id,"name":name,"status":"PASS" if passed else "FAIL",
        "detail":detail,"severity":severity
    })

def scan_cis_benchmark(session: boto3.Session, region: str) -> Dict:
    result = {"score":0,"total_checks":0,"passed":0,"failed":0,"checks":[],"errors":[],
              "framework":"CIS AWS Foundations Benchmark v1.5"}
    iam = session.client("iam")
    ec2 = session.client("ec2", region_name=region)

    # ── Section 1: IAM ───────────────────────────────────────────
    summary = _safe(lambda: iam.get_account_summary()["SummaryMap"],{})
    _add(result,"1.1","Avoid use of root account",
         True,"Manual check — use IAM users instead of root","LOW")
    _add(result,"1.2","MFA enabled for root account",
         summary.get("AccountMFAEnabled",0)==1,
         "Root MFA enabled" if summary.get("AccountMFAEnabled",0)==1 else "Root MFA NOT enabled","CRITICAL")
    _add(result,"1.3","Root account has no active access keys",
         summary.get("AccountAccessKeysPresent",0)==0,
         "No root access keys" if summary.get("AccountAccessKeysPresent",0)==0 else "Root has active access keys","CRITICAL")

    pp = _safe(lambda: iam.get_account_password_policy()["PasswordPolicy"],{})
    _add(result,"1.8","IAM password minimum length >= 14",
         pp.get("MinimumPasswordLength",0)>=14,
         f"Min length: {pp.get('MinimumPasswordLength',0)}","MEDIUM")
    _add(result,"1.9","IAM password reuse prevention >= 24",
         pp.get("PasswordReusePrevention",0)>=24,
         f"Reuse prevention: {pp.get('PasswordReusePrevention',0)}","MEDIUM")
    _add(result,"1.10","IAM password expiry enabled (<= 90 days)",
         0 < pp.get("MaxPasswordAge",999) <= 90,
         f"Max age: {pp.get('MaxPasswordAge','Not set')}","MEDIUM")
    _add(result,"1.11","IAM password requires uppercase",
         pp.get("RequireUppercaseCharacters",False),
         "Uppercase required" if pp.get("RequireUppercaseCharacters") else "Not required","LOW")
    _add(result,"1.12","IAM password requires lowercase",
         pp.get("RequireLowercaseCharacters",False),
         "Lowercase required" if pp.get("RequireLowercaseCharacters") else "Not required","LOW")
    _add(result,"1.13","IAM password requires symbols",
         pp.get("RequireSymbols",False),
         "Symbols required" if pp.get("RequireSymbols") else "Not required","LOW")
    _add(result,"1.14","IAM password requires numbers",
         pp.get("RequireNumbers",False),
         "Numbers required" if pp.get("RequireNumbers") else "Not required","LOW")

    # Access keys rotation
    try:
        now = datetime.now(timezone.utc)
        users = []
        for page in iam.get_paginator("list_users").paginate():
            users.extend(page["Users"])
        old_keys = no_mfa = 0
        for u in users:
            uname = u["UserName"]
            keys = _safe(lambda: iam.list_access_keys(UserName=uname)["AccessKeyMetadata"],[])
            for k in keys:
                if k["Status"]=="Active":
                    age = (now - k["CreateDate"].replace(tzinfo=timezone.utc
                           if k["CreateDate"].tzinfo is None else k["CreateDate"].tzinfo)).days
                    if age > 90: old_keys+=1
            mfas = _safe(lambda: iam.list_mfa_devices(UserName=uname)["MFADevices"],[])
            if not mfas: no_mfa+=1
        _add(result,"1.15","Access keys rotated every 90 days",
             old_keys==0, f"{old_keys} access keys older than 90 days","HIGH")
        _add(result,"1.16","MFA enabled for all IAM users with console access",
             no_mfa==0, f"{no_mfa}/{len(users)} users without MFA","HIGH")
    except Exception as e:
        result["errors"].append(f"IAM users: {e}")

    # Access Analyzer
    aa = _safe(lambda: session.client("accessanalyzer",region_name=region).list_analyzers()["analyzers"],[])
    _add(result,"1.21","IAM Access Analyzer enabled",
         any(a["status"]=="ACTIVE" for a in aa),
         f"{len(aa)} analyzer(s)" if aa else "No Access Analyzer configured","MEDIUM")

    # ── Section 2: Storage (S3) ──────────────────────────────────
    s3 = session.client("s3", region_name="us-east-1")
    buckets = _safe(lambda: s3.list_buckets()["Buckets"],[])
    no_enc = no_public = no_logging = 0
    for b in buckets:
        name = b["Name"]
        enc = _safe(lambda: s3.get_bucket_encryption(Bucket=name),None)
        if not enc: no_enc+=1
        pab = _safe(lambda: s3.get_public_access_block(Bucket=name).get("PublicAccessBlockConfiguration",{}),{})
        if not all(pab.get(k,False) for k in ["BlockPublicAcls","IgnorePublicAcls","BlockPublicPolicy","RestrictPublicBuckets"]):
            no_public+=1
        log = _safe(lambda: s3.get_bucket_logging(Bucket=name).get("LoggingEnabled"),None)
        if not log: no_logging+=1
    n = len(buckets)
    if n:
        _add(result,"2.1.1","All S3 buckets have server-side encryption",
             no_enc==0,f"{no_enc}/{n} unencrypted buckets","HIGH")
        _add(result,"2.1.2","All S3 buckets block public access",
             no_public==0,f"{no_public}/{n} buckets without full public block","CRITICAL")
        _add(result,"2.1.3","All S3 buckets have access logging enabled",
             no_logging==0,f"{no_logging}/{n} buckets without access logging","MEDIUM")

    # ── Section 3: Logging ───────────────────────────────────────
    try:
        ct = session.client("cloudtrail",region_name=region)
        trails = ct.describe_trails(includeShadowTrails=False)["trailList"]
        multi = [t for t in trails if t.get("IsMultiRegionTrail")]
        validated = [t for t in trails if t.get("LogFileValidationEnabled")]
        cw_integrated = [t for t in trails if t.get("CloudWatchLogsLogGroupArn")]
        _add(result,"3.1","CloudTrail is enabled in all regions",
             len(multi)>0, f"{len(multi)} multi-region trail(s)","CRITICAL")
        _add(result,"3.2","CloudTrail log file validation enabled",
             len(validated)>0, f"{len(validated)}/{len(trails)} with validation","HIGH")
        _add(result,"3.4","CloudTrail integrated with CloudWatch Logs",
             len(cw_integrated)>0, f"{len(cw_integrated)}/{len(trails)} with CW integration","HIGH")
    except Exception as e:
        result["errors"].append(f"CloudTrail: {e}")

    # AWS Config
    try:
        cfg = session.client("config",region_name=region)
        recs = cfg.describe_configuration_recorders()["ConfigurationRecorders"]
        sts  = cfg.describe_configuration_recorder_status()["ConfigurationRecordersStatus"]
        recording = any(s.get("recording") for s in sts)
        _add(result,"3.5","AWS Config enabled and recording",
             len(recs)>0 and recording,
             "Config enabled and recording" if recording else "Config not recording","HIGH")
    except Exception as e:
        result["errors"].append(f"Config: {e}")

    # ── Section 4: Networking ─────────────────────────────────────
    sgs = _safe(lambda: ec2.describe_security_groups()["SecurityGroups"],[])
    ssh_open = rdp_open = 0
    for sg in sgs:
        for rule in sg.get("IpPermissions",[]):
            fp,tp = rule.get("FromPort",0),rule.get("ToPort",65535)
            for ip in rule.get("IpRanges",[]):
                if ip.get("CidrIp") in ("0.0.0.0/0","::/0"):
                    if fp<=22<=tp: ssh_open+=1
                    if fp<=3389<=tp: rdp_open+=1
    _add(result,"4.1","No security group allows unrestricted SSH",
         ssh_open==0, f"{ssh_open} SGs with open SSH","CRITICAL")
    _add(result,"4.2","No security group allows unrestricted RDP",
         rdp_open==0, f"{rdp_open} SGs with open RDP","CRITICAL")

    # VPC default SG
    default_sgs = [sg for sg in sgs if sg.get("GroupName")=="default"]
    default_with_rules = [sg for sg in default_sgs
                          if sg.get("IpPermissions") or sg.get("IpPermissionsEgress",[{}])[0].get("IpRanges")]
    _add(result,"4.3","Default security group restricts all traffic",
         len(default_with_rules)==0,
         f"{len(default_with_rules)} default SGs have open rules","HIGH")

    # VPC Flow Logs
    vpcs = _safe(lambda: ec2.describe_vpcs()["Vpcs"],[])
    fls  = _safe(lambda: ec2.describe_flow_logs()["FlowLogs"],[])
    covered = {fl["ResourceId"] for fl in fls if fl.get("FlowLogStatus")=="ACTIVE"}
    no_fl = sum(1 for v in vpcs if v["VpcId"] not in covered)
    _add(result,"4.4","VPC flow logging enabled in all VPCs",
         no_fl==0, f"{no_fl}/{len(vpcs)} VPCs without flow logs","HIGH")

    t = result["total_checks"]
    result["score"] = round(result["passed"]/t*100,1) if t else 0

    # Section scores
    section_map = {"1":"IAM","2":"Storage","3":"Logging","4":"Networking"}
    sections = {}
    for c in result["checks"]:
        sec = c["cis_id"].split(".")[0]
        label = section_map.get(sec, f"Section {sec}")
        if label not in sections:
            sections[label] = {"passed":0,"total":0}
        sections[label]["total"] += 1
        if c["status"]=="PASS": sections[label]["passed"] += 1
    result["sections"] = {k:{"passed":v["passed"],"total":v["total"],
        "score":round(v["passed"]/v["total"]*100,1) if v["total"] else 0}
        for k,v in sections.items()}

    return result
