"""
CSPM – Compute Security Scanner
Checks EC2, Lambda for security misconfigurations.
"""
import boto3
from datetime import datetime, timezone
from typing import Dict

def _safe(fn, default=None):
    try: return fn()
    except: return default

def _add(result, name, passed, detail, severity="MEDIUM"):
    result["total_checks"] += 1
    result["passed" if passed else "failed"] += 1
    result["checks"].append({"name": name, "status": "PASS" if passed else "FAIL",
                              "detail": detail, "severity": severity})

def scan_cspm_compute(session: boto3.Session, region: str) -> Dict:
    result = {"score":0,"total_checks":0,"passed":0,"failed":0,"checks":[],"resources":[],"errors":[]}
    ec2 = session.client("ec2", region_name=region)

    # ── EC2 ───────────────────────────────────────────────────────
    instances = []
    try:
        for page in ec2.get_paginator("describe_instances").paginate():
            for r in page["Reservations"]:
                instances.extend(r["Instances"])
    except Exception as e:
        result["errors"].append(f"EC2 list: {e}")

    no_imdsv2 = public_ip = no_profile = old_ami = 0
    for i in instances:
        iid   = i.get("InstanceId","?")
        itype = i.get("InstanceType","?")
        state = i.get("State",{}).get("Name","?")
        az    = i.get("Placement",{}).get("AvailabilityZone","?")

        # IMDSv2
        imds = i.get("MetadataOptions",{}).get("HttpTokens","optional")
        if imds != "required": no_imdsv2 += 1

        # Public IP
        if i.get("PublicIpAddress"): public_ip += 1

        # IAM instance profile
        if not i.get("IamInstanceProfile"): no_profile += 1

        result["resources"].append({
            "type":"EC2","id":iid,"instance_type":itype,"state":state,"az":az,
            "imdsv2": imds=="required","public_ip": bool(i.get("PublicIpAddress")),
            "iam_profile": bool(i.get("IamInstanceProfile")),
        })

    total_ec2 = len(instances)
    if total_ec2:
        _add(result,"EC2 IMDSv2 enforced on all instances", no_imdsv2==0,
             f"{no_imdsv2}/{total_ec2} instances not enforcing IMDSv2","HIGH")
        _add(result,"No EC2 instances with public IP (use ELB instead)", public_ip==0,
             f"{public_ip}/{total_ec2} instances have public IPs","MEDIUM")
        _add(result,"All EC2 instances have IAM instance profiles", no_profile==0,
             f"{no_profile}/{total_ec2} instances have no IAM profile","MEDIUM")
    else:
        _add(result,"EC2 instances scanned", True,"No EC2 instances found","LOW")

    # EBS default encryption
    ebs_enc = _safe(lambda: ec2.get_ebs_encryption_by_default()["EbsEncryptionByDefault"], False)
    _add(result,"EBS encryption by default enabled", ebs_enc,
         "EBS default encryption is ON" if ebs_enc else "EBS default encryption is OFF","HIGH")

    # Unattached EBS volumes
    vols = _safe(lambda: ec2.describe_volumes(Filters=[{"Name":"status","Values":["available"]}])["Volumes"],[])
    _add(result,"No unattached EBS volumes", len(vols)==0,
         f"{len(vols)} unattached volumes wasting cost/risk" if vols else "No unattached volumes","LOW")

    # Public AMIs (owned by account)
    try:
        acct = session.client("sts").get_caller_identity()["Account"]
        amis = ec2.describe_images(Owners=[acct])["Images"]
        public_amis = [a for a in amis if a.get("Public")]
        _add(result,"No account AMIs are public", len(public_amis)==0,
             f"{len(public_amis)} AMIs are publicly shared" if public_amis else "No public AMIs","HIGH")
    except Exception as e:
        result["errors"].append(f"AMI check: {e}")

    # ── Lambda ───────────────────────────────────────────────────
    try:
        lam = session.client("lambda", region_name=region)
        fns = lam.list_functions()["Functions"]
        no_tracing = no_vpc = old_runtime = 0
        dead_runtimes = {"nodejs12.x","nodejs10.x","python2.7","python3.6","ruby2.5","java8"}
        for f in fns:
            if f.get("TracingConfig",{}).get("Mode") != "Active": no_tracing += 1
            if not f.get("VpcConfig",{}).get("VpcId"): no_vpc += 1
            if f.get("Runtime","") in dead_runtimes: old_runtime += 1
            result["resources"].append({
                "type":"Lambda","id":f["FunctionName"],"runtime":f.get("Runtime","?"),
                "tracing": f.get("TracingConfig",{}).get("Mode")=="Active",
                "in_vpc": bool(f.get("VpcConfig",{}).get("VpcId")),
            })
        if fns:
            _add(result,"All Lambda functions have X-Ray tracing", no_tracing==0,
                 f"{no_tracing}/{len(fns)} without tracing","LOW")
            _add(result,"Lambda functions use supported runtimes", old_runtime==0,
                 f"{old_runtime}/{len(fns)} using EOL runtimes","HIGH")
    except Exception as e:
        result["errors"].append(f"Lambda: {e}")

    t = result["total_checks"]
    result["score"] = round(result["passed"]/t*100,1) if t else 0
    return result
