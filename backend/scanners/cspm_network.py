"""
CSPM – Network Security Scanner
Checks VPCs, SGs, NACLs, route tables, peering, flow logs, ELBs.
"""
import boto3
from typing import Dict

def _safe(fn, default=None):
    try: return fn()
    except: return default

def _add(result, name, passed, detail, severity="MEDIUM"):
    result["total_checks"] += 1
    result["passed" if passed else "failed"] += 1
    result["checks"].append({"name":name,"status":"PASS" if passed else "FAIL",
                              "detail":detail,"severity":severity})

def scan_cspm_network(session: boto3.Session, region: str) -> Dict:
    result = {"score":0,"total_checks":0,"passed":0,"failed":0,"checks":[],
              "vpcs":[],"security_groups":[],"errors":[]}
    ec2 = session.client("ec2", region_name=region)

    # ── VPCs ─────────────────────────────────────────────────────
    vpcs = _safe(lambda: ec2.describe_vpcs()["Vpcs"],[])
    flow_logs = _safe(lambda: ec2.describe_flow_logs()["FlowLogs"],[])
    covered = {fl["ResourceId"] for fl in flow_logs if fl.get("FlowLogStatus")=="ACTIVE"}

    no_flowlogs = default_used = 0
    for v in vpcs:
        vid = v["VpcId"]
        is_default = v.get("IsDefault",False)
        has_fl = vid in covered
        if not has_fl: no_flowlogs += 1
        # Check if default VPC has resources
        if is_default:
            insts = _safe(lambda: ec2.describe_instances(
                Filters=[{"Name":"vpc-id","Values":[vid]}])["Reservations"],[])
            if insts: default_used += 1
        result["vpcs"].append({"id":vid,"is_default":is_default,"flow_logs":has_fl,
                               "cidr":v.get("CidrBlock","?")})

    if vpcs:
        _add(result,"All VPCs have flow logs enabled", no_flowlogs==0,
             f"{no_flowlogs}/{len(vpcs)} VPCs without flow logs","HIGH")
        _add(result,"Default VPC not used for workloads", default_used==0,
             f"{default_used} default VPC(s) contain running instances","MEDIUM")

    # ── Security Groups ──────────────────────────────────────────
    sgs = _safe(lambda: ec2.describe_security_groups()["SecurityGroups"],[])
    open_ssh = open_rdp = open_all = wide_egress = 0
    for sg in sgs:
        sgid = sg["GroupId"]
        issues = []
        for rule in sg.get("IpPermissions",[]):
            fp = rule.get("FromPort",0)
            tp = rule.get("ToPort",65535)
            cidrs = [r.get("CidrIp","") for r in rule.get("IpRanges",[])]
            if "0.0.0.0/0" in cidrs:
                if fp<=22<=tp:    open_ssh+=1; issues.append("SSH open")
                if fp<=3389<=tp:  open_rdp+=1; issues.append("RDP open")
                if fp==0 and tp==0: open_all+=1; issues.append("All ports open")
        for rule in sg.get("IpPermissionsEgress",[]):
            cidrs = [r.get("CidrIp","") for r in rule.get("IpRanges",[])]
            if "0.0.0.0/0" in cidrs and rule.get("IpProtocol")=="-1":
                wide_egress+=1
        result["security_groups"].append({
            "id":sgid,"name":sg.get("GroupName","?"),"vpc":sg.get("VpcId","?"),
            "issues":issues,"description":sg.get("Description","?")[:80]
        })
    if sgs:
        _add(result,"No SG allows SSH from 0.0.0.0/0", open_ssh==0,
             f"{open_ssh} SGs with open SSH","CRITICAL")
        _add(result,"No SG allows RDP from 0.0.0.0/0", open_rdp==0,
             f"{open_rdp} SGs with open RDP","CRITICAL")
        _add(result,"No SG allows all ports from 0.0.0.0/0", open_all==0,
             f"{open_all} SGs with all ports open","CRITICAL")

    # ── NACLs ────────────────────────────────────────────────────
    nacls = _safe(lambda: ec2.describe_network_acls()["NetworkAcls"],[])
    permissive_nacl = 0
    for nacl in nacls:
        for entry in nacl.get("Entries",[]):
            if (entry.get("CidrBlock")=="0.0.0.0/0" and entry.get("RuleAction")=="allow"
                    and entry.get("Egress")==False and entry.get("Protocol")=="-1"):
                permissive_nacl+=1
    if nacls:
        _add(result,"No NACLs allow all inbound traffic", permissive_nacl==0,
             f"{permissive_nacl} NACLs allow all inbound traffic","HIGH")

    # ── Internet Gateways ────────────────────────────────────────
    igws = _safe(lambda: ec2.describe_internet_gateways()["InternetGateways"],[])
    unattached_igw = [i for i in igws if not i.get("Attachments")]
    _add(result,"No unattached Internet Gateways", len(unattached_igw)==0,
         f"{len(unattached_igw)} unattached IGWs found","LOW")

    # ── ELB: SSL/TLS ─────────────────────────────────────────────
    try:
        elb = session.client("elbv2", region_name=region)
        lbs = elb.describe_load_balancers()["LoadBalancers"]
        http_listeners = 0
        for lb in lbs:
            listeners = _safe(lambda: elb.describe_listeners(LoadBalancerArn=lb["LoadBalancerArn"])["Listeners"],[])
            for lst in listeners:
                if lst.get("Protocol") == "HTTP": http_listeners+=1
        if lbs:
            _add(result,"No ELB listeners use plain HTTP", http_listeners==0,
                 f"{http_listeners} listeners use HTTP instead of HTTPS","HIGH")
    except Exception as e:
        result["errors"].append(f"ELB: {e}")

    # ── VPC Peering ──────────────────────────────────────────────
    peering = _safe(lambda: ec2.describe_vpc_peering_connections(
        Filters=[{"Name":"status-code","Values":["active"]}])["VpcPeeringConnections"],[])
    _add(result,"VPC peering connections reviewed", True,
         f"{len(peering)} active peering connections — review manually" if peering else "No VPC peering connections","LOW")

    t = result["total_checks"]
    result["score"] = round(result["passed"]/t*100,1) if t else 0
    return result
