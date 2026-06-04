"""
WAF & Firewall Management Scanner
Checks WAFv2 Web ACLs, Network Firewall, Shield, CloudFront WAF.
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

def scan_waf_firewall(session: boto3.Session, region: str) -> Dict:
    result = {"score":0,"total_checks":0,"passed":0,"failed":0,"checks":[],
              "waf_acls":[],"network_firewall":[],"errors":[]}

    # ── WAFv2 Regional ───────────────────────────────────────────
    try:
        waf = session.client("wafv2", region_name=region)
        acls = waf.list_web_acls(Scope="REGIONAL")["WebACLs"]
        if acls:
            for acl in acls:
                detail = _safe(lambda: waf.get_web_acl(
                    Name=acl["Name"],Scope="REGIONAL",Id=acl["Id"])["WebACL"],{})
                rules = detail.get("Rules",[])
                logging_on = _safe(lambda: bool(waf.get_logging_configuration(
                    ResourceArn=detail.get("ARN",""))["LoggingConfiguration"]),False)
                result["waf_acls"].append({
                    "name":acl["Name"],"id":acl["Id"],"scope":"REGIONAL",
                    "rules":len(rules),"logging":logging_on,
                })
            # Check if ALBs/APIs are associated
            no_logging = sum(1 for a in result["waf_acls"] if not a["logging"])
            _add(result,"Regional WAF Web ACLs exist", True,
                 f"{len(acls)} regional Web ACLs configured","HIGH")
            _add(result,"All WAF Web ACLs have logging enabled", no_logging==0,
                 f"{no_logging}/{len(acls)} Web ACLs without logging","MEDIUM")
        else:
            _add(result,"Regional WAF Web ACLs configured", False,
                 "No regional WAF Web ACLs — resources may be unprotected","HIGH")
    except Exception as e:
        result["errors"].append(f"WAF Regional: {e}")

    # ── WAFv2 CloudFront (global) ─────────────────────────────────
    try:
        waf_global = session.client("wafv2", region_name="us-east-1")
        cf_acls = waf_global.list_web_acls(Scope="CLOUDFRONT")["WebACLs"]
        _add(result,"CloudFront WAF Web ACLs configured", len(cf_acls)>0,
             f"{len(cf_acls)} CloudFront Web ACLs" if cf_acls else "No CloudFront WAF configured","MEDIUM")
        for acl in cf_acls:
            result["waf_acls"].append({"name":acl["Name"],"id":acl["Id"],"scope":"CLOUDFRONT","rules":0})
    except Exception as e:
        result["errors"].append(f"WAF CloudFront: {e}")

    # ── Network Firewall ─────────────────────────────────────────
    try:
        nfw = session.client("network-firewall", region_name=region)
        firewalls = nfw.list_firewalls()["Firewalls"]
        if firewalls:
            for fw in firewalls:
                detail = _safe(lambda: nfw.describe_firewall(FirewallName=fw["FirewallName"])["Firewall"],{})
                logging = _safe(lambda: nfw.describe_logging_configuration(FirewallName=fw["FirewallName"]),{})
                result["network_firewall"].append({
                    "name":fw["FirewallName"],"status":detail.get("FirewallStatus",{}).get("Status","?"),
                    "logging": bool(logging.get("LoggingConfiguration",{}).get("LogDestinationConfigs")),
                })
            _add(result,"AWS Network Firewall deployed", True,
                 f"{len(firewalls)} Network Firewall(s) deployed","HIGH")
        else:
            _add(result,"AWS Network Firewall deployed", False,
                 "No Network Firewall found — consider for VPC traffic inspection","MEDIUM")
    except Exception as e:
        result["errors"].append(f"Network Firewall: {e}")

    # ── Shield ───────────────────────────────────────────────────
    try:
        shield = session.client("shield", region_name="us-east-1")
        sub = _safe(lambda: shield.describe_subscription()["Subscription"],None)
        _add(result,"AWS Shield Advanced enabled", sub is not None,
             f"Shield Advanced active, tier: {sub.get('ProactiveCaseSupportEnabled','?')}" if sub else "Only Shield Standard active","LOW")
    except Exception as e:
        result["errors"].append(f"Shield: {e}")

    # ── Check ELBs without WAF association ───────────────────────
    try:
        elb = session.client("elbv2", region_name=region)
        lbs = elb.describe_load_balancers()["LoadBalancers"]
        albs = [lb for lb in lbs if lb.get("Type")=="application"]
        if albs:
            waf = session.client("wafv2", region_name=region)
            no_waf = 0
            for lb in albs:
                assoc = _safe(lambda: waf.get_web_acl_for_resource(
                    ResourceArn=lb["LoadBalancerArn"]).get("WebACL"),None)
                if not assoc: no_waf+=1
            _add(result,"All ALBs are protected by WAF", no_waf==0,
                 f"{no_waf}/{len(albs)} ALBs have no WAF Web ACL","HIGH")
    except Exception as e:
        result["errors"].append(f"ALB WAF check: {e}")

    t = result["total_checks"]
    result["score"] = round(result["passed"]/t*100,1) if t else 0
    return result
