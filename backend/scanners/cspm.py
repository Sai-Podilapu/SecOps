"""
Unified CSPM Scanner — calls all sub-scanners and returns combined results.
"""
import boto3
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from scanners.cspm_compute   import scan_cspm_compute
from scanners.cspm_container import scan_cspm_container
from scanners.cspm_database  import scan_cspm_database
from scanners.cspm_network   import scan_cspm_network
from scanners.secrets_management import scan_secrets_management
from scanners.waf_firewall   import scan_waf_firewall
from scanners.cis_benchmark  import scan_cis_benchmark

def run_cspm_scan(access_key: str, secret_key: str, region: str) -> dict:
    session = boto3.Session(aws_access_key_id=access_key,
                            aws_secret_access_key=secret_key, region_name=region)
    try:
        sts = session.client("sts")
        r = sts.get_caller_identity()
        identity = {"account_id":r["Account"],"user_id":r["UserId"],"arn":r["Arn"]}
    except Exception as e:
        identity = {"error":str(e)}

    scanners = {
        "compute":   lambda: scan_cspm_compute(session, region),
        "container": lambda: scan_cspm_container(session, region),
        "database":  lambda: scan_cspm_database(session, region),
        "network":   lambda: scan_cspm_network(session, region),
        "secrets":   lambda: scan_secrets_management(session, region),
        "waf":       lambda: scan_waf_firewall(session, region),
        "cis":       lambda: scan_cis_benchmark(session, region),
    }

    labels = {
        "compute":"Compute Security","container":"Container Security",
        "database":"Database Security","network":"Network Security",
        "secrets":"Secrets Management","waf":"WAF & Firewall","cis":"CIS Benchmark",
    }

    modules = {}
    with ThreadPoolExecutor(max_workers=7) as ex:
        futures = {ex.submit(fn): key for key, fn in scanners.items()}
        for fut in as_completed(futures):
            key = futures[fut]
            try:
                res = fut.result()
                res["label"] = labels[key]
                modules[key] = res
            except Exception as e:
                modules[key] = {"label":labels[key],"score":0,"total_checks":0,
                                "passed":0,"failed":0,"checks":[],"error":str(e)}

    total_checks = sum(m.get("total_checks",0) for m in modules.values())
    total_passed = sum(m.get("passed",0) for m in modules.values())
    overall = round(sum(m.get("score",0) for m in modules.values())/len(modules),1) if modules else 0

    all_failures = []
    sev_rank = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}
    for key, m in modules.items():
        for c in m.get("checks",[]):
            if c.get("status")=="FAIL":
                c["module"] = labels[key]
                all_failures.append(c)
    all_failures.sort(key=lambda c: sev_rank.get(c.get("severity","LOW"),3))

    return {
        "identity":identity,"region":region,
        "scan_time":str(datetime.now(timezone.utc))[:19],
        "overall_score":overall,
        "total_checks":total_checks,"total_passed":total_passed,
        "total_failed":total_checks-total_passed,
        "modules":modules,
        "top_failures":all_failures[:25],
    }
