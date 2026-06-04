"""
Secrets Management Scanner
Checks AWS Secrets Manager, SSM Parameter Store, and detects hardcoded secrets in env vars.
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
    result["checks"].append({"name":name,"status":"PASS" if passed else "FAIL",
                              "detail":detail,"severity":severity})

def scan_secrets_management(session: boto3.Session, region: str) -> Dict:
    result = {"score":0,"total_checks":0,"passed":0,"failed":0,"checks":[],
              "secrets":[],"parameters":[],"lambda_issues":[],"errors":[]}
    now = datetime.now(timezone.utc)

    # ── Secrets Manager ──────────────────────────────────────────
    try:
        sm = session.client("secretsmanager", region_name=region)
        secrets = []
        paginator = sm.get_paginator("list_secrets")
        for page in paginator.paginate():
            secrets.extend(page["SecretList"])

        if secrets:
            not_rotated = old_rotation = no_rotation = 0
            for s in secrets:
                name_ = s.get("Name","?")
                last_rotated = s.get("LastRotatedDate")
                rotation_on  = s.get("RotationEnabled",False)
                days_old = (now - last_rotated.replace(tzinfo=timezone.utc
                    if last_rotated.tzinfo is None else last_rotated.tzinfo)).days if last_rotated else 999
                if not rotation_on: no_rotation += 1
                if last_rotated and days_old > 90: old_rotation += 1
                result["secrets"].append({
                    "name": name_,"rotation_enabled":rotation_on,
                    "last_rotated": str(last_rotated)[:10] if last_rotated else "Never",
                    "days_since_rotation": days_old if last_rotated else None,
                })
            n = len(secrets)
            _add(result,"All secrets have rotation enabled", no_rotation==0,
                 f"{no_rotation}/{n} secrets without rotation","HIGH")
            _add(result,"All secrets rotated within 90 days", old_rotation==0,
                 f"{old_rotation}/{n} secrets not rotated in 90+ days","MEDIUM")
        else:
            _add(result,"Secrets Manager in use", False,
                 "No secrets found in Secrets Manager — consider migrating from env vars","MEDIUM")
    except Exception as e:
        result["errors"].append(f"Secrets Manager: {e}")

    # ── SSM Parameter Store ──────────────────────────────────────
    try:
        ssm = session.client("ssm", region_name=region)
        params = ssm.describe_parameters()["Parameters"]
        if params:
            not_secure = [p for p in params if p.get("Type") != "SecureString"]
            _add(result,"All SSM parameters use SecureString type", len(not_secure)==0,
                 f"{len(not_secure)}/{len(params)} parameters are not SecureString","MEDIUM")
            for p in params[:30]:
                result["parameters"].append({
                    "name":p["Name"],"type":p.get("Type","?"),
                    "last_modified":str(p.get("LastModifiedDate","?"))[:10],
                    "secure": p.get("Type")=="SecureString",
                })
        else:
            _add(result,"SSM Parameter Store usage checked", True,
                 "No SSM parameters found","LOW")
    except Exception as e:
        result["errors"].append(f"SSM: {e}")

    # ── Lambda env var secret detection ──────────────────────────
    try:
        lam = session.client("lambda", region_name=region)
        fns = lam.list_functions()["Functions"]
        suspect_keys = {"password","secret","key","token","api_key","apikey",
                        "passwd","pwd","credential","auth","private"}
        flagged = []
        for f in fns:
            env = f.get("Environment",{}).get("Variables",{})
            for k in env:
                if any(s in k.lower() for s in suspect_keys):
                    flagged.append({"function":f["FunctionName"],"variable":k})
        _add(result,"No Lambda functions expose secrets in env vars", len(flagged)==0,
             f"{len(flagged)} suspicious env variable(s) found" if flagged else "No suspected secrets in env vars",
             "HIGH")
        result["lambda_issues"] = flagged[:20]
    except Exception as e:
        result["errors"].append(f"Lambda env check: {e}")

    # ── KMS ──────────────────────────────────────────────────────
    try:
        kms = session.client("kms", region_name=region)
        keys = kms.list_keys()["Keys"]
        cmks = []
        for k in keys[:20]:
            meta = _safe(lambda: kms.describe_key(KeyId=k["KeyId"])["KeyMetadata"],{})
            if meta.get("KeyManager")=="CUSTOMER" and meta.get("KeyState")=="Enabled":
                cmks.append(k)
        _add(result,"Customer-managed KMS keys in use", len(cmks)>0,
             f"{len(cmks)} CMKs active" if cmks else "No customer-managed KMS keys — using AWS-managed only","MEDIUM")
    except Exception as e:
        result["errors"].append(f"KMS: {e}")

    t = result["total_checks"]
    result["score"] = round(result["passed"]/t*100,1) if t else 0
    return result
