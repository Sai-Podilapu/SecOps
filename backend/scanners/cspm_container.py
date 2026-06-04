"""
CSPM – Container Security Scanner
Checks ECS tasks, ECS clusters, ECR repositories, EKS clusters.
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

def scan_cspm_container(session: boto3.Session, region: str) -> Dict:
    result = {"score":0,"total_checks":0,"passed":0,"failed":0,"checks":[],
              "ecr":[],"ecs":[],"eks":[],"errors":[]}

    # ── ECR ──────────────────────────────────────────────────────
    try:
        ecr = session.client("ecr", region_name=region)
        repos = ecr.describe_repositories()["repositories"]
        no_scan = no_immutable = no_enc = 0
        for r in repos:
            scan_on_push = r.get("imageScanningConfiguration",{}).get("scanOnPush",False)
            immutable    = r.get("imageTagMutability","MUTABLE") == "IMMUTABLE"
            enc_type     = r.get("encryptionConfiguration",{}).get("encryptionType","AES256")
            if not scan_on_push: no_scan += 1
            if not immutable:    no_immutable += 1
            result["ecr"].append({"name":r["repositoryName"],"scan_on_push":scan_on_push,
                                   "immutable":immutable,"encryption":enc_type})
        if repos:
            _add(result,"All ECR repos scan images on push", no_scan==0,
                 f"{no_scan}/{len(repos)} repos missing scan-on-push","HIGH")
            _add(result,"All ECR repos have immutable tags", no_immutable==0,
                 f"{no_immutable}/{len(repos)} repos allow mutable tags","MEDIUM")
        else:
            _add(result,"ECR repositories checked", True,"No ECR repositories found","LOW")
    except Exception as e:
        result["errors"].append(f"ECR: {e}")

    # ── ECS ──────────────────────────────────────────────────────
    try:
        ecs = session.client("ecs", region_name=region)
        clusters = ecs.list_clusters()["clusterArns"]
        if clusters:
            cluster_details = ecs.describe_clusters(clusters=clusters,
                include=["SETTINGS","STATISTICS"])["clusters"]
            no_insights = 0
            for c in cluster_details:
                cname = c.get("clusterName","?")
                insights = any(s.get("name")=="containerInsights" and s.get("value")=="enabled"
                               for s in c.get("settings",[]))
                if not insights: no_insights += 1
                result["ecs"].append({"name":cname,"status":c.get("status","?"),
                                      "container_insights":insights,
                                      "running_tasks":c.get("statistics",[])})
            _add(result,"All ECS clusters have Container Insights enabled", no_insights==0,
                 f"{no_insights}/{len(cluster_details)} clusters without insights","MEDIUM")

            # Task definitions — check for privileged containers
            task_arns = ecs.list_task_definitions(status="ACTIVE")["taskDefinitionArns"][:20]
            privileged_tasks = 0
            root_tasks = 0
            for arn in task_arns:
                td = _safe(lambda: ecs.describe_task_definition(taskDefinition=arn)["taskDefinition"],{})
                for cd in td.get("containerDefinitions",[]):
                    if cd.get("privileged"): privileged_tasks += 1
                    if cd.get("user","") in ("root","0","","0:0"): root_tasks += 1
            if task_arns:
                _add(result,"No ECS tasks run as privileged", privileged_tasks==0,
                     f"{privileged_tasks} privileged container definitions found","CRITICAL")
                _add(result,"No ECS tasks run as root user", root_tasks==0,
                     f"{root_tasks} task definitions run containers as root","HIGH")
        else:
            _add(result,"ECS clusters checked", True,"No ECS clusters found","LOW")
    except Exception as e:
        result["errors"].append(f"ECS: {e}")

    # ── EKS ──────────────────────────────────────────────────────
    try:
        eks = session.client("eks", region_name=region)
        cluster_names = eks.list_clusters()["clusters"]
        if cluster_names:
            no_logging = no_private = old_k8s = 0
            for cname in cluster_names:
                c = eks.describe_cluster(name=cname)["cluster"]
                log_types = [lt for lt in c.get("logging",{}).get("clusterLogging",[])
                             if lt.get("enabled")]
                has_logging = len(log_types) > 0
                private_ep  = c.get("resourcesVpcConfig",{}).get("endpointPrivateAccess",False)
                public_ep   = c.get("resourcesVpcConfig",{}).get("endpointPublicAccess",True)
                version     = c.get("version","0")
                if not has_logging: no_logging += 1
                if public_ep and not private_ep: no_private += 1
                result["eks"].append({"name":cname,"version":version,
                                      "logging":has_logging,"private_endpoint":private_ep,
                                      "public_endpoint":public_ep,"status":c.get("status","?")})
            _add(result,"All EKS clusters have control plane logging", no_logging==0,
                 f"{no_logging}/{len(cluster_names)} clusters without logging","HIGH")
            _add(result,"EKS API endpoint is private or restricted", no_private==0,
                 f"{no_private}/{len(cluster_names)} clusters with fully public API endpoint","HIGH")
        else:
            _add(result,"EKS clusters checked", True,"No EKS clusters found","LOW")
    except Exception as e:
        result["errors"].append(f"EKS: {e}")

    t = result["total_checks"]
    result["score"] = round(result["passed"]/t*100,1) if t else 0
    return result
