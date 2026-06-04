"""
CSPM – Database Security Scanner
Checks RDS, DynamoDB, ElastiCache, Redshift.
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

def scan_cspm_database(session: boto3.Session, region: str) -> Dict:
    result = {"score":0,"total_checks":0,"passed":0,"failed":0,"checks":[],
              "rds":[],"dynamodb":[],"errors":[]}

    # ── RDS ──────────────────────────────────────────────────────
    try:
        rds = session.client("rds", region_name=region)
        instances = rds.describe_db_instances()["DBInstances"]
        if instances:
            unenc = public = no_backup = no_multiaz = no_minor = deletion_no = 0
            for db in instances:
                did  = db["DBInstanceIdentifier"]
                enc  = db.get("StorageEncrypted",False)
                pub  = db.get("PubliclyAccessible",False)
                bak  = db.get("BackupRetentionPeriod",0)
                maz  = db.get("MultiAZ",False)
                del_prot = db.get("DeletionProtection",False)
                minor = db.get("AutoMinorVersionUpgrade",False)
                if not enc:   unenc += 1
                if pub:       public += 1
                if bak == 0:  no_backup += 1
                if not maz:   no_multiaz += 1
                if not del_prot: deletion_no += 1
                if not minor: no_minor += 1
                result["rds"].append({
                    "id":did,"engine":db.get("Engine","?"),"class":db.get("DBInstanceClass","?"),
                    "encrypted":enc,"public":pub,"multi_az":maz,"backup_days":bak,
                    "deletion_protection":del_prot,"auto_minor_upgrade":minor,
                    "status":db.get("DBInstanceStatus","?"),
                })
            n = len(instances)
            _add(result,"All RDS instances encrypted at rest", unenc==0,
                 f"{unenc}/{n} unencrypted","CRITICAL")
            _add(result,"No RDS instances publicly accessible", public==0,
                 f"{public}/{n} publicly accessible","CRITICAL")
            _add(result,"All RDS instances have backups enabled", no_backup==0,
                 f"{no_backup}/{n} with backup retention=0","HIGH")
            _add(result,"All RDS instances are Multi-AZ", no_multiaz==0,
                 f"{no_multiaz}/{n} single-AZ","HIGH")
            _add(result,"All RDS instances have deletion protection", deletion_no==0,
                 f"{deletion_no}/{n} without deletion protection","MEDIUM")
            _add(result,"All RDS instances auto-upgrade minor versions", no_minor==0,
                 f"{no_minor}/{n} not auto-upgrading minor versions","MEDIUM")

        # RDS snapshots public check
        snaps = _safe(lambda: rds.describe_db_snapshots(SnapshotType="public")["DBSnapshots"],[])
        _add(result,"No public RDS snapshots", len(snaps)==0,
             f"{len(snaps)} public snapshots found" if snaps else "No public snapshots","CRITICAL")

    except Exception as e:
        result["errors"].append(f"RDS: {e}")

    # ── DynamoDB ─────────────────────────────────────────────────
    try:
        ddb = session.client("dynamodb", region_name=region)
        table_names = ddb.list_tables()["TableNames"]
        if table_names:
            no_enc = no_pitr = 0
            for tname in table_names[:20]:
                t = _safe(lambda: ddb.describe_table(TableName=tname)["Table"],{})
                enc  = t.get("SSEDescription",{}).get("Status","DISABLED") == "ENABLED"
                pitr = _safe(lambda: ddb.describe_continuous_backups(TableName=tname
                    )["ContinuousBackupsDescription"]["PointInTimeRecoveryDescription"
                    ]["PointInTimeRecoveryStatus"]=="ENABLED", False)
                if not enc:  no_enc += 1
                if not pitr: no_pitr += 1
                result["dynamodb"].append({"name":tname,"encrypted":enc,"pitr":pitr})
            n = len(table_names)
            _add(result,"All DynamoDB tables encrypted at rest", no_enc==0,
                 f"{no_enc}/{n} tables not encrypted","HIGH")
            _add(result,"All DynamoDB tables have PITR enabled", no_pitr==0,
                 f"{no_pitr}/{n} tables without point-in-time recovery","MEDIUM")
    except Exception as e:
        result["errors"].append(f"DynamoDB: {e}")

    # ── ElastiCache ──────────────────────────────────────────────
    try:
        ec = session.client("elasticache", region_name=region)
        clusters = ec.describe_cache_clusters()["CacheClusters"]
        if clusters:
            no_enc = no_auth = 0
            for c in clusters:
                enc = c.get("AtRestEncryptionEnabled",False)
                auth = c.get("AuthTokenEnabled",False)
                if not enc:  no_enc += 1
                if not auth: no_auth += 1
            n = len(clusters)
            _add(result,"All ElastiCache clusters encrypted at rest", no_enc==0,
                 f"{no_enc}/{n} clusters not encrypted","HIGH")
            _add(result,"All ElastiCache clusters require auth token", no_auth==0,
                 f"{no_auth}/{n} clusters without auth token","MEDIUM")
    except Exception as e:
        result["errors"].append(f"ElastiCache: {e}")

    t = result["total_checks"]
    result["score"] = round(result["passed"]/t*100,1) if t else 0
    return result
