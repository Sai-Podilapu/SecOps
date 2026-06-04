"""
Azure Resource Discovery — Scanner (Phase 1)
Uses Azure Resource Graph to discover all resources across subscriptions.
Falls back to direct ARM APIs for costs, IAM, and subscription details.
"""

import json
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Any, Optional

try:
    from azure.identity import ClientSecretCredential
    from azure.mgmt.resource import ResourceManagementClient
    from azure.mgmt.resource.subscriptions import SubscriptionClient
    from azure.mgmt.costmanagement import CostManagementClient
    from azure.mgmt.authorization import AuthorizationManagementClient
    from azure.core.exceptions import HttpResponseError
    from azure.mgmt.resourcegraph import ResourceGraphClient
    from azure.mgmt.resourcegraph.models import QueryRequest
    AZURE_AVAILABLE = True
except ImportError:
    AZURE_AVAILABLE = False


def build_credential(tenant_id: str, client_id: str, client_secret: str):
    if not AZURE_AVAILABLE:
        raise ImportError("azure-* packages not installed")
    return ClientSecretCredential(
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
    )


def get_identity(credential, subscription_id: str) -> Dict:
    try:
        sub_client = SubscriptionClient(credential)
        sub = sub_client.subscriptions.get(subscription_id)
        return {
            "subscription_id": sub.subscription_id,
            "display_name": sub.display_name,
            "tenant_id": sub.tenant_id,
            "state": str(sub.state),
        }
    except Exception as e:
        return {"subscription_id": subscription_id, "error": str(e)}


def get_subscriptions(credential, selected: Optional[str] = None) -> List[str]:
    if selected:
        return [selected]
    try:
        client = SubscriptionClient(credential)
        return [s.subscription_id for s in client.subscriptions.list()
                if str(s.state).lower() == "enabled"]
    except Exception:
        return [selected] if selected else []


def get_all_resources(credential, subscription_id: str) -> Dict:
    """
    Query ALL resources via Azure Resource Graph.
    Returns resources grouped by type.
    """
    grouped: Dict[str, List] = {}
    try:
        rg_client = ResourceGraphClient(credential)
        query = """
        Resources
        | project id, name, type, location, resourceGroup, subscriptionId,
                  tags, kind, properties, sku
        | order by type asc
        """
        skip = 0
        page_size = 1000
        while True:
            req = QueryRequest(
                subscriptions=[subscription_id],
                query=query,
                options={"top": page_size, "skip": skip},
            )
            resp = rg_client.resources(req)
            rows = resp.data if resp.data else []
            if not rows:
                break
            for row in rows:
                rtype = (row.get("type") or "Unknown").lower()
                tags_raw = row.get("tags") or {}
                tags = tags_raw if isinstance(tags_raw, dict) else {}
                grouped.setdefault(rtype, []).append({
                    "resourceId":   row.get("id", "—"),
                    "resourceName": row.get("name") or tags.get("Name", "—"),
                    "resourceGroup": row.get("resourceGroup", "—"),
                    "region":       row.get("location", "—"),
                    "kind":         row.get("kind", "—"),
                    "tags":         tags,
                })
            skip += len(rows)
            if len(rows) < page_size:
                break
    except Exception as e:
        grouped["_error"] = [{"error": str(e)}]
    return grouped


def get_resource_groups(credential, subscription_id: str) -> List[Dict]:
    try:
        client = ResourceManagementClient(credential, subscription_id)
        return [
            {"name": rg.name, "location": rg.location,
             "tags": rg.tags or {}, "state": rg.properties.provisioning_state if rg.properties else "—"}
            for rg in client.resource_groups.list()
        ]
    except Exception as e:
        return [{"error": str(e)}]


def get_costs(credential, subscription_id: str) -> Dict:
    result = {"by_service": {}, "by_region": {}, "total": 0,
              "period": "", "forecast": None}
    try:
        now = datetime.now(timezone.utc)
        start = now.replace(day=1).strftime("%Y-%m-%d")
        end = now.strftime("%Y-%m-%d")
        result["period"] = f"{start} → {end}"

        client = CostManagementClient(credential)
        scope = f"/subscriptions/{subscription_id}"

        # By service
        resp = client.query.usage(
            scope=scope,
            parameters={
                "type": "Usage",
                "timeframe": "Custom",
                "timePeriod": {"from": start + "T00:00:00Z", "to": end + "T23:59:59Z"},
                "dataset": {
                    "granularity": "None",
                    "aggregation": {"totalCost": {"name": "Cost", "function": "Sum"}},
                    "grouping": [{"type": "Dimension", "name": "ServiceName"}],
                },
            },
        )
        if resp and resp.rows:
            for row in resp.rows:
                cost = float(row[0]) if row else 0
                service = str(row[1]) if len(row) > 1 else "Unknown"
                if cost > 0.001:
                    result["by_service"][service] = round(cost, 4)
        result["total"] = round(sum(result["by_service"].values()), 2)

        # By region
        resp2 = client.query.usage(
            scope=scope,
            parameters={
                "type": "Usage",
                "timeframe": "Custom",
                "timePeriod": {"from": start + "T00:00:00Z", "to": end + "T23:59:59Z"},
                "dataset": {
                    "granularity": "None",
                    "aggregation": {"totalCost": {"name": "Cost", "function": "Sum"}},
                    "grouping": [{"type": "Dimension", "name": "ResourceLocation"}],
                },
            },
        )
        if resp2 and resp2.rows:
            for row in resp2.rows:
                cost = float(row[0]) if row else 0
                region = str(row[1]) if len(row) > 1 else "Unknown"
                if cost > 0.001:
                    result["by_region"][region] = round(cost, 4)
    except Exception as e:
        result["error"] = str(e)
    return result


def get_iam_summary(credential, subscription_id: str) -> Dict:
    try:
        auth_client = AuthorizationManagementClient(credential, subscription_id)
        scope = f"/subscriptions/{subscription_id}"
        assignments = list(auth_client.role_assignments.list_for_scope(scope))
        definitions = list(auth_client.role_definitions.list(scope))
        return {
            "role_assignments": len(assignments),
            "role_definitions": len(definitions),
            "custom_roles": len([d for d in definitions if d.role_type == "CustomRole"]),
        }
    except Exception as e:
        return {"error": str(e)}


def scan_all(tenant_id: str, client_id: str, client_secret: str,
             subscription_id: Optional[str] = None) -> Dict:
    results = {
        "identity": {},
        "subscriptions": [],
        "resources": {},
        "resource_counts": {},
        "summary": {},
        "resource_groups": [],
        "costs": {},
        "iam_summary": {},
        "scan_time": str(datetime.now(timezone.utc))[:19],
        "errors": [],
        "cloud": "azure",
    }

    try:
        credential = build_credential(tenant_id, client_id, client_secret)
        subs = get_subscriptions(credential, subscription_id)
        results["subscriptions"] = subs

        if not subs:
            results["errors"].append("No enabled subscriptions found.")
            return results

        target_sub = subs[0]
        results["identity"] = get_identity(credential, target_sub)
        results["resource_groups"] = get_resource_groups(credential, target_sub)
        results["costs"] = get_costs(credential, target_sub)
        results["iam_summary"] = get_iam_summary(credential, target_sub)
        results["resources"][target_sub] = get_all_resources(credential, target_sub)

        # Counts
        counts: Dict[str, int] = {}
        for rtype, items in results["resources"][target_sub].items():
            if not rtype.startswith("_"):
                counts[rtype] = len(items)
        results["resource_counts"][target_sub] = counts

        # Summary
        summary: Dict[str, int] = {}
        for rtype, cnt in counts.items():
            summary[rtype] = summary.get(rtype, 0) + cnt
        results["summary"] = dict(sorted(summary.items(), key=lambda x: x[1], reverse=True))

    except Exception as e:
        results["errors"].append(str(e))

    return results
