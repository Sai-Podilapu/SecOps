"""
Cost Explorer Scanner
Fetches MTD cost data for the risk dashboard
"""

import boto3
from datetime import datetime, timezone
from typing import Dict


def scan_costs(session: boto3.Session) -> Dict:
    result = {
        "total": 0,
        "forecast": None,
        "by_service": {},
        "period": "",
        "errors": [],
    }

    try:
        ce  = session.client("ce", region_name="us-east-1")
        now = datetime.now(timezone.utc)
        end   = now.strftime("%Y-%m-%d")
        start = now.replace(day=1).strftime("%Y-%m-%d")
        result["period"] = f"{start} → {end}"

        resp = ce.get_cost_and_usage(
            TimePeriod={"Start": start, "End": end},
            Granularity="MONTHLY",
            Metrics=["UnblendedCost"],
            GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}],
        )
        for period in resp.get("ResultsByTime", []):
            for g in period.get("Groups", []):
                cost = float(g["Metrics"]["UnblendedCost"]["Amount"])
                if cost > 0:
                    result["by_service"][g["Keys"][0]] = round(cost, 4)
        result["total"] = round(sum(result["by_service"].values()), 4)

        try:
            import calendar
            last_day = calendar.monthrange(now.year, now.month)[1]
            end_fc   = now.replace(day=last_day).strftime("%Y-%m-%d")
            if start != end_fc:
                fc = ce.get_cost_forecast(
                    TimePeriod={"Start": end, "End": end_fc},
                    Metric="UNBLENDED_COST",
                    Granularity="MONTHLY",
                )
                result["forecast"] = round(float(fc["Total"]["Amount"]), 2)
        except Exception:
            pass

    except Exception as e:
        result["errors"].append(str(e))

    return result
