"""
Audit Log — records every remediation action taken.
In-memory for now. In production, persist to DynamoDB or RDS.
"""

from datetime import datetime, timezone
from typing import List, Dict

AUDIT_LOG: List[Dict] = []


def log_action(
    action_id: str,
    action_label: str,
    resource_id: str,
    resource_type: str,
    region: str,
    status: str,          # SUCCESS | FAILED | SKIPPED
    detail: str,
    before_state: dict = None,
    after_state: dict  = None,
    executed_by: str   = "sai-user",
):
    entry = {
        "id":            len(AUDIT_LOG) + 1,
        "timestamp":     str(datetime.now(timezone.utc))[:19],
        "action_id":     action_id,
        "action_label":  action_label,
        "resource_id":   resource_id,
        "resource_type": resource_type,
        "region":        region,
        "status":        status,
        "detail":        detail,
        "before_state":  before_state or {},
        "after_state":   after_state  or {},
        "executed_by":   executed_by,
    }
    AUDIT_LOG.append(entry)
    return entry


def get_audit_log() -> List[Dict]:
    return list(reversed(AUDIT_LOG))  # newest first
