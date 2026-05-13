"""
Policy Store
Manages auto-remediation policies in memory.
Each policy defines: WHEN (trigger condition) → DO (action) with safeguards.
"""

import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional

# ── Built-in policy templates ─────────────────────────────────────────────────
DEFAULT_POLICIES = [
    {
        "id":          "policy-s3-public",
        "name":        "Auto-Block S3 Public Access",
        "description": "Automatically blocks public access on any S3 bucket that is found to be publicly accessible.",
        "trigger":     "s3_public_access",
        "action":      "s3_block_public_access",
        "category":    "S3",
        "severity_threshold": "CRITICAL",
        "enabled":     False,
        "dry_run":     True,
        "max_per_run": 5,
        "exclude_resources": [],
        "created":     "2026-05-01T00:00:00",
        "built_in":    True,
        "run_count":   0,
        "last_run":    None,
    },
    {
        "id":          "policy-sg-ssh",
        "name":        "Auto-Remove Open SSH Rules",
        "description": "Automatically removes inbound SSH (port 22) rules that allow access from 0.0.0.0/0.",
        "trigger":     "sg_open_ssh",
        "action":      "sg_remove_open_ssh",
        "category":    "Network",
        "severity_threshold": "CRITICAL",
        "enabled":     False,
        "dry_run":     True,
        "max_per_run": 10,
        "exclude_resources": [],
        "created":     "2026-05-01T00:00:00",
        "built_in":    True,
        "run_count":   0,
        "last_run":    None,
    },
    {
        "id":          "policy-sg-rdp",
        "name":        "Auto-Remove Open RDP Rules",
        "description": "Automatically removes inbound RDP (port 3389) rules that allow access from 0.0.0.0/0.",
        "trigger":     "sg_open_rdp",
        "action":      "sg_remove_open_rdp",
        "category":    "Network",
        "severity_threshold": "CRITICAL",
        "enabled":     False,
        "dry_run":     True,
        "max_per_run": 10,
        "exclude_resources": [],
        "created":     "2026-05-01T00:00:00",
        "built_in":    True,
        "run_count":   0,
        "last_run":    None,
    },
    {
        "id":          "policy-s3-encrypt",
        "name":        "Auto-Enable S3 Encryption",
        "description": "Automatically enables AES-256 server-side encryption on unencrypted S3 buckets.",
        "trigger":     "s3_no_encryption",
        "action":      "s3_enable_encryption",
        "category":    "S3",
        "severity_threshold": "HIGH",
        "enabled":     False,
        "dry_run":     True,
        "max_per_run": 5,
        "exclude_resources": [],
        "created":     "2026-05-01T00:00:00",
        "built_in":    True,
        "run_count":   0,
        "last_run":    None,
    },
    {
        "id":          "policy-s3-versioning",
        "name":        "Auto-Enable S3 Versioning",
        "description": "Automatically enables versioning on S3 buckets that do not have it enabled.",
        "trigger":     "s3_no_versioning",
        "action":      "s3_enable_versioning",
        "category":    "S3",
        "severity_threshold": "MEDIUM",
        "enabled":     False,
        "dry_run":     True,
        "max_per_run": 10,
        "exclude_resources": [],
        "created":     "2026-05-01T00:00:00",
        "built_in":    True,
        "run_count":   0,
        "last_run":    None,
    },
    {
        "id":          "policy-iam-password",
        "name":        "Auto-Enforce Password Policy",
        "description": "Automatically applies a strong IAM password policy if none exists.",
        "trigger":     "iam_no_password_policy",
        "action":      "iam_enforce_password_policy",
        "category":    "IAM",
        "severity_threshold": "HIGH",
        "enabled":     False,
        "dry_run":     True,
        "max_per_run": 1,
        "exclude_resources": [],
        "created":     "2026-05-01T00:00:00",
        "built_in":    True,
        "run_count":   0,
        "last_run":    None,
    },
]

# In-memory policy store
_policies: Dict[str, Dict] = {p["id"]: p for p in DEFAULT_POLICIES}


def get_policies() -> List[Dict]:
    return list(_policies.values())


def get_policy_by_id(policy_id: str) -> Optional[Dict]:
    return _policies.get(policy_id)


def save_policy(data: Dict) -> Dict:
    policy_id = data.get("id") or f"policy-custom-{uuid.uuid4().hex[:8]}"
    policy = {
        "id":                 policy_id,
        "name":               data.get("name", "Custom Policy"),
        "description":        data.get("description", ""),
        "trigger":            data.get("trigger", ""),
        "action":             data.get("action", ""),
        "category":           data.get("category", "Custom"),
        "severity_threshold": data.get("severity_threshold", "HIGH"),
        "enabled":            data.get("enabled", False),
        "dry_run":            data.get("dry_run", True),
        "max_per_run":        data.get("max_per_run", 5),
        "exclude_resources":  data.get("exclude_resources", []),
        "created":            data.get("created", str(datetime.now(timezone.utc))[:19]),
        "built_in":           False,
        "run_count":          data.get("run_count", 0),
        "last_run":           data.get("last_run", None),
    }
    _policies[policy_id] = policy
    return policy


def toggle_policy(policy_id: str) -> Optional[Dict]:
    if policy_id not in _policies:
        return None
    _policies[policy_id]["enabled"] = not _policies[policy_id]["enabled"]
    return _policies[policy_id]


def delete_policy(policy_id: str) -> bool:
    if policy_id in _policies and not _policies[policy_id].get("built_in"):
        del _policies[policy_id]
        return True
    return False


def update_policy_run(policy_id: str):
    if policy_id in _policies:
        _policies[policy_id]["run_count"] = _policies[policy_id].get("run_count", 0) + 1
        _policies[policy_id]["last_run"]  = str(datetime.now(timezone.utc))[:19]
