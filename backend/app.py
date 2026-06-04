"""
Multi-Cloud SecOps Platform — Flask Backend
Supports: AWS (boto3) and Azure (azure-sdk)
Port: 5000
"""

from flask import Flask, request, jsonify
from flask_cors import CORS

# ── AWS scanners ──────────────────────────────────────────────────────────────
from scanners.discovery  import scan_all            as aws_discovery
from scanners.compliance import run_compliance_scan  as aws_compliance
from scanners.risk       import run_risk_scan        as aws_risk
from scanners.cspm       import run_cspm_scan        as aws_cspm
from scanners.maturity   import run_maturity_scan    as aws_maturity
from scanners.wellarch   import run_wellarch_scan    as aws_wellarch

# ── Azure scanners ─────────────────────────────────────────────────────────────
from azure_scanners.discovery  import scan_all            as az_discovery
from azure_scanners.compliance import run_compliance_scan  as az_compliance
from azure_scanners.risk       import run_risk_scan        as az_risk
from azure_scanners.cspm       import run_cspm_scan        as az_cspm
from azure_scanners.maturity   import run_maturity_scan    as az_maturity
from azure_scanners.wellarch   import run_wellarch_scan    as az_wellarch

app = Flask(__name__)
CORS(app, origins=[
    "http://localhost:3000", "http://127.0.0.1:3000",
    "http://localhost:4200", "http://127.0.0.1:4200",
])


# ── Helpers ───────────────────────────────────────────────────────────────────

def _aws_creds(data):
    ak = data.get("accessKey", "").strip()
    sk = data.get("secretKey", "").strip()
    all_regions = data.get("allRegions", False)
    rg = None if all_regions else (data.get("region", "").strip() or "us-east-1")
    return ak, sk, rg


def _az_creds(data):
    tenant   = data.get("tenantId",       "").strip()
    client   = data.get("clientId",       "").strip()
    secret   = data.get("clientSecret",   "").strip()
    sub      = data.get("subscriptionId", "").strip() or None
    return tenant, client, secret, sub


# ══════════════════════════════════════════════════════════════════════════════
# AWS Endpoints
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/scan", methods=["POST"])
def aws_scan_discovery():
    data = request.get_json()
    ak, sk, rg = _aws_creds(data)
    if not ak or not sk:
        return jsonify({"error": "AWS credentials required."}), 400
    return jsonify(aws_discovery(ak, sk, rg))


@app.route("/api/compliance/scan", methods=["POST"])
def aws_scan_compliance():
    data = request.get_json()
    ak, sk, rg = _aws_creds(data)
    if not ak or not sk:
        return jsonify({"error": "AWS credentials required."}), 400
    return jsonify(aws_compliance(ak, sk, rg or "us-east-1"))


@app.route("/api/risk/scan", methods=["POST"])
def aws_scan_risk():
    data = request.get_json()
    ak, sk, rg = _aws_creds(data)
    if not ak or not sk:
        return jsonify({"error": "AWS credentials required."}), 400
    return jsonify(aws_risk(ak, sk, rg or "us-east-1"))


@app.route("/api/cspm/scan", methods=["POST"])
def aws_cspm_scan():
    data = request.get_json()
    ak, sk, rg = _aws_creds(data)
    if not ak or not sk:
        return jsonify({"error": "AWS credentials required."}), 400
    return jsonify(aws_cspm(ak, sk, rg or "us-east-1"))


@app.route("/api/maturity/scan", methods=["POST"])
def aws_maturity_scan():
    data = request.get_json()
    ak, sk, rg = _aws_creds(data)
    if not ak or not sk:
        return jsonify({"error": "AWS credentials required."}), 400
    return jsonify(aws_maturity(ak, sk, rg or "us-east-1"))


@app.route("/api/wellarch/scan", methods=["POST"])
def aws_wellarch_scan():
    data = request.get_json()
    ak, sk, rg = _aws_creds(data)
    if not ak or not sk:
        return jsonify({"error": "AWS credentials required."}), 400
    return jsonify(aws_wellarch(ak, sk, rg or "us-east-1"))


# ══════════════════════════════════════════════════════════════════════════════
# Azure Endpoints
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/azure/scan", methods=["POST"])
def az_scan_discovery():
    data = request.get_json()
    t, c, s, sub = _az_creds(data)
    if not t or not c or not s:
        return jsonify({"error": "Azure credentials required (tenantId, clientId, clientSecret)."}), 400
    return jsonify(az_discovery(t, c, s, sub))


@app.route("/api/azure/compliance/scan", methods=["POST"])
def az_scan_compliance():
    data = request.get_json()
    t, c, s, sub = _az_creds(data)
    if not t or not c or not s or not sub:
        return jsonify({"error": "Azure credentials + subscriptionId required."}), 400
    return jsonify(az_compliance(t, c, s, sub))


@app.route("/api/azure/risk/scan", methods=["POST"])
def az_scan_risk():
    data = request.get_json()
    t, c, s, sub = _az_creds(data)
    if not t or not c or not s or not sub:
        return jsonify({"error": "Azure credentials + subscriptionId required."}), 400
    return jsonify(az_risk(t, c, s, sub))


@app.route("/api/azure/cspm/scan", methods=["POST"])
def az_cspm_scan():
    data = request.get_json()
    t, c, s, sub = _az_creds(data)
    if not t or not c or not s or not sub:
        return jsonify({"error": "Azure credentials + subscriptionId required."}), 400
    return jsonify(az_cspm(t, c, s, sub))


@app.route("/api/azure/maturity/scan", methods=["POST"])
def az_maturity_scan():
    data = request.get_json()
    t, c, s, sub = _az_creds(data)
    if not t or not c or not s or not sub:
        return jsonify({"error": "Azure credentials + subscriptionId required."}), 400
    return jsonify(az_maturity(t, c, s, sub))


@app.route("/api/azure/wellarch/scan", methods=["POST"])
def az_wellarch_scan():
    data = request.get_json()
    t, c, s, sub = _az_creds(data)
    if not t or not c or not s or not sub:
        return jsonify({"error": "Azure credentials + subscriptionId required."}), 400
    return jsonify(az_wellarch(t, c, s, sub))


# ── Health ────────────────────────────────────────────────────────────────────

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok", "phases": 6, "port": 5000,
        "clouds": ["aws", "azure"], "mode": "read-only"
    })


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)
