"""
AWS Security Platform — Unified Backend (All 5 Phases)
Flask Backend — port 5015
"""

from flask import Flask, request, jsonify
from flask_cors import CORS

from scanners.discovery  import scan_all
from scanners.compliance import run_compliance_scan
from scanners.risk       import run_risk_scan
from scanner             import run_remediation_scan
from executor            import execute_action
from audit               import get_audit_log
from policy_store        import get_policies, save_policy, toggle_policy, delete_policy
from auto_engine         import run_auto_remediation, get_executions
from auto_scanner        import run_scan as run_auto_scan

app = Flask(__name__)
CORS(app)

def _creds(data):
    return data.get("accessKey","").strip(), data.get("secretKey","").strip(), data.get("region","").strip()

# Phase 1
@app.route("/api/scan", methods=["POST"])
def scan_discovery():
    data = request.get_json()
    ak, sk, rg = _creds(data)
    if not ak or not sk: return jsonify({"error": "Credentials required."}), 400
    return jsonify(scan_all(ak, sk, rg or None))

# Phase 2
@app.route("/api/compliance/scan", methods=["POST"])
def scan_compliance():
    data = request.get_json()
    ak, sk, rg = _creds(data)
    if not ak or not sk: return jsonify({"error": "Credentials required."}), 400
    return jsonify(run_compliance_scan(ak, sk, rg or "us-east-1"))

# Phase 3
@app.route("/api/risk/scan", methods=["POST"])
def scan_risk():
    data = request.get_json()
    ak, sk, rg = _creds(data)
    if not ak or not sk: return jsonify({"error": "Credentials required."}), 400
    return jsonify(run_risk_scan(ak, sk, rg or "ap-south-1"))

# Phase 4 Manual Remediation
@app.route("/api/remediation/scan", methods=["POST"])
def remediation_scan():
    data = request.get_json()
    ak, sk, rg = _creds(data)
    if not rg: rg = "ap-south-1"
    if not ak or not sk: return jsonify({"error": "Credentials required."}), 400
    return jsonify(run_remediation_scan(ak, sk, rg))

@app.route("/api/remediation/execute", methods=["POST"])
def remediation_execute():
    data = request.get_json()
    ak, sk, rg = _creds(data)
    if not rg: rg = "ap-south-1"
    action_id = data.get("actionId","").strip()
    resource  = data.get("resource", {})
    params    = data.get("params", {})
    if not all([ak, sk, action_id]): return jsonify({"error": "accessKey, secretKey, and actionId required."}), 400
    return jsonify(execute_action(ak, sk, rg, action_id, resource, params))

@app.route("/api/remediation/audit", methods=["GET"])
def remediation_audit():
    return jsonify({"log": get_audit_log()})

@app.route("/api/remediation/actions", methods=["GET"])
def remediation_actions():
    from scanner import ACTION_CATALOG
    return jsonify(ACTION_CATALOG)

# Phase 5 Auto Remediation
@app.route("/api/auto/scan", methods=["POST"])
def auto_scan():
    data = request.get_json()
    ak, sk, rg = _creds(data)
    if not rg: rg = "ap-south-1"
    if not ak or not sk: return jsonify({"error": "Credentials required."}), 400
    return jsonify(run_auto_scan(ak, sk, rg))

@app.route("/api/auto/policies", methods=["GET"])
def list_policies():
    return jsonify({"policies": get_policies()})

@app.route("/api/auto/policies", methods=["POST"])
def create_policy():
    return jsonify({"policy": save_policy(request.get_json())})

@app.route("/api/auto/policies/<policy_id>/toggle", methods=["POST"])
def toggle_pol(policy_id):
    p = toggle_policy(policy_id)
    if not p: return jsonify({"error": "Policy not found"}), 404
    return jsonify({"policy": p})

@app.route("/api/auto/policies/<policy_id>/delete", methods=["POST"])
def delete_pol(policy_id):
    return jsonify({"success": delete_policy(policy_id)})

@app.route("/api/auto/trigger", methods=["POST"])
def trigger():
    data = request.get_json()
    ak, sk, rg = _creds(data)
    if not rg: rg = "ap-south-1"
    if not ak or not sk: return jsonify({"error": "Credentials required."}), 400
    return jsonify({"results": run_auto_remediation(ak, sk, rg, policy_id=data.get("policy_id"))})

@app.route("/api/auto/executions", methods=["GET"])
def auto_executions():
    return jsonify({"executions": get_executions()})

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status":"ok","phases":[1,2,3,4,5],"port":5015})

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5015)
