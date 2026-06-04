# Multi-Cloud SecOps Platform

Full 6-phase cloud security suite for **AWS** and **Azure** with a one-click cloud switcher.

---

## 🌩 Cloud Support

| Feature                  | AWS                          | Azure                              |
|--------------------------|------------------------------|------------------------------------|
| Phase 1 — Asset Inventory | AWS Config / Resource Graph  | Azure Resource Graph               |
| Phase 2 — Compliance      | Config Rules, SecurityHub    | Defender for Cloud, Policy         |
| Phase 3 — Risk Dashboard  | GuardDuty, Inspector, Macie  | Defender Alerts, Advisor, Monitor  |
| Phase 4 — CSPM            | Compute, S3, RDS, Network    | Compute, Storage, Network, KV, SQL |
| Phase 5 — Maturity        | 5-domain score               | 5-domain score                     |
| Phase 6 — Well-Architected| 6-pillar AWS WAF              | 5-pillar Azure WAF                 |

---

## 🚀 Quick Start

### 1. Install Python dependencies

```bash
cd backend
pip install -r requirements.txt
python app.py
```

### 2. Start Angular frontend

```bash
cd frontend
npm install
ng serve
```

Open http://localhost:4200

---

## 🔑 AWS Credentials

Create an IAM User or Role with:
- `ReadOnlyAccess` managed policy
- `SecurityAudit` managed policy (for Config, SecurityHub)

Provide Access Key ID and Secret Access Key in the form.

---

## 🔑 Azure Credentials (Service Principal)

### Create an App Registration

```bash
# Create service principal
az ad sp create-for-rbac --name "secops-reader" --role Reader \
  --scopes /subscriptions/<SUBSCRIPTION_ID>

# Add Security Reader role
az role assignment create \
  --assignee <APP_ID> \
  --role "Security Reader" \
  --scope /subscriptions/<SUBSCRIPTION_ID>
```

This outputs:
```json
{
  "appId":        "→ Client ID",
  "password":     "→ Client Secret",
  "tenant":       "→ Tenant ID"
}
```

Provide these three values + your Subscription ID in the Azure credentials form.

### Required Roles
| Role                | Purpose                          |
|---------------------|----------------------------------|
| Reader              | All resource enumeration         |
| Security Reader     | Defender for Cloud, assessments  |
| (Optional) Cost Management Reader | Cost & Usage data  |

---

## 🔄 Switching Clouds

Use the **AWS / Azure toggle** at the top of the left sidebar. Each cloud maintains its own:
- Saved credentials (pre-fills forms)
- Scan results per module (independently cached)
- State — switching does NOT clear results

---

## 🏗 Architecture

```
frontend/src/app/
├── app.component.ts          ← Cloud switcher + routing
├── components/
│   ├── credentials/          ← AWS credentials form
│   ├── modules/              ← AWS dashboard components (6 phases)
│   └── azure/                ← Azure dashboard components (6 phases)
└── services/api.service.ts   ← Unified HTTP client (AWS + Azure)

backend/
├── app.py                    ← Flask routes (AWS + Azure)
├── scanners/                 ← AWS scanner modules
└── azure_scanners/           ← Azure scanner modules
```
