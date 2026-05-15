# AWS Security Platform — All 5 Phases Unified

A complete AWS security management platform with 5 integrated modules and dark/light mode UI.

## Modules

| Phase | Module | Endpoint |
|-------|--------|----------|
| 1 | Asset Discovery | `POST /api/scan` |
| 2 | Compliance Checker | `POST /api/compliance/scan` |
| 3 | Risk Dashboard | `POST /api/risk/scan` |
| 4 | Manual Remediation | `POST /api/remediation/scan` |
| 5 | Auto Remediation | `POST /api/auto/scan` |

## Quick Start

### Linux/Mac
```bash
chmod +x start.sh
./start.sh
```

### Windows
```
start.bat
```

### Manual
```bash
# Terminal 1 — Backend
cd backend
pip install -r requirements.txt
python app.py          # runs on :5015

# Terminal 2 — Frontend
cd frontend
npm install
npm start              # runs on :3015
```

Open **http://localhost:3015** in your browser.

## UI Features
- **Dark / Light mode** toggle in the top-right header
- Module switcher (all 5 phases) in the header navigation
- Status bar showing scan state for each module
- Phase 5 includes policy editor, dry-run preview, and live auto-remediation
