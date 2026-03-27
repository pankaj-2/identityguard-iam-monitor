# IdentityGuard — Entra ID Threat Detection & IAM Monitoring Toolkit

## What it does

IdentityGuard ingests Microsoft Entra ID sign-in logs, user profiles, and service principal data to automatically detect identity threats such as impossible travel, over-privileged accounts, and expiring SPN secrets. It then passes the findings to Gemini 1.5 Flash, which produces a risk score and user access review (UAR) recommendations, and renders everything into a single self-contained HTML security dashboard.

## Features

- Impossible travel detection across sign-in logs
- Permanent privileged role exposure detection
- Service principal over-privilege and secret expiry audit
- GenAI-powered risk scoring and UAR recommendations (Gemini 1.5 Flash)
- Automated HTML security dashboard

## Tech stack

Python · Pandas · Google Gemini API (free tier) · Mock data matching Microsoft Graph API v1.0 schema

## Quick start

```bash
pip install -r requirements.txt
cp .env.example .env   # add your GEMINI_API_KEY
python main.py
# Report: reporting/output/report.html
```

## Architecture

```
Mock data (CSV / JSON)
        │
        ▼
collector/graph_signin_logs.py   ← generates Graph-API-shaped records
        │
        ▼
analysis/
  ├── impossible_travel.py       ← velocity / geo checks
  ├── privilege_audit.py         ← permanent admins, MFA gaps
  └── service_principal_risk.py  ← owner roles, expired secrets
        │
        ▼
analysis/genai_analyzer.py       ← Gemini 1.5 Flash scoring + UAR
        │
        ▼
reporting/risk_report.py         ← self-contained HTML dashboard
        │
        ▼
reporting/output/report.html     ← final deliverable
```

## Mock data

`USE_MOCK_DATA=True` — all data matches real Microsoft Graph API `signIn` and `user` response shapes. No Azure subscription required to run.

## Microsoft Graph API shapes used

- `GET /auditLogs/signIns`
- `GET /users?$select=assignedRoles,lastSignInDateTime`
- `GET /servicePrincipals?$select=keyCredentials,passwordCredentials`

## Sample output

```
Risk Score: 78/100 (HIGH)
Impossible travel events: 3
Privileged accounts flagged: 13
SPNs with critical issues: 6
```

