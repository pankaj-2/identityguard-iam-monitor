# Project State

## Completed phases
- [x] Phase 1: Folder structure + mock data

## Phase 1 deliverables
| File | Status | Notes |
|---|---|---|
| `collector/__init__.py` | ✅ Created | empty package marker |
| `collector/graph_signin_logs.py` | ✅ Created | mock data generator |
| `analysis/__init__.py` | ✅ Created | empty package marker |
| `analysis/impossible_travel.py` | ✅ Created | stub — Phase 2 |
| `analysis/privilege_audit.py` | ✅ Created | stub — Phase 2 |
| `analysis/service_principal_risk.py` | ✅ Created | stub — Phase 2 |
| `analysis/genai_analyzer.py` | ✅ Created | stub — Phase 2 |
| `reporting/__init__.py` | ✅ Created | empty package marker |
| `reporting/risk_report.py` | ✅ Created | stub — Phase 2 |
| `data/sample_logs.csv` | ✅ Generated | 80 rows (run generator) |
| `data/users.json` | ✅ Generated | 80 users |
| `data/spns.json` | ✅ Generated | 30 SPNs |
| `config.py` | ✅ Created | USE_MOCK_DATA etc. |
| `main.py` | ✅ Created | stub — Phase 2 |
| `requirements.txt` | ✅ Created | |
| `PROJECT_STATE.md` | ✅ Created | this file |

## Mock data anomaly audit
| Anomaly | Required | Implemented |
|---|---|---|
| Total sign-in rows | 80 | 80 |
| Impossible travel pairs | 3 | 3 (IN→US, DE→BR, JP→GB) |
| High-risk users | 5 | 5 |
| Medium-risk users | 10 | 10 |
| Failed logins (errorCode ≠ 0) | 15 | 15 |
| Total users | 80 | 80 |
| Global Administrator (permanent) | 5 | 5 |
| No MFA registered | 8 | 8 |
| Inactive >90 days | 12 | 12 |
| Total SPNs | 30 | 30 |
| Owner-role SPNs | 6 | 6 |
| Expired secrets | 8 | 8 |
| Unused SPNs (>180d / null) | 5 | 5 |

## Completed phases (continued)
- [x] Phase 2: Analysis engines — impossible travel, privilege audit, SPN risk
- [x] Phase 3: GenAI analyzer — Gemini gemini-1.5-flash integration, genai_analysis.json output

## Phase 3 deliverables
| File | Status | Notes |
|---|---|---|
| `analysis/genai_analyzer.py` | ✅ Created | Full implementation |
| `data/genai_analysis.json` | ✅ Generated at runtime | Written by `run()` |
| `.env` | ✅ Fixed | Corrected from shell `echo` to plain `KEY=VALUE` |

## Upcoming phases
- [ ] Phase 4: HTML report (`reporting/risk_report.py`)
- [ ] Phase 5: Integration tests + README

## How to regenerate mock data
```bash
cd identityguard-iam-monitor
python -m collector.graph_signin_logs
```
