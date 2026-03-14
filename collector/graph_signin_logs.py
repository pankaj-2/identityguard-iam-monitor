"""
collector/graph_signin_logs.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Mock data generator that mimics the Microsoft Graph API response shapes for:
  - signIn logs   → data/sample_logs.csv
  - users         → data/users.json
  - servicePrincipals → data/spns.json

Run standalone:  python -m collector.graph_signin_logs
"""

from __future__ import annotations

import csv
import json
import os
import random
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Reproducible seed so the same file is generated on every run
# ---------------------------------------------------------------------------
random.seed(42)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

SIGN_IN_CSV = DATA_DIR / "sample_logs.csv"
USERS_JSON = DATA_DIR / "users.json"
SPNS_JSON = DATA_DIR / "spns.json"

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
NOW = datetime(2026, 3, 14, 8, 0, 0, tzinfo=timezone.utc)

COUNTRIES = [
    "US", "IN", "GB", "DE", "FR", "AU", "CA", "JP", "BR", "SG",
    "NL", "SE", "NO", "CH", "AE", "ZA", "MX", "IT", "ES", "KR",
]

CITIES_BY_COUNTRY: dict[str, list[str]] = {
    "US": ["New York", "Austin", "Chicago", "Seattle", "Los Angeles"],
    "IN": ["Mumbai", "Bengaluru", "Delhi", "Hyderabad", "Chennai"],
    "GB": ["London", "Manchester", "Birmingham", "Edinburgh", "Leeds"],
    "DE": ["Berlin", "Munich", "Frankfurt", "Hamburg", "Cologne"],
    "FR": ["Paris", "Lyon", "Marseille", "Nice", "Toulouse"],
    "AU": ["Sydney", "Melbourne", "Brisbane", "Perth", "Adelaide"],
    "CA": ["Toronto", "Vancouver", "Montreal", "Ottawa", "Calgary"],
    "JP": ["Tokyo", "Osaka", "Kyoto", "Yokohama", "Nagoya"],
    "BR": ["São Paulo", "Rio de Janeiro", "Brasília", "Salvador", "Curitiba"],
    "SG": ["Singapore"],
    "NL": ["Amsterdam", "Rotterdam", "The Hague"],
    "SE": ["Stockholm", "Gothenburg", "Malmö"],
    "NO": ["Oslo", "Bergen", "Trondheim"],
    "CH": ["Zurich", "Geneva", "Basel"],
    "AE": ["Dubai", "Abu Dhabi"],
    "ZA": ["Cape Town", "Johannesburg", "Pretoria"],
    "MX": ["Mexico City", "Guadalajara", "Monterrey"],
    "IT": ["Rome", "Milan", "Naples", "Florence"],
    "ES": ["Madrid", "Barcelona", "Valencia", "Seville"],
    "KR": ["Seoul", "Busan", "Incheon"],
}

CLIENT_APPS = [
    "Browser",
    "Mobile Apps and Desktop clients",
    "Exchange ActiveSync",
    "SMTP",
    "Other clients",
]

ROLES = [
    "User",
    "Helpdesk Administrator",
    "Security Reader",
    "Reports Reader",
    "Global Reader",
    "Teams Administrator",
    "Exchange Administrator",
    "Compliance Administrator",
    "SharePoint Administrator",
]

RISK_LEVELS = ["none", "low", "medium", "high"]
RISK_STATES = ["none", "atRisk", "confirmedCompromised", "dismissed", "remediated"]

ERROR_CODES = {
    0: "Success",
    50126: "Invalid username or password",
    50074: "User did not satisfy MFA requirement",
    53003: "Blocked by Conditional Access",
    90095: "Admin consent required",
    65001: "User or admin has not consented to use the app",
}

FIRST_NAMES = [
    "Arjun", "Priya", "Rahul", "Neha", "Vikram", "Ananya", "Suresh",
    "Deepa", "Rohan", "Kavya", "James", "Emily", "Michael", "Sarah",
    "David", "Jessica", "Robert", "Ashley", "William", "Amanda",
    "Carlos", "Sofia", "Miguel", "Isabella", "Lucas", "Valentina",
    "Yuki", "Sakura", "Kenji", "Aiko", "Lars", "Ingrid", "Erik",
    "Astrid", "Lukas", "Hannah", "Maximilian", "Lena", "Felix",
    "Emma", "Pierre", "Marie", "Antoine", "Camille", "Nicolas",
    "Oliver", "Charlotte", "Harry", "Amelia", "George", "Olivia",
    "Rajan", "Sunita", "Mohan", "Geeta", "Sanjay", "Rekha",
    "Ahmed", "Fatima", "Omar", "Layla", "Hassan", "Nour",
    "Chen", "Wei", "Jing", "Ming", "Hui", "Fang",
    "Raj", "Meera", "Ajay", "Pooja", "Nikhil", "Divya",
    "Akira", "Hana", "Ryo", "Yuna", "Sota", "Miu",
]

LAST_NAMES = [
    "Sharma", "Patel", "Kumar", "Singh", "Reddy", "Nair", "Menon",
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia",
    "Martinez", "Davis", "Miller", "Wilson", "Moore", "Taylor",
    "Anderson", "Thomas", "Jackson", "White", "Harris", "Martin",
    "Lee", "Thompson", "Young", "Allen", "Walker", "Hall",
    "Muller", "Schmidt", "Schneider", "Fischer", "Weber", "Meyer",
    "Tanaka", "Sato", "Suzuki", "Yamamoto", "Watanabe", "Ito",
    "Dupont", "Bernard", "Moreau", "Laurent", "Simon", "Michel",
    "Cohen", "Levy", "Dubois", "Fontaine", "Leroy", "Girard",
    "Santos", "Oliveira", "Souza", "Lima", "Costa", "Pereira",
    "Al-Rashid", "Hassan", "Ibrahim", "Mohammed", "Abdullah",
    "Nguyen", "Tran", "Le", "Pham", "Hoang",
]

SPN_NAMES = [
    "AzureDevOpsServicePrincipal", "BackupAutomationApp", "ComplianceScannerSP",
    "DataPipelineOrchestrator", "EmailRelayConnector", "FinanceReportingApp",
    "GitHubActionsDeployer", "HRSystemIntegration", "IdentityGovernanceSP",
    "JiraCloudConnector", "KeyVaultAccessor", "LogAnalyticsCollector",
    "MonitoringAgentSP", "NightlyBatchProcessor", "OnboardingAutomation",
    "PowerBIDatasetRefresher", "QuarantineManagerSP", "ReportingServiceSP",
    "SecurityAuditAutomation", "TeamsNotificationBot",
    "UserProvisioningService", "VaultSecretsReader", "WebhookRelayApp",
    "XeroFinanceConnector", "YammerIntegrationSP", "ZendeskSyncService",
    "AlertOrchestrationSP", "BackupVerificationApp", "CertRenewalBot",
    "DisasterRecoveryAgent",
]

SPN_APP_ROLES = [
    "Owner", "Contributor", "Reader",
    "Application.ReadWrite.All", "Directory.ReadWrite.All",
    "Mail.Send", "Files.ReadWrite.All", "User.Read.All",
    "Device.ReadWrite.All", "Policy.ReadWrite.ConditionalAccess",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _uuid() -> str:
    return str(uuid.uuid4())


def _random_name() -> tuple[str, str]:
    first = random.choice(FIRST_NAMES)
    last = random.choice(LAST_NAMES)
    return first, last


def _upn(first: str, last: str, domain: str = "contoso.com") -> str:
    return f"{first.lower()}.{last.lower()}@{domain}"


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _random_past(max_days: int = 30) -> datetime:
    delta = timedelta(
        days=random.randint(0, max_days),
        hours=random.randint(0, 23),
        minutes=random.randint(0, 59),
        seconds=random.randint(0, 59),
    )
    return NOW - delta


def _ip() -> str:
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


def _country() -> str:
    return random.choice(COUNTRIES)


def _city(country: str) -> str:
    cities = CITIES_BY_COUNTRY.get(country, ["Unknown"])
    return random.choice(cities)


def _future_date(min_days: int = 30, max_days: int = 730) -> datetime:
    return NOW + timedelta(days=random.randint(min_days, max_days))


def _past_date(min_days: int = 1, max_days: int = 500) -> datetime:
    return NOW - timedelta(days=random.randint(min_days, max_days))


# ---------------------------------------------------------------------------
# Generate sign-in log rows
# ---------------------------------------------------------------------------

def _build_signin_row(
    user_id: str,
    upn: str,
    display_name: str,
    country: str | None = None,
    created_dt: datetime | None = None,
    risk_level: str = "none",
    risk_state: str = "none",
    error_code: int = 0,
) -> dict[str, Any]:
    cc = country or _country()
    city = _city(cc)
    dt = created_dt or _random_past(30)
    return {
        "id": _uuid(),
        "userPrincipalName": upn,
        "displayName": display_name,
        "ipAddress": _ip(),
        "location_city": city,
        "location_countryOrRegion": cc,
        "createdDateTime": _iso(dt),
        "riskLevel": risk_level,
        "riskState": risk_state,
        "clientAppUsed": random.choice(CLIENT_APPS),
        "status_errorCode": error_code,
    }


def generate_signin_logs(users: list[dict]) -> list[dict[str, Any]]:
    """
    Build exactly 80 sign-in rows with the required anomaly distribution.

    Anomaly budget
    --------------
    - 3  impossible-travel pairs  → 6 rows with special timestamps
    - 5  high-risk users          → 5 rows
    - 10 medium-risk users        → 10 rows
    - 15 failed logins            → spread across remaining rows
    - Rest are normal successful logins

    Total = 80 rows.
    """
    rows: list[dict] = []

    upns = [u["userPrincipalName"] for u in users]
    display_names = {u["userPrincipalName"]: u["displayName"] for u in users}

    used_indices: set[int] = set()

    # Helper to pick a fresh user index
    def pick_user(exclude: set[int] | None = None) -> int:
        pool = [i for i in range(len(upns)) if i not in (exclude or set())]
        idx = random.choice(pool)
        used_indices.add(idx)
        return idx

    # --- 3 impossible-travel pairs -------------------------------------------
    impossible_pairs: list[tuple[str, str]] = []  # (country_a, country_b)
    it_country_pairs = [("IN", "US"), ("DE", "BR"), ("JP", "GB")]
    for (ca, cb) in it_country_pairs:
        idx = pick_user()
        upn = upns[idx]
        dname = display_names[upn]
        base_time = _random_past(25)
        # First login
        rows.append(_build_signin_row(upn, upn, dname, country=ca, created_dt=base_time))
        # Second login: same user, 8–14 min later, different country
        later = base_time + timedelta(minutes=random.randint(8, 14))
        rows.append(_build_signin_row(upn, upn, dname, country=cb, created_dt=later))
        impossible_pairs.append((ca, cb))

    # --- 5 high-risk users ----------------------------------------------------
    high_risk_indices = set()
    for _ in range(5):
        idx = pick_user(exclude=high_risk_indices)
        high_risk_indices.add(idx)
        upn = upns[idx]
        dname = display_names[upn]
        state = random.choice(["atRisk", "confirmedCompromised"])
        rows.append(_build_signin_row(upn, upn, dname, risk_level="high", risk_state=state))

    # --- 10 medium-risk users -------------------------------------------------
    med_risk_indices = set()
    for _ in range(10):
        idx = pick_user(exclude=high_risk_indices | med_risk_indices)
        med_risk_indices.add(idx)
        upn = upns[idx]
        dname = display_names[upn]
        rows.append(
            _build_signin_row(upn, upn, dname, risk_level="medium", risk_state="atRisk")
        )

    # --- 15 failed logins (spread across remaining budget) --------------------
    fail_codes = [c for c in ERROR_CODES if c != 0]
    rows_so_far = len(rows)                  # 6 + 5 + 10 = 21
    remaining_slots = 80 - rows_so_far       # 59
    fail_count = 15
    normal_count = remaining_slots - fail_count  # 44

    # Normal rows
    for _ in range(normal_count):
        idx = random.randint(0, len(upns) - 1)
        upn = upns[idx]
        dname = display_names[upn]
        rows.append(_build_signin_row(upn, upn, dname))

    # Failed rows
    for _ in range(fail_count):
        idx = random.randint(0, len(upns) - 1)
        upn = upns[idx]
        dname = display_names[upn]
        rows.append(
            _build_signin_row(upn, upn, dname, error_code=random.choice(fail_codes))
        )

    random.shuffle(rows)
    return rows


def write_signin_csv(rows: list[dict]) -> None:
    fieldnames = [
        "id", "userPrincipalName", "displayName",
        "ipAddress", "location_city", "location_countryOrRegion",
        "createdDateTime", "riskLevel", "riskState",
        "clientAppUsed", "status_errorCode",
    ]
    with open(SIGN_IN_CSV, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    print(f"[mock] Written {len(rows)} sign-in rows → {SIGN_IN_CSV}")


# ---------------------------------------------------------------------------
# Generate users
# ---------------------------------------------------------------------------

def generate_users() -> list[dict[str, Any]]:
    """
    80 users with:
    - 5  Global Administrator (permanent)
    - 8  no MFA registered
    - 12 inactive >90 days
    """
    users: list[dict] = []

    # Assign role buckets
    global_admin_slots = set(random.sample(range(80), 5))
    no_mfa_slots = set(random.sample(range(80), 8))
    inactive_slots = set(random.sample(range(80), 12))

    for i in range(80):
        first, last = _random_name()
        upn = _upn(first, last)
        display = f"{first} {last}"

        # Role
        if i in global_admin_slots:
            roles = ["Global Administrator"]
        else:
            roles = [random.choice(ROLES)]

        # Last sign-in
        if i in inactive_slots:
            last_signin = _iso(NOW - timedelta(days=random.randint(91, 365)))
        else:
            last_signin = _iso(_random_past(30))

        # MFA
        mfa = i not in no_mfa_slots

        users.append({
            "id": _uuid(),
            "displayName": display,
            "userPrincipalName": upn,
            "assignedRoles": roles,
            "lastSignInDateTime": last_signin,
            "accountEnabled": random.random() > 0.05,  # ~95 % enabled
            "mfaRegistered": mfa,
        })

    return users


def write_users_json(users: list[dict]) -> None:
    with open(USERS_JSON, "w", encoding="utf-8") as fh:
        json.dump(users, fh, indent=2)
    print(f"[mock] Written {len(users)} users → {USERS_JSON}")


# ---------------------------------------------------------------------------
# Generate service principals
# ---------------------------------------------------------------------------

def _key_credential(expired: bool = False) -> dict:
    if expired:
        end = _past_date(1, 365)
    else:
        end = _future_date(30, 730)
    return {"endDateTime": _iso(end), "type": "AsymmetricX509Cert"}


def _password_credential(expired: bool = False) -> dict:
    if expired:
        end = _past_date(1, 365)
    else:
        end = _future_date(30, 730)
    return {"endDateTime": _iso(end)}


def generate_spns() -> list[dict[str, Any]]:
    """
    30 SPNs with:
    - 6  Owner role
    - 8  expired secrets (passwordCredentials endDateTime in past)
    - 5  unused (lastSignInDateTime null or >180 days ago)
    """
    owner_slots = set(random.sample(range(30), 6))
    expired_slots = set(random.sample(range(30), 8))
    unused_slots = set(random.sample(range(30), 5))

    spns: list[dict] = []
    for i, name in enumerate(SPN_NAMES):
        role = "Owner" if i in owner_slots else random.choice(SPN_APP_ROLES[1:])

        # keyCredentials (cert — always a couple, not marked expired here)
        key_creds = [_key_credential(expired=False)]

        # passwordCredentials — expired if in expired_slots
        is_expired = i in expired_slots
        pwd_creds = [_password_credential(expired=is_expired)]

        # lastSignInDateTime — null or stale if unused
        if i in unused_slots:
            if random.random() < 0.4:
                last_signin = None
            else:
                last_signin = _iso(NOW - timedelta(days=random.randint(181, 540)))
        else:
            last_signin = _iso(_random_past(60))

        spns.append({
            "id": _uuid(),
            "displayName": name,
            "appRoles": [role],
            "keyCredentials": key_creds,
            "passwordCredentials": pwd_creds,
            "lastSignInDateTime": last_signin,
        })

    return spns


def write_spns_json(spns: list[dict]) -> None:
    with open(SPNS_JSON, "w", encoding="utf-8") as fh:
        json.dump(spns, fh, indent=2)
    print(f"[mock] Written {len(spns)} service principals → {SPNS_JSON}")


# ---------------------------------------------------------------------------
# Public API — called by main.py or can be run standalone
# ---------------------------------------------------------------------------

def generate_all_mock_data() -> dict[str, Any]:
    """Generate all mock data files and return in-memory dicts."""
    users = generate_users()
    write_users_json(users)

    signin_rows = generate_signin_logs(users)
    write_signin_csv(signin_rows)

    spns = generate_spns()
    write_spns_json(spns)

    return {"users": users, "signin_logs": signin_rows, "spns": spns}


# ---------------------------------------------------------------------------
# Standalone entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    generate_all_mock_data()
    print("[mock] Phase 1 mock data generation complete.")
