"""
analysis/service_principal_risk.py
------------------------------------
Audits Azure AD Service Principals (SPNs) for security risks.

Detects four risk categories:
  1. OWNER_ROLE              — SPN has Owner role → CRITICAL
                               (Owner can manage all resources in the subscription)
  2. EXPIRED_SECRET          — Password/client secret is expired → HIGH
                               (stale credential, may indicate poor lifecycle mgmt)
  3. SECRET_EXPIRING_SOON    — Secret expires within 30 days → MEDIUM
                               (proactive: rotate before it breaks or gets abused)
  4. UNUSED_SPN              — Last sign-in null or >180 days ago → MEDIUM
                               (attack surface: dormant app with valid credentials)

Usage (standalone):
    python -m analysis.service_principal_risk
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DATA_DIR = Path(__file__).resolve().parent.parent / "data"
SPNS_JSON = DATA_DIR / "spns.json"

# Use the known reference date to keep results deterministic with mock data
REFERENCE_DATE = datetime(2026, 3, 14, 14, 24, 19, tzinfo=timezone.utc)

EXPIRY_WARN_DAYS: int = 30      # warn if secret expires within this many days
UNUSED_DAYS_THRESHOLD: int = 180  # flag SPN as unused after this many days


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_dt(dt_str: str | None) -> datetime | None:
    """Parse ISO-8601 datetime string → aware datetime, or None."""
    if not dt_str:
        return None
    return datetime.fromisoformat(dt_str.replace("Z", "+00:00"))


def _days_from_now(future_dt: datetime, reference: datetime) -> float:
    """Return days until future_dt. Negative = already expired."""
    return (future_dt - reference).total_seconds() / 86_400.0


def _days_since(past_dt: datetime, reference: datetime) -> float:
    """Return days since past_dt."""
    return (reference - past_dt).total_seconds() / 86_400.0


def _all_credential_end_dates(spn: dict[str, Any]) -> list[datetime]:
    """
    Collect all credential expiry dates (password + key credentials).
    Returns a flat list of aware datetime objects.
    """
    dates: list[datetime] = []

    for cred in spn.get("passwordCredentials", []):
        dt = _parse_dt(cred.get("endDateTime"))
        if dt:
            dates.append(dt)

    for cred in spn.get("keyCredentials", []):
        dt = _parse_dt(cred.get("endDateTime"))
        if dt:
            dates.append(dt)

    return dates


# ---------------------------------------------------------------------------
# Detection functions — one per risk category
# ---------------------------------------------------------------------------

def _detect_owner_role(spn: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Flag: SPN holds 'Owner' role.
    Owner grants full control over Azure subscription resources —
    no SPN should routinely hold this.
    """
    if "Owner" not in spn.get("appRoles", []):
        return []

    return [
        {
            "spn_name": spn["displayName"],
            "finding_type": "OWNER_ROLE",
            "severity": "CRITICAL",
            "detail": (
                f"Service principal '{spn['displayName']}' has the 'Owner' role, "
                "granting full resource management rights over the subscription."
            ),
            "recommendation": (
                "Replace 'Owner' with the least-privilege role needed (e.g., Contributor, "
                "or a custom role scoped to specific resource groups). "
                "Conduct an immediate access review and audit recent activity. "
                "Rotate all associated credentials and enable Defender for Cloud alerts."
            ),
        }
    ]


def _detect_expired_secrets(
    spn: dict[str, Any], reference: datetime = REFERENCE_DATE
) -> list[dict[str, Any]]:
    """
    Flag: one or more password credentials are expired.
    Expired secrets indicate poor lifecycle management and may leave
    orphaned credentials that an attacker could enumerate.
    """
    findings: list[dict[str, Any]] = []

    for cred in spn.get("passwordCredentials", []):
        end_dt = _parse_dt(cred.get("endDateTime"))
        if end_dt is None:
            continue
        if end_dt < reference:
            days_ago = int(_days_since(end_dt, reference))
            findings.append(
                {
                    "spn_name": spn["displayName"],
                    "finding_type": "EXPIRED_SECRET",
                    "severity": "HIGH",
                    "detail": (
                        f"Service principal '{spn['displayName']}' has a client secret "
                        f"that expired {days_ago} day(s) ago "
                        f"(expired: {end_dt.date().isoformat()})."
                    ),
                    "recommendation": (
                        "Delete the expired credential immediately and generate a new "
                        "secret with a maximum lifetime of 12 months. "
                        "Store the new secret in Azure Key Vault and rotate on a "
                        "regular schedule. Enable certificate-based auth where possible."
                    ),
                }
            )

    return findings


def _detect_secrets_expiring_soon(
    spn: dict[str, Any], reference: datetime = REFERENCE_DATE
) -> list[dict[str, Any]]:
    """
    Flag: one or more password credentials expire within EXPIRY_WARN_DAYS.
    Proactive warning to rotate before the secret expires (avoiding outages
    or attackers exploiting a last-minute emergency rotation window).
    """
    findings: list[dict[str, Any]] = []

    for cred in spn.get("passwordCredentials", []):
        end_dt = _parse_dt(cred.get("endDateTime"))
        if end_dt is None:
            continue
        days_left = _days_from_now(end_dt, reference)
        if 0 <= days_left <= EXPIRY_WARN_DAYS:
            findings.append(
                {
                    "spn_name": spn["displayName"],
                    "finding_type": "SECRET_EXPIRING_SOON",
                    "severity": "MEDIUM",
                    "detail": (
                        f"Service principal '{spn['displayName']}' has a client secret "
                        f"expiring in {int(days_left)} day(s) "
                        f"(expires: {end_dt.date().isoformat()})."
                    ),
                    "recommendation": (
                        f"Rotate the client secret before {end_dt.date().isoformat()}. "
                        "Use Azure Key Vault with automatic secret rotation where "
                        "possible. Consider migrating to certificate-based auth or "
                        "managed identity to eliminate manual rotation."
                    ),
                }
            )

    return findings


def _detect_unused_spn(
    spn: dict[str, Any], reference: datetime = REFERENCE_DATE
) -> list[dict[str, Any]]:
    """
    Flag: SPN has never signed in (null lastSignInDateTime) or has not 
    signed in for >UNUSED_DAYS_THRESHOLD days.
    Dormant SPNs with valid credentials are a significant attack surface.
    """
    last_signin_str: str | None = spn.get("lastSignInDateTime")
    last_signin = _parse_dt(last_signin_str)

    if last_signin is None:
        detail = (
            f"Service principal '{spn['displayName']}' has no recorded sign-in activity "
            "(lastSignInDateTime is null). It may be an abandoned application."
        )
        days_label = "never used"
    else:
        days_idle = _days_since(last_signin, reference)
        if days_idle <= UNUSED_DAYS_THRESHOLD:
            return []
        detail = (
            f"Service principal '{spn['displayName']}' has not signed in for "
            f"{int(days_idle)} day(s) (last seen: {last_signin.date().isoformat()})."
        )
        days_label = f"{int(days_idle)} days idle"

    return [
        {
            "spn_name": spn["displayName"],
            "finding_type": "UNUSED_SPN",
            "severity": "MEDIUM",
            "detail": detail,
            "recommendation": (
                f"Investigate whether '{spn['displayName']}' is still required ({days_label}). "
                "If the application is decommissioned, delete the SPN and revoke all "
                "associated credentials. If it is still needed, document its purpose and "
                "reset credentials to ensure only authorised parties hold them."
            ),
        }
    ]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run(spns_path: Path = SPNS_JSON) -> list[dict[str, Any]]:
    """
    Load spns.json, audit each SPN for security risks, and return findings.

    Args:
        spns_path: Path to SPNs JSON. Defaults to data/spns.json.

    Returns:
        List of finding dicts, each with keys:
            spn_name, finding_type, severity, detail, recommendation.
    """
    with open(spns_path, encoding="utf-8") as fh:
        spns: list[dict[str, Any]] = json.load(fh)

    findings: list[dict[str, Any]] = []

    for spn in spns:
        findings.extend(_detect_owner_role(spn))
        findings.extend(_detect_expired_secrets(spn))
        findings.extend(_detect_secrets_expiring_soon(spn))
        findings.extend(_detect_unused_spn(spn))

    # Sort by severity: CRITICAL → HIGH → MEDIUM → LOW
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda f: severity_order.get(f["severity"], 99))

    return findings


# ---------------------------------------------------------------------------
# Standalone entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    results = run()
    print(json.dumps(results, indent=2))
    print(f"\n[service_principal_risk] {len(results)} finding(s) detected.")
