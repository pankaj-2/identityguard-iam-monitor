"""
analysis/privilege_audit.py
-----------------------------
Audits Azure AD user privilege configurations for security risks.

Detects three categories of findings:
  1. PERMANENT_GLOBAL_ADMIN  — Global Administrator without PIM-eligible flag
                               (principle of least privilege violation)
  2. NO_MFA_REGISTERED       — Any user with no MFA registered
  3. INACTIVE_PRIVILEGED     — User inactive >90 days who holds a privileged role

Privileged roles (per Microsoft's tiered model):
  - Global Administrator (highest)
  - Compliance Administrator
  - Exchange Administrator
  - Helpdesk Administrator
  - Security Reader
  - SharePoint Administrator
  - Teams Administrator

Usage (standalone):
    python -m analysis.privilege_audit
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
USERS_JSON = DATA_DIR / "users.json"

REFERENCE_DATE = datetime(2026, 3, 14, 14, 24, 19, tzinfo=timezone.utc)
INACTIVE_DAYS_THRESHOLD: int = 90

# Roles that grant elevated access and are considered privileged.
# "User" is excluded — it is the base non-privileged role.
PRIVILEGED_ROLES: frozenset[str] = frozenset(
    {
        "Global Administrator",
        "Compliance Administrator",
        "Exchange Administrator",
        "Helpdesk Administrator",
        "Security Reader",
        "SharePoint Administrator",
        "Teams Administrator",
        "Reports Reader",
        "Global Reader",
    }
)

# Roles that are considered high-privilege (above basic admin)
HIGH_PRIVILEGE_ROLES: frozenset[str] = frozenset(
    {
        "Global Administrator",
        "Compliance Administrator",
        "Exchange Administrator",
        "SharePoint Administrator",
        "Teams Administrator",
    }
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_dt(dt_str: str | None) -> datetime | None:
    """Parse an ISO-8601 datetime string into an aware datetime, or None."""
    if not dt_str:
        return None
    # Handle trailing 'Z' for UTC
    dt_str = dt_str.replace("Z", "+00:00")
    return datetime.fromisoformat(dt_str)


def _days_inactive(last_signin: datetime | None, reference: datetime) -> float | None:
    """Return days since last sign-in, or None if no sign-in on record."""
    if last_signin is None:
        return None
    delta = reference - last_signin
    return delta.total_seconds() / 86_400.0


# ---------------------------------------------------------------------------
# Detection functions
# ---------------------------------------------------------------------------

def _detect_permanent_global_admin(user: dict[str, Any]) -> dict[str, Any] | None:
    """
    Flag: Global Administrator role assigned permanently (no pimEligible flag).

    Data contract: users.json does NOT contain a 'pimEligible' field, which
    means all Global Admin assignments are treated as permanent.
    """
    roles: list[str] = user.get("assignedRoles", [])
    if "Global Administrator" not in roles:
        return None

    # If the JSON had a pimEligible field, we'd short-circuit here.
    # Absence of the field → permanent assignment.
    is_pim_eligible: bool = user.get("pimEligible", False)
    if is_pim_eligible:
        return None

    return {
        "user": user["userPrincipalName"],
        "finding_type": "PERMANENT_GLOBAL_ADMIN",
        "role": "Global Administrator",
        "severity": "HIGH",
        "recommendation": (
            "Convert permanent Global Administrator assignment to PIM (Privileged "
            "Identity Management) just-in-time activation. "
            "Require approval, MFA on activation, and set maximum activation duration "
            "to 8 hours. Assign to a dedicated break-glass account only."
        ),
    }


def _detect_no_mfa(user: dict[str, Any]) -> dict[str, Any] | None:
    """
    Flag: User has no MFA method registered.
    All users require MFA; privileged roles elevate to HIGH, others to MEDIUM.
    """
    if user.get("mfaRegistered", True):
        return None

    roles: list[str] = user.get("assignedRoles", [])
    is_privileged = any(r in HIGH_PRIVILEGE_ROLES for r in roles)
    severity = "HIGH" if is_privileged else "MEDIUM"
    primary_role = roles[0] if roles else "User"

    return {
        "user": user["userPrincipalName"],
        "finding_type": "NO_MFA_REGISTERED",
        "role": primary_role,
        "severity": severity,
        "recommendation": (
            "Enroll user in Microsoft Authenticator or FIDO2 security key immediately. "
            "Block sign-in until MFA is registered via a Conditional Access policy "
            "targeting the user. For privileged accounts, enforce phishing-resistant "
            "MFA (FIDO2 or certificate-based authentication)."
        ),
    }


def _detect_inactive_privileged(
    user: dict[str, Any], reference: datetime = REFERENCE_DATE
) -> dict[str, Any] | None:
    """
    Flag: User has a privileged role AND has been inactive for >90 days.
    Accounts idle this long are high-risk if compromised — attacker has
    a long window before detection via normal sign-in pattern analysis.
    """
    roles: list[str] = user.get("assignedRoles", [])
    privileged = [r for r in roles if r in PRIVILEGED_ROLES]
    if not privileged:
        return None

    last_signin_str: str | None = user.get("lastSignInDateTime")
    last_signin = _parse_dt(last_signin_str)
    days = _days_inactive(last_signin, reference)

    if days is None or days <= INACTIVE_DAYS_THRESHOLD:
        return None

    # Severity: HIGH_PRIVILEGE_ROLES that are inactive → HIGH; others → MEDIUM
    is_high_priv = any(r in HIGH_PRIVILEGE_ROLES for r in privileged)
    severity = "HIGH" if is_high_priv else "MEDIUM"
    primary_role = privileged[0]

    return {
        "user": user["userPrincipalName"],
        "finding_type": "INACTIVE_PRIVILEGED_USER",
        "role": primary_role,
        "severity": severity,
        "recommendation": (
            f"User has not signed in for {int(days)} days while holding {primary_role}. "
            "Disable the account or remove privileged roles immediately. "
            "Conduct an access review (Entra Identity Governance) to determine if "
            "the role is still required. If the account is a service account, "
            "rotate all associated credentials."
        ),
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run(users_path: Path = USERS_JSON) -> list[dict[str, Any]]:
    """
    Load users.json, audit each user for privilege misconfigurations,
    and return a flat list of findings.

    Args:
        users_path: Path to users JSON. Defaults to data/users.json.

    Returns:
        List of finding dicts, each with keys:
            user, finding_type, role, severity, recommendation.
    """
    with open(users_path, encoding="utf-8") as fh:
        users: list[dict[str, Any]] = json.load(fh)

    findings: list[dict[str, Any]] = []

    for user in users:
        # Run each detector; append non-None results
        for detector in (
            _detect_permanent_global_admin,
            _detect_no_mfa,
            _detect_inactive_privileged,
        ):
            result = detector(user)
            if result is not None:
                findings.append(result)

    # Sort: CRITICAL > HIGH > MEDIUM > LOW
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda f: severity_order.get(f["severity"], 99))

    return findings


# ---------------------------------------------------------------------------
# Standalone entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    results = run()
    print(json.dumps(results, indent=2))
    print(f"\n[privilege_audit] {len(results)} finding(s) detected.")
