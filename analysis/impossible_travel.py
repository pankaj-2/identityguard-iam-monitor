"""
analysis/impossible_travel.py
-------------------------------
Detects impossible travel events in Azure AD sign-in logs.

Impossible travel: two sign-ins for the same user within 15 minutes
from different countries/regions — physically impossible unless
credentials are compromised or shared.

Usage (standalone):
    python -m analysis.impossible_travel
"""

from __future__ import annotations

import json
import os
from itertools import combinations
from pathlib import Path
from typing import Any

import pandas as pd

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DATA_DIR = Path(__file__).resolve().parent.parent / "data"
SAMPLE_LOGS_CSV = DATA_DIR / "sample_logs.csv"

WINDOW_MINUTES: int = 15  # flag pairs closer than this


# ---------------------------------------------------------------------------
# Core detection logic
# ---------------------------------------------------------------------------

def _load_logs(csv_path: Path = SAMPLE_LOGS_CSV) -> pd.DataFrame:
    """Load sign-in CSV and parse & sort timestamps."""
    df = pd.read_csv(csv_path, parse_dates=["createdDateTime"])
    df.sort_values(["userPrincipalName", "createdDateTime"], inplace=True)
    df.reset_index(drop=True, inplace=True)
    return df


def _detect_impossible_pairs(df: pd.DataFrame, window_minutes: int = WINDOW_MINUTES) -> list[dict[str, Any]]:
    """
    For each user with ≥2 logins: compare every pair of sign-ins.
    Flag pairs where:
      - time delta ≤ window_minutes, AND
      - countries differ.

    Returns a list of finding dicts (one per flagged pair).
    """
    findings: list[dict[str, Any]] = []

    for user, group in df.groupby("userPrincipalName"):
        # Need at least two rows to compare
        if len(group) < 2:
            continue

        rows = group.to_dict("records")

        for row_a, row_b in combinations(rows, 2):
            t_a: pd.Timestamp = row_a["createdDateTime"]
            t_b: pd.Timestamp = row_b["createdDateTime"]
            country_a: str = str(row_a["location_countryOrRegion"])
            country_b: str = str(row_b["location_countryOrRegion"])

            # Ensure chronological order
            if t_a > t_b:
                t_a, t_b = t_b, t_a
                row_a, row_b = row_b, row_a
                country_a, country_b = country_b, country_a

            delta_minutes: float = (t_b - t_a).total_seconds() / 60.0

            if delta_minutes <= window_minutes and country_a != country_b:
                findings.append(
                    {
                        "user": user,
                        "login1_time": t_a.isoformat(),
                        "login1_country": country_a,
                        "login2_time": t_b.isoformat(),
                        "login2_country": country_b,
                        "minutes_apart": round(delta_minutes, 2),
                        "severity": "CRITICAL",
                    }
                )

    # Sort by how close together the logins are (most suspicious first)
    findings.sort(key=lambda f: f["minutes_apart"])
    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run(csv_path: Path = SAMPLE_LOGS_CSV) -> list[dict[str, Any]]:
    """
    Load sign-in data, detect impossible travel, and return findings.

    Args:
        csv_path: Path to the sign-in logs CSV. Defaults to data/sample_logs.csv.

    Returns:
        List of finding dicts, each with keys:
            user, login1_time, login1_country, login2_time,
            login2_country, minutes_apart, severity.
    """
    df = _load_logs(csv_path)
    return _detect_impossible_pairs(df)


# ---------------------------------------------------------------------------
# Standalone entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    results = run()
    print(json.dumps(results, indent=2))
    print(f"\n[impossible_travel] {len(results)} finding(s) detected.")
