"""
main.py
-------
IdentityGuard IAM Monitor — full pipeline entry point.

Runs all four analysis engines in sequence, then generates the HTML report.

Usage:
    python main.py
"""

from analysis.impossible_travel import run as travel_run
from analysis.privilege_audit import run as priv_run
from analysis.service_principal_risk import run as spn_run
from analysis.genai_analyzer import run as genai_run
from reporting.risk_report import generate_report
import json, os

os.makedirs("reporting/output", exist_ok=True)
os.makedirs("data", exist_ok=True)

print("[1/5] Running impossible travel detection...")
travel = travel_run()
print(f"  Found {len(travel)} events")

print("[2/5] Running privilege audit...")
privs = priv_run()
print(f"  Found {len(privs)} findings")

print("[3/5] Running SPN risk scan...")
spns = spn_run()
print(f"  Found {len(spns)} findings")

print("[4/5] Running GenAI analysis (Gemini)...")
genai = genai_run()
print(f"  Risk score: {genai['overall_risk_score']}")

print("[5/5] Generating HTML report...")
generate_report(travel, privs, spns, genai)
print("  Report: reporting/output/report.html")
print("Done.")
