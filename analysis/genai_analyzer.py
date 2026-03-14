"""
analysis/genai_analyzer.py
---------------------------
Phase 3 – GenAI Analyzer.

Orchestrates all three detection engines, packages their findings into a
compact JSON summary, and sends it to Gemini (gemini-1.5-flash) for:
  • Overall risk score (0-100)
  • Risk level (CRITICAL / HIGH / MEDIUM / LOW)
  • Top-3 threats
  • User-Access-Review decisions (APPROVE / REVOKE / REVIEW per user)
  • Executive summary (≤3 sentences)

The raw Gemini JSON response is written to data/genai_analysis.json and
also returned as a Python dict.

Usage (standalone):
    python -m analysis.genai_analyzer
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
import google.generativeai as genai

from analysis import impossible_travel, privilege_audit, service_principal_risk

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
ROOT_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT_DIR / "data"
OUTPUT_JSON = DATA_DIR / "genai_analysis.json"

# ---------------------------------------------------------------------------
# Prompt template
# ---------------------------------------------------------------------------
_PROMPT_TEMPLATE = """You are an IAM security analyst reviewing an identity \
security assessment. Analyze these findings and return \
ONLY a valid JSON object (no markdown, no explanation):
{{
  "overall_risk_score": <0-100>,
  "risk_level": "<CRITICAL|HIGH|MEDIUM|LOW>",
  "top_3_threats": ["string", "string", "string"],
  "uar_decisions": [
    {{
      "user": "<userPrincipalName>",
      "decision": "<APPROVE|REVOKE|REVIEW>",
      "justification": "<one sentence>"
    }}
  ],
  "executive_summary": "<3 sentences max>"
}}

Findings:
{findings_json}
"""


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _collect_findings() -> dict[str, Any]:
    """
    Call all three detection engines and return a structured summary dict.

    Each engine's output is stored under its own key so Gemini sees
    clearly which detection category produced which findings.
    """
    travel_findings: list[dict[str, Any]] = impossible_travel.run()
    privilege_findings: list[dict[str, Any]] = privilege_audit.run()
    spn_findings: list[dict[str, Any]] = service_principal_risk.run()

    return {
        "impossible_travel": {
            "count": len(travel_findings),
            "findings": travel_findings,
        },
        "privilege_audit": {
            "count": len(privilege_findings),
            "findings": privilege_findings,
        },
        "service_principal_risk": {
            "count": len(spn_findings),
            "findings": spn_findings,
        },
        "metadata": {
            "total_findings": (
                len(travel_findings) + len(privilege_findings) + len(spn_findings)
            ),
            "severity_counts": _count_severities(
                travel_findings + privilege_findings + spn_findings
            ),
        },
    }


def _count_severities(findings: list[dict[str, Any]]) -> dict[str, int]:
    """Return a dict of severity → count across all combined findings."""
    counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for finding in findings:
        sev = finding.get("severity", "LOW")
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _call_gemini(findings_summary: dict[str, Any]) -> dict[str, Any]:
    """
    Send the findings summary to Gemini gemini-1.5-flash and return parsed JSON.

    Applies a 4-second sleep before the API call to respect the free-tier
    rate limit (15 RPM on the free tier).

    Returns the parsed dict on success, or a fallback error dict on failure.
    """
    findings_json = json.dumps(findings_summary, indent=2)
    prompt = _PROMPT_TEMPLATE.format(findings_json=findings_json)

    print("[genai_analyzer] Sleeping 4 s (free-tier rate-limit guard)…")
    time.sleep(4)

    print("[genai_analyzer] Calling Gemini API…")
    model = genai.GenerativeModel("gemini-1.5-flash")
    response = model.generate_content(prompt)

    raw_text: str = response.text.strip()

    # Gemini sometimes wraps the JSON in markdown fences — strip them.
    if raw_text.startswith("```"):
        lines = raw_text.splitlines()
        # Drop the opening fence line (e.g. "```json") and closing fence.
        inner_lines = [
            line for line in lines[1:]
            if not line.strip().startswith("```")
        ]
        raw_text = "\n".join(inner_lines).strip()

    try:
        parsed: dict[str, Any] = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        print(f"[genai_analyzer] WARNING: Could not parse Gemini response as JSON: {exc}")
        print(f"[genai_analyzer] Raw response:\n{raw_text}")
        parsed = {
            "error": "JSON parse failure",
            "raw_response": raw_text,
            "overall_risk_score": -1,
            "risk_level": "UNKNOWN",
            "top_3_threats": [],
            "uar_decisions": [],
            "executive_summary": "Gemini response could not be parsed.",
        }

    return parsed


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run() -> dict[str, Any]:
    """
    Full Phase 3 pipeline:
      1. Load GEMINI_API_KEY from .env
      2. Collect findings from all three detection engines
      3. Call Gemini for AI-powered risk analysis
      4. Persist result to data/genai_analysis.json
      5. Return parsed result dict

    Returns:
        Dict containing Gemini's risk assessment (overall_risk_score,
        risk_level, top_3_threats, uar_decisions, executive_summary).
    """
    # --- 1. Load API key -------------------------------------------------------
    env_path = ROOT_DIR / ".env"
    load_dotenv(dotenv_path=env_path, override=True)

    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise EnvironmentError(
            f"GEMINI_API_KEY not found. "
            f"Add it to {env_path} as: GEMINI_API_KEY=<your-key>"
        )

    genai.configure(api_key=api_key)
    key_tail: str = api_key[-6:] if isinstance(api_key, str) else "??????"
    print(f"[genai_analyzer] API key loaded (…{key_tail})")

    # --- 2. Collect findings ---------------------------------------------------
    print("[genai_analyzer] Running detection engines…")
    findings_summary = _collect_findings()
    total = findings_summary["metadata"]["total_findings"]
    print(f"[genai_analyzer] Collected {total} total finding(s).")

    # --- 3. Call Gemini ---------------------------------------------------------
    result: dict[str, Any]
    try:
        result = _call_gemini(findings_summary)
    except Exception as exc:  # noqa: BLE001
        print(f"[genai_analyzer] ERROR calling Gemini: {exc}")
        result = {
            "error": str(exc),
            "overall_risk_score": -1,
            "risk_level": "UNKNOWN",
            "top_3_threats": [],
            "uar_decisions": [],
            "executive_summary": f"Gemini API call failed: {exc}",
        }

    # --- 4. Persist to disk ----------------------------------------------------
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_JSON, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)
    print(f"[genai_analyzer] Result written to {OUTPUT_JSON}")

    # --- 5. Return ----------------------------------------------------------------
    return result


# ---------------------------------------------------------------------------
# Standalone entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    result = run()
    print(json.dumps(result, indent=2))
