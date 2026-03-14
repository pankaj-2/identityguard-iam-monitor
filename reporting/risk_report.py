"""
reporting/risk_report.py
-------------------------
Phase 4 – HTML Report Generator.

Consumes the outputs of all four analysis engines and renders a single
self-contained HTML file at reporting/output/report.html.

All CSS is inline; the file has zero external dependencies.

Public API:
    generate_report(travel, privs, spns, genai) -> None
"""

from __future__ import annotations

import html
import itertools
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
ROOT_DIR = Path(__file__).resolve().parent.parent
OUTPUT_DIR = ROOT_DIR / "reporting" / "output"
OUTPUT_HTML = OUTPUT_DIR / "report.html"


# ---------------------------------------------------------------------------
# Colour helpers
# ---------------------------------------------------------------------------

def _risk_banner_style(score: int | float) -> tuple[str, str]:
    """Return (background colour, text colour) for the risk score banner."""
    if score > 70:
        return "#c0392b", "#ffffff"   # red
    if score >= 40:
        return "#e67e22", "#ffffff"   # amber
    return "#27ae60", "#ffffff"       # green


def _severity_badge(severity: str) -> str:
    """Return an inline-styled HTML <span> badge for the given severity."""
    colours: dict[str, tuple[str, str]] = {
        "CRITICAL": ("#c0392b", "#fff"),
        "HIGH":     ("#e74c3c", "#fff"),
        "MEDIUM":   ("#e67e22", "#fff"),
        "LOW":      ("#27ae60", "#fff"),
    }
    bg, fg = colours.get(severity.upper(), ("#7f8c8d", "#fff"))
    return (
        f'<span style="background:{bg};color:{fg};padding:2px 8px;'
        f'border-radius:12px;font-size:0.78em;font-weight:700;'
        f'letter-spacing:0.04em;">{html.escape(severity)}</span>'
    )


def _uar_row_style(decision: str) -> str:
    """Return a background style string for a UAR table row."""
    colours = {
        "APPROVE": "background:#eafaf1;",
        "REVIEW":  "background:#fef9e7;",
        "REVOKE":  "background:#fdedec;",
    }
    return colours.get(decision.upper(), "")


def _uar_badge(decision: str) -> str:
    """Return a styled badge for an APPROVE / REVIEW / REVOKE decision."""
    colours: dict[str, tuple[str, str]] = {
        "APPROVE": ("#27ae60", "#fff"),
        "REVIEW":  ("#e67e22", "#fff"),
        "REVOKE":  ("#c0392b", "#fff"),
    }
    bg, fg = colours.get(decision.upper(), ("#7f8c8d", "#fff"))
    return (
        f'<span style="background:{bg};color:{fg};padding:3px 10px;'
        f'border-radius:12px;font-size:0.8em;font-weight:700;">'
        f'{html.escape(decision)}</span>'
    )


# ---------------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------------

def _build_css() -> str:
    return """
    <style>
      *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
      body {
        font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
        background: #f0f2f5;
        color: #2c3e50;
        font-size: 15px;
        line-height: 1.6;
      }
      a { color: inherit; text-decoration: none; }

      /* ── HEADER ─────────────────────────────────────────────── */
      .header {
        background: linear-gradient(135deg, #1a1f36 0%, #2d3561 100%);
        color: #fff;
        padding: 24px 40px;
        display: flex;
        align-items: center;
        justify-content: space-between;
        box-shadow: 0 4px 16px rgba(0,0,0,0.25);
      }
      .header-title {
        font-size: 1.55rem;
        font-weight: 700;
        letter-spacing: 0.03em;
      }
      .header-shield {
        font-size: 1.8rem;
        margin-right: 14px;
      }
      .header-meta {
        font-size: 0.82rem;
        opacity: 0.75;
        text-align: right;
        line-height: 1.5;
      }

      /* ── MAIN CONTENT ────────────────────────────────────────── */
      .content {
        max-width: 1200px;
        margin: 0 auto;
        padding: 32px 24px 60px;
      }

      /* ── RISK BANNER ─────────────────────────────────────────── */
      .risk-banner {
        border-radius: 14px;
        padding: 32px 40px;
        text-align: center;
        margin-bottom: 28px;
        box-shadow: 0 4px 20px rgba(0,0,0,0.15);
      }
      .risk-banner .score { font-size: 5rem; font-weight: 900; line-height: 1; }
      .risk-banner .label { font-size: 1.05rem; font-weight: 600; opacity: 0.9; margin-top: 6px; }

      /* ── SUMMARY BOX ─────────────────────────────────────────── */
      .executive-summary {
        background: #ffffff;
        border-left: 5px solid #2d3561;
        border-radius: 0 10px 10px 0;
        padding: 20px 24px;
        margin-bottom: 28px;
        box-shadow: 0 2px 10px rgba(0,0,0,0.07);
        font-size: 0.96rem;
        line-height: 1.7;
        color: #34495e;
      }
      .executive-summary h2 {
        font-size: 1rem;
        font-weight: 700;
        color: #2d3561;
        margin-bottom: 10px;
        text-transform: uppercase;
        letter-spacing: 0.07em;
      }

      /* ── METRICS ROW ─────────────────────────────────────────── */
      .metrics-row {
        display: grid;
        grid-template-columns: repeat(4, 1fr);
        gap: 16px;
        margin-bottom: 34px;
      }
      .metric-card {
        background: #fff;
        border-radius: 12px;
        padding: 22px 18px;
        text-align: center;
        box-shadow: 0 2px 12px rgba(0,0,0,0.07);
        border-top: 4px solid #2d3561;
      }
      .metric-card .value {
        font-size: 2.4rem;
        font-weight: 800;
        color: #2d3561;
        line-height: 1;
      }
      .metric-card .desc {
        font-size: 0.8rem;
        color: #7f8c8d;
        margin-top: 8px;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.04em;
      }

      /* ── SECTION HEADINGS ───────────────────────────────────── */
      .section-heading {
        font-size: 1.1rem;
        font-weight: 700;
        color: #1a1f36;
        margin-bottom: 14px;
        padding-bottom: 8px;
        border-bottom: 2px solid #e0e4ef;
        text-transform: uppercase;
        letter-spacing: 0.05em;
      }
      .section { margin-bottom: 38px; }

      /* ── TABLES ─────────────────────────────────────────────── */
      .tbl-wrap {
        border-radius: 10px;
        overflow: hidden;
        box-shadow: 0 2px 12px rgba(0,0,0,0.08);
      }
      table {
        width: 100%;
        border-collapse: collapse;
        font-size: 0.88rem;
      }
      thead th {
        background: #1a1f36;
        color: #fff;
        padding: 11px 14px;
        text-align: left;
        font-weight: 600;
        text-transform: uppercase;
        font-size: 0.78rem;
        letter-spacing: 0.06em;
      }
      tbody tr {
        border-bottom: 1px solid #ecf0f4;
        transition: background 0.15s;
      }
      tbody tr:last-child { border-bottom: none; }
      tbody tr:hover { background: #f7f9fc !important; }
      tbody td {
        padding: 11px 14px;
        background: #fff;
        vertical-align: top;
        line-height: 1.5;
      }
      .row-critical td { background: #fff0f0 !important; }
      .row-critical:hover td { background: #ffe4e4 !important; }

      /* ── TOP THREATS ─────────────────────────────────────────── */
      .threats-list {
        list-style: none;
        display: flex;
        flex-direction: column;
        gap: 12px;
      }
      .threats-list li {
        background: #fff;
        border-left: 5px solid #c0392b;
        border-radius: 0 10px 10px 0;
        padding: 14px 18px;
        box-shadow: 0 2px 10px rgba(0,0,0,0.07);
        font-size: 0.93rem;
        color: #2c3e50;
        display: flex;
        align-items: flex-start;
        gap: 12px;
      }
      .threats-list li .num {
        background: #c0392b;
        color: #fff;
        font-weight: 800;
        font-size: 0.85rem;
        border-radius: 50%;
        width: 26px;
        height: 26px;
        display: flex;
        align-items: center;
        justify-content: center;
        flex-shrink: 0;
      }

      /* ── EMPTY STATE ─────────────────────────────────────────── */
      .empty-state {
        background: #fff;
        border-radius: 10px;
        padding: 30px;
        text-align: center;
        color: #95a5a6;
        font-style: italic;
        box-shadow: 0 2px 8px rgba(0,0,0,0.05);
      }

      /* ── FOOTER ──────────────────────────────────────────────── */
      .footer {
        text-align: center;
        color: #b0b8c9;
        font-size: 0.78rem;
        margin-top: 50px;
        padding-top: 20px;
        border-top: 1px solid #dde2ec;
      }

      @media (max-width: 900px) {
        .metrics-row { grid-template-columns: repeat(2, 1fr); }
      }
      @media (max-width: 600px) {
        .metrics-row { grid-template-columns: 1fr; }
        .header { flex-direction: column; gap: 12px; }
      }
    </style>
    """


def _build_header(timestamp: str) -> str:
    return f"""
    <header class="header">
      <div style="display:flex;align-items:center;">
        <span class="header-shield">🛡️</span>
        <span class="header-title">IdentityGuard — IAM Threat Detection Report</span>
      </div>
      <div class="header-meta">
        Generated&nbsp;{html.escape(timestamp)}<br>
        Azure AD · Gemini AI Analysis
      </div>
    </header>
    """


def _build_risk_banner(score: int | float, risk_level: str) -> str:
    try:
        score_int = int(score)
    except (TypeError, ValueError):
        score_int = 0

    bg, fg = _risk_banner_style(score_int)
    return f"""
    <div class="risk-banner" style="background:{bg};color:{fg};">
      <div class="score">{score_int}</div>
      <div class="label">Overall Risk Score / 100 &nbsp;·&nbsp; {html.escape(str(risk_level))}</div>
    </div>
    """


def _build_executive_summary(summary_text: str) -> str:
    return f"""
    <div class="executive-summary">
      <h2>Executive Summary</h2>
      {html.escape(summary_text)}
    </div>
    """


def _build_metrics(
    travel: list[dict[str, Any]],
    privs: list[dict[str, Any]],
    spns: list[dict[str, Any]],
    users_json_path: Path,
) -> str:
    # Total users analyzed
    try:
        with open(users_json_path, encoding="utf-8") as fh:
            total_users = len(json.load(fh))
    except Exception:
        total_users = "—"

    # Impossible travel events
    travel_count = len(travel)

    # Privileged accounts flagged (unique users in privs)
    priv_users_flagged = len({f.get("user", "") for f in privs})

    # SPNs with CRITICAL issues
    critical_spns = len([s for s in spns if s.get("severity", "") == "CRITICAL"])

    cards = [
        (str(total_users),      "Total Users Analyzed"),
        (str(travel_count),     "Impossible Travel Events"),
        (str(priv_users_flagged), "Privileged Accounts Flagged"),
        (str(critical_spns),   "SPNs with Critical Issues"),
    ]

    items = "".join(
        f'<div class="metric-card">'
        f'<div class="value">{v}</div>'
        f'<div class="desc">{d}</div>'
        f'</div>'
        for v, d in cards
    )
    return f'<div class="metrics-row">{items}</div>'


def _build_travel_table(travel: list[dict[str, Any]]) -> str:
    if not travel:
        return '<div class="empty-state">No impossible travel events detected.</div>'

    rows = ""
    for f in travel:
        is_critical = f.get("severity", "") == "CRITICAL"
        row_cls = ' class="row-critical"' if is_critical else ""
        severity_html = _severity_badge(f.get("severity", ""))
        rows += (
            f"<tr{row_cls}>"
            f"<td>{html.escape(str(f.get('user', '')))}</td>"
            f"<td>{html.escape(str(f.get('login1_country', '')))}</td>"
            f"<td>{html.escape(str(f.get('login2_country', '')))}</td>"
            f"<td>{html.escape(str(f.get('minutes_apart', '')))}</td>"
            f"<td>{severity_html}</td>"
            f"</tr>"
        )

    return f"""
    <div class="tbl-wrap">
      <table>
        <thead>
          <tr>
            <th>User</th>
            <th>From</th>
            <th>To</th>
            <th>Gap (mins)</th>
            <th>Severity</th>
          </tr>
        </thead>
        <tbody>{rows}</tbody>
      </table>
    </div>
    """


def _build_privilege_table(privs: list[dict[str, Any]]) -> str:
    if not privs:
        return '<div class="empty-state">No privilege audit findings.</div>'

    rows = ""
    for f in privs:
        severity_html = _severity_badge(f.get("severity", ""))
        rows += (
            f"<tr>"
            f"<td>{html.escape(str(f.get('user', '')))}</td>"
            f"<td>{html.escape(str(f.get('finding_type', '')))}</td>"
            f"<td>{html.escape(str(f.get('role', '')))}</td>"
            f"<td>{severity_html}</td>"
            f"<td style='font-size:0.83em;color:#555;'>"
            f"{html.escape(str(f.get('recommendation', '')))}</td>"
            f"</tr>"
        )

    return f"""
    <div class="tbl-wrap">
      <table>
        <thead>
          <tr>
            <th>User</th>
            <th>Finding</th>
            <th>Role</th>
            <th>Severity</th>
            <th>Recommendation</th>
          </tr>
        </thead>
        <tbody>{rows}</tbody>
      </table>
    </div>
    """


def _build_spn_table(spns: list[dict[str, Any]]) -> str:
    if not spns:
        return '<div class="empty-state">No SPN risk findings.</div>'

    rows = ""
    for f in spns:
        severity_html = _severity_badge(f.get("severity", ""))
        rows += (
            f"<tr>"
            f"<td>{html.escape(str(f.get('spn_name', '')))}</td>"
            f"<td style='font-size:0.83em;'>{html.escape(str(f.get('detail', f.get('finding_type', ''))))}</td>"
            f"<td>{severity_html}</td>"
            f"<td style='font-size:0.83em;color:#555;'>"
            f"{html.escape(str(f.get('recommendation', '')))}</td>"
            f"</tr>"
        )

    return f"""
    <div class="tbl-wrap">
      <table>
        <thead>
          <tr>
            <th>SPN Name</th>
            <th>Finding</th>
            <th>Severity</th>
            <th>Recommendation</th>
          </tr>
        </thead>
        <tbody>{rows}</tbody>
      </table>
    </div>
    """


def _build_uar_table(uar_decisions: list[dict[str, Any]]) -> str:
    if not uar_decisions:
        return '<div class="empty-state">No UAR decisions available.</div>'

    rows = ""
    for d in uar_decisions:
        decision = str(d.get("decision", ""))
        row_style = _uar_row_style(decision)
        badge = _uar_badge(decision)
        rows += (
            f'<tr style="{row_style}">'
            f"<td>{html.escape(str(d.get('user', '')))}</td>"
            f"<td>{badge}</td>"
            f"<td style='font-size:0.87em;color:#444;'>"
            f"{html.escape(str(d.get('justification', '')))}</td>"
            f"</tr>"
        )

    return f"""
    <div class="tbl-wrap">
      <table>
        <thead>
          <tr>
            <th>User</th>
            <th>Decision</th>
            <th>Justification</th>
          </tr>
        </thead>
        <tbody>{rows}</tbody>
      </table>
    </div>
    """


def _build_top_threats(threats: list[str]) -> str:
    if not threats:
        return '<div class="empty-state">No threat information available.</div>'

    top_three: list[str] = list(itertools.islice(threats, 3))
    items = "".join(
        f'<li><span class="num">{i + 1}</span>{html.escape(threat)}</li>'
        for i, threat in enumerate(top_three)
    )
    return f'<ul class="threats-list">{items}</ul>'


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_report(
    travel: list[dict[str, Any]],
    privs: list[dict[str, Any]],
    spns: list[dict[str, Any]],
    genai: dict[str, Any],
) -> None:
    """
    Build a self-contained HTML report and write it to reporting/output/report.html.

    Args:
        travel:  List of impossible-travel finding dicts.
        privs:   List of privilege-audit finding dicts.
        spns:    List of SPN-risk finding dicts.
        genai:   Dict returned by genai_analyzer.run() (includes risk score,
                 executive summary, UAR decisions, top threats).
    """
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    score = genai.get("overall_risk_score", 0)
    risk_level = genai.get("risk_level", "UNKNOWN")
    executive_summary = genai.get("executive_summary", "No summary available.")
    uar_decisions: list[dict[str, Any]] = genai.get("uar_decisions", [])
    top_threats: list[str] = genai.get("top_3_threats", [])

    users_json_path = ROOT_DIR / "data" / "users.json"

    css       = _build_css()
    header    = _build_header(timestamp)
    banner    = _build_risk_banner(score, risk_level)
    summary   = _build_executive_summary(executive_summary)
    metrics   = _build_metrics(travel, privs, spns, users_json_path)
    travel_t  = _build_travel_table(travel)
    priv_t    = _build_privilege_table(privs)
    spn_t     = _build_spn_table(spns)
    uar_t     = _build_uar_table(uar_decisions)
    threats   = _build_top_threats(top_threats)

    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>IdentityGuard — IAM Threat Detection Report</title>
  <meta name="description" content="AI-powered Azure AD IAM threat detection report.">
  {css}
</head>
<body>
  {header}
  <div class="content">
    {banner}
    {summary}
    {metrics}

    <div class="section">
      <div class="section-heading">🚨 Impossible Travel Events</div>
      {travel_t}
    </div>

    <div class="section">
      <div class="section-heading">🔑 Privilege Audit Findings</div>
      {priv_t}
    </div>

    <div class="section">
      <div class="section-heading">⚙️ Service Principal Risk</div>
      {spn_t}
    </div>

    <div class="section">
      <div class="section-heading">📋 User Access Review (UAR) Decisions</div>
      {uar_t}
    </div>

    <div class="section">
      <div class="section-heading">🔥 Top 3 Threats (AI Assessment)</div>
      {threats}
    </div>

    <div class="footer">
      IdentityGuard IAM Monitor &nbsp;·&nbsp; Generated {html.escape(timestamp)}
      &nbsp;·&nbsp; Powered by Google Gemini AI
    </div>
  </div>
</body>
</html>"""

    OUTPUT_HTML.write_text(html_doc, encoding="utf-8")
    print(f"[risk_report] HTML report written to {OUTPUT_HTML}")


# ---------------------------------------------------------------------------
# Standalone entry point — reads existing genai_analysis.json from disk
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from analysis.impossible_travel import run as travel_run
    from analysis.privilege_audit import run as priv_run
    from analysis.service_principal_risk import run as spn_run

    _genai_path = ROOT_DIR / "data" / "genai_analysis.json"
    if not _genai_path.exists():
        raise FileNotFoundError(
            f"genai_analysis.json not found at {_genai_path}. "
            "Run main.py first (or python -m analysis.genai_analyzer)."
        )

    with open(_genai_path, encoding="utf-8") as _fh:
        _genai = json.load(_fh)

    generate_report(travel_run(), priv_run(), spn_run(), _genai)
