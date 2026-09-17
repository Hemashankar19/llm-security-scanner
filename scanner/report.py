"""Report generation - turns a ScanReport into something a human reads.

Two outputs:
  * a terminal summary (for the CLI)
  * a self-contained HTML pentest-style report mapped to OWASP LLM categories

The HTML report is what makes this feel like a real security tool rather than a
script: severity-ranked findings, the exact probe used, the target's response,
and a remediation note per OWASP category.
"""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone

from scanner.models import OWASP_LLM, ScanReport, Severity

# One remediation blurb per OWASP category we probe.
REMEDIATION = {
    "LLM01": ("Treat all user input as untrusted. Separate instructions from data, "
              "constrain the model with output filtering, and never rely on the "
              "system prompt alone to enforce security boundaries."),
    "LLM02": ("Keep secrets out of the prompt entirely. Enforce least-privilege on "
              "backend data the model can reach, and scrub PII/credentials from "
              "context before it is sent to the model."),
    "LLM06": ("Apply least-privilege to tools. Require human approval for sensitive "
              "actions, validate tool arguments, and scope tokens narrowly."),
    "LLM07": ("Assume the system prompt is extractable. Put no secrets in it; enforce "
              "authorization in application code, not in prompt instructions."),
}

_SEV_COLOR = {
    Severity.CRITICAL: "#7f1d1d", Severity.HIGH: "#b91c1c",
    Severity.MEDIUM: "#c2410c", Severity.LOW: "#a16207", Severity.INFO: "#374151",
}


def print_summary(report: ScanReport) -> None:
    findings = report.findings
    print("\n" + "=" * 60)
    print(f"  Scan complete: {report.target_name}")
    print(f"  Attacks run: {report.attacks_run}   Findings: {len(findings)}")
    print("=" * 60)
    if not findings:
        print("  No vulnerabilities detected. [ok]")
        return
    for f in findings:
        a = f.attack
        print(f"  [{f.severity.value.upper():8}] {a.category} {a.id}  {a.name}")
        print(f"             {f.result.judge_rationale}")
    print("=" * 60)


def render_json(report: ScanReport) -> str:
    """Machine-readable report - for CI, dashboards, or diffing runs over time."""
    payload = {
        "target": report.target_name,
        "generated": datetime.now(timezone.utc).isoformat(),
        "attacks_run": report.attacks_run,
        "findings_count": len(report.findings),
        "by_category": report.summary_by_category(),
        "findings": [
            {
                "id": f.attack.id,
                "category": f.attack.category,
                "category_name": f.attack.category_name,
                "name": f.attack.name,
                "severity": f.severity.value,
                "confidence": round(f.result.confidence, 3),
                "detected_by": f.result.detected_by,
                "rationale": f.result.judge_rationale,
            }
            for f in report.findings
        ],
    }
    return json.dumps(payload, indent=2)


def render_html(report: ScanReport) -> str:
    findings = report.findings
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    cards = "\n".join(_finding_card(f) for f in findings) or \
        "<p class='ok'>No vulnerabilities detected in this run.</p>"

    cat_rows = "\n".join(
        f"<tr><td>{cat} {html.escape(OWASP_LLM.get(cat, ''))}</td><td>{n}</td></tr>"
        for cat, n in sorted(report.summary_by_category().items())
    ) or "<tr><td>None</td><td>0</td></tr>"

    return _TEMPLATE.format(
        target=html.escape(report.target_name),
        generated=generated,
        attacks_run=report.attacks_run,
        findings_count=len(findings),
        cat_rows=cat_rows,
        cards=cards,
    )


def _finding_card(f) -> str:
    a = f.attack
    color = _SEV_COLOR.get(f.severity, "#374151")
    remediation = REMEDIATION.get(a.category, "Review against the OWASP LLM Top 10.")
    return f"""
    <div class="card">
      <div class="card-head" style="border-left:6px solid {color}">
        <span class="sev" style="background:{color}">{f.severity.value.upper()}</span>
        <span class="cat">{a.category} &middot; {html.escape(a.category_name)}</span>
        <span class="id">{a.id}</span>
      </div>
      <h3>{html.escape(a.name)}</h3>
      <p class="meta"><b>Goal:</b> {html.escape(a.goal)}</p>
      <p class="meta"><b>Verdict:</b> {html.escape(f.result.judge_rationale)}
         <span class="conf">(confidence {f.result.confidence:.0%}, via {f.result.detected_by})</span></p>
      <details><summary>Probe sent</summary><pre>{html.escape(a.prompt)}</pre></details>
      <details><summary>Target response</summary><pre>{html.escape(f.result.response)}</pre></details>
      <p class="rem"><b>Remediation:</b> {html.escape(remediation)}</p>
    </div>"""


_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>LLM Security Scan Report</title>
<style>
  body{{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
       margin:0;background:#f8fafc;color:#0f172a;line-height:1.5}}
  header{{background:#0f172a;color:#fff;padding:28px 32px}}
  header h1{{margin:0 0 4px;font-size:22px}}
  header p{{margin:0;color:#94a3b8;font-size:14px}}
  main{{max-width:920px;margin:0 auto;padding:24px 20px}}
  .stats{{display:flex;gap:16px;flex-wrap:wrap;margin-bottom:24px}}
  .stat{{background:#fff;border:1px solid #e2e8f0;border-radius:10px;
        padding:16px 20px;flex:1;min-width:140px}}
  .stat b{{display:block;font-size:28px}}
  table{{width:100%;border-collapse:collapse;background:#fff;border:1px solid #e2e8f0;
        border-radius:10px;overflow:hidden;margin-bottom:28px}}
  td{{padding:10px 14px;border-top:1px solid #e2e8f0;font-size:14px}}
  .card{{background:#fff;border:1px solid #e2e8f0;border-radius:10px;
        padding:18px 20px;margin-bottom:16px}}
  .card-head{{display:flex;align-items:center;gap:10px;padding-left:12px;margin:-4px 0 8px}}
  .sev{{color:#fff;font-size:11px;font-weight:700;padding:2px 8px;border-radius:4px}}
  .cat{{font-size:13px;color:#475569}} .id{{margin-left:auto;font-size:12px;color:#94a3b8}}
  .card h3{{margin:4px 0 8px;font-size:16px}}
  .meta{{margin:4px 0;font-size:14px}} .conf{{color:#64748b;font-size:12px}}
  details{{margin:8px 0}} summary{{cursor:pointer;font-size:13px;color:#2563eb}}
  pre{{background:#0f172a;color:#e2e8f0;padding:12px;border-radius:8px;
      overflow-x:auto;font-size:12.5px;white-space:pre-wrap}}
  .rem{{background:#f1f5f9;border-radius:8px;padding:10px 12px;font-size:13.5px;margin-top:10px}}
  .ok{{background:#dcfce7;padding:16px;border-radius:10px;color:#166534}}
  footer{{max-width:920px;margin:0 auto;padding:16px 20px;color:#94a3b8;font-size:12px}}
</style></head>
<body>
<header>
  <h1>LLM Application Security Scan</h1>
  <p>Target: {target} &middot; Generated {generated}</p>
</header>
<main>
  <div class="stats">
    <div class="stat"><b>{attacks_run}</b>Attacks run</div>
    <div class="stat"><b>{findings_count}</b>Findings</div>
  </div>
  <h2>Findings by OWASP category</h2>
  <table>{cat_rows}</table>
  <h2>Findings ({findings_count})</h2>
  {cards}
</main>
<footer>Generated by llm-security-scanner. Mapped to the OWASP Top 10 for LLM
Applications. For use only against systems you own or are authorised to test.</footer>
</body></html>"""
