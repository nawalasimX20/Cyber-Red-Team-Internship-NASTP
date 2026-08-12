"""
report.py
Turns the list of result dicts produced by modules.py into:
  1. juice_report.json  - raw machine-readable results
  2. juice_report.html  - color-coded scorecard for human review

All attacker-controlled/echoed text (payloads, evidence) is HTML-escaped
before being embedded in the report. The DVWA version of this tool learned
that lesson the hard way: an unescaped XSS payload captured as "evidence"
executed inside the report itself when opened in a browser.
"""

import json
import html
from datetime import datetime

RESULT_COLORS = {
    "VULNERABLE": "#e74c3c",
    "NOT TRIGGERED": "#2ecc71",
    "INFO": "#3498db",
}


def save_json(results, path="juice_report.json"):
    with open(path, "w") as f:
        json.dump(results, f, indent=2)
    return path


def save_html(results, target_url, path="juice_report.html"):
    counts = {"VULNERABLE": 0, "NOT TRIGGERED": 0, "INFO": 0}
    for r in results:
        counts[r["result"]] = counts.get(r["result"], 0) + 1

    rows = []
    for r in results:
        color = RESULT_COLORS.get(r["result"], "#7f8c8d")
        rows.append(f"""
        <tr>
          <td>{html.escape(r['category'])}</td>
          <td>{html.escape(r['test_name'])}</td>
          <td><code>{html.escape(r['request'])}</code></td>
          <td><span class="badge" style="background:{color}">{html.escape(r['result'])}</span></td>
          <td><code>{html.escape(r['evidence'])}</code></td>
          <td>{html.escape(r['detail'])}</td>
        </tr>""")

    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>OWASP Juice Shop - Automated Top 10:2025 Report</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; background:#f4f6f8; margin:0; padding:32px; color:#222; }}
  h1 {{ margin-bottom:4px; }}
  .meta {{ color:#666; margin-bottom:24px; }}
  .summary {{ display:flex; gap:16px; margin-bottom:24px; }}
  .card {{ background:#fff; border-radius:8px; padding:16px 24px; box-shadow:0 1px 3px rgba(0,0,0,0.1); }}
  .card .num {{ font-size:28px; font-weight:700; }}
  table {{ width:100%; border-collapse:collapse; background:#fff; box-shadow:0 1px 3px rgba(0,0,0,0.1); }}
  th, td {{ text-align:left; padding:10px 12px; border-bottom:1px solid #eee; vertical-align:top; font-size:13px; }}
  th {{ background:#2c3e50; color:#fff; position:sticky; top:0; }}
  code {{ font-size:12px; word-break:break-word; }}
  .badge {{ color:#fff; padding:3px 10px; border-radius:12px; font-size:12px; font-weight:600; white-space:nowrap; }}
</style>
</head>
<body>
  <h1>OWASP Juice Shop - Automated OWASP Top 10:2025 Report</h1>
  <div class="meta">Target: {html.escape(target_url)} &nbsp;|&nbsp; Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>

  <div class="summary">
    <div class="card"><div class="num" style="color:{RESULT_COLORS['VULNERABLE']}">{counts['VULNERABLE']}</div>Vulnerable</div>
    <div class="card"><div class="num" style="color:{RESULT_COLORS['NOT TRIGGERED']}">{counts['NOT TRIGGERED']}</div>Not triggered</div>
    <div class="card"><div class="num" style="color:{RESULT_COLORS['INFO']}">{counts['INFO']}</div>Info</div>
    <div class="card"><div class="num">{len(results)}</div>Total tests</div>
  </div>

  <table>
    <tr><th>Category</th><th>Test</th><th>Request</th><th>Result</th><th>Evidence</th><th>Detail</th></tr>
    {''.join(rows)}
  </table>
</body>
</html>"""

    with open(path, "w") as f:
        f.write(html_doc)
    return path
