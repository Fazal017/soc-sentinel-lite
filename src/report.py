"""Single-file HTML report generator (no external assets, no JS libs).

Produces a self-contained ``report.html``: summary cards, top offending
IPs, a MITRE ATT&CK coverage table and a full alert timeline table.
Safe for sample data only — all values are HTML-escaped.
"""

from __future__ import annotations

import html
from collections import Counter
from datetime import datetime

SEV_COLOUR = {
    "critical": "#dc2626", "high": "#ea580c",
    "medium": "#ca8a04", "low": "#16a34a",
}


def _esc(v) -> str:
    return html.escape("" if v is None else str(v))


def _sev_badge(sev: str) -> str:
    colour = SEV_COLOUR.get(sev.lower(), "#6b7280")
    return (f'<span style="background:{colour};color:#fff;padding:2px 8px;'
            f'border-radius:999px;font-size:12px">{_esc(sev.upper())}</span>')


def generate_html(alerts: list[dict], events: list[dict],
                  generated_at: str | None = None) -> str:
    generated_at = generated_at or datetime.now().isoformat(timespec="seconds")
    total_events = len(events)
    failed = sum(1 for e in events if e["event_type"] == "failed_login")
    success = sum(1 for e in events if e["event_type"] == "successful_login")
    by_sev = Counter(a["severity"] for a in alerts)
    top_ips = Counter(a["src_ip"] for a in alerts if a["src_ip"]).most_common(5)
    mitre = sorted({(a["mitre_technique"], a["mitre_tactic"], a["mitre_name"])
                    for a in alerts if a["mitre_technique"]})
    max_risk = max((a["risk_score"] for a in alerts), default=0)

    rows = "\n".join(
        f"<tr><td>{_esc(a['first_seen'])}</td><td>{_esc(a['rule_id'])} — {_esc(a['rule_name'])}</td>"
        f"<td>{_sev_badge(a['severity'])}</td><td><b>{a['risk_score']}</b></td>"
        f"<td>{_esc(a['src_ip'])}</td><td>{_esc(a['user'])}</td>"
        f"<td>{_esc(a['mitre_technique'])}</td><td>{_esc(a['description'])}</td></tr>"
        for a in alerts
    ) or '<tr><td colspan="8">No alerts — no rule thresholds were crossed.</td></tr>'

    ip_rows = "\n".join(
        f"<tr><td>{_esc(ip)}</td><td>{n}</td></tr>" for ip, n in top_ips
    ) or '<tr><td colspan="2">—</td></tr>'

    mitre_rows = "\n".join(
        f"<tr><td>{_esc(t)}</td><td>{_esc(tac)}</td><td>{_esc(name)}</td></tr>"
        for t, tac, name in mitre
    ) or '<tr><td colspan="3">—</td></tr>'

    def card(label, value, colour="#111827"):
        return (f'<div style="flex:1;min-width:140px;background:#f9fafb;border:1px solid #e5e7eb;'
                f'border-radius:10px;padding:16px"><div style="font-size:12px;color:#6b7280">'
                f'{label}</div><div style="font-size:28px;font-weight:700;color:{colour}">'
                f'{value}</div></div>')

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>SOC Sentinel Lite — Detection Report</title>
<style>body{{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
margin:32px auto;max-width:1000px;padding:0 16px;color:#111827}}
table{{border-collapse:collapse;width:100%;font-size:14px}}
th,td{{border:1px solid #e5e7eb;padding:8px;text-align:left;vertical-align:top}}
th{{background:#111827;color:#fff}} tr:nth-child(even){{background:#f9fafb}}
h1{{font-size:26px}} h2{{margin-top:32px}} .cards{{display:flex;gap:12px;flex-wrap:wrap}}
code{{background:#f3f4f6;padding:1px 5px;border-radius:4px}}</style></head>
<body>
<h1>&#128737; SOC Sentinel Lite — Detection Report</h1>
<p>Generated <code>{_esc(generated_at)}</code> &middot; Pure-Python mini-SOC (stdlib only).
Sample / lab data only — all IPs are RFC 5737 documentation ranges.</p>
<div class="cards">
{card("Total alerts", len(alerts), "#dc2626")}
{card("Events parsed", total_events)}
{card("Failed logins", failed, "#ea580c")}
{card("Successful logins", success, "#16a34a")}
{card("Highest risk", max_risk, "#dc2626")}
{card("Critical", by_sev.get("critical", 0), "#dc2626")}
{card("High", by_sev.get("high", 0), "#ea580c")}
{card("Medium", by_sev.get("medium", 0), "#ca8a04")}
</div>
<h2>Top offending IPs</h2>
<table><tr><th>Source IP</th><th>Alerts</th></tr>{ip_rows}</table>
<h2>MITRE ATT&amp;CK coverage</h2>
<table><tr><th>Technique</th><th>Tactic</th><th>Name</th></tr>{mitre_rows}</table>
<h2>Alert timeline</h2>
<table><tr><th>First seen</th><th>Rule</th><th>Severity</th><th>Risk</th>
<th>Source IP</th><th>User</th><th>MITRE</th><th>Description</th></tr>{rows}</table>
<p style="color:#6b7280;font-size:13px">SOC Sentinel Lite v1.0.0 &middot;
Detections are correlations over lab logs, not proof of compromise —
triage every alert before acting. See README.md for limitations.</p>
</body></html>
"""


def write_report(path: str, alerts: list[dict], events: list[dict]) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(generate_html(alerts, events))
