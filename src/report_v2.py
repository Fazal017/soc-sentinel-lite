"""HTML report for Sentinel v2 incidents (stdlib only, no JS libs).

One card per incident, with the full attack chain rendered as a
stage-by-stage timeline (stage -> MITRE -> timestamp -> evidence),
plus the graph summary, baseline summary and suppressed chains, so
an analyst can audit both what was flagged *and* what was dropped.
"""

from __future__ import annotations

import html
from datetime import datetime

SEV_COLOUR = {"critical": "#dc2626", "high": "#ea580c",
              "medium": "#ca8a04", "low": "#16a34a"}


def _esc(v) -> str:
    return html.escape("" if v is None else str(v))


def _badge(sev: str) -> str:
    colour = SEV_COLOUR.get(sev.lower(), "#6b7280")
    return (f'<span style="background:{colour};color:#fff;padding:2px 8px;'
            f'border-radius:999px;font-size:12px">{_esc(sev.upper())}</span>')


def generate_incident_html(incidents, suppressed, graph_summary, baseline_summary,
                           total_events: int, generated_at: str | None = None) -> str:
    generated_at = generated_at or datetime.now().isoformat(timespec="seconds")

    def incident_card(inc, suppressed_card=False):
        stages = "\n".join(
            f"<li><b>{i}. {_esc(s['stage'].replace('_', ' ').title())}</b> "
            f"— {_esc(s['mitre_technique'])} {_esc(s['mitre_name'])} "
            f"({_esc(s['mitre_tactic'])})<br>"
            f"<span style='color:#6b7280'>{_esc(s['timestamp'])} &middot; "
            f"user={_esc(s['user'])} &middot; {_esc(s['src_ip'])} &middot; "
            f"{_esc(s['host'])}</span><br>{_esc(s['detail'])}<br>"
            f"<code>{_esc(s['evidence'])}</code></li>"
            for i, s in enumerate(inc["stages"], 1)
        )
        fb = ""
        if inc.get("feedback_applied"):
            fb = (f"<p><b>Analyst feedback applied:</b> "
                  f"{_esc(inc['feedback_applied'].get('note', ''))} "
                  f"(multiplier {inc.get('feedback_multiplier')})</p>")
        sup = ""
        if suppressed_card:
            sup = f"<p><i>{_esc(inc.get('suppressed_reason', ''))}</i></p>"
        return f"""
<div style="border:1px solid #e5e7eb;border-radius:10px;padding:16px;margin:16px 0">
<h3>{_esc(inc.get('incident_id', ''))} — user {_esc(inc['user'])} {_badge(inc['severity'])}
<span style="font-size:20px"> risk {inc['risk_score']}/100</span></h3>
<p>Chain length <b>{inc['chain_length']}</b> &middot;
MITRE sequence <code>{_esc(' &rarr; '.join(inc['mitre_sequence']))}</code><br>
{ _esc(inc['first_seen'])} &rarr; {_esc(inc['last_seen'])} &middot;
Brute force: {_esc(inc['brute_force_subtype'])} ({inc['brute_force_count']} failures, {inc['brute_force_span_hours']}h) &middot;
IPs: {_esc(', '.join(inc['ips']))} &middot; Hosts: {_esc(', '.join(inc['hosts']))}<br>
Rarity {inc.get('rarity')} &middot; Asset criticality {inc.get('asset_criticality')} &middot;
Time decay {inc.get('time_decay')} &middot; Raw score {inc.get('risk_score_raw')}</p>
{fb}{sup}
<ol>{stages}</ol>
<p style="color:#6b7280;font-size:13px">Rarity reasons: {_esc('; '.join(inc.get('rarity_reasons', [])))}</p>
</div>"""

    inc_cards = "\n".join(incident_card(i) for i in incidents) or "<p>No incidents above threshold.</p>"
    sup_cards = "\n".join(incident_card(s, True) for s in suppressed) or "<p>None suppressed.</p>"

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>SOC Sentinel v2 — Attack-Chain Incident Report</title>
<style>body{{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
margin:32px auto;max-width:1000px;padding:0 16px;color:#111827}}
table{{border-collapse:collapse;width:100%;font-size:14px}}
th,td{{border:1px solid #e5e7eb;padding:8px;text-align:left;vertical-align:top}}
th{{background:#111827;color:#fff}} tr:nth-child(even){{background:#f9fafb}}
h1{{font-size:26px}} h2{{margin-top:32px}} .cards{{display:flex;gap:12px;flex-wrap:wrap}}
code{{background:#f3f4f6;padding:1px 5px;border-radius:4px}}</style></head>
<body>
<h1>Sentinel Graph v2 — Attack-Chain Incident Report</h1>
<p>Generated <code>{_esc(generated_at)}</code> &middot; Temporal attack-chain
reconstruction, not isolated alerts. Sample / lab data only — all IPs are
RFC 5737 documentation ranges.</p>
<div class="cards">
<div style="flex:1;min-width:140px;background:#f9fafb;border:1px solid #e5e7eb;border-radius:10px;padding:16px"><div style="font-size:12px;color:#6b7280">Incidents</div><div style="font-size:28px;font-weight:700;color:#dc2626">{len(incidents)}</div></div>
<div style="flex:1;min-width:140px;background:#f9fafb;border:1px solid #e5e7eb;border-radius:10px;padding:16px"><div style="font-size:12px;color:#6b7280">Suppressed (below threshold)</div><div style="font-size:28px;font-weight:700">{len(suppressed)}</div></div>
<div style="flex:1;min-width:140px;background:#f9fafb;border:1px solid #e5e7eb;border-radius:10px;padding:16px"><div style="font-size:12px;color:#6b7280">Events parsed</div><div style="font-size:28px;font-weight:700">{total_events}</div></div>
<div style="flex:1;min-width:140px;background:#f9fafb;border:1px solid #e5e7eb;border-radius:10px;padding:16px"><div style="font-size:12px;color:#6b7280">Graph nodes / edges</div><div style="font-size:28px;font-weight:700">{graph_summary.get('nodes', 0)} / {graph_summary.get('edges', 0)}</div></div>
</div>
<h2>Graph summary</h2>
<p>Users: {_esc(', '.join(graph_summary.get('users', [])))}<br>
Hosts: {_esc(', '.join(graph_summary.get('hosts', [])))}<br>
IPs: {_esc(', '.join(graph_summary.get('ips', [])))}</p>
<h2>Baseline (7-day history)</h2>
<p>History events: {baseline_summary.get('total_history_events', 0)} &middot;
Peer failure-rate median: {baseline_summary.get('peer_failure_rate_median')}<br>
Per-user baselines: {_esc(str(baseline_summary.get('per_user', {})))}</p>
<h2>Incidents — one per attack chain</h2>
{inc_cards}
<h2>Suppressed chains (auditable, not hidden)</h2>
{sup_cards}
<p style="color:#6b7280;font-size:13px">SOC Sentinel v2.0.0 &middot;
Chains are reconstructions over lab logs, not proof of compromise —
triage every incident before acting. See README.md for limitations.</p>
</body></html>
"""


def write_incident_report(path: str, incidents, suppressed, graph_summary,
                         baseline_summary, total_events: int) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(generate_incident_html(incidents, suppressed, graph_summary,
                                        baseline_summary, total_events))
