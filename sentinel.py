#!/usr/bin/env python3
"""SOC Sentinel Lite — mini SOC / SIEM in pure Python (stdlib only).

Ingest auth/syslog-style logs, correlate them against Sigma-like rules,
map detections to MITRE ATT&CK, score risk, and emit alerts to SQLite,
JSON and a self-contained HTML report.

Usage:
    python3 sentinel.py --input logs/sample_auth.log --output report.html --json alerts.json
    python3 sentinel.py --input logs/sample_auth.log --rules rules/ --db alerts.db
    python3 sentinel.py --input /var/log/auth.log --output report.html --quiet

No network access, no external dependencies, no real credentials.
All sample data uses RFC 5737 documentation IPs only.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Allow `python3 sentinel.py` from the repo root without installation.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from src.detector import detect
from src.parser import parse_file
from src.report import write_report
from src.rules import load_rules
from src.storage import alert_counts, init_db, store_alerts


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sentinel.py",
        description="SOC Sentinel Lite — detect attacks in auth/syslog logs.")
    p.add_argument("--input", required=True,
                   help="Path to an auth.log / syslog file to analyse.")
    p.add_argument("--rules", default="rules",
                   help="Directory of Sigma-like YAML rules (default: rules).")
    p.add_argument("--output", default="report.html",
                   help="Path for the HTML report (default: report.html).")
    p.add_argument("--db", default="alerts.db",
                   help="SQLite database for alerts (default: alerts.db).")
    p.add_argument("--json", default=None,
                   help="Optional path to also write alerts as JSON.")
    p.add_argument("--quiet", action="store_true",
                   help="Only print the final summary line.")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    try:
        rules = load_rules(args.rules)
    except (FileNotFoundError, ValueError) as exc:
        print(f"[error] cannot load rules: {exc}", file=sys.stderr)
        return 2
    try:
        events = parse_file(args.input)
    except FileNotFoundError:
        print(f"[error] input file not found: {args.input}", file=sys.stderr)
        return 2

    alerts = detect(events, rules)

    conn = init_db(args.db)
    inserted, skipped = store_alerts(conn, alerts)
    counts = alert_counts(conn)
    conn.close()

    write_report(args.output, alerts, events)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(alerts, fh, indent=2)

    sev = ", ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "none"
    if not args.quiet:
        print(f"[+] Parsed {len(events)} events from {args.input}")
        print(f"[+] Loaded {len(rules)} rules from {args.rules}")
        print(f"[+] {len(alerts)} alert(s) detected ({sev})")
        for a in alerts:
            print(f"    [{a['severity'].upper():8}] {a['risk_score']:3d}  "
                  f"{a['rule_id']} {a['rule_name']:<38} {a['src_ip'] or '-':15} "
                  f"user={a['user'] or '-'}  {a['mitre_technique']}")
        print(f"[+] Stored {inserted} new alert(s) in {args.db} "
              f"({skipped} duplicate(s) skipped)")
        print(f"[+] HTML report: {args.output}")
        if args.json:
            print(f"[+] JSON alerts:  {args.json}")
    else:
        print(f"{len(alerts)} alert(s) | {sev} | report: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
