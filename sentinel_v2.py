#!/usr/bin/env python3
"""SOC Sentinel v2 — Sentinel Graph: Temporal Attack-Chain Reconstruction.

v1 scores isolated alerts. v2 reconstructs the *attack chain*:

    logs -> parser -> temporal entity graph -> peer-group baseline
    -> chain reconstruction -> v2 risk scoring (with analyst feedback)
    -> ONE incident per chain + graph.json + HTML report

Usage:
    python3 sentinel_v2.py --input logs/sample_auth.log --history logs/history_7d.log --output report_v2.html --json incidents.json --graph graph.json
    python3 sentinel_v2.py --input logs/advanced_chain.log --history logs/history_7d.log --output report_v2.html --json incidents.json --graph graph.json
    python3 sentinel_v2.py --input logs/normal_user.log --history logs/history_7d.log --output report_v2.html --json incidents.json --graph graph.json

Stdlib only, no network, sample IPs are RFC 5737 only.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from src.baseline import Baseline
from src.chain import reconstruct_chains
from src.graph import build_graph
from src.parser import parse_file
from src.report_v2 import write_incident_report
from src.scoring_v2 import INCIDENT_THRESHOLD, load_feedback, score_chains


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sentinel_v2.py",
        description="SOC Sentinel v2 — temporal attack-chain reconstruction.")
    p.add_argument("--input", default="logs/sample_auth.log",
                   help="Log file to analyse (default: logs/sample_auth.log).")
    p.add_argument("--history", default="logs/history_7d.log",
                   help="7-day history log for baselining (default: logs/history_7d.log).")
    p.add_argument("--output", default="report_v2.html",
                   help="Path for the HTML incident report (default: report_v2.html).")
    p.add_argument("--json", default="incidents.json",
                   help="Path for incidents JSON (default: incidents.json).")
    p.add_argument("--graph", default="graph.json",
                   help="Path for the entity-graph JSON (default: graph.json).")
    p.add_argument("--feedback", default="incidents/feedback.json",
                   help="Analyst feedback file (default: incidents/feedback.json).")
    p.add_argument("--quiet", action="store_true")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    t0 = time.perf_counter()
    try:
        events = parse_file(args.input)
    except FileNotFoundError:
        print(f"[error] input file not found: {args.input}", file=sys.stderr)
        return 2
    history_events: list[dict] = []
    if args.history:
        try:
            history_events = parse_file(args.history)
        except FileNotFoundError:
            print(f"[warn] history file not found: {args.history} — "
                  "continuing with an empty baseline", file=sys.stderr)
    baseline = Baseline(history_events)
    graph = build_graph(events)
    chains = reconstruct_chains(events, baseline)
    feedback = load_feedback(args.feedback)
    incidents, suppressed = score_chains(chains, baseline, events, feedback)
    elapsed = time.perf_counter() - t0
    events_per_sec = len(events) / elapsed if elapsed > 0 else 0.0

    graph.save(args.graph)
    with open(args.json, "w", encoding="utf-8") as fh:
        json.dump({
            "incidents": incidents,
            "suppressed": suppressed,
            "graph_summary": graph.summary(),
            "baseline_summary": baseline.summary(),
            "benchmark": {
                "events": len(events),
                "history_events": len(history_events),
                "seconds": round(elapsed, 3),
                "events_per_sec": round(events_per_sec, 1),
            },
        }, fh, indent=2)
    write_incident_report(args.output, incidents, suppressed,
                          graph.summary(), baseline.summary(), len(events))

    if not args.quiet:
        print(f"[+] Parsed {len(events)} events from {args.input} "
              f"({events_per_sec:.0f} events/sec)")
        print(f"[+] Baseline learned from {len(history_events)} history events "
              f"({len(baseline.users)} users, peer failure-rate median "
              f"{baseline.peer_failure_median:.3f})")
        print(f"[+] Graph: {graph.summary()['nodes']} nodes, "
              f"{graph.summary()['edges']} edges")
        print(f"[+] {len(chains)} chain(s) reconstructed, "
              f"{len(incidents)} incident(s) >= threshold {INCIDENT_THRESHOLD}, "
              f"{len(suppressed)} suppressed")
        for inc in incidents:
            print(f"    [{inc['severity'].upper():8}] {inc['risk_score']:3d}  "
                  f"{inc['incident_id']} user={inc['user']} "
                  f"stages={inc['chain_length']} "
                  f"({' -> '.join(inc['mitre_sequence'])}) "
                  f"{inc['first_seen']} -> {inc['last_seen']}")
        for sup in suppressed:
            print(f"    [SUPPRESSED] {sup['risk_score']:3d}  {sup['incident_id']} "
                  f"user={sup['user']} stages={sup['chain_length']} — {sup['suppressed_reason']}")
        print(f"[+] Graph: {args.graph}")
        print(f"[+] Incidents: {args.json}")
        print(f"[+] HTML report: {args.output}")
    else:
        print(f"{len(incidents)} incident(s) | {len(suppressed)} suppressed | report: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
