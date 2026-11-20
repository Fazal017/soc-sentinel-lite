"""Risk scoring v2 (Sentinel Graph).

A v1 alert score is ``severity + count`` — it cannot tell a 2-stage
typo burst from a 5-stage intrusion, and it never learns from the
analyst.  v2 scores a whole *chain*:

    risk = chain_length * rarity * asset_criticality * time_decay
           (x analyst-feedback multiplier)

in concrete terms (all factors are explicit and auditable):

* ``chain_length`` — 20 points per linked stage, so a 2-stage chain
  starts at 40 and a full 5-stage chain at 100.  Length is the
  strongest signal: real intrusions chain, mistakes do not.  A
  2-stage chain only clears the incident threshold (40) when its
  rarity / asset factors push it over — a known-user typo burst
  (rarity ~0) scores ~20 and is suppressed, while a slow brute
  force followed by a login from an unseen IP (rarity ~0.35,
  privileged account) scores ~41 and is an incident.
* ``rarity`` — 0.5 + max baseline deviation of the chain's events
  (``src/baseline.py``).  A chain built from the user's usual IP/host/
  hours gets 0.5–0.7; a chain from unseen IPs, unseen hosts, at 02:00
  gets 1.3–1.5.
* ``asset_criticality`` — host / account criticality: ``db01`` 1.4,
  ``web01`` 1.0, any other host 1.1; privileged accounts
  (``root`` / ``admin`` / ``deploy``) add ×1.2.  A chain that reaches
  the database matters more than one that stays on a web host.
* ``time_decay`` — chains are scored against the newest event in the
  input: within 1 day = 1.0, then ``exp(-age_days / 7)`` floored at
  0.5, so a week-old chain is still visible but no longer "critical".
* ``feedback`` — analyst feedback in ``incidents/feedback.json`` can
  mark a pattern (user + stage sequence, or user + brute-force
  subtype) as a false positive.  A matching entry multiplies the
  score by its ``weight`` (default 0.4) and is recorded on the
  incident as ``feedback_applied``.  Feedback is a *re-weight*, not a
  delete: the incident stays visible, with its lowered score and the
  reason, so the next run learns without hiding history.

The result is capped at 100 and floored at 0.  Chains scoring below
``INCIDENT_THRESHOLD`` (40) are not emitted as incidents — they are
returned separately as ``suppressed`` so an analyst can audit what
was dropped and why (the normal-user case in the tests).
"""

from __future__ import annotations

import json
import math
from datetime import datetime

INCIDENT_THRESHOLD = 40

ASSET_CRITICALITY = {
    "db01": 1.4,
    "web01": 1.0,
    "app01": 1.2,
    "prod01": 1.5,
}
PRIVILEGED_USERS = {"root", "admin", "deploy"}
DEFAULT_FEEDBACK_WEIGHT = 0.4


def load_feedback(path: str | None) -> list[dict]:
    """Load analyst feedback; missing / empty file means no feedback."""
    if not path:
        return []
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        return []
    if isinstance(data, dict):
        return data.get("feedback", [])
    return data if isinstance(data, list) else []


def feedback_multiplier(chain: dict, feedback: list[dict]) -> tuple[float, dict | None]:
    """Return (multiplier, matching entry) for a chain, or (1.0, None)."""
    for entry in feedback:
        if entry.get("verdict") != "false_positive":
            continue
        if entry.get("user") and entry["user"] != chain.get("user"):
            continue
        pattern = entry.get("pattern")  # e.g. "brute_force" or "brute_force+initial_access"
        if pattern:
            stages = "+".join(chain.get("stage_names", []))
            if pattern not in stages and pattern != chain.get("brute_force_subtype"):
                continue
        return float(entry.get("weight", DEFAULT_FEEDBACK_WEIGHT)), entry
    return 1.0, None


def score_chain(chain: dict, baseline=None, events: list[dict] | None = None,
                feedback: list[dict] | None = None,
                reference_time: datetime | None = None) -> dict:
    """Score one chain in place and return it (adds risk fields)."""
    chain_length = chain["chain_length"]
    # Rarity: max baseline deviation over the chain's stage events.
    rarity = 0.0
    reasons: list[str] = []
    if baseline is not None and events:
        stage_times = {s["timestamp"] for s in chain["stages"]}
        for e in events:
            if e.get("timestamp") and e["timestamp"].isoformat() in stage_times:
                dev, rs = baseline.score_event(e)
                if dev > rarity:
                    rarity = dev
                    reasons = rs
    elif baseline is not None:
        # No event list: score the stage representative (user/host/ip).
        for s in chain["stages"]:
            ev = {"user": s.get("user"), "host": s.get("host"),
                  "src_ip": s.get("src_ip"), "event_type": "successful_login",
                  "timestamp": datetime.fromisoformat(s["timestamp"]) if s.get("timestamp") else None}
            dev, rs = baseline.score_event(ev)
            rarity = max(rarity, dev)
            if dev == rarity:
                reasons = rs
    rarity_factor = 0.5 + rarity
    # Asset criticality: most critical host in the chain.
    asset = max((ASSET_CRITICALITY.get(h, 1.1) for h in chain.get("hosts", [])), default=1.0)
    if chain.get("user") in PRIVILEGED_USERS:
        asset *= 1.2
    # Time decay vs. the newest event in the input (or the chain end).
    decay = 1.0
    if reference_time is not None and chain.get("last_seen"):
        last = datetime.fromisoformat(chain["last_seen"])
        age_days = max(0.0, (reference_time - last).total_seconds() / 86400.0)
        decay = max(0.5, math.exp(-age_days / 7.0)) if age_days > 1.0 else 1.0
    raw = chain_length * 20 * rarity_factor * asset * decay
    mult, entry = feedback_multiplier(chain, feedback or [])
    risk = raw * mult
    chain["rarity"] = round(rarity, 3)
    chain["rarity_reasons"] = reasons
    chain["asset_criticality"] = round(asset, 2)
    chain["time_decay"] = round(decay, 3)
    chain["feedback_multiplier"] = mult
    chain["feedback_applied"] = entry
    chain["risk_score_raw"] = round(raw, 1)
    chain["risk_score"] = int(min(100, max(0, round(risk))))
    chain["severity"] = ("critical" if chain["risk_score"] >= 80 else
                         "high" if chain["risk_score"] >= 60 else
                         "medium" if chain["risk_score"] >= 40 else "low")
    return chain


def score_chains(chains: list[dict], baseline=None, events: list[dict] | None = None,
                 feedback: list[dict] | None = None) -> tuple[list[dict], list[dict]]:
    """Score all chains; split into (incidents >= threshold, suppressed)."""
    reference = None
    if events:
        times = [e["timestamp"] for e in events if e.get("timestamp")]
        reference = max(times) if times else None
    scored = [score_chain(c, baseline, events, feedback, reference) for c in chains]
    scored.sort(key=lambda c: (-c["risk_score"], c["first_seen"] or ""))
    incidents = [c for c in scored if c["risk_score"] >= INCIDENT_THRESHOLD]
    suppressed = [c for c in scored if c["risk_score"] < INCIDENT_THRESHOLD]
    # Deterministic incident IDs.
    for i, inc in enumerate(incidents, 1):
        stamp = (inc["first_seen"] or "")[:16].replace("-", "").replace(":", "").replace("T", "-")
        inc["incident_id"] = f"INC-{inc['user'].upper()}-{stamp}-{i:02d}"
    for i, sup in enumerate(suppressed, 1):
        stamp = (sup["first_seen"] or "")[:16].replace("-", "").replace(":", "").replace("T", "-")
        sup["incident_id"] = f"SUP-{sup['user'].upper()}-{stamp}-{i:02d}"
        sup["suppressed_reason"] = (
            f"risk {sup['risk_score']} < threshold {INCIDENT_THRESHOLD} — "
            f"{sup['chain_length']}-stage chain, rarity {sup['rarity']}")
    return incidents, suppressed
