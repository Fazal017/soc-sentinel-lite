"""Detection engine: sliding-window correlation over parsed events.

Each rule produces alerts shaped as::

    {
      "rule_id": "R001", "rule_name": "SSH Brute Force",
      "severity": "high", "risk_score": 79,
      "src_ip": "203.0.113.45", "user": "admin",
      "first_seen": "2026-11-20T10:15:32", "last_seen": "...",
      "count": 6, "mitre_tactic": "Credential Access",
      "mitre_technique": "T1110.001", "mitre_name": "Password Guessing",
      "evidence": [... up to 5 raw log lines ...],
      "description": "...",
    }

Deduplication: one alert per (rule_id, src_ip, user, window-start).
A repeat of the same behaviour in a later window creates a new alert —
that is by design, so an analyst sees persistence, not just a first hit.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta

from .geo import country_for, country_name
from .rules import Rule, get_rule


def _window(events, start, minutes):
    end = start + timedelta(minutes=minutes)
    return [e for e in events if start <= e["timestamp"] <= end]


def _alert(rule: Rule, *, src_ip, user, first, last, count, evidence, description):
    return {
        "rule_id": rule.id,
        "rule_name": rule.name,
        "severity": rule.severity,
        "risk_score": rule.risk_score(count),
        "src_ip": src_ip,
        "user": user,
        "first_seen": first.isoformat() if first else None,
        "last_seen": last.isoformat() if last else None,
        "count": count,
        "mitre_tactic": rule.mitre_tactic,
        "mitre_technique": rule.mitre_technique,
        "mitre_name": rule.mitre_name,
        "evidence": [e["raw"] for e in evidence[:5]],
        "description": description,
    }


def _detect_brute_force(events, rule: Rule):
    """R001 — N failed logins from one IP inside the window."""
    alerts, seen = [], set()
    failed = [e for e in events if e["event_type"] == "failed_login" and e["src_ip"]]
    by_ip = defaultdict(list)
    for e in failed:
        by_ip[e["src_ip"]].append(e)
    for ip, evs in by_ip.items():
        evs.sort(key=lambda e: e["timestamp"])
        for start_ev in evs:
            key = (ip, start_ev["timestamp"].date(), start_ev["timestamp"].hour)
            window = _window(evs, start_ev["timestamp"], rule.window_minutes)
            if len(window) >= rule.threshold and key not in seen:
                seen.add(key)
                users = sorted({e["user"] for e in window if e["user"]})
                alerts.append(_alert(
                    rule, src_ip=ip, user=", ".join(users) or None,
                    first=window[0]["timestamp"], last=window[-1]["timestamp"],
                    count=len(window), evidence=window,
                    description=(f"{len(window)} failed SSH logins from {ip} "
                                 f"within {rule.window_minutes} minutes "
                                 f"(users: {', '.join(users)}).")))
                break  # one alert per IP per hour-bucket; later windows re-fire
    return alerts


def _detect_success_after_bruteforce(events, rule: Rule, brute_ips):
    """R002 — successful login from an IP that brute-forced recently."""
    alerts = []
    for e in events:
        if e["event_type"] != "successful_login" or not e["src_ip"]:
            continue
        for bf_ip, bf_time in brute_ips:
            if e["src_ip"] == bf_ip and timedelta(0) <= e["timestamp"] - bf_time <= timedelta(minutes=rule.window_minutes):
                alerts.append(_alert(
                    rule, src_ip=e["src_ip"], user=e["user"],
                    first=bf_time, last=e["timestamp"], count=2, evidence=[e],
                    description=(f"Successful login for '{e['user']}' from {e['src_ip']} "
                                 f"{int((e['timestamp'] - bf_time).total_seconds() // 60)} min "
                                 f"after brute-force activity — possible compromise.")))
                break
    return alerts


def _detect_root_login(events, rule: Rule):
    """R003 — successful login as root (privileged account)."""
    alerts = []
    for e in events:
        if e["event_type"] == "successful_login" and e["user"] == "root":
            alerts.append(_alert(
                rule, src_ip=e["src_ip"], user="root",
                first=e["timestamp"], last=e["timestamp"], count=1, evidence=[e],
                description=(f"Successful ROOT login from {e['src_ip']}. "
                             f"Root should never log in directly over SSH.")))
    return alerts


def _detect_user_enumeration(events, rule: Rule):
    """R004 — one IP trying many distinct usernames (scan / enumeration)."""
    alerts, seen = [], set()
    failed = [e for e in events if e["event_type"] == "failed_login" and e["src_ip"]]
    by_ip = defaultdict(list)
    for e in failed:
        by_ip[e["src_ip"]].append(e)
    for ip, evs in by_ip.items():
        evs.sort(key=lambda e: e["timestamp"])
        for start_ev in evs:
            window = _window(evs, start_ev["timestamp"], rule.window_minutes)
            users = {e["user"] for e in window if e["user"]}
            if len(users) >= rule.threshold and ip not in seen:
                seen.add(ip)
                alerts.append(_alert(
                    rule, src_ip=ip, user=", ".join(sorted(users)),
                    first=window[0]["timestamp"], last=window[-1]["timestamp"],
                    count=len(users), evidence=window,
                    description=(f"{len(users)} distinct usernames probed from {ip} "
                                 f"within {rule.window_minutes} minutes — "
                                 f"user-enumeration / port-scan behaviour.")))
                break
    return alerts


def _detect_impossible_travel(events, rule: Rule):
    """R005 — same user, two countries, faster than travel allows."""
    alerts, seen = [], set()
    logins = [e for e in events
              if e["event_type"] == "successful_login" and e["src_ip"]
              and country_for(e["src_ip"])]
    by_user = defaultdict(list)
    for e in logins:
        by_user[e["user"]].append(e)
    for user, evs in by_user.items():
        evs.sort(key=lambda e: e["timestamp"])
        for i, a in enumerate(evs):
            for b in evs[i + 1:]:
                if b["timestamp"] - a["timestamp"] > timedelta(minutes=rule.window_minutes):
                    break
                ca, cb = country_for(a["src_ip"]), country_for(b["src_ip"])
                if ca and cb and ca != cb and (user, a["src_ip"], b["src_ip"]) not in seen:
                    seen.add((user, a["src_ip"], b["src_ip"]))
                    alerts.append(_alert(
                        rule, src_ip=b["src_ip"], user=user,
                        first=a["timestamp"], last=b["timestamp"], count=2,
                        evidence=[a, b],
                        description=(f"User '{user}' logged in from "
                                     f"{country_name(ca)} ({a['src_ip']}) and "
                                     f"{country_name(cb)} ({b['src_ip']}) "
                                     f"{int((b['timestamp'] - a['timestamp']).total_seconds() // 60)} min apart — "
                                     f"impossible travel, possible session hijack.")))
    return alerts


def _detect_sudo_abuse(events, rule: Rule):
    """R006 — repeated sudo failures, then (optionally) a sudo success."""
    alerts, seen = [], set()
    failures = [e for e in events if e["event_type"] == "sudo_failure" and e["user"]]
    by_user = defaultdict(list)
    for e in failures:
        by_user[e["user"]].append(e)
    for user, evs in by_user.items():
        evs.sort(key=lambda e: e["timestamp"])
        for start_ev in evs:
            window = _window(evs, start_ev["timestamp"], rule.window_minutes)
            if len(window) >= rule.threshold and user not in seen:
                seen.add(user)
                later = [e for e in events
                         if e["event_type"] == "sudo_success" and e["user"] == user
                         and window[-1]["timestamp"] <= e["timestamp"]
                         <= window[-1]["timestamp"] + timedelta(minutes=rule.window_minutes)]
                desc = (f"{len(window)} failed sudo attempts by '{user}' within "
                        f"{rule.window_minutes} minutes.")
                if later:
                    desc += " Followed by a successful sudo to root — possible privilege escalation."
                alerts.append(_alert(
                    rule, src_ip=window[0]["src_ip"], user=user,
                    first=window[0]["timestamp"], last=window[-1]["timestamp"],
                    count=len(window), evidence=window + later[:2], description=desc))
                break
    return alerts


DETECTORS = {
    "R001": _detect_brute_force,
    "R003": _detect_root_login,
    "R004": _detect_user_enumeration,
    "R005": _detect_impossible_travel,
    "R006": _detect_sudo_abuse,
}


def detect(events: list[dict], rules: list[Rule]) -> list[dict]:
    """Run all enabled rules over *events*; return alerts sorted by risk."""
    alerts: list[dict] = []
    # Brute-force IPs feed R002, so run R001 first and reuse its output.
    brute_ips: list[tuple[str, object]] = []
    r001 = get_rule(rules, "R001")
    if r001:
        bf = _detect_brute_force(events, r001)
        alerts.extend(bf)
        for a in bf:
            if a["first_seen"]:
                brute_ips.append((a["src_ip"], datetime.fromisoformat(a["first_seen"])))
    for rule in rules:
        if rule.id == "R001":
            continue
        if rule.id == "R002":
            alerts.extend(_detect_success_after_bruteforce(events, rule, brute_ips))
        elif rule.id in DETECTORS:
            alerts.extend(DETECTORS[rule.id](events, rule))
    # De-duplicate identical (rule, ip, user, first_seen) alerts, keep highest score.
    dedup: dict[tuple, dict] = {}
    for a in alerts:
        key = (a["rule_id"], a["src_ip"], a["user"], a["first_seen"])
        if key not in dedup or a["risk_score"] > dedup[key]["risk_score"]:
            dedup[key] = a
    out = sorted(dedup.values(),
                 key=lambda a: (-a["risk_score"], a["first_seen"] or ""))
    return out
