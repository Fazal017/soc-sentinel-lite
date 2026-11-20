"""Attack-chain reconstruction (v2) — Sentinel Graph.

v1 emits one alert per rule per window: a brute force is R001, the
login after it is R002, the sudo abuse is R006 — seven separate alerts
for what is, in reality, one intrusion.  An analyst has to re-assemble
the story by hand, and a *slow* attacker never trips any single rule
at all.

v2 instead reconstructs the *chain* — one incident per intrusion,
linking stages in causal + temporal order through the entity graph:

    Stage 1  RECON / BRUTE FORCE   T1110.001 / T1595.001
             fast (>=5 failures / 5 min, one IP) OR
             slow (<5 failures/hour, >=8 over 6 h) OR
             distributed (same user, 3+ IPs, >=6 failures / 24 h)
    Stage 2  INITIAL ACCESS        T1078
             successful login for the same user, after stage 1,
             from an attacking IP (or a new IP)
    Stage 3  PRIVILEGE ESCALATION  T1548.003
             sudo failures then a sudo success to root, same user/host
    Stage 4  LATERAL MOVEMENT      T1021.004 / T1078
             successful login for the same user on a *different* host
    Stage 5  DATA STAGING          T1074 / T1048
             sudo success whose command stages data for exfiltration
             (tar / scp / rsync / zip / mysqldump / cat /etc/shadow)

A chain is anchored on stage 1: without a brute-force precursor,
ordinary logins and sudo use — however noisy — are *not* an incident.
That is the false-positive control: a known user who mistypes five
times from their usual IP at 10:00 builds at most a 2-stage, low-rarity
chain, which scores below the incident threshold and is dropped.

Stages are linked only if they share the user (and, where relevant,
the IP / host) and fall inside a 24-hour chain window.  Each incident
carries its full stage list, MITRE technique sequence, time span,
evidence lines and the graph nodes it touched — one incident, one story.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import timedelta

STAGING_KEYWORDS = (
    "tar ", "tar -", "scp ", "rsync", "zip ", "mysqldump",
    "/etc/shadow", "cat /etc/passwd", "curl ", "wget ",
    "stage.tar", "exfil",
)
# Commands that are staging *only* when they appear after a compromise
# in a chain — a lone tar in a cron job is not an incident on its own.

STAGE_MITRE = {
    "brute_force": ("T1110.001", "Password Guessing", "Credential Access"),
    "initial_access": ("T1078", "Valid Accounts", "Initial Access"),
    "privilege_escalation": ("T1548.003", "Sudo and Sudo Caching", "Privilege Escalation"),
    "lateral_movement": ("T1021.004", "SSH", "Lateral Movement"),
    "data_staging": ("T1074", "Data Staged", "Collection"),
}

CHAIN_WINDOW = timedelta(hours=24)
SLOW_WINDOW = timedelta(hours=6)


def _is_staging(event: dict) -> bool:
    text = ((event.get("sudo_detail") or "") + " " + (event.get("message") or "")).lower()
    return any(k in text for k in STAGING_KEYWORDS)


def _stage(technique: str, event: dict, detail: str = "") -> dict:
    mitre, name, tactic = STAGE_MITRE[technique]
    return {
        "stage": technique, "mitre_technique": mitre, "mitre_name": name,
        "mitre_tactic": tactic,
        "timestamp": event["timestamp"].isoformat() if event.get("timestamp") else None,
        "user": event.get("user"), "src_ip": event.get("src_ip"),
        "host": event.get("host"), "detail": detail,
        "evidence": event.get("raw"),
    }


def detect_brute_force_clusters(events: list[dict]) -> list[dict]:
    """Detect brute-force clusters per user, classified fast/slow/distributed.

    Returns one cluster per user (the strongest / earliest), with:
    ``subtype`` in {fast, slow, distributed, mixed}, ``failures``,
    ``ips``, ``first_seen``, ``last_seen``, ``max_per_hour``.
    A cluster needs >=5 failures in 24 h for the same user.

    Plus IP-anchored clusters: an attacker who enumerates *many*
    usernames from one IP (the classic v1 sample — 6 users, 1 IP)
    never reaches 5 failures for any single user, so per-user
    clustering alone would miss it entirely.  An IP with >=5 failures
    in 6 h therefore also forms a cluster, anchored on the user who
    later logs in successfully from that IP.  IP clusters whose
    failures are already covered by a per-user cluster are skipped,
    so the same attack is never counted twice.
    """
    by_user: dict[str, list[dict]] = defaultdict(list)
    for e in events:
        if e["event_type"] == "failed_login" and e.get("user"):
            by_user[e["user"]].append(e)
    clusters = []
    for user, evs in by_user.items():
        evs = sorted(evs, key=lambda e: e["timestamp"])
        if len(evs) < 5:
            continue
        # Sliding 6-hour window: the densest slow window.
        best: list[dict] = []
        for start in evs:
            window = [e for e in evs if start["timestamp"] <= e["timestamp"] <= start["timestamp"] + SLOW_WINDOW]
            if len(window) > len(best):
                best = window
        if len(best) < 5:
            best = evs
        ips = sorted({e["src_ip"] for e in best if e.get("src_ip")})
        # Max failures in any single 60-minute window (per IP, worst IP).
        max_per_hour = 0
        for ip in ips or [None]:
            ip_evs = [e for e in best if e.get("src_ip") == ip]
            for s in ip_evs:
                n = sum(1 for e in ip_evs if s["timestamp"] <= e["timestamp"] <= s["timestamp"] + timedelta(hours=1))
                max_per_hour = max(max_per_hour, n)
        span = (best[-1]["timestamp"] - best[0]["timestamp"]).total_seconds() / 3600.0
        fast = False
        for ip in ips:
            ip_evs = [e for e in evs if e.get("src_ip") == ip]
            for s in ip_evs:
                n = sum(1 for e in ip_evs
                        if s["timestamp"] <= e["timestamp"]
                        <= s["timestamp"] + timedelta(minutes=5))
                if n >= 5:
                    fast = True
        distributed = len(ips) >= 3 and len(best) >= 6
        slow = (not fast) and len(best) >= 8 and span >= 2.0 and max_per_hour <= 4
        if distributed and slow:
            subtype = "mixed"  # slow *and* distributed — the hardest to catch
        elif distributed:
            subtype = "distributed"
        elif slow:
            subtype = "slow"
        elif fast:
            subtype = "fast"
        else:
            # >=5 failures in 6 h, not fast/slow/distributed by the strict
            # definitions — still a brute-force cluster, just unclassified.
            subtype = "cluster"
        clusters.append({
            "user": user, "subtype": subtype, "failures": best,
            "count": len(best), "ips": ips,
            "first_seen": best[0]["timestamp"], "last_seen": best[-1]["timestamp"],
            "max_per_hour": max_per_hour, "span_hours": round(span, 2),
            "distributed": distributed, "slow": slow, "fast": fast,
            "anchor": "user",
            "target_users": sorted({e["user"] for e in best if e.get("user")}),
        })
    # -- IP-anchored clusters (enumeration / many-users-one-IP) --------
    covered = {e.get("raw") for c in clusters for e in c["failures"]}
    by_ip: dict[str, list[dict]] = defaultdict(list)
    for e in events:
        if e["event_type"] == "failed_login" and e.get("src_ip"):
            by_ip[e["src_ip"]].append(e)
    for ip, evs in by_ip.items():
        evs = sorted(evs, key=lambda e: e["timestamp"])
        best: list[dict] = []
        for start in evs:
            window = [e for e in evs if start["timestamp"] <= e["timestamp"] <= start["timestamp"] + SLOW_WINDOW]
            if len(window) > len(best):
                best = window
        if len(best) < 5:
            continue
        # Who later logged in successfully from this IP? That is the
        # compromised account; fall back to the most-tried username.
        later = [e for e in events
                 if e["event_type"] == "successful_login" and e.get("src_ip") == ip
                 and best[0]["timestamp"] <= e["timestamp"] <= best[0]["timestamp"] + CHAIN_WINDOW]
        user = later[0]["user"] if later else Counter(e["user"] for e in best).most_common(1)[0][0]
        covered_frac = (sum(1 for e in best if e.get("raw") in covered) / len(best)) if best else 0.0
        if covered_frac >= 0.8:
            continue  # already explained by a per-user cluster
        overlap = any(
            c.get("anchor") == "user" and c["user"] == user and ip in c["ips"]
            and c["first_seen"] <= best[-1]["timestamp"] and best[0]["timestamp"] <= c["last_seen"]
            for c in clusters)
        if overlap:
            continue  # same user + IP already has a per-user chain
        span = (best[-1]["timestamp"] - best[0]["timestamp"]).total_seconds() / 3600.0
        fast = any(sum(1 for e in evs if s["timestamp"] <= e["timestamp"] <= s["timestamp"] + timedelta(minutes=5)) >= 5
                   for s in evs)
        clusters.append({
            "user": user, "subtype": "fast" if fast else "cluster",
            "failures": best, "count": len(best), "ips": [ip],
            "first_seen": best[0]["timestamp"], "last_seen": best[-1]["timestamp"],
            "max_per_hour": len(best), "span_hours": round(span, 2),
            "distributed": False, "slow": False, "fast": fast,
            "anchor": "ip",
            "target_users": sorted({e["user"] for e in best if e.get("user")}),
        })
    return sorted(clusters, key=lambda c: c["first_seen"])


def reconstruct_chains(events: list[dict], baseline=None) -> list[dict]:
    """Link stages into incidents. Returns raw chains (unscored).

    Each chain dict has: ``user``, ``stages`` (ordered), ``ips``,
    ``hosts``, ``first_seen``, ``last_seen``, ``mitre_sequence``.
    """
    events = sorted(events, key=lambda e: (e["timestamp"] is None, e["timestamp"]))
    clusters = detect_brute_force_clusters(events)
    chains = []
    for cl in clusters:
        user = cl["user"]
        start, end = cl["first_seen"], cl["last_seen"]
        window_end = start + CHAIN_WINDOW
        stages = [_stage("brute_force", cl["failures"][0],
                         detail=f"{cl['subtype']} brute force: {cl['count']} failed logins "
                                f"from {len(cl['ips'])} IP(s) over {cl['span_hours']}h "
                                f"(max {cl['max_per_hour']}/hour)")]
        stages[0]["timestamp"] = start.isoformat()
        # Stage 2 — initial access: success for same user after stage 1.
        success = [e for e in events
                   if e["event_type"] == "successful_login" and e.get("user") == user
                   and start <= e["timestamp"] <= window_end]
        initial = None
        for e in success:
            if e.get("src_ip") in cl["ips"] or e["timestamp"] >= cl["failures"][-1]["timestamp"]:
                initial = e
                break
        if not initial:
            # Brute force with no success is still a chain, but a short one.
            chains.append(_chain_dict(user, stages, cl))
            continue
        stages.append(_stage("initial_access", initial,
                             detail=f"successful login for '{user}' from {initial.get('src_ip')} "
                                    f"on {initial.get('host')}"))
        first_host = initial.get("host")
        # Stage 3 — privilege escalation: sudo failure(s) then sudo success.
        sudo_fail = [e for e in events
                     if e["event_type"] == "sudo_failure" and e.get("user") == user
                     and initial["timestamp"] <= e["timestamp"] <= window_end]
        sudo_ok = [e for e in events
                   if e["event_type"] == "sudo_success" and e.get("user") == user
                   and initial["timestamp"] <= e["timestamp"] <= window_end]
        esc_event = None
        if sudo_fail and sudo_ok:
            esc_event = next((e for e in sudo_ok if e["timestamp"] >= sudo_fail[0]["timestamp"]), sudo_ok[0])
            stages.append(_stage("privilege_escalation", esc_event,
                                 detail=f"{len(sudo_fail)} sudo failure(s), then sudo success "
                                        f"to root ({esc_event.get('sudo_detail') or ''})"))
        elif sudo_fail:
            stages.append(_stage("privilege_escalation", sudo_fail[0],
                                 detail=f"{len(sudo_fail)} sudo failure(s) by '{user}' (no success yet)"))
        # Stage 4 — lateral movement: success on a *different* host.
        lateral = None
        for e in success:
            if e["timestamp"] >= initial["timestamp"] and e.get("host") != first_host:
                lateral = e
                break
        if lateral:
            stages.append(_stage("lateral_movement", lateral,
                                 detail=f"login for '{user}' on new host {lateral.get('host')} "
                                        f"from {lateral.get('src_ip')}"))
        # Stage 5 — data staging: sudo success with a staging command,
        # after initial access (preferably after lateral movement).
        anchor = lateral["timestamp"] if lateral else initial["timestamp"]
        staging = [e for e in sudo_ok
                   if e["timestamp"] >= anchor and _is_staging(e)]
        if staging:
            # Do not double-count the escalation sudo event as staging
            # unless it is itself a staging command.
            s = staging[0]
            if not any(st["stage"] == "data_staging" for st in stages):
                stages.append(_stage("data_staging", s,
                                     detail=f"staging command: {s.get('sudo_detail') or s.get('message')}"))
        chains.append(_chain_dict(user, stages, cl))
    return chains


def _chain_dict(user: str, stages: list[dict], cluster: dict) -> dict:
    first = stages[0]["timestamp"]
    last = stages[-1]["timestamp"]
    return {
        "user": user,
        "stages": stages,
        "chain_length": len(stages),
        "stage_names": [s["stage"] for s in stages],
        "mitre_sequence": [s["mitre_technique"] for s in stages],
        "mitre_tactics": [s["mitre_tactic"] for s in stages],
        "ips": cluster["ips"],
        "hosts": sorted({s["host"] for s in stages if s.get("host")}),
        "first_seen": first, "last_seen": last,
        "brute_force_subtype": cluster["subtype"],
        "brute_force_count": cluster["count"],
        "brute_force_span_hours": cluster["span_hours"],
    }
