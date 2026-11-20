#!/usr/bin/env python3
"""Generate a synthetic 7-day auth history for Sentinel v2 baselining.

Output: ``logs/history_7d.log`` — ~2,000 syslog lines, Nov 13-19 2026,
deterministic (``random.seed(42)``), stdlib only.

What it contains, and why:
* **Normal traffic (~2,000 events):** users alice, bob, carol, deploy
  log in from their usual IP (203.0.113.10) on their usual host
  (web01), 08:00-18:00, with routine sudo (systemctl status,
  journalctl, apt update), cron jobs and disconnects.  Occasional
  single failed login (~2%, followed later by a success) — normal
  mistyping, not an attack.  One event every 5 minutes, 24h/day,
  so the file is a realistic week, not just working hours.
* **A slow attack embedded in the history (~18 events):** the
  ``admin`` account is probed 2-3 times a day from 192.0.2.99,
  always at night, never succeeding.  It is there on purpose: the
  peer-group baseline uses the *median* failure rate, so one
  attacked account cannot drag the baseline with it — and the
  baseline for ``admin`` correctly ends up with a high failure
  rate, which is itself a signal.

All IPs are RFC 5737 documentation ranges. No real hosts, no real
credentials, no network.

Usage:
    python3 scripts/generate_history.py
    python3 scripts/generate_history.py --output logs/history_7d.log --days 7
"""

from __future__ import annotations

import argparse
import random
from datetime import datetime, timedelta
from pathlib import Path

USERS = ["alice", "bob", "carol", "deploy"]
NORMAL_IP = "203.0.113.10"
NORMAL_HOST = "web01"
SLOW_ATTACK_IP = "192.0.2.99"
SLOW_ATTACK_USER = "admin"

BENIGN_SUDO = [
    "/usr/bin/systemctl status nginx",
    "/usr/bin/systemctl status app",
    "/usr/bin/journalctl -u nginx",
    "/usr/bin/journalctl -u app",
    "/usr/bin/apt update",
    "/usr/bin/systemctl reload nginx",
]
CRON_CMDS = [
    "(root) CMD (/usr/local/bin/backup.sh)",
    "(deploy) CMD (cd /opt/app && ./healthcheck.sh)",
    "(root) CMD (/usr/sbin/logrotate /etc/logrotate.conf)",
]

MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
          "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def fmt(ts: datetime, host: str, service: str, pid: int, msg: str) -> str:
    return (f"{MONTHS[ts.month - 1]} {ts.day:2d} {ts.strftime('%H:%M:%S')} "
            f"{host} {service}[{pid}]: {msg}")


def generate(days: int = 7, seed: int = 42) -> list[str]:
    rng = random.Random(seed)
    lines: list[str] = []
    start = datetime(2026, 11, 13, 0, 0, 0)
    port = 48000
    # One event every 5 minutes for `days` days: 7 * 24 * 12 = 2016.
    steps = days * 24 * 12
    for i in range(steps):
        ts = start + timedelta(minutes=5 * i)
        hour = ts.hour
        working = 8 <= hour <= 18
        roll = rng.random()
        user = rng.choice(USERS)
        port += rng.randint(1, 7)
        if working and roll < 0.45:
            lines.append(fmt(ts, NORMAL_HOST, "sshd", 2140,
                             f"Accepted password for {user} from {NORMAL_IP} port {port} ssh2"))
        elif working and roll < 0.60:
            lines.append(fmt(ts, NORMAL_HOST, "sudo", 0,
                             f"{user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; "
                             f"COMMAND={rng.choice(BENIGN_SUDO)}"))
        elif roll < 0.70:
            lines.append(fmt(ts, NORMAL_HOST, "CRON", 301, rng.choice(CRON_CMDS)))
        elif working and roll < 0.78:
            lines.append(fmt(ts, NORMAL_HOST, "sshd", 2140,
                             f"Disconnected from user {user} {NORMAL_IP} port {port} [preauth]"))
        elif working and roll < 0.80:
            # Normal mistype: one failure, no cluster.
            lines.append(fmt(ts, NORMAL_HOST, "sshd", 2140,
                             f"Failed password for {user} from {NORMAL_IP} port {port} ssh2"))
        elif working:
            lines.append(fmt(ts, NORMAL_HOST, "sshd", 2140,
                             f"Accepted publickey for {user} from {NORMAL_IP} port {port} ssh2"))
        else:
            # Overnight: mostly cron / backup, occasional deploy healthcheck.
            if roll < 0.7:
                lines.append(fmt(ts, NORMAL_HOST, "CRON", 301, rng.choice(CRON_CMDS)))
            else:
                lines.append(fmt(ts, NORMAL_HOST, "sshd", 2140,
                                 f"Accepted publickey for deploy from {NORMAL_IP} port {port} ssh2"))
    # Slow attack embedded in the history: admin, 2-3x/day, night only.
    for day in range(days):
        for _ in range(rng.choice([2, 3])):
            ts = start + timedelta(days=day, hours=rng.randint(1, 4),
                                   minutes=rng.randint(0, 59))
            lines.append(fmt(ts, NORMAL_HOST, "sshd", 2140,
                             f"Failed password for invalid user {SLOW_ATTACK_USER} "
                             f"from {SLOW_ATTACK_IP} port {51000 + rng.randint(0, 99)} ssh2"))
    # Sort chronologically (syslog order) — the slow-attack lines were
    # appended out of order.
    def _ts(line: str) -> datetime:
        parts = line.split()
        mon = MONTHS.index(parts[0]) + 1
        day = int(parts[1])
        h, m, s = (int(p) for p in parts[2].split(":"))
        return datetime(2026, mon, day, h, m, s)
    lines.sort(key=_ts)
    return lines


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate logs/history_7d.log")
    ap.add_argument("--output", default="logs/history_7d.log")
    ap.add_argument("--days", type=int, default=7)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()
    lines = generate(days=args.days, seed=args.seed)
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[+] Wrote {len(lines)} events to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
