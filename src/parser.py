"""Log parser for syslog / auth.log style lines.

Supported lines (all sample / lab data only — TEST-NET IPs, no real hosts):

    Nov 20 10:15:32 web01 sshd[1234]: Failed password for invalid user admin from 203.0.113.45 port 22 ssh2
    Nov 20 10:16:01 web01 sshd[1234]: Accepted password for alice from 203.0.113.10 port 22 ssh2
    Nov 20 10:20:11 web01 sudo: bob : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/cat /etc/shadow
    Nov 20 10:21:00 web01 sudo: bob : user NOT in sudoers ; TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/systemctl restart nginx

Each parsed event is a dict with a normalised ``event_type``:
``failed_login``, ``successful_login``, ``sudo_failure``, ``sudo_success``,
``connection_closed`` or ``other``.
"""

from __future__ import annotations

import re
from datetime import datetime

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

# Nov 20 10:15:32 web01 sshd[1234]: <message>
SYSLOG_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+"
    r"(?P<service>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$"
)

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
FAILED_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)"
)
ACCEPTED_RE = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\S+)"
)
SUDO_RE = re.compile(
    r"sudo:\s+(?P<user>\S+)\s*:\s*(?P<detail>.*?)(?:\s*;\s*TTY=.*)?$"
)


def parse_timestamp(mon: str, day: str, time_str: str, year: int = 2026) -> datetime:
    """Parse a syslog timestamp (syslog carries no year; default 2026)."""
    hour, minute, second = (int(p) for p in time_str.split(":"))
    return datetime(year, MONTHS[mon], int(day), hour, minute, second)


def parse_line(line: str, year: int = 2026) -> dict | None:
    """Parse one log line. Returns None for blank / unparsable lines."""
    line = line.strip()
    if not line:
        return None
    m = SYSLOG_RE.match(line)
    if not m:
        return {"raw": line, "event_type": "unparsed", "timestamp": None,
                "host": None, "service": None, "user": None, "src_ip": None}
    msg = m.group("msg")
    service = m.group("service")
    event = {
        "raw": line,
        "timestamp": parse_timestamp(m.group("mon"), m.group("day"),
                                     m.group("time"), year),
        "host": m.group("host"),
        "service": service,
        "user": None,
        "src_ip": None,
        "message": msg,
        "event_type": "other",
    }
    ip_m = IP_RE.search(msg)
    if ip_m:
        event["src_ip"] = ip_m.group(0)

    fm = FAILED_RE.search(msg)
    if fm:
        event.update(event_type="failed_login", user=fm.group("user"),
                     src_ip=fm.group("ip"))
        return event
    am = ACCEPTED_RE.search(msg)
    if am:
        event.update(event_type="successful_login", user=am.group("user"),
                     src_ip=am.group("ip"))
        return event
    if service == "sudo" or msg.startswith("sudo:"):
        sm = SUDO_RE.search(msg) or SUDO_RE.search("sudo: " + msg)
        user = sm.group("user") if sm else None
        detail = sm.group("detail") if sm else msg
        if user:
            event["user"] = user
        if "NOT in sudoers" in msg or "incorrect password attempt" in msg:
            event["event_type"] = "sudo_failure"
        elif "COMMAND=" in msg:
            event["event_type"] = "sudo_success"
        event["sudo_detail"] = detail
        return event
    if "Connection closed" in msg or "Disconnected" in msg:
        event["event_type"] = "connection_closed"
        return event
    return event


def parse_file(path: str, year: int = 2026) -> list[dict]:
    """Parse a whole log file, skipping blank lines."""
    events = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            ev = parse_line(line, year=year)
            if ev is not None:
                events.append(ev)
    # Syslog files are normally chronological; sort defensively so
    # sliding-window rules behave the same on shuffled input.
    events.sort(key=lambda e: (e["timestamp"] is None, e["timestamp"]))
    return events
