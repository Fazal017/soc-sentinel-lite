"""SQLite alert store with deduplication.

Schema (one row per alert; ``UNIQUE`` on the natural key prevents the
same alert being stored twice when the same log is re-ingested)::

    alerts(rule_id, src_ip, user, first_seen, last_seen, severity,
           risk_score, mitre_technique, description, evidence_json)
"""

from __future__ import annotations

import json
import sqlite3

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id TEXT NOT NULL,
    rule_name TEXT,
    src_ip TEXT,
    user TEXT,
    first_seen TEXT,
    last_seen TEXT,
    severity TEXT,
    risk_score INTEGER,
    mitre_tactic TEXT,
    mitre_technique TEXT,
    mitre_name TEXT,
    description TEXT,
    evidence_json TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    UNIQUE(rule_id, src_ip, user, first_seen)
);
"""


def init_db(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.execute(SCHEMA)
    conn.commit()
    return conn


def store_alerts(conn: sqlite3.Connection, alerts: list[dict]) -> tuple[int, int]:
    """Insert alerts; returns (inserted, duplicates_skipped)."""
    inserted = skipped = 0
    for a in alerts:
        try:
            conn.execute(
                """INSERT INTO alerts
                   (rule_id, rule_name, src_ip, user, first_seen, last_seen,
                    severity, risk_score, mitre_tactic, mitre_technique,
                    mitre_name, description, evidence_json)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                # Normalise None -> "" : SQLite treats NULLs as distinct in
                # a UNIQUE constraint, so a NULL src_ip would never dedup.
                (a["rule_id"], a["rule_name"], a["src_ip"] or "", a["user"] or "",
                 a["first_seen"], a["last_seen"], a["severity"], a["risk_score"],
                 a["mitre_tactic"], a["mitre_technique"], a["mitre_name"],
                 a["description"], json.dumps(a["evidence"])),
            )
            inserted += 1
        except sqlite3.IntegrityError:
            skipped += 1
    conn.commit()
    return inserted, skipped


def alert_counts(conn: sqlite3.Connection) -> dict:
    rows = conn.execute(
        "SELECT severity, COUNT(*) FROM alerts GROUP BY severity").fetchall()
    return {sev: n for sev, n in rows}
