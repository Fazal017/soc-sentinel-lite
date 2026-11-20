"""Tests for SOC Sentinel Lite — run with:  python3 -m unittest discover -s tests -v"""

import os
import sys
import unittest
from datetime import datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.detector import detect
from src.parser import parse_file, parse_line
from src.report import generate_html
from src.rules import load_rules
from src.storage import init_db, store_alerts

ROOT = os.path.join(os.path.dirname(__file__), "..")
RULES = load_rules(os.path.join(ROOT, "rules"))


def ev(minutes, event_type, ip=None, user=None, base=datetime(2026, 11, 20, 10, 0, 0)):
    return {"raw": "synthetic", "timestamp": base + timedelta(minutes=minutes),
            "host": "web01", "service": "sshd", "user": user, "src_ip": ip,
            "message": "", "event_type": event_type}


def rule(rule_id):
    return next(r for r in RULES if r.id == rule_id)


class TestParser(unittest.TestCase):
    def test_failed_login_parsed(self):
        e = parse_line("Nov 20 10:15:32 web01 sshd[2140]: Failed password for "
                       "invalid user admin from 203.0.113.45 port 22 ssh2")
        self.assertEqual(e["event_type"], "failed_login")
        self.assertEqual(e["user"], "admin")
        self.assertEqual(e["src_ip"], "203.0.113.45")
        self.assertEqual(e["timestamp"], datetime(2026, 11, 20, 10, 15, 32))

    def test_accepted_login_parsed(self):
        e = parse_line("Nov 20 10:16:01 web01 sshd[2140]: Accepted password "
                       "for alice from 203.0.113.10 port 22 ssh2")
        self.assertEqual(e["event_type"], "successful_login")
        self.assertEqual(e["user"], "alice")

    def test_sudo_failure_parsed(self):
        e = parse_line("Nov 20 10:20:11 web01 sudo: bob : user NOT in sudoers ; "
                       "TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/id")
        self.assertEqual(e["event_type"], "sudo_failure")
        self.assertEqual(e["user"], "bob")

    def test_blank_and_garbage_lines_do_not_crash(self):
        self.assertIsNone(parse_line(""))
        self.assertIsNotNone(parse_line("not a syslog line at all"))


class TestRules(unittest.TestCase):
    def test_all_six_rules_load_with_mitre(self):
        self.assertEqual(len(RULES), 6)
        ids = {r.id for r in RULES}
        self.assertEqual(ids, {"R001", "R002", "R003", "R004", "R005", "R006"})
        for r in RULES:
            self.assertTrue(r.mitre_technique.startswith("T"),
                            f"{r.id} missing MITRE technique")

    def test_risk_score_scales_and_caps_at_100(self):
        r = rule("R002")  # critical, base 90
        self.assertEqual(r.risk_score(1), 90)
        self.assertEqual(r.risk_score(99), 100)


class TestDetector(unittest.TestCase):
    def test_brute_force_fires_at_threshold(self):
        events = [ev(i, "failed_login", "203.0.113.45", f"user{i}") for i in range(5)]
        alerts = detect(events, RULES)
        r001 = [a for a in alerts if a["rule_id"] == "R001"]
        self.assertEqual(len(r001), 1)
        self.assertEqual(r001[0]["mitre_technique"], "T1110.001")
        self.assertGreaterEqual(r001[0]["risk_score"], 75)

    def test_four_failures_do_not_fire(self):
        events = [ev(i, "failed_login", "203.0.113.45", f"user{i}") for i in range(4)]
        self.assertEqual([a for a in detect(events, RULES) if a["rule_id"] == "R001"], [])

    def test_root_login_fires(self):
        events = [ev(0, "successful_login", "198.51.100.23", "root")]
        alerts = detect(events, RULES)
        self.assertEqual([a["rule_id"] for a in alerts], ["R003"])

    def test_impossible_travel_fires(self):
        events = [ev(0, "successful_login", "203.0.113.10", "alice"),   # PK
                  ev(25, "successful_login", "198.51.100.10", "alice")]  # US
        alerts = detect(events, RULES)
        self.assertTrue(any(a["rule_id"] == "R005" for a in alerts))

    def test_same_country_logins_do_not_fire_impossible_travel(self):
        events = [ev(0, "successful_login", "203.0.113.10", "alice"),
                  ev(25, "successful_login", "203.0.113.45", "alice")]
        self.assertEqual([a for a in detect(events, RULES) if a["rule_id"] == "R005"], [])

    def test_sudo_abuse_fires(self):
        events = [ev(i * 2, "sudo_failure", None, "bob") for i in range(3)]
        alerts = detect(events, RULES)
        self.assertTrue(any(a["rule_id"] == "R006" for a in alerts))

    def test_success_after_bruteforce_fires(self):
        events = ([ev(i, "failed_login", "203.0.113.45", f"u{i}") for i in range(5)]
                  + [ev(6, "successful_login", "203.0.113.45", "admin")])
        self.assertTrue(any(a["rule_id"] == "R002" for a in detect(events, RULES)))


class TestEndToEnd(unittest.TestCase):
    def test_sample_log_produces_all_six_rules(self):
        events = parse_file(os.path.join(ROOT, "logs", "sample_auth.log"))
        self.assertGreaterEqual(len(events), 120)
        alerts = detect(events, RULES)
        found = {a["rule_id"] for a in alerts}
        self.assertEqual(found, {"R001", "R002", "R003", "R004", "R005", "R006"},
                         f"missing rules, got {found}: {alerts}")
        html = generate_html(alerts, events)
        self.assertIn("SOC Sentinel Lite", html)
        self.assertIn("T1110.001", html)
        conn = init_db(":memory:")
        inserted, skipped = store_alerts(conn, alerts)
        self.assertEqual(inserted, len(alerts))
        inserted2, skipped2 = store_alerts(conn, alerts)  # dedup on re-ingest
        self.assertEqual((inserted2, skipped2), (0, len(alerts)))


if __name__ == "__main__":
    unittest.main()
