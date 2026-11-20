"""Tests for SOC Sentinel v2 — Sentinel Graph attack-chain reconstruction.

Run with:  python3 -m unittest discover -s tests -v
(v1 tests in test_detector.py must still pass alongside these.)
"""

import copy
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.baseline import Baseline
from src.chain import detect_brute_force_clusters, reconstruct_chains
from src.detector import detect as v1_detect
from src.graph import build_graph
from src.parser import parse_file
from src.report_v2 import generate_incident_html
from src.rules import load_rules
from src.scoring_v2 import feedback_multiplier, load_feedback, score_chains

ROOT = os.path.join(os.path.dirname(__file__), "..")
RULES = load_rules(os.path.join(ROOT, "rules"))
HISTORY = parse_file(os.path.join(ROOT, "logs", "history_7d.log"))
BASELINE = Baseline(HISTORY)


def ev(minutes, event_type, ip=None, user=None, host="web01",
       base=datetime(2026, 11, 21, 0, 0, 0), message="", sudo_detail=""):
    return {"raw": f"synthetic {event_type} {user} {ip} {host}",
            "timestamp": base + timedelta(minutes=minutes),
            "host": host, "service": "sshd", "user": user, "src_ip": ip,
            "message": message, "event_type": event_type,
            "sudo_detail": sudo_detail}


def chains_for(events):
    return reconstruct_chains(events, BASELINE)


def scored(events, feedback=None):
    chains = chains_for(events)
    return score_chains(chains, BASELINE, events, feedback or [])


class TestSlowAndDistributed(unittest.TestCase):
    def test_slow_brute_force_detected(self):
        # 9 failures, ~1.5/hour over 5+ hours, one IP — v1 never fires.
        events = [ev(m, "failed_login", "203.0.113.77", "deploy")
                  for m in (0, 40, 80, 120, 160, 200, 240, 280, 320)]
        events.append(ev(330, "successful_login", "203.0.113.77", "deploy"))
        clusters = detect_brute_force_clusters(events)
        self.assertEqual(len(clusters), 1)
        self.assertEqual(clusters[0]["subtype"], "slow")
        self.assertEqual(clusters[0]["count"], 9)
        self.assertEqual([a for a in v1_detect(events, RULES)
                          if a["rule_id"] == "R001"], [],
                         "v1 must miss a slow brute force")
        incidents, _ = scored(events)
        self.assertEqual(len(incidents), 1)

    def test_distributed_brute_force_detected(self):
        # Same user, 3 IPs, 9 failures in 80 minutes — no single IP is loud.
        ips = ["203.0.113.77", "192.0.2.88", "198.51.100.99"]
        events = [ev(m * 10, "failed_login", ips[m % 3], "deploy") for m in range(9)]
        events.append(ev(100, "successful_login", ips[0], "deploy"))
        clusters = detect_brute_force_clusters(events)
        self.assertEqual(len(clusters), 1)
        self.assertEqual(clusters[0]["subtype"], "distributed")
        self.assertEqual(len(clusters[0]["ips"]), 3)

    def test_fast_brute_force_still_detected(self):
        events = [ev(m, "failed_login", "203.0.113.77", "deploy") for m in range(5)]
        events.append(ev(6, "successful_login", "203.0.113.77", "deploy"))
        clusters = detect_brute_force_clusters(events)
        self.assertEqual(clusters[0]["subtype"], "fast")


class TestAdvancedChain(unittest.TestCase):
    def setUp(self):
        self.events = parse_file(os.path.join(ROOT, "logs", "advanced_chain.log"))

    def test_advanced_chain_links_five_stages(self):
        chains = chains_for(self.events)
        self.assertEqual(len(chains), 1, f"expected 1 chain, got {chains}")
        chain = chains[0]
        self.assertEqual(chain["chain_length"], 5)
        self.assertEqual(chain["stage_names"],
                         ["brute_force", "initial_access", "privilege_escalation",
                          "lateral_movement", "data_staging"])
        self.assertEqual(chain["mitre_sequence"],
                         ["T1110.001", "T1078", "T1548.003", "T1021.004", "T1074"])

    def test_advanced_chain_is_one_incident_not_seven_alerts(self):
        incidents, suppressed = scored(self.events)
        self.assertEqual(len(incidents), 1)
        self.assertEqual(suppressed, [])
        inc = incidents[0]
        self.assertEqual(inc["risk_score"], 100)
        self.assertEqual(inc["severity"], "critical")
        self.assertIn("db01", inc["hosts"])
        self.assertEqual(len(inc["ips"]), 3)

    def test_advanced_chain_v1_misses_the_brute_force(self):
        alerts = v1_detect(self.events, RULES)
        ids = {a["rule_id"] for a in alerts}
        self.assertNotIn("R001", ids, "v1 must not see the slow/distributed brute force")
        self.assertNotIn("R002", ids, "v1 must not see the login after it")

    def test_chain_incident_has_timespan_and_mitre(self):
        incidents, _ = scored(self.events)
        inc = incidents[0]
        self.assertLess(inc["first_seen"], inc["last_seen"])
        self.assertEqual(len(inc["mitre_sequence"]), 5)
        self.assertTrue(inc["incident_id"].startswith("INC-DEPLOY-"))


class TestNormalUser(unittest.TestCase):
    def test_normal_user_not_flagged(self):
        events = parse_file(os.path.join(ROOT, "logs", "normal_user.log"))
        incidents, suppressed = scored(events)
        self.assertEqual(incidents, [])
        self.assertEqual(len(suppressed), 1)
        self.assertEqual(suppressed[0]["user"], "alice")
        self.assertLess(suppressed[0]["risk_score"], 40)

    def test_normal_user_v1_false_positive(self):
        # v1 fires critical alerts for alice *and* for bob/carol, who
        # did nothing — same IP, same 30-minute window. That is the
        # false-positive problem v2 exists to fix.
        events = parse_file(os.path.join(ROOT, "logs", "normal_user.log"))
        alerts = v1_detect(events, RULES)
        r002 = [a for a in alerts if a["rule_id"] == "R002"]
        self.assertGreaterEqual(len(r002), 1)
        self.assertTrue(all(a["severity"] == "critical" for a in r002))


class TestBaseline(unittest.TestCase):
    def test_history_baseline_learns_alice(self):
        self.assertGreaterEqual(len(HISTORY), 1900)
        self.assertIn("alice", BASELINE.users)
        self.assertIn("web01", BASELINE.users["alice"]["hosts"])
        self.assertIn("203.0.113.10", BASELINE.users["alice"]["ips"])
        self.assertTrue(all(8 <= h <= 18 for h in BASELINE.users["alice"]["hour_set"]))

    def test_baseline_normal_login_low_deviation(self):
        e = ev(600, "successful_login", "203.0.113.10", "alice")  # 10:00, usual IP/host
        score, reasons = BASELINE.score_event(e)
        self.assertLess(score, 0.3, f"normal login scored {score}: {reasons}")

    def test_baseline_off_hours_unseen_high_deviation(self):
        e = ev(120, "successful_login", "203.0.113.77", "deploy", host="db01")  # 02:00, unseen
        score, reasons = BASELINE.score_event(e)
        self.assertGreaterEqual(score, 0.6, f"attacker login scored {score}: {reasons}")


class TestScoringAndFeedback(unittest.TestCase):
    def test_five_stage_chain_scores_higher_than_two_stage(self):
        adv = parse_file(os.path.join(ROOT, "logs", "advanced_chain.log"))
        norm = parse_file(os.path.join(ROOT, "logs", "normal_user.log"))
        adv_inc, _ = scored(adv)
        _, norm_sup = scored(norm)
        self.assertGreater(adv_inc[0]["risk_score"], norm_sup[0]["risk_score"])

    def test_feedback_reduces_score(self):
        events = parse_file(os.path.join(ROOT, "logs", "advanced_chain.log"))
        chains = chains_for(events)
        no_fb, _ = score_chains(copy.deepcopy(chains), BASELINE, events, [])
        fb = [{"user": "deploy", "pattern": "brute_force",
               "verdict": "false_positive", "weight": 0.4,
               "note": "test feedback"}]
        with_fb, _ = score_chains(copy.deepcopy(chains), BASELINE, events, fb)
        # Raw score is capped at 100, so a 0.4 feedback weight on a
        # 100-point chain lands at ~81 (201.6 * 0.4), not 40 — the
        # reduction is still real and auditable, just capped at the top.
        self.assertLess(with_fb[0]["risk_score"], no_fb[0]["risk_score"])
        self.assertLessEqual(with_fb[0]["risk_score"], 85)
        self.assertEqual(with_fb[0]["feedback_multiplier"], 0.4)
        self.assertIsNotNone(with_fb[0]["feedback_applied"])

    def test_feedback_multiplier_no_match_is_one(self):
        chain = {"user": "deploy", "stage_names": ["brute_force"],
                 "brute_force_subtype": "slow"}
        mult, entry = feedback_multiplier(
            chain, [{"user": "alice", "pattern": "brute_force",
                     "verdict": "false_positive", "weight": 0.4}])
        self.assertEqual((mult, entry), (1.0, None))

    def test_empty_feedback_file_loads_cleanly(self):
        self.assertEqual(load_feedback("/tmp/does-not-exist-feedback.json"), [])
        fb = load_feedback(os.path.join(ROOT, "incidents", "feedback.json"))
        self.assertIsInstance(fb, list)
        self.assertGreaterEqual(len(fb), 1)


class TestGraph(unittest.TestCase):
    def test_graph_export_valid(self):
        events = parse_file(os.path.join(ROOT, "logs", "advanced_chain.log"))
        g = build_graph(events)
        data = g.to_dict()
        self.assertIn("nodes", data)
        self.assertIn("edges", data)
        self.assertIn("summary", data)
        ids = {n["id"] for n in data["nodes"]}
        self.assertIn("user:deploy", ids)
        self.assertIn("host:db01", ids)
        self.assertIn("ip:203.0.113.77", ids)
        self.assertGreater(len(data["edges"]), 0)
        self.assertEqual(data["summary"]["nodes"], len(data["nodes"]))

    def test_graph_round_trip_save_load(self):
        from src.graph import TemporalGraph
        events = parse_file(os.path.join(ROOT, "logs", "advanced_chain.log"))
        g = build_graph(events)
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "graph.json")
            g.save(path)
            g2 = TemporalGraph.load(path)
            self.assertEqual(len(g2.nodes), len(g.nodes))
            self.assertEqual(len(g2.edges), len(g.edges))
            with open(path, encoding="utf-8") as fh:
                self.assertEqual(json.load(fh)["summary"]["nodes"], len(g.nodes))

    def test_v2_report_renders_incident(self):
        events = parse_file(os.path.join(ROOT, "logs", "advanced_chain.log"))
        incidents, suppressed = scored(events)
        g = build_graph(events)
        html = generate_incident_html(incidents, suppressed, g.summary(),
                                      BASELINE.summary(), len(events))
        self.assertIn("INC-DEPLOY-", html)
        self.assertIn("T1110.001", html)
        self.assertIn("Data Staged", html)


if __name__ == "__main__":
    unittest.main()
